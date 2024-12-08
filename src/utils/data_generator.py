import json
import logging
import re
import subprocess
import boto3
from botocore.exceptions import ClientError
import logging
import requests
from src.utils.snyk_handler import SnykHandler
from src.config.snyk_config import SnykConfig
from src.constants import file_name_constants, url_constants, snyk_constants
from src.utils.config_loader import ConfigLoader
from src.constants.aws_constants import AWSConstants
from src.utils.eks_handler import EKSHandler
from src.config.aws_config import AWSConfig


class DataGenerator:
    def __init__(self):
        self.config = ConfigLoader.load_config("config.yaml")
        self.region = AWSConstants.AWS_REGION
        self.account_id = self.config["aws"]["account_id"]
        self.repo_url = f"{self.account_id }.dkr.ecr.{self.region}.amazonaws.com"

    def enrich_issue(self, issue):
        """
        Helper function to dynamically fetch and populate issue fields.
        """
        project_name = issue["project_name"]

        # Fetch and populate fields
        issue["image_url"] = issue.get("image_url", self.get_img_from_ecr(project_name))
        (
            issue["base_img"],
            issue["base_img_type"],
            issue["nginx_version"],
        ) = (
            issue.get("base_img", None),
            issue.get("base_img_type", None),
            issue.get("nginx_version", None)
            or self.get_image_base_ref_name(project_name),
        )
        issue["base_img_os"] = issue.get(
            "base_img_os", self.img_os_checker(issue["image_url"])
        )
        issue["base_img_arch"] = issue.get(
            "base_img_arch", self.get_image_architecture(issue["image_url"])
        )

        if issue["base_img_os"] == "linux":
            (
                issue["base_img_os_id"],
                issue["base_img_os_version"],
            ) = (
                issue.get("base_img_os_id"),
                issue.get("base_img_os_version"),
            ) or self.linux_base_img_details(
                project_name, issue["image_url"], issue["base_img"]
            )
        return issue

    def generate_project_data_json(self):
        snyk_api_scan_enabled = str(self.config["snyk"]["snyk_api_enabled"]).lower()
        enriched_project_issues = []
        EKS_ECR_OUTPUT_FILE = file_name_constants.EKS_ECR_OUTPUT_FILE
        DEBIAN_URL = url_constants.DEBIAN_URL
        DEBIAN_VULNS_OUTPUT_FILE = file_name_constants.DEBIAN_VULNS_OUTPUT_FILE
        PROJECT_ISSUE_OUTPUT_FILE = file_name_constants.PROJECT_LIST_JSON_FILE_PATH
        self.ecr_login()

        debian_data_set = self.download_debian_security_tracker(
            DEBIAN_URL, DEBIAN_VULNS_OUTPUT_FILE
        )
        check_latest_ecr_in_eks = str(
            self.config["deployment"]["check_latest_ecr_in_eks"]
        ).lower()

        if check_latest_ecr_in_eks == "true":
            logging.info(
                "EKS check is enabled. Comparing ECR images to versions in EKS"
            )
            latest_image_versions_json = self.get_latest_ecr_img(EKS_ECR_OUTPUT_FILE)
        else:
            latest_image_versions_json = None
            logging.info("EKS check is disabled. Skipping Latest ECR image check.")

        if snyk_api_scan_enabled == "true":
            logging.info(
                "Snyk API scan is enabled. Fetching project issues from Snyk API."
            )
            snyk_config_handler = SnykConfig(self.config)
            SNYK_ORG_ID = snyk_config_handler.get_snyk_org_id()
            SNYK_API_TOKEN = snyk_config_handler.get_snyk_api_token()
            LIMIT_PROJECTS = snyk_constants.LIMIT_PROJECTS
            SEVERITY_SELECTION = snyk_constants.SEVERITY_SELECTION
            PROJECT_FILTER = snyk_constants.PROJECT_FILTER

            snyk_handler = SnykHandler(SNYK_API_TOKEN, SNYK_ORG_ID)

            scanner_project_issues = snyk_handler.get_project_issues(
                project_selection=LIMIT_PROJECTS,
                severity_selection=SEVERITY_SELECTION,
                project_name_filter=PROJECT_FILTER,
            )

            self.ecr_login()

            for issue in scanner_project_issues:
                enriched_project_issues.append(self.enrich_issue(issue))

            with open(PROJECT_ISSUE_OUTPUT_FILE, "w") as json_file:
                json.dump(enriched_project_issues, json_file, indent=4)

            logging.info(f"Generated project JSON saved to {PROJECT_ISSUE_OUTPUT_FILE}")

        else:
            logging.info(
                "Snyk API scan is disabled. Fetching project issues from local file."
            )
            try:
                with open(PROJECT_ISSUE_OUTPUT_FILE, "r") as json_file:
                    loaded_data = json.load(json_file)
                    for issue in loaded_data:
                        enriched_project_issues.append(self.enrich_issue(issue))
            except FileNotFoundError:
                logging.error(
                    f"File {PROJECT_ISSUE_OUTPUT_FILE} does not exist. No project issues to load."
                )
                raise FileNotFoundError

        return enriched_project_issues, latest_image_versions_json, debian_data_set

    def get_img_from_ecr(self, project_name):
        """
        Gets the ECR image data by fetching the image digest for the specified repository and image tag using boto3.

        Args:
            repository_name (str): The name of the ECR repository.
            image_tag (str): The tag of the image.

        Returns:
            str: The ECR image URL with the digest, or None if the image is not found.
        """

        try:
            repository_name, image_tag = project_name.split(":")
        except ValueError:
            logging.error(
                f"Invalid project name format: {project_name}. Expected format 'repository_name:image_tag'."
            )
            raise

        logging.info(
            f"Fetching ECR image data for repository: {repository_name}, image tag: {image_tag}"
        )

        ecr_client = boto3.client("ecr", region_name=self.region)

        try:
            response = ecr_client.describe_images(
                repositoryName=repository_name, imageIds=[{"imageTag": image_tag}]
            )

            image_digest = response["imageDetails"][0]["imageDigest"]
            registry = self.repo_url
            image_url = f"{registry}/{repository_name}@{image_digest}"
            logging.info(f"Retrieved image URL: {image_url}")

            return image_url

        except ClientError as e:
            logging.error(
                f"Failed to fetch image data for {repository_name} with tag {image_tag}: {e}"
            )
            raise

    def ecr_login(self):
        """
        Logs into AWS ECR using the AWS CLI.
        """
        try:
            command = f"aws ecr get-login-password --region {self.region} | docker login --username AWS --password-stdin {self.repo_url}"
            subprocess.run(command, shell=True, check=True)
            logging.info(f"Logged into ECR for repo: {self.repo_url}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to log in to ECR: {e}")
            raise

    def docker_pull(self, image):
        """
        Pulls a Docker image from a repository.
        """
        try:
            command = f"docker pull {self.repo_url}/{image}"
            subprocess.run(command, shell=True, check=True)
            logging.info(f"Successfully pulled image: {image}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to pull image {image}: {e}")
            raise

    def get_image_base_ref_name(self, image):
        """
        Retrieves the .NET base image reference name from Docker image labels.
        """
        try:
            command = f"docker inspect {self.repo_url}/{image}"
            result = subprocess.run(
                command, shell=True, check=True, capture_output=True, text=True
            )
            inspect_data = json.loads(result.stdout)
            base_img = inspect_data[0]["Config"]["Labels"].get(
                "image.base.ref.name", ""
            )
            base_img_type = "dotnet"
            nginx_version = None
            if not base_img.startswith("mcr"):
                base_img_type = "nginx"
                env_vars = inspect_data[0]["Config"].get("Env", [])
                for env in env_vars:
                    if env.startswith("NGINX_VERSION="):
                        nginx_version = env.split("=")[1]
                        break
            logging.info(
                f"Retrieved .NET base image ref name: {base_img} for image: {image}"
            )
            return base_img, base_img_type, nginx_version
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to inspect image {image}: {e}")
            raise

    def img_os_checker(self, image_url):
        """
        Retrieves the Container OS.
        """
        try:
            command = ["docker", "pull", image_url]
            subprocess.run(command, capture_output=True, text=True, check=True)
            img_os = "linux"
        except subprocess.CalledProcessError as e:
            img_os = "windows"

        return img_os

    def linux_base_img_details(self, project_name, image_url, base_img):
        """
        Checks the linux os base image.
        """

        try:
            command = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "cat",
                image_url,
                "/etc/os-release",
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            os_info = dict(
                line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
            )

            base_img_os_id = os_info.get("ID", "").strip('"')
            if base_img_os_id == "alpine":
                match = re.search(r"alpine([\d\w.-]+)", base_img)
                base_img_os_version = match.group(1)
            elif base_img_os_id == "debian":
                base_img_os_version = os_info.get("VERSION_CODENAME", "").strip('"')

            return base_img_os_id, base_img_os_version

        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to check Linux OS details for {project_name}: {e}")
            raise

    def get_image_architecture(self, image_url):
        """
        Retrieves the architecture type of a Docker image (e.g., ARM, AMD).

        Args:
            image_url (str): The URL of the Docker image.

        Returns:
            str: The architecture type of the image.
        """
        try:
            command = ["docker", "inspect", "--format='{{.Architecture}}'", image_url]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            architecture = result.stdout.strip().strip("'")
            logging.info(
                f"Retrieved architecture type: {architecture} for image: {image_url}"
            )
            return architecture
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to retrieve architecture type for {image_url}: {e}")
            raise

    def download_debian_security_tracker(self, debian_url, debian_json_file_path):
        """
        Downloads JSON data from the specified URL and saves it to a local file.
        """
        try:
            response = requests.get(debian_url)
            response.raise_for_status()

            debian_data_set = response.json()

            with open(debian_json_file_path, "w", encoding="utf-8") as file:
                json.dump(debian_data_set, file, indent=4, ensure_ascii=False)
            logging.info(
                f"Debian Security Tracker JSON data has been downloaded and saved to {debian_json_file_path}"
            )

            return debian_data_set

        except requests.exceptions.RequestException as e:
            logging.error(f"An error occurred while downloading DEBINA JSON data: {e}")
            raise

    def env_checker(self):
        deploy_value = str(self.config["deployment"]["multi_cluster_scan"]).lower()
        is_multi_cluster = ConfigLoader.validate_deploy_value(deploy_value)

        if is_multi_cluster:
            aws_handler = AWSConfig(env="prod", config=self.config)
            aws_account = aws_handler.get_aws_config()
            kube_context = aws_handler.get_kube_context()
            namespace_to_scan_1 = aws_account["kube_namespace"]

            prod_2_handler = AWSConfig(env="prod_2", config=self.config)
            prod_2_account = prod_2_handler.get_aws_config()
            prod_2_kube_context = prod_2_handler.get_kube_context()
            namespace_to_scan_2 = prod_2_account["kube_namespace"]
        else:
            aws_handler = AWSConfig(env="dev", config=self.config)
            aws_account = aws_handler.get_aws_config()
            kube_context = aws_handler.get_kube_context()
            namespace_to_scan_1 = aws_account["kube_namespace"]
            namespace_to_scan_2 = aws_account["kube_namespace_2"]

        return {
            "is_multi_cluster": is_multi_cluster,
            "aws_env": "prod" if is_multi_cluster else "dev",
            "kube_context": kube_context,
            "namespace_to_scan_1": namespace_to_scan_1,
            "prod_2_kube_context": prod_2_kube_context
            if is_multi_cluster
            else kube_context,
            "namespace_to_scan_2": namespace_to_scan_2,
        }

    def get_latest_ecr_img(self, eks_ecr_file_path: str):
        eks_handler = EKSHandler()
        env_details = self.env_checker()

        aws_env = env_details["aws_env"]
        logging.info(f"AWS environment: {aws_env}")

        try:
            SCANNED_CLUSTER_CONTEXT_1 = env_details["kube_context"]
            SCANNED_NAMESPACE_1 = env_details["namespace_to_scan_1"]

            SCANNED_CLUSTER_CONTEXT_2 = env_details["prod_2_kube_context"]
            SCANNED_NAMESPACE_2 = env_details["namespace_to_scan_2"]

            logging.info("Fetching Latest ECR data...")

            ecr_data = eks_handler.get_ecr_data_from_eks(
                SCANNED_CLUSTER_CONTEXT_1,
                SCANNED_CLUSTER_CONTEXT_2,
                SCANNED_NAMESPACE_1,
                SCANNED_NAMESPACE_2,
            )
            ecr_combined_versions = sorted(ecr_data.get("ecr_image_versions", []))
            with open(eks_ecr_file_path, "w") as json_file:
                json.dump(ecr_combined_versions, json_file, indent=4)

            logging.info(
                f"EKS ECR Image JSON data has been downloaded and saved to {eks_ecr_file_path}"
            )

            return ecr_combined_versions

        except Exception as e:
            logging.error(f"Failed to fetch latest ECR data: {e}")
            raise
