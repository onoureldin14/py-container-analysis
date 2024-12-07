import subprocess
import json
import logging
import requests
import re


def check_latest(vulnerability, step_messages):
    """
    Checks if the image is the latest for the specified vulnerability.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        step_messages (dict): Step messages containing the pass and fail criteria.

    Returns:
        dict: Result of the latest image check.
    """
    image_type = vulnerability.get("base_img_type", "")

    # Determine which function to call based on the image type
    if image_type == "dotnet":
        return check_dotnet_latest(vulnerability, step_messages)
    else:
        return check_nginx_latest(vulnerability, step_messages)


def check_dotnet_latest(vulnerability, step_messages):
    """
    Checks if the base image is the latest by the .NET team using the PowerShell script.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    image = vulnerability.get("base_img", "")
    image_url = vulnerability.get("image_url", "")

    try:
        command = f"curl -sSL https://raw.githubusercontent.com/dotnet/dotnet-docker/main/documentation/scripts/check-latest-base.ps1 | pwsh /dev/stdin {image_url} {image}"
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )

        if "True" in result.stdout:
            return {"success": True, "message": step_messages["PASS"]["message"]}
        else:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": f"Not using DOTNET Latest Image. {step_messages['FAIL']['recommendation']}",
            }
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute .NET latest check: {str(e)}")
        raise


def get_nginx_image_version(image_hash: str) -> str:
    """
    Inspect the Docker image and extract the NGINX_VERSION from the environment variables.

    Parameters:
    - image_hash (str): Docker image hash.

    Returns:
    - str: The version of NGINX from the Docker image environment variables.
    """
    # Run docker inspect command to get image details
    result = subprocess.run(
        ["docker", "inspect", image_hash], capture_output=True, text=True
    )

    if result.returncode != 0:
        logging.error(f"Failed to inspect Docker image: {result.stderr}")
        raise RuntimeError(f"Failed to inspect Docker image: {result.stderr}")

    # Load the JSON output from the inspect command
    image_info = json.loads(result.stdout)
    if not image_info:
        raise ValueError("Empty or invalid inspect data")

    # Extract the environment variables from the Config section
    env_vars = image_info[0].get("Config", {}).get("Env", [])
    nginx_version = None

    # Search for NGINX_VERSION in environment variables
    for env in env_vars:
        if env.startswith("NGINX_VERSION="):
            nginx_version = env.split("=")[1]
            break

    if not nginx_version:
        raise RuntimeError("NGINX_VERSION not found in environment variables")

    return nginx_version


def check_nginx_latest(vulnerability: dict, step_messages: dict) -> dict:
    """
    Check if the provided nginx image is the latest available for a specified architecture on Docker Hub.
    Then, compare the image version against a local version.

    Parameters:
    - vulnerability (dict): A dictionary containing image details, with 'image_url' and 'base_img_arch' keys.
    - step_messages (dict): A dictionary containing pass/fail messages and recommendations.

    Returns:
    - dict: A dictionary containing 'success', 'message', and optional 'recommendation' keys.
    """
    image_url = vulnerability.get("image_url", "")
    architecture = vulnerability.get("base_img_arch", "")
    local_version = vulnerability.get("nginx_version", "")

    # Extract current digest from image URL
    digest_match = re.search(r"@sha256:[a-fA-F0-9]+", image_url)
    if not digest_match:
        logging.error("Invalid image digest format.")
        raise

    image_name = "nginx"
    url = f"https://registry.hub.docker.com/v2/repositories/library/{image_name}/tags/latest"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            images = response.json().get("images", [])
            latest_digest = None
            for image in images:
                if image.get("architecture") == architecture:
                    latest_digest = image.get("digest")
                    break

            if not latest_digest:
                logging.error(f"No image found for architecture {architecture}.")
                raise

            # Check if the latest image is already cached locally
            local_image_check = subprocess.run(
                ["docker", "inspect", f"{image_name}@{latest_digest}"],
                capture_output=True,
                text=True,
            )

            if local_image_check.returncode == 0:
                logging.info(
                    f"Image {image_name}@{latest_digest} is already cached locally."
                )
            else:
                # Pull the latest image if not cached locally
                pull_result = subprocess.run(
                    ["docker", "pull", f"{image_name}@{latest_digest}"],
                    capture_output=True,
                    text=True,
                )
                if pull_result.returncode != 0:
                    logging.error(f"Failed to pull image: {pull_result.stderr}")
                    raise

            # Compare the pulled or cached image version with the local version
            latest_version = get_nginx_image_version(latest_digest)
            if latest_version == local_version:
                return {"success": True, "message": step_messages["PASS"]["message"]}
            else:
                return {
                    "success": False,
                    "message": step_messages["FAIL"]["message"],
                    "recommendation": f"{step_messages['FAIL']['recommendation']}. Re-build the nginx container to upgrade from version {local_version} to version {latest_version}",
                }
        else:
            logging.error(f"Failed to query Dockerhub Registry: {response.text}")
            raise

    except Exception as e:
        logging.error(f"Failed to check if nginx image is latest: {e}")
        raise
