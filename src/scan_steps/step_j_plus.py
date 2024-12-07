import logging
import re
import requests
import os
import json
from src.constants import file_name_constants, url_constants
from src.utils.calculate_similarity import calculate_similarity


def check_distro_fix(vulnerability, debian_data, step_messages):
    """
    Checks if CVE has a fix in the distro.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        step_messages (dict): Step messages containing the pass and fail criteria.

    Returns:
        dict: Result of the latest image check.
    """
    image_type = vulnerability.get("base_img_os_id", "")

    # Determine which function to call based on the image type
    if image_type == "debian":
        return check_debian_distro_fix(vulnerability, debian_data, step_messages)
    elif image_type == "alpine":
        return check_alpine_distro_fix(vulnerability, step_messages)

    return {
        "success": True,
        "message": "Step has been skipped due to the base image not Debian or Alpine",
    }


def download_alpine_security_tracker(vulnerability):
    """
    Downloads JSON data from the specified URL and saves it to a local file.
    """
    try:
        ALPINE_VERSION = re.match(
            r"^\d+(\.\d+)*", vulnerability.get("base_img_os_version")
        ).group()
        ALPINE_URL = f"{url_constants.ALPINE_URL}/v{ALPINE_VERSION}/main.json"
        ALPINE_DATASET_FILE_PATH = (
            f"{file_name_constants.ALPINE_VULNS_OUTPUT_FILE}_v{ALPINE_VERSION}.json"
        )

        if os.path.exists(ALPINE_DATASET_FILE_PATH):
            logging.info(
                f"Alpine Data already exists at {ALPINE_DATASET_FILE_PATH}. Skipping download."
            )
            return ALPINE_DATASET_FILE_PATH

        response = requests.get(ALPINE_URL)
        response.raise_for_status()

        alpine_data_set = response.json()

        with open(ALPINE_DATASET_FILE_PATH, "w", encoding="utf-8") as file:
            json.dump(alpine_data_set, file, indent=4, ensure_ascii=False)
        logging.info(
            f"Alpine Security Tracker JSON data has been downloaded and saved to {ALPINE_DATASET_FILE_PATH}"
        )
        return ALPINE_DATASET_FILE_PATH

    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while downloading ALPINE JSON data: {e}")
        raise


def check_alpine_distro_fix(vulnerability, step_messages):
    """
    Checks the downloaded JSON file for the given vulnerability data and recommends a package upgrade if necessary.

    Parameters:
    - vulnerability (dict): The dictionary containing package and CVE information.

    Returns:
    - str: A recommendation message for upgrading the package if the CVE is found, otherwise None.
    """
    # Extract details from the vulnerability dictionary
    cve = vulnerability.get("issue_cve")[0]
    package_full_name = vulnerability.get("package_name")
    package_name = package_full_name.split("/")[0].lower()
    package_version_id = vulnerability.get("package_version")[0]

    if not cve or not package_name or not package_version_id:
        logging.error(
            "Alpine SecFix Processing Error: Missing required data. Ensure 'cve', 'package_name', 'package_version_id' are present."
        )
        raise

    try:
        # Call the JSON download function to ensure the file exists
        json_file_path = download_alpine_security_tracker(vulnerability)

        # Load the JSON data from the file
        with open(json_file_path, "r", encoding="utf-8") as file:
            alpine_data = json.load(file)

        # Search for the package in the JSON data
        for package in alpine_data.get("packages", []):
            pkg_details = package.get("pkg", {})

            if pkg_details.get("name") == package_name:
                secfixes = pkg_details.get("secfixes", {})

                # Check each version's CVE list for the given CVE ID
                for version, cve_list in secfixes.items():
                    if cve in cve_list:
                        recommendation = f"The package {package_full_name} should be upgraded from version {package_version_id} to {version} to address CVE: {cve}."
                        return {
                            "success": False,
                            "message": step_messages["FAIL"]["message"],
                            "recommendation": recommendation,
                        }

        return {
            "success": True,
            "message": step_messages["PASS"]["message"],
        }
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON file: {json_file_path}")
    except Exception as e:
        logging.error(f"An error occurred while processing the Alpine JSON data: {e}")
        raise


def fetch_cve_details(cve_id, debian_data_set):
    """
    Fetches all occurrences of a specific CVE from the locally stored JSON data, searching through all packages.

    Args:
    - cve_id (str): The CVE ID to search for.

    Returns:
    - list: A list of dictionaries containing the details of the CVE if found, otherwise an empty list.
    """
    matches = []

    try:
        for package, cves in debian_data_set.items():
            if cve_id in cves:
                cve_details = cves[cve_id]
                match = {"package": package, "details": cve_details}
                matches.append(match)
        return matches
    except Exception as e:
        logging.error(f"An error with Debian Data Set occurred: {e}")
        raise


def find_closest_match(
    version1: str, version2: list, cve: str, threshold: float = 80.0
):
    """
    Find the closest version match from a list of versions with a similarity higher than the specified threshold.

    Args:
        version1 (str): The version string to compare against.
        version2 (str): The version string to compare.
        threshold (float): The similarity threshold percentage.

    Returns:
        tuple or False: The closest matching version and its similarity percentage if above threshold, otherwise None.
    """

    try:
        similarity = calculate_similarity(version1, version2)

        if similarity >= threshold:
            return version2, similarity

        return False
    except Exception as e:
        logging.error(
            f"Failed calculate similarity for {cve} between {version1} and {version2}: {e}"
        )
        raise


def check_debian_distro_fix(vulnerability, debian_data, step_messages):
    """
    Checks if the package version from PROJECT_ISSUES matches any fixed or unfixed status
    in the Debian security tracker data.
    """
    cve = vulnerability.get("issue_cve", [""])[0]
    package_name = vulnerability.get("package_name", "").split("/")[0].lower()
    package_version = vulnerability.get("package_version", [""])[0]

    debian_matched_data = fetch_cve_details(cve, debian_data)

    if not debian_matched_data:
        recommendation = f" {cve} not matched for in Debian distro.If you're not already using Alpine Linux (https://github.com/dotnet/dotnet-docker/blob/main/samples/selecting-tags.md#alpine), you may want to consider using it instead because of its security focus and low number of vulnerabilities"

        return {
            "success": True,
            "message": step_messages["PASS"]["message"],
            "recommendation": recommendation,
        }

    for match in debian_matched_data:
        linux_package = match["package"].lower()
        details = match["details"]

        if package_name != linux_package:
            continue

        for release_name, release_info in details.get("releases", {}).items():
            status = release_info["status"]
            linux_package_version = next(
                iter(release_info.get("repositories", {}).values())
            )

            if package_version in linux_package_version:
                recommendation = f" Package: {package_name}, Version: {package_version} has status: {status} in https://security-tracker.debian.org/tracker/{cve}."
                if status == "resolved":
                    return {
                        "success": False,
                        "message": step_messages["FAIL"]["message"],
                        "recommendation": recommendation,
                    }
                else:
                    message = step_messages["PASS"]["message"] + recommendation
                    return {
                        "success": True,
                        "message": message,
                    }
            else:
                closest_version = find_closest_match(
                    package_version, linux_package_version, cve, threshold=80.0
                )
                if closest_version:
                    matched_version, similarity = closest_version
                    additional_message = (
                        f"Package: {package_name}, Version: {package_version} "
                        f"matched with {matched_version},  (similarity {similarity:.2f}%). Has status: {status} in {release_name}."
                    )
                    additional_info = "Please Validate Version Similarity. "

                    recommendation = additional_message + additional_info
                    if status == "resolved":
                        return {
                            "success": False,
                            "message": step_messages["FAIL"]["message"],
                            "recommendation": recommendation,
                        }

                    else:
                        base_message = step_messages["PASS"]["message"]
                        message = base_message + additional_message + additional_info
                        return {
                            "success": True,
                            "message": message,
                        }
                else:
                    base_message = step_messages["PASS"]["message"]
                    message_1 = f"Package: {package_name}, no similar versions to {package_version} found in distro."
                    message_2 = f"Validate https://security-tracker.debian.org/tracker/{cve} in Distro. "
                    message = base_message + message_1 + message_2
                    return {
                        "success": True,
                        "message": message,
                    }
