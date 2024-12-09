import subprocess
import logging
import re


def check_latest_image_version(vulnerability, step_messages):
    """
    Check if the project is using the latest image version.
    If not, set the status message and recommendation.
    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    image_url = vulnerability.get("image_url", "")
    base_img_os = vulnerability.get("base_img_os", "")
    base_img_arch = vulnerability.get("base_img_arch", "")

    try:
        command = f"curl -sSL https://raw.githubusercontent.com/dotnet/dotnet-docker/main/documentation/scripts/resolve-image-digest.ps1 | pwsh /dev/stdin {image_url} -Os {base_img_os} -Architecture {base_img_arch}"
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )

        if "True" in result.stdout:
            return {
                "success": True,
                "message": step_messages["PASS"]["message"],
            }
        else:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": step_messages["FAIL"]["recommendation"],
            }
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to execute Latest Image Check: {str(e)}")
        raise
