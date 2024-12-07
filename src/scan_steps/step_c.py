import subprocess
import logging


def check_dotnet_support(vulnerability, step_messages):
    """
    Checks if the base image is supported by the .NET team using the PowerShell script.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    image = vulnerability.get("base_img", "")
    image_type = vulnerability.get("base_img_type", "")

    if image_type != "dotnet":
        return {
            "success": True,
            "message": "Step has been skipped due to the base image not being DotNet",
        }

    try:
        command = f"curl -sSL https://raw.githubusercontent.com/dotnet/dotnet-docker/main/documentation/scripts/check-tag-support.ps1 | pwsh /dev/stdin {image}"
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
        logging.error(f"Failed to execute .NET support check: {str(e)}")
        raise
