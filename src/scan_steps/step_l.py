import logging
import subprocess
import re


def check_pkg_in_linux_base_distro(vulnerability, step_messages):
    """
    Checks if the vulnerable package is installed in linux base distro using the PowerShell script.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    project_name = vulnerability.get("project_name")
    base_img_arch = vulnerability.get("base_img_arch")
    base_img_os_id = vulnerability.get("base_img_os_id")
    base_img_os_version = vulnerability.get("base_img_os_version")
    if base_img_os_id == "alpine":
        base_img_os_version = re.match(r"^\d+(\.\d+)*", base_img_os_version).group()

    image_name = f"{base_img_arch}/{base_img_os_id}:{base_img_os_version}"
    package_name = vulnerability.get("package_name", "").split("/")[0].lower()

    try:
        command = f"curl -s https://raw.githubusercontent.com/dotnet/dotnet-docker/main/documentation/scripts/check-package-install.ps1 | pwsh /dev/stdin {package_name} {image_name}"
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )

        if "True" in result.stdout:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": step_messages["FAIL"]["recommendation"],
            }
        else:
            return {"success": True, "message": step_messages["PASS"]["message"]}

    except subprocess.CalledProcessError as e:
        logging.error(
            f"Failed to check package in Linux distro base image for {project_name}: {e}"
        )
        raise
