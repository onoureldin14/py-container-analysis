import logging
import subprocess


def check_pkg_installed_by_dotnet(vulnerability, step_messages):
    """
    Checks if the vulnerable package is installed by dotnet using the PowerShell script.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    project_name = vulnerability.get("project_name")
    base_img = vulnerability.get("base_img")
    package_name = vulnerability.get("package_name", "").split("/")[0].lower()
    image_type = vulnerability.get("base_img_type", "")

    if image_type != "dotnet":
        return {
            "success": True,
            "message": "Step has been skipped due to the image not being DotNet",
        }

    try:
        command = f"curl -sSL https://raw.githubusercontent.com/dotnet/dotnet-docker/main/documentation/scripts/check-package-install.ps1 | pwsh /dev/stdin {package_name} {base_img}"
        result = subprocess.run(
            command, shell=True, check=True, capture_output=True, text=True
        )

        if "True" in result.stdout:
            return {"success": True, "message": step_messages["PASS"]["message"]}
        else:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": step_messages["FAIL"]["recommendation"],
            }
    except subprocess.CalledProcessError as e:
        logging.error(
            f"Failed to check if package is Installed by DotNet for {project_name}: {e}"
        )
