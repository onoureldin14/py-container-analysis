import logging
import subprocess


def check_package_upgrade(vulnerability, step_messages):
    image_url = vulnerability.get("image_url")
    package_name = vulnerability.get("package_name").split("/")[1]
    base_img_os_id = vulnerability.get("base_img_os_id")
    if base_img_os_id == "alpine":
        argument = f"apk update > /dev/null && apk list -u | grep {package_name}"
    else:
        argument = (
            f"apt update > /dev/null && apt list --upgradable | grep {package_name}"
        )

    try:
        docker_command = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "--entrypoint",
                "/bin/sh",
                image_url,
                "-c",
                argument,
            ],
            capture_output=True,
            text=True,
        )

        output = docker_command.stdout.strip()

        if output:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": output,
            }
        else:
            return {
                "success": True,
                "message": step_messages["PASS"]["message"],
            }

    except subprocess.CalledProcessError as e:
        logging.error(f"Error checking docker packages in docker run command: {e}")
        raise
