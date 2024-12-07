from src.scan_steps.step_a import check_latest_image_version
from src.scan_steps.step_c import check_dotnet_support
from src.scan_steps.step_e import check_latest
from src.scan_steps.step_g import check_vuln_source
from src.scan_steps.step_j import check_package_upgrade
from src.scan_steps.step_j_plus import check_distro_fix
from src.scan_steps.step_l import check_pkg_in_linux_base_distro
from src.scan_steps.step_n import check_pkg_installed_by_dotnet
from src.scan_steps.step_p import check_critical_severity
import logging


class HealthCheck:
    def __init__(
        self, vulnerability, latest_image_versions, debian_data_set, step_messages
    ):
        self.vulnerability = vulnerability
        self.latest_image_versions = latest_image_versions
        self.debian_data_set = debian_data_set
        self.failed_checks = []
        self.passed_checks = []
        self.step_messages = step_messages

    def run_checks(self):
        """
        Run all defined health check steps and aggregate the results.
        """
        project_name = self.vulnerability.get("project_name", "")
        issue_id = self.vulnerability.get("issue_id", "")

        if self.latest_image_versions is None:
            img_version_check_message = self.step_messages["IMG_VERSION_CHECK_MISSING"]
        else:
            img_version_check_message = self.step_messages["IMG_VERSION_CHECK"]

        check_functions = [
            (
                "IMG_VERSION_CHECK",
                check_latest_image_version,
                [
                    self.vulnerability,
                    self.latest_image_versions,
                    img_version_check_message,
                ],
            ),
            (
                "DOTNET_SUPPORTED_BASE_CHECK",
                check_dotnet_support,
                [self.vulnerability, self.step_messages["DOTNET_SUPPORTED_BASE_CHECK"]],
            ),
            (
                "LATEST_BASE_CHECK",
                check_latest,
                [self.vulnerability, self.step_messages["LATEST_BASE_CHECK"]],
            ),
            (
                "VULN_SOURCE_CHECK",
                check_vuln_source,
                [self.vulnerability, self.step_messages["VULN_SOURCE_CHECK"]],
            ),
            (
                "UPGRADE_AVAILABILITY_CHECK",
                check_package_upgrade,
                [self.vulnerability, self.step_messages["UPGRADE_AVAILABILITY_CHECK"]],
            ),
            (
                "FIX_AVAILABILITY_CHECK",
                check_distro_fix,
                [
                    self.vulnerability,
                    self.debian_data_set,
                    self.step_messages["FIX_AVAILABILITY_CHECK"],
                ],
            ),
            (
                "LINUX_DISTRO_PKG_CHECK",
                check_pkg_in_linux_base_distro,
                [self.vulnerability, self.step_messages["LINUX_DISTRO_PKG_CHECK"]],
            ),
            (
                "DOTNET_CUSTOM_PKG_CHECK",
                check_pkg_installed_by_dotnet,
                [self.vulnerability, self.step_messages["DOTNET_CUSTOM_PKG_CHECK"]],
            ),
            (
                "CRITICAL_SEVERITY_CHECK",
                check_critical_severity,
                [self.vulnerability, self.step_messages["CRITICAL_SEVERITY_CHECK"]],
            ),
        ]
        logging.info(f"Began running Health Checks on {project_name}")

        for check_name, check_function, args in check_functions:
            try:
                logging.info(
                    f"Running check: {check_name} on {project_name}:{issue_id} "
                )
                result = check_function(*args)
                if result["success"]:
                    self.passed_checks.append(
                        {"name": check_name, "message": result["message"]}
                    )
                else:
                    self.failed_checks.append(
                        {
                            "name": check_name,
                            "message": result["message"],
                            "recommendation": result.get("recommendation", ""),
                        }
                    )
            except Exception as e:
                logging.error(
                    f"Failed to Run Check {check_name} on {project_name}: {issue_id} : {e}"
                )
                raise
        return {
            "failed_checks": self.failed_checks,
            "passed_checks": self.passed_checks,
        }
