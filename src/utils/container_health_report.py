import json
import re
import logging
from src.constants.messages import STEP_MESSAGES
from src.constants import url_constants
from src.scan_steps.health_check import HealthCheck


class ContainerHealthReport:
    def __init__(self, vulnerabilities, latest_image_versions, debian_data_set):
        self.vulnerabilities = vulnerabilities
        self.latest_image_versions = latest_image_versions
        self.debian_data_set = debian_data_set

    def generate_report(self):
        report = []
        for vulnerability in self.vulnerabilities:
            health_check = HealthCheck(
                vulnerability,
                self.latest_image_versions,
                self.debian_data_set,
                STEP_MESSAGES,
            )

            check_results = health_check.run_checks()
            package_name = vulnerability.get("package_name", "")
            package_version = vulnerability.get("package_version", [""])[0]
            package_cve = vulnerability.get("issue_cve", [""])[0]
            base_img_os_id = vulnerability.get("base_img_os_id")
            issue_severity = vulnerability.get("issue_severity").upper()
            link = None
            if base_img_os_id == "alpine":
                alpine_version = re.match(
                    r"^\d+(\.\d+)*", vulnerability.get("base_img_os_version")
                ).group()
                alpine_link = f"{url_constants.ALPINE_URL}/v{alpine_version}/main.json"
                link = alpine_link
            elif base_img_os_id == "debian":
                debian_link = f"{url_constants.DEBIAN_URL}/{package_cve}"
                link = debian_link

            package_details = (
                f"Severity: {issue_severity}, Package: {package_name}, Version: {package_version}, "
                f"CVE: {package_cve}, Distro_Link: {link}"
            )

            if check_results:
                report_entry = {
                    "project_name": vulnerability["project_name"],
                    "project_url": vulnerability["project_url"],
                    "issue": vulnerability.get("issue_title", ""),
                    "issue_url": vulnerability.get("issue_url", ""),
                    "issue_details": package_details,
                    "failed_checks": check_results["failed_checks"],
                    "passed_checks": check_results["passed_checks"],
                }
                report.append(report_entry)

        return report

    def save_report(self, output_file):
        report = self.generate_report()
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
        logging.info(f"Health report saved to {output_file}")
