import logging
import json
from src.utils.data_generator import DataGenerator
from src.container_health_report import ContainerHealthReport
from src.utils.generate_excel_report import generate_excel_report
from src.constants import file_name_constants


class ProjectStateManager:
    def __init__(self):
        # Automatically execute both steps in sequence
        project_data, latest_versions, debian_data_set = self.generate_project_data()
        self.generate_health_json(project_data, latest_versions, debian_data_set)
        self.generate_health_excel()

    def generate_project_data(self):
        """
        Generates project data and saves it to a JSON file.
        Returns the generated project issues and latest image versions.
        """
        try:
            # Get both project issues and the latest image versions
            (
                project_issues,
                latest_image_versions,
                debian_distro_data_set,
            ) = DataGenerator().generate_project_data_json()

            # Log success
            logging.info("Project data generated and saved successfully.")
            return project_issues, latest_image_versions, debian_distro_data_set

        except Exception as e:
            logging.error(f"Failed to generate project data: {e}")
            raise

    def generate_health_json(
        self, project_issues, latest_image_versions, debian_distro_data_set
    ):
        """
        Generates a health report based on the provided project issues and latest image versions.
        """
        try:
            # Generate the health report using the provided data
            HEALTH_REPORT_JSON_FILE_PATH = (
                file_name_constants.HEALTH_REPORT_JSON_FILE_PATH
            )
            health_report = ContainerHealthReport(
                project_issues, latest_image_versions, debian_distro_data_set
            )
            health_report.save_report(HEALTH_REPORT_JSON_FILE_PATH)
            logging.info("Health report JSON generated and saved successfully.")

        except Exception as e:
            logging.error(f"Failed to generate health report JSON: {e}")
            raise

    def generate_health_excel(self):
        """
        Generates a health report based on the provided project issues and latest image versions.
        """
        try:
            # Generate the health report using the provided data
            HEALTH_REPORT_JSON_FILE_PATH = (
                file_name_constants.HEALTH_REPORT_JSON_FILE_PATH
            )
            HEALTH_REPORT_EXCEL_FILE_PATH = (
                file_name_constants.HEALTH_REPORT_EXCEL_FILE_PATH
            )
            generate_excel_report(
                HEALTH_REPORT_JSON_FILE_PATH, HEALTH_REPORT_EXCEL_FILE_PATH
            )
            logging.info("Health report EXCEL generated and saved successfully.")

        except Exception as e:
            logging.error(f"Failed to generate health report EXCEL: {e}")
            raise
