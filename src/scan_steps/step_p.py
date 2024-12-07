import logging


def check_critical_severity(vulnerability, step_messages):
    """
    Checks if the vulnerable package is critical in severity.

    Args:
        vulnerability (dict): The vulnerability dictionary containing image information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """

    project_name = vulnerability.get("project_name")
    severity = vulnerability.get("issue_severity").lower()

    try:
        if "critical" in severity:
            return {
                "success": False,
                "message": step_messages["FAIL"]["message"],
                "recommendation": step_messages["FAIL"]["recommendation"],
            }
        else:
            return {"success": True, "message": step_messages["PASS"]["message"]}
    except ValueError as e:
        logging.error(f"Failed to check Issue Severity for {project_name}: {e}")
        raise
