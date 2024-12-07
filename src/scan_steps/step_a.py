def check_latest_image_version(vulnerability, latest_image_versions, step_messages):
    """
    Check if the project is using the latest image version.
    If not, set the status message and recommendation.
    """
    project_name = vulnerability.get("project_name", "")
    if not latest_image_versions or project_name not in latest_image_versions:
        return {
            "success": False,
            "message": step_messages["FAIL"]["message"],
            "recommendation": step_messages["FAIL"]["recommendation"],
        }
    else:
        return {"success": True, "message": step_messages["PASS"]["message"]}
