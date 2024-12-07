def check_vuln_source(vulnerability, step_messages):
    """
    Check if the source of the vulnerability is related to base image by analyzing the issue_title or issue_id.

    Args:
        vulnerability (dict): The vulnerability dictionary containing title and ID information.
        shared_config (dict): Optional configuration for shared constants.

    Returns:
        dict: Dictionary containing success, message, and recommendation keys.
    """
    nginx_keywords = ["nginx"]
    dotnet_keywords = [".net", "asp.net", "dotnet"]
    base_img_type = vulnerability.get("base_img_type", "").lower()
    issue_title = vulnerability.get("issue_title", "").lower()
    issue_id = vulnerability.get("issue_id", "").lower()
    keywords = []
    if base_img_type == "nginx":
        keywords = nginx_keywords
    elif base_img_type == "dotnet":
        keywords = dotnet_keywords

    if any(keyword in issue_title for keyword in keywords) or any(
        keyword in issue_id for keyword in keywords
    ):
        return {
            "success": False,
            "message": step_messages["FAIL"]["message"],
            "recommendation": step_messages["FAIL"]["recommendation"],
        }
    else:
        return {"success": True, "message": step_messages["PASS"]["message"]}
