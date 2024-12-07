import requests
import logging


class SnykHandler:
    def __init__(self, snyk_api_key, snyk_org_id):
        self.snyk_api_key = snyk_api_key
        self.snyk_org_id = snyk_org_id
        self.snyk_base_url = "https://api.snyk.io"
        self.headers = {
            "Authorization": f"token {self.snyk_api_key}",
            "Content-Type": "application/json",
        }
        self.snyk_api_version = "2024-08-25"

    def get_snyk_ecr_projects(self, severity_selection: list):
        endpoint = f"/rest/orgs/{self.snyk_org_id}/projects?"
        results = []
        url = f"{self.snyk_base_url}{endpoint}&version={self.snyk_api_version}&origins=ecr"
        logging.info("Fetching SNYK Issues from ECR Projects")
        try:
            while url:
                response = requests.get(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                results.extend(data.get("data", []))
                next_url = data.get("links", {}).get("next")
                if next_url and not next_url.startswith("http"):
                    next_url = f"{self.snyk_base_url}{next_url}"
                url = next_url

            projects_with_issues = {}
            for project in results:
                attributes = project.get("attributes", {})
                project_name = attributes.get("name")
                project_id = project.get("id", "")

                # Filter projects based on naming pattern (optional check, adjust as needed)
                if project_name and project_id and len(project_name.split(":")) == 2:
                    # Check if the project has HIGH or CRITICAL issues
                    if self.issues_found(project_id, severity_selection):
                        projects_with_issues[project_name] = project_id

            projects_with_issues = dict(sorted(projects_with_issues.items()))
            project_count = len(projects_with_issues)
            logging.info(f"Total CRITICAL ECR Projects Found: {project_count}")
            return projects_with_issues
        except Exception as e:
            logging.error(f"Failed to Fetch ECR Projects from SNYK: {e}")
            raise

    def issues_found(self, project_id, severity: list):
        """Helper function to check if a project has HIGH or CRITICAL issues."""
        endpoint = f"/v1/org/{self.snyk_org_id}/project/{project_id}/aggregated-issues"
        url = f"{self.snyk_base_url}{endpoint}"
        severity = [s.lower() for s in severity]
        try:
            while url:
                response = requests.post(url, headers=self.headers)
                response.raise_for_status()
                data = response.json()
                issues = data.get("issues", [])

                if any(
                    issue.get("issueData", {}).get("severity") in severity
                    for issue in issues
                ):
                    return True

                next_url = data.get("links", {}).get("next")
                if next_url and not next_url.startswith("http"):
                    next_url = f"{self.snyk_base_url}{next_url}"
                url = next_url
        except Exception as e:
            logging.error(f"Failed to check issues for project {project_id}: {e}")
            raise

    def get_project_issues(
        self, project_selection=None, severity_selection=None, project_name_filter=None
    ):
        try:
            # Validate severity_selection
            valid_severities = ["critical", "high", "medium", "low"]
            if severity_selection:
                if not isinstance(severity_selection, list) or not all(
                    sev.lower() in valid_severities for sev in severity_selection
                ):
                    raise ValueError(
                        f"Invalid severity selection. Must be a list containing: {valid_severities}"
                    )
                severity_selection = [sev.lower() for sev in severity_selection]
            else:
                severity_selection = ["critical"]

            # Validate project_name_filter
            if project_name_filter and not isinstance(project_name_filter, str):
                raise ValueError(
                    "Invalid project_name_filter. Must be a string in the format 'project-name:project-version'."
                )

            # Fetch projects
            projects = self.get_snyk_ecr_projects(severity_selection)

            # Filter projects based on the project_name_filter if provided
            if project_name_filter:
                projects = {
                    name: id
                    for name, id in projects.items()
                    if name == project_name_filter
                }
                if not projects:
                    logging.error(
                        f"No projects found matching the name: {project_name_filter}"
                    )
                    raise

            # Additional filtering for project selection
            if project_selection is not None and isinstance(project_selection, int):
                projects = dict(list(projects.items())[:project_selection])

            project_issues = []

            for project_name, project_id in projects.items():
                endpoint = (
                    f"/v1/org/{self.snyk_org_id}/project/{project_id}/aggregated-issues"
                )
                url = f"{self.snyk_base_url}{endpoint}"

                project_issues_count = 0
                exclude_project = False

                while url:
                    response = requests.post(url, headers=self.headers)
                    response.raise_for_status()
                    data = response.json()
                    issues = data.get("issues", [])

                    for issue in issues:
                        issue_data = issue.get("issueData", {})
                        severity = issue_data.get("severity")
                        if severity in severity_selection:
                            updated_issue = {
                                "project_name": project_name,
                                "project_ID": project_id,
                                "project_url": f"https://app.snyk.io/org/youlend/project/{project_id}",
                                "issue_title": issue_data.get("title"),
                                "issue_id": issue_data.get("id"),
                                "issue_url": issue_data.get("url"),
                                "issue_severity": severity,
                                "issue_cwe": issue_data.get("identifiers", {}).get(
                                    "CWE", []
                                ),
                                "issue_cve": issue_data.get("identifiers", {}).get(
                                    "CVE", []
                                ),
                                "package_name": issue.get("pkgName"),
                                "package_version": issue.get("pkgVersions"),
                            }
                            for existing_issue in project_issues:
                                if (
                                    existing_issue["project_ID"] == project_id
                                    and existing_issue["issue_id"]
                                    == updated_issue["issue_id"]
                                ):
                                    existing_issue.update(updated_issue)
                                    break
                            else:
                                project_issues.append(updated_issue)

                            project_issues_count += 1
                    if exclude_project:
                        break
                    next_url = data.get("links", {}).get("next")
                    if next_url and not next_url.startswith("http"):
                        next_url = f"{self.snyk_base_url}{next_url}"
                    url = next_url

                logging.info(
                    f"CRITICAL issues found for {project_name}: {project_issues_count} issues."
                )
        except Exception as e:
            logging.error(f"Failed to Fetch CRITICAL ECR Issues in SNYK: {e}")
            raise

        return project_issues
