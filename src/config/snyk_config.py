class SnykConfig:
    def __init__(self, config):
        self.config = config

    def get_snyk_org_id(self):
        return self.config["snyk"]["org_id"]

    def get_snyk_api_token(self):
        return self.config["snyk"]["api_token"]
