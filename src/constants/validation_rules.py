dev_environments = ["namespace", "namespace-2"]

validation_rules = {
    "aws.account_id": {
        "required": True,
        "type": "str",
        "format": "numeric-12-digits",
    },
    "deployment.multi_cluster_scan": {
        "required": True,
        "type": "bool",
        "choices": ["true", "false"],
    },
    "deployment.check_latest_ecr_in_eks": {
        "required": True,
        "type": "bool",
        "choices": ["true", "false"],
    },
    "deployment.test_namespace_1": {
        "required": False,
        "type": "alphabetic-hyphen",
        "format": "str",
        "choices": dev_environments,
    },
    "deployment.test_namespace_2": {
        "required": False,
        "type": "alphabetic-hyphen",
        "format": "str",
        "choices": dev_environments,
    },
    "snyk.org_id": {"required": True, "type": "str"},
    "snyk.api_token": {"required": True, "type": "str", "format": "snyk_api_token"},
}
