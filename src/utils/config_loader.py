import os
import yaml
import logging
import re
import argparse
from src.constants.validation_rules import validation_rules
from src.constants import file_name_constants


class ConfigLoader:
    @staticmethod
    def ensure_output_directory_exists(directory=file_name_constants.JSON_OUTPUT_DIR):
        """Check if the directory exists, and create it if it doesn't."""
        if not os.path.exists(directory):
            os.makedirs(directory)
            logging.info(f"Directory created: {directory}")
        else:
            logging.info(f"Directory already exists: {directory}")

    @staticmethod
    def mask_sensitive_value(key, value):
        """Mask sensitive values."""
        sensitive_keys = ["snyk_api_token", "org_id", "webhook"]
        if any(sensitive_key in key for sensitive_key in sensitive_keys):
            return "*" * len(str(value))
        return value

    @staticmethod
    def validate_deploy_value(value):
        value_lower = str(value).lower()
        logging.info(f"Validating deployment value: {value}")
        if value_lower not in {"true", "false"}:
            raise argparse.ArgumentTypeError(
                "Invalid value for deployment. Must be 'true' or 'false'."
            )
        return value_lower == "true"

    @staticmethod
    def validate_value(key, value, rules):
        """
        General purpose validator that checks the given value against a set of rules.
        :param key: The configuration key being validated.
        :param value: The value to validate.
        :param rules: A dictionary with the validation rules.
        :return: The validated value.
        """
        masked_value = ConfigLoader.mask_sensitive_value(key, value)
        logging.info(f"Validating {key}: {masked_value} with rules: {rules}")

        if not rules.get("required", False) and (value is None or value == ""):
            logging.info(f"{key} is optional and not provided. Skipping validation.")
            return

        # Check required fields
        if rules.get("required", False) and (value is None or value == ""):
            raise ValueError(f"{key} is required but was not provided.")

        if "type" in rules:
            if rules["type"] == "int" and not isinstance(value, int):
                raise ValueError(
                    f"{key} must be an integer. Got {type(value).__name__}."
                )
            if rules["type"] == "str" and not isinstance(value, str):
                raise ValueError(f"{key} must be a string. Got {type(value).__name__}.")

        if "format" in rules:
            if rules["format"] == "url":
                if not isinstance(value, str) or not value.startswith("http"):
                    raise ValueError(f"Invalid URL format for {key}: {value}")
            if rules["format"] == "alphabetic-hyphen":
                pattern = r"^[a-zA-Z]+-[a-zA-Z]+$"
                if not isinstance(value, str) or not re.match(pattern, value):
                    raise ValueError(
                        f"{key} must be an alphabetic string with a hyphen between two alphabetic parts. Got {value}."
                    )
            if rules["format"] == "snyk_api_token":
                if not isinstance(value, str) or len(value) < 10:
                    raise ValueError(
                        f"Invalid Snyk API token for {key}: {value}. Must be more than 10-character string."
                    )
            if rules["format"] == "numeric-12-digits":
                if not isinstance(value, str) or not re.fullmatch(r"^\d{12}$", value):
                    raise ValueError(
                        f"{key} must be a numeric string with exactly 12 digits. Got: {value}."
                    )

        if "choices" in rules:
            if str(value).lower() not in rules["choices"]:
                raise ValueError(
                    f"Invalid choice for {key}: '{value}'. Valid options are: {rules['choices']}"
                )

        return value

    @staticmethod
    def validate_config(config):
        """
        Validates the entire config using the validation rules.
        :param config: The configuration dictionary to validate.
        :return: None. Raises ValueError on validation errors.
        """
        for key_path, rules in validation_rules.items():
            keys = key_path.split(".")
            value = config
            for key in keys:
                value = value.get(key, None)
                if value is None:
                    break
            ConfigLoader.validate_value(key_path, value, rules)
        snyk_api_enabled = str(
            config.get("snyk", {}).get("snyk_api_enabled", "false")
        ).lower()
        if snyk_api_enabled == "true":
            if not config["snyk"].get("org_id"):
                raise ValueError(
                    "snyk.org_id is required when snyk_api_enabled is true."
                )
            if not config["snyk"].get("api_token"):
                raise ValueError(
                    "snyk.api_token is required when snyk_api_enabled is true."
                )

        ConfigLoader.ensure_output_directory_exists()

    @staticmethod
    def load_config(file_path):
        logging.info(f"Loading config from {file_path}")
        try:
            with open(file_path, "r") as file:
                config = yaml.safe_load(file)
                logging.debug(f"Config loaded: {config}")
                ConfigLoader.validate_config(config)
                logging.info(f"Config validated successfully")
                return config
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            raise
