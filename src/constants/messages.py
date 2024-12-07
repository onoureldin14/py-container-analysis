STEP_MESSAGES = {
    "IMG_VERSION_CHECK": {
        "FAIL": {
            "message": "Scanner not targeting latest image version",
            "recommendation": "Ensure that the latest image version is used. Check why the image version in the scanning tool does not match the image used in the environment.",
        },
        "PASS": {"message": "The project is using the latest image version."},
    },
    "IMG_VERSION_CHECK_MISSING": {
        "FAIL": {
            "message": "Latest image version check has been skipped",
            "recommendation": "Ensure you enable the check_latest_ecr_in_eks and configure your EKS cluster.",
        }
    },
    "DOTNET_SUPPORTED_BASE_CHECK": {
        "FAIL": {
            "message": "Built from a non-supported base image",
            "recommendation": "Update the base image to a supported version. If you are using an unsupported version, upgrade your project configurations to target a supported version.",
        },
        "PASS": {"message": "The base image is supported by provider."},
    },
    "LATEST_BASE_CHECK": {
        "FAIL": {
            "message": "Might be built from an outdated base image",
            "recommendation": "Rebuild your image using the latest base version. This ensures all latest security patches and improvements are included.",
        },
        "PASS": {"message": "The base image is the latest available."},
    },
    "VULN_SOURCE_CHECK": {
        "FAIL": {
            "message": "Source of vulnerability found in base image",
            "recommendation": "Check the base image repository or maintainers to address this issue.",
        },
        "PASS": {"message": "Vulnerability not linked to the base image."},
    },
    "UPGRADE_AVAILABILITY_CHECK": {
        "FAIL": {
            "message": "A upgrade is available for the vulnerable package. ",
            "recommendation": "",
        },
        "PASS": {
            "message": "Upgrade not available for the vulnerable package. Wait for a upgrade from the package maintainers or consider using an alternative package.",
        },
    },
    "FIX_AVAILABILITY_CHECK": {
        "FAIL": {
            "message": "A fix is available in the LINUX DISTRO for the vulnerable package. ",
            "recommendation": "",
        },
        "PASS": {
            "message": "Fix NOT available for the vulnerable package. Wait for a Fix from the package maintainers or consider using an alternative package.",
        },
    },
    "LINUX_DISTRO_PKG_CHECK": {
        "FAIL": {
            "message": "Vulnerable package introduced by the Linux distribution",
            "recommendation": "Upgrade or replace the package as soon as a patched version is available.",
        },
        "PASS": {
            "message": "Vulnerable package NOT introduced from the Linux distribution. Open your Dockerfile to determine how the package is being installed"
        },
    },
    "DOTNET_CUSTOM_PKG_CHECK": {
        "FAIL": {
            "message": "Package not installed by the base image",
            "recommendation": "Review your Dockerfile or build configuration to understand how the package is being introduced.",
        },
        "PASS": {"message": "Package is installed by the base image or known source."},
    },
    "CRITICAL_SEVERITY_CHECK": {
        "FAIL": {
            "message": "Critical severity issue detected",
            "recommendation": "Address this issue as a high priority. Consider reaching out to the maintainers or using temporary workarounds.",
        },
        "PASS": {"message": "No critical severity issues detected."},
    },
}
