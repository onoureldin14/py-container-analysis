# py-container-analysis

Python repository for creating an Excel report on how to react to container vulnerabilities.

## Table of Contents

- Introduction
- Features
- Installation
- Usage
- Configuration
- [Project Structure](#project-structure)
- Contributing
- License

## Introduction

`py-container-analysis` is a Python-based tool designed to generate comprehensive Excel reports on container vulnerabilities. It helps in identifying, analyzing, and providing recommendations for container security issues.

## Features

- Fetches container data from EKS clusters.
- Analyzes container vulnerabilities using Snyk.
- Generates detailed Excel reports with vulnerability information and recommendations.
- Supports multiple Kubernetes contexts and namespaces.
- Validates configuration settings.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/py-container-analysis.git
    cd py-container-analysis
    ```

2. Create and activate a virtual environment:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

1. Configure the application by editing the [`config.yaml`](config.yaml ) file. Refer to the Configuration section for details.

2. Run the main script to generate the report:
    ```sh
    python main.py
    ```

3. The generated reports will be saved in the [`analysischeck_output`](analysischeck_output ) directory.

## Configuration

The configuration file [`config.yaml`](config.yaml ) contains settings for deployment and Snyk integration. Here is an example configuration:

```yaml
deployment:
  check_latest_ecr_in_eks: false
  multi_cluster_scan: false
  test_namespace_1: namespace
  test_namespace_2: namespace-2

snyk:
```yaml
org_id: "your_snyk_org_id"
api_token: "your_snyk_api_token"
```
'''

## Project Structure
'''
.DS_Store
.gitignore
[.pre-commit-config.yaml](http://_vscodecontentref_/1)
[config.yaml](http://_vscodecontentref_/2)
[config.yaml.example](http://_vscodecontentref_/3)
analysischeck_output/
[main.py](http://_vscodecontentref_/4)
path/
    to/
        venv/
[README.md](http://_vscodecontentref_/5)
[requirements.txt](http://_vscodecontentref_/6)
src/
    config/
        aws_config.py
        snyk_config.py
    constants/
        aws_constants.py
        file_name_constants.py
        snyk_constants.py
        url_constants.py
        validation_rules.py
    container_analysis_report.py
    scan_steps/
        step_a.py
        step_c.py
        step_e.py
        step_g.py
        step_j.py
        step_j_plus.py
        step_l.py
        step_n.py
        analysis_check.py
    utils/
        calculate_similarity.py
        config_loader.py
        data_generator.py
        eks_handler.py
        generate_excel_report.py
        logging_handler.py
        project_state_manager.py
        snyk_handler.py
        '''


## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
