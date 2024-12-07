from src.constants.aws_constants import AWSConstants


class AWSConfig:
    def __init__(self, env, config):
        self.env = env
        self.config = config
        self.aws_config = self.get_aws_config()

    def get_aws_config(self):
        """Retrieve AWS configuration based on the environment."""
        aws_config = AWSConstants.AWS_ENVS.get(self.env)
        if not aws_config:
            raise ValueError(f"Invalid environment: {self.env}")

        # Dynamically update account_id from config
        aws_config["account"] = self.config["aws"]["account_id"]

        if self.env == "dev" and self.config:
            aws_config["kube_namespace"] = self.config["deployment"]["test_namespace_1"]
            aws_config["kube_namespace_2"] = self.config["deployment"][
                "test_namespace_2"
            ]
        return aws_config

    def get_eks_cluster_name(self):
        """Generate EKS cluster name."""
        return f"{self.aws_config['eks_cluster_environment']}-eks-{self.aws_config['eks_cluster_color']}"

    def get_kube_context(self):
        """Generate Kubernetes context ARN."""
        eks_cluster_name = self.get_eks_cluster_name()
        return f"arn:aws:eks:{self.aws_config['region']}:{self.aws_config['account']}:cluster/{eks_cluster_name}"
