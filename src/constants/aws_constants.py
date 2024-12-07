class AWSConstants:
    AWS_REGION = "eu-west-2"
    AWS_REGION_2 = "us-east-2"

    AWS_ENVS = {
        "prod": {
            "region": f"{AWS_REGION}",
            "account": None,
            "eks_cluster_color": "blue",
            "eks_cluster_environment": "prod",
            "kube_namespace": "prod-ns",
        },
        "prod_2": {
            "region": f"{AWS_REGION_2}",
            "account": None,
            "eks_cluster_color": "green",
            "eks_cluster_environment": "prod2",
            "kube_namespace": "prod-ns-2",
        },
        "dev": {
            "region": f"{AWS_REGION}",
            "account": None,
            "eks_cluster_color": "green",
            "eks_cluster_environment": "dev",
            "kube_namespace": None,
            "kube_namespace_2": None,
        },
    }
