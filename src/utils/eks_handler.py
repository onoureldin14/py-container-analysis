from kubernetes import client, config


class EKSHandler:
    def __init__(self):
        self.api_instance = None

    def load_kube_config(self, context):
        """
        Load the Kubernetes configuration for the specific context.
        """
        config.load_kube_config(context=context)
        self.api_instance = client.CoreV1Api()

    def get_pods(self, namespace):
        """
        Get all pods in the specified namespace.
        """
        pods = self.api_instance.list_namespaced_pod(namespace)
        return pods.items

    @staticmethod
    def get_container_version(container):
        """
        Get the version of the container based on the image tag.
        """
        image = container.image
        return image.split(":")[-1] if ":" in image else "unknown"

    def get_cluster_versions(self, context, namespace):
        """
        Get the container versions for all relevant pods in the specified namespace.
        """
        self.load_kube_config(context)
        pods = self.get_pods(namespace)
        container_versions = {}

        for pod in pods:
            if pod.metadata.name.startswith("yl"):
                # Regular containers
                for container in pod.spec.containers:
                    if container.name.startswith("yl"):
                        if container.name not in container_versions:  # Avoid duplicates
                            container_version = self.get_container_version(container)
                            container_versions[container.name] = container_version
                        break  # Skip to the next pod (to handle replicas)

                # Init containers
                if pod.spec.init_containers:
                    for init_container in pod.spec.init_containers:
                        if init_container.name.startswith("yl"):
                            if (
                                init_container.name not in container_versions
                            ):  # Avoid duplicates
                                init_container_version = self.get_container_version(
                                    init_container
                                )
                                container_versions[
                                    init_container.name
                                ] = init_container_version
                            break  # Skip to the next pod (to handle replicas)

        return container_versions

    @staticmethod
    def remove_duplicate_versions(production_versions, production_2_versions):
        """
        Remove entries from production_2_versions if there's an exact match in production_versions.
        """
        to_remove = []
        for name, version in production_2_versions.items():
            if name in production_versions and production_versions[name] == version:
                to_remove.append(name)

        for name in to_remove:
            del production_2_versions[name]

    def get_ecr_data_from_eks(
        self,
        prod_kube_context,
        prod_2_kube_context,
        prod_kube_namespace,
        prod_2_kube_namespace,
    ):
        """
        Get the ECR data by retrieving and processing container versions across different clusters.
        """
        context_namespace_map = {
            "production_cluster": {
                "context": prod_kube_context,
                "namespace": prod_kube_namespace,
            },
            "production_2_cluster": {
                "context": prod_2_kube_context,
                "namespace": prod_2_kube_namespace,
            },
        }

        combined_versions = {}
        output_set = set()

        # Collect versions for each cluster
        for cluster, info in context_namespace_map.items():
            context = info["context"]
            namespace = info["namespace"]
            cluster_versions = self.get_cluster_versions(context, namespace)
            combined_versions[cluster] = cluster_versions

            # Add each "name:version" pair to the output set
            for name, version in cluster_versions.items():
                output_set.add(f"{name}:{version}")

        # Remove duplicates from production_2_cluster
        self.remove_duplicate_versions(
            combined_versions.get("production_cluster", {}),
            combined_versions.get("production_2_cluster", {}),
        )

        # Convert the set to a list for JSON serialization
        output_list = list(output_set)

        # Prepare the combined output data
        data = {
            "production_cluster": combined_versions.get("production_cluster", {}),
            "production_2_cluster": combined_versions.get("production_2_cluster", {}),
            "ecr_image_versions": output_list,
        }
        return data
