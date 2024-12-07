from difflib import SequenceMatcher


def calculate_similarity(version1: str, version2: str) -> float:
    """
    Calculate the similarity percentage between two version strings.

    Args:
        version1 (str): The first version string.
        version2 (str): The second version string.

    Returns:
        float: Similarity percentage between the two version strings.
    """
    # Create a SequenceMatcher object
    matcher = SequenceMatcher(None, version1, version2)
    # Get the ratio of similarity
    similarity_ratio = matcher.ratio()
    # Convert the ratio to a percentage
    similarity_percentage = similarity_ratio * 100
    return similarity_percentage
