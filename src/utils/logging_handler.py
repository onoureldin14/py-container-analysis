import logging


def LoggingHandler(level):
    """
    Configures the logging settings for the application.

    Parameters:
        level: The logging level to set, which determines the severity of the messages that are logged.
    """
    logging.basicConfig(
        level=level, format="%(asctime)s - %(message)s", datefmt="%H:%M:%S"
    )
