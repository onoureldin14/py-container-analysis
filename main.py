import logging
from src.utils.logging_handler import LoggingHandler
from src.utils.project_state_manager import ProjectStateManager


if __name__ == "__main__":
    LoggingHandler(level=logging.INFO)
    manager = ProjectStateManager()
