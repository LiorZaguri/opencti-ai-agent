import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from config.settings import LOG_LEVEL

def setup_logger(
        name: str = "CTIAgentLogger",
        log_dir: str = "data/logs",
        component_type: str = "system",
        console_level: int = getattr(logging, LOG_LEVEL),
        file_level: int = logging.DEBUG,
        propagate: bool = False
) -> logging.Logger:
    """Configure and return a logger with file and console handlers."""
    # Get the project root directory (assuming this file is in utils/ directory)
    project_root: str = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Create absolute path to logs directory in project root
    logs_absolute_path: str = os.path.join(project_root, log_dir)

    # Create logs directory if it doesn't exist
    os.makedirs(logs_absolute_path, exist_ok=True)

    # Set up log file with timestamp and component type using absolute path
    log_filename: str = os.path.join(logs_absolute_path, f"{component_type}_{datetime.now().strftime('%Y-%m-%d')}.log")

    # Rest of the function remains the same
    logger = logging.getLogger(name)
    logger.setLevel(min(console_level, file_level))
    logger.propagate = propagate

    # Only add handlers if they don't exist already
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)

        # File handler with rotation
        file_handler = TimedRotatingFileHandler(
            log_filename,
            when="midnight",
            interval=1,
            backupCount=30
        )
        file_handler.setLevel(file_level)

        # Formatter
        formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)

        # Attach handlers
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

    return logger