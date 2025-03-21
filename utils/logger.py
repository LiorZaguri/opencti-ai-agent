import logging
import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from config.settings import LOG_LEVEL

def setup_logger(
        name="CTIAgentLogger",
        log_dir="logs",
        console_level=getattr(logging, LOG_LEVEL),
        file_level=logging.DEBUG,
        propagate=False
):
    """Configure and return a logger with file and console handlers."""
    # Create logs directory if it doesn't exist
    os.makedirs(log_dir, exist_ok=True)

    # Set up log file with timestamp
    log_filename = os.path.join(log_dir, f"agent_{datetime.now().strftime('%Y-%m-%d')}.log")

    # Get or create logger
    logger = logging.getLogger(name)
    logger.setLevel(min(console_level, file_level))
    logger.propagate = propagate

    # Only add handlers if they don't exist already
    if not logger.handlers:
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(console_level)

        # File handler with rotation (one file per day, keep 30 days of logs)
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


# Create the default logger instance
logger = setup_logger()