"""Logging configuration and setup for the port scanner.

Provides centralized logging infrastructure with file-based output to
a configured log directory. Logs are flushed automatically on program exit.
"""
import logging
import os
import atexit

import port_scanner.config as conf

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def setup_logger(name: str, level=logging.INFO) -> logging.Logger:
    """Initialize and configure a logger with file-based output.

    Creates a logger that writes to a file handler in the configured log directory.
    Automatically registers an exit handler to flush all handlers when the program
    terminates.

    Args:
        name (str): Logger name (typically the module or component name).
        level (int, optional): Logging level (default: logging.INFO).

    Returns:
        logging.Logger: Configured logger instance ready for use.

    Raises:
        PermissionError: If unable to create log directory or write to log file.
    """
    log_dir = conf.LOG_DIR

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Try to create file handler, exit if permission denied
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "port_scanner.log")
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    logger.addHandler(file_handler)

    logger.info("Logging initialized.")

    # Flush on exit
    atexit.register(lambda: [h.flush() for h in logger.handlers])

    return logger