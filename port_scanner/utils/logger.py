import logging
import os
import atexit

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

def setup_logger(name: str, level=logging.INFO) -> logging.Logger:
    log_dir = "/var/log/port-scanner/"
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Try to create file handler, exit if permission denied
    try:
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "port_scanner.log")
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)
    except (PermissionError, OSError):
        print(f"port scanner: You don't have privileges to run port scanner on this device.")
        exit(1)

    # Flush on exit
    atexit.register(lambda: [h.flush() for h in logger.handlers])
    
    return logger

logger = setup_logger("port_scanner")