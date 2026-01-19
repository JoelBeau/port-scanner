import logging

def setup_logger(name: str, log_file: str, level=logging.INFO) -> logging.Logger:
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    
    return logger

# Create global logger instance
logger = setup_logger("port_scanner", "port_scanner.log")