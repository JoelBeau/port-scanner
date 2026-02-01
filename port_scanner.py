import asyncio
import time

from utils.logger import logger
from utils.models import Arguments
from utils.scanner_utils import scan


def main():
    """Main entry point for the port scanner."""
    flags = Arguments().args
    
    logger.info("Starting port scanner...")
    start = time.time()
    
    asyncio.run(scan(**flags))
    
    end = time.time()
    
    logger.info("Port scanning completed.")
    logger.info(f"Total scanning time: {end - start:.2f} seconds")


if __name__ == "__main__":
    main()