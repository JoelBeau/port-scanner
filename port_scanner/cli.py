import asyncio
import time

from log import logger
from models.arguments import Arguments
from core.scanner import scan
from core.output import display_results


def main():

    """Main entry point for the port scanner."""
    flags = Arguments().args
    
    logger.info("Starting port scanner...")
    start = time.time()
    
    results = asyncio.run(scan(**flags))

    display_results(results, flags['output'])
    
    end = time.time()

    logger.info("Port scanning completed.")
    logger.info(f"Total scanning time: {end - start:.2f} seconds")