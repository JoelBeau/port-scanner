import asyncio
import time

from port_scanner.log import logger
from port_scanner.models.arguments import Arguments
from port_scanner.core.scanner import scan
from port_scanner.core.output import display_results


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