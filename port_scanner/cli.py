import asyncio
import time

import port_scanner.log as log
import port_scanner.core.output as output
import port_scanner.utils.validation as validation
import port_scanner.core.scanner as scanner

from port_scanner.models.arguments import Arguments


def main():
    """Main entry point for the port scanner."""

    validation.check_root_privileges()

    logger = log.setup_logger("port_scanner")

    flags = Arguments().args
    
    logger.info("Starting port scanner...")
    start = time.time()
    
    results = asyncio.run(scanner.scan(**flags))

    output.display_results(results, flags['output'])
    
    end = time.time()

    logger.info("Port scanning completed.")
    logger.info(f"Total scanning time: {end - start:.2f} seconds")