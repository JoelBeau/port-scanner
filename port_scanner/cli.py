"""Command-line interface for the port scanner.

Provides the main entry point that orchestrates the scanning workflow:
- Validates prerequisites (root privileges)
- Parses command-line arguments
- Initiates concurrent scanning
- Displays results in the requested format
- Logs performance metrics
"""
import asyncio
import time

import port_scanner.log as log
import port_scanner.core.output as output
import port_scanner.utils.validation as validation
import port_scanner.core.scanner as scanner

from port_scanner.models.arguments import Arguments


def main():
    """Execute the port scanning workflow.

    This function orchestrates the complete scanning process:
    1. Verifies root privileges (required for SYN scanning)
    2. Sets up logging infrastructure
    3. Parses and validates command-line arguments
    4. Runs concurrent host/port scanning via asyncio
    5. Formats and displays results
    6. Reports performance metrics

    Raises:
        PortScannerError: If root privileges are missing or argument parsing fails.
        Exception: Any unexpected errors during scanning are caught and logged.
    """
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