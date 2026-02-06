"""Command-line interface for the port scanner.

Provides the main entry point that orchestrates the scanning workflow:
- Validates prerequisites (root privileges)
- Parses command-line arguments
- Initiates concurrent scanning
- Displays results in the requested format
- Logs performance metrics
"""
import asyncio
import sys
import time

import port_scanner.log as log
import port_scanner.config as conf
import port_scanner.core.output as output
import port_scanner.utils.validation as validation
import port_scanner.core.scanner as scanner

from port_scanner.errors import PortScannerError
from port_scanner.models.arguments import Arguments


def main():
    """Execute the port scanning workflow.

    This function orchestrates the complete scanning process:
    1. Verifies root privileges (required for SYN scanning)
    2. Sets up logging infrastructure
    3. Parses and validates command-line arguments
    4. Runs concurrent host/port scanning via asyncio
    5. Formats and displays results

    Returns:
        int: EXIT_SUCCESS (0) on successful completion, EXIT_FAILURE (1) on error.
    """
    try:
        validation.check_root_privileges()

        logger = log.setup_logger("port_scanner")

        flags = Arguments().args
        logger.info(f"Parsed command-line arguments successfully with: {flags}")

        logger_message = "Starting port scanner..."
        logger.info(logger_message)
        print(logger_message)

        start = time.time()

        results = asyncio.run(scanner.scan(**flags))

        output.display_results(results, flags['output'])

        end = time.time()

        scanning_time_message = f"Port scanning completed in {end - start:.2f} seconds."
        logger.info(scanning_time_message)
        print(scanning_time_message)
        
        return conf.EXIT_SUCCESS
    
    except PortScannerError as e:
        print(e, file=sys.stderr)
        return conf.EXIT_FAILURE
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        return conf.EXIT_FAILURE