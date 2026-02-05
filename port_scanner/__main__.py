"""Entry point for the port scanner application.

Provides the main entry point and error handling for the port scanner CLI.
"""
import sys
from port_scanner.errors import PortScannerError
from port_scanner.cli import main
from port_scanner import config as conf


def run():
    """Execute the port scanner and handle errors.

    Runs the main CLI entry point and gracefully handles both PortScannerError
    exceptions and unexpected errors, returning appropriate exit codes.

    Returns:
        int: EXIT_SUCCESS (0) on successful completion, EXIT_FAILURE (1) on error.
    """
    try:
        main()
    except PortScannerError as e:
        print(e)
        return conf.EXIT_FAILURE
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return conf.EXIT_FAILURE
    return conf.EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(run())