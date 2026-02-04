"""Command-line argument parsing and validation.

Provides argument parser configuration and the Arguments class that handles
parsing and validation of all CLI options.
"""
import argparse
import sys

import port_scanner.config as conf
from ..utils import validation


class ArgParser(argparse.ArgumentParser):
    """Custom argument parser with enhanced error handling.

    Extends argparse.ArgumentParser to provide cleaner error output that
    includes help text and exits with status code -1.
    """

    def error(self, message):
        """Handle argument parsing errors with enhanced output.

        Writes error message to stderr, displays help text, and exits
        with status code -1.

        Args:
            message (str): Error message from argparse.
        """
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_help()
        sys.exit(-1)


class Arguments:
    """Parser and container for command-line arguments.

    Configures an argument parser with all available options for the port scanner
    and parses command-line arguments into a dictionary of flags.
    """

    def __init__(self):
        """Initialize argument parser and parse command-line arguments.

        Sets up all argument definitions and immediately parses sys.argv,
        storing the result in self.args.
        """
        self.parser = ArgParser(
            description="Port Scanner - A tool for scanning ports and retrieving banners."
        )
        self.args = self._get_flags()

    # Parse flags with argument parser
    def _get_flags(self):
        """Parse and return command-line arguments.

        Defines all available command-line options with their types, defaults,
        and help text. Performs validation on all inputs and returns a dictionary
        of parsed arguments.

        Returns:
            dict: Dictionary of parsed arguments with keys: target, port, scan_type,
                  verbosity, output, retry, timeout, user_agent, exclude, banner.
        """

        self.parser.add_argument(
            "-t",
            "--target",
            type=validation.parse_ips,
            required=True,
            help="Specify the target IP or range of IPs to scan",
        )
        self.parser.add_argument(
            "-p",
            "--port",
            type=validation.parse_port_range,
            default=conf.DEFAULT_PORT_RANGE,
            help="Specify the range of ports to scan (e.g., 1-1024 or 80)",
        )
        self.parser.add_argument(
            "-s",
            "--scan-type",
            choices=conf.SCAN_CHOICES,
            default=conf.DEFAULT_PORT_SCAN_TYPE,
            help="Choose the type of scan to perform",
        )
        self.parser.add_argument(
            "-v",
            "--verbosity",
            type=int,
            choices=conf.VERBOSITY_LEVELS,
            default=conf.DEFAULT_VERBOSE_LEVEL,
            help="Enable verbose output",
        )
        self.parser.add_argument(
            "-o",
            "--output",
            type=validation.parse_outputs,
            default=conf.DEFAULT_OUTPUT_MEDIUM,
            help="Specify the output format or file",
        )
        self.parser.add_argument(
            "-r",
            "--retry",
            type=int,
            help="Number of retries on failed connection attempts",
            default=conf.DEFAULT_RETRY_COUNT,
        )
        self.parser.add_argument(
            "-T",
            "--timeout",
            type=int,
            default=conf.DEFAULT_TIMEOUT,
            help="Specify the timeout duration for connection attempts",
        )
        self.parser.add_argument(
            "-u",
            "--user-agent",
            type=str,
            default=conf.DEFAULT_USER_AGENT,
            help="Specify a custom user-agent string for HTTP-based scans",
        )
        self.parser.add_argument(
            "-e",
            "--exclude",
            type=validation.parse_exclusions,
            help="Exclude specific IPs or ports from the scan",
        )
        self.parser.add_argument(
            "-b",
            "--banner",
            action="store_true",
            default=conf.DEFAULT_SERVICE_BANNER_GRAB,
            help="Enable service banner grabbing",
        )

        args = self.parser.parse_args()

        return vars(args)