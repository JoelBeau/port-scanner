import argparse
import sys

import port_scanner.config as conf
from ..utils import validation


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_help()
        sys.exit(-1)


class Arguments:

    def __init__(self):
        self.parser = ArgParser(
            description="Port Scanner - A tool for scanning ports and retrieving banners."
        )
        self.args = self._get_flags()

    # Parse flags with arguement parser
    def _get_flags(self):

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