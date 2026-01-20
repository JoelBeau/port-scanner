import argparse
import socket
import sys
import ipaddress as ipa
import utils.conf as conf


class Port:

    def __init__(self, host, port, status, is_open=False):
        self._host = host
        self._port = port
        self._status = status
        self._is_open = is_open
        self._service_banner = None

    def check(self):
        return self._is_open

    def get_port(self):
        return self._port

    def get_host(self):
        return self._host

    def get_status(self):
        return self._status

    def get_service_banner(self):
        return self._service_banner

    def set_service_banner(self, banner):
        self._service_banner = banner

    def __iter__(self):
        return iter(
            [
                self._host,
                self._port,
                self._status,
                self._is_open,
                self._service_banner if self._service_banner else "N/A",
            ]
        )

    def to_dict(self):
        return {
            "host": self._host,
            "port": self._port,
            "status": self._status,
            "is_open": self._is_open,
            "service_banner": self._service_banner if self._service_banner else "N/A",
        }

    def __str__(self):
        return f"{self._host}:{self._port} status: {self._status} "


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_help()
        sys.exit(-1)


class Arguements:

    def __init__(self):
        self.parser = ArgParser(
            description="Port Scanner - A tool for scanning ports and retrieving banners."
        )
        self.args = self.get_flags()

    # Parse flags with arguement parser
    def get_flags(self):

        self.parser.add_argument(
            "-t",
            "--target",
            type=self.parse_ips,
            required=True,
            help="Specify the target IP or range of IPs to scan",
        )
        self.parser.add_argument(
            "-p",
            "--port",
            type=self.parse_port_range,
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
            choices=conf.VERBOSITY_LEVELS,
            default=conf.DEFAULT_VERBOSE_LEVEL,
            help="Enable verbose output",
        )
        self.parser.add_argument(
            "-o",
            "--output",
            type=self.parse_outputs,
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
            type=self.parse_exclusions,
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

    def parse_outputs(self, output):

        formats = ["json", "csv", "txt", "text"]

        # If outputting to a file
        if "." in output:
            return (output, conf.OUTPUT_TO_FILE)

        # If just outputting to the terminal
        if output in formats:
            return (output, conf.OUTPUT_TO_CONSOLE)
        
        raise argparse.ArgumentTypeError(conf.INVALID_OUTPUT_FORMAT_ERROR_MSG)

    def parse_exclusions(self, value: str):
        if "," not in value:
            return list(self.validate_exclusions(value.strip()))
        else:
            exclusions = value.split(",")
            modified_exclusions = []
            for e in exclusions:
                modified_exclusions.append(self.validate_exclusions(e.strip()))
            return modified_exclusions

    def validate_exclusions(self, value: str):
        try:
            if "." in value:
                ip = ipa.IPv4Address(value)
                return int(ip)
            else:
                p = int(value)
                if p > conf.MAXIMUM_PORT or p == conf.PORT_NOT_ALLOWED:
                    raise ValueError
                else:
                    return p
        except ValueError as e:
            raise argparse.ArgumentTypeError(f"{conf.INVALID_PORT_EXCLUSION_ERROR_MSG}: {e} ")
        except ipa.AddressValueError as e:
            raise argparse.ArgumentTypeError(f"{conf.INVALID_IP_EXCLUSION_ERROR_MSG}: {e} ")

    def parse_ips(self, ips: str):
        # Check if it's CIDR notation
        if "/" in ips:
            try:
                network = ipa.IPv4Network(ips, strict=False)
            except ipa.NetmaskValueError as e:
                raise argparse.ArgumentTypeError(f"{conf.INVALID_CIDR_ERROR_MSG}: {e}")
            return list(network)
        # Not in CIDR notation
        elif "-" not in ips:
            try:
                ip = ipa.IPv4Address(ips)
            except ipa.AddressValueError as e:
                try:
                    resolved_ip = ipa.IPv4Address(socket.gethostbyname(ips))
                    return resolved_ip
                except socket.gaierror as e:
                    raise argparse.ArgumentTypeError(f"{conf.INVALID_IP_ERROR_MSG}: {e}")
            return ips
        else:
            try:
                ips = ips.split("-")
                start = int(ipa.IPv4Address(ips[0]))
                end = int(ipa.IPv4Address(ips[1]))
                # Make sure each address is a valid address
                for ip in range(start, end):
                    ip = ipa.IPv4Address(ip)
                return range(start, end)
            except ipa.AddressValueError as e:
                raise argparse.ArgumentTypeError(f"{conf.INVALID_IP_RANGE_ERROR_MSG}: {e}")

    def parse_port_range(self, ports: str):
        delim = "," if "," in ports else "-" if "-" in ports else None
        try:
            if not delim:
                port = int(ports)
                if port < conf.MINIMUM_PORT or port > conf.MAXIMUM_PORT:
                    raise ValueError
                return port
            else:
                start, end = map(int, ports.split(delim))
                print(start, end)
                if start > end or start == conf.PORT_NOT_ALLOWED or end > conf.MAXIMUM_PORT:
                    raise ValueError
                return range(start, end + 1)

        except ValueError as ve:
            if not delim:
                raise argparse.ArgumentTypeError(f"{conf.INVALID_PORT_MSG}: {ve}")
            else:
                raise argparse.ArgumentTypeError(f"{conf.INVALID_PORT_RANGE_ERROR_MSG}: {ve}")