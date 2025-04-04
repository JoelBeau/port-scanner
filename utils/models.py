import argparse
import sys
import ipaddress as ipa

class Port:

    def __init__(self, host, port, status, is_open=False):
        self.__host = host
        self.__port = port
        self.__status = status
        self.__is_open = is_open

    def check(self):
        return self.__is_open

    def get_port(self):
        return self.__port

    def get_host(self):
        return self.__host

    def get_status(self):
        return self.__status

    def __str__(self):
        return f"{self.__host}:{self.__port} status: {self.__status} "

class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_help()
        sys.exit(-1)

class Arguements:

    def __init__(self):
        self.parser = ArgParser(description="Port Scanner - A tool for scanning ports and retrieving banners.")
        self.args = self.get_flags()

    #Parse flags with arguement parser
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
            default=range(1,1025),
            help="Specify the range of ports to scan (e.g., 1-1024 or 80)",
        )
        self.parser.add_argument(
            "-s",
            "--scan-type",
            choices=["tcp", "syn"],
            default="tcp",
            help="Choose the type of scan to perform",
        )
        self.parser.add_argument(
            "-v", "--verbose", action="store_true", help="Enable verbose output"
        )
        self.parser.add_argument("-o", "--output", help="Specify the output format or file")
        self.parser.add_argument(
            "-r",
            "--retry",
            type=int,
            help="Number of retries on failed connection attempts",
        )
        self.parser.add_argument(
            "-n", "--no-resolve", action="store_true", help="Disable reverse DNS resolution"
        )
        self.parser.add_argument(
            "-u",
            "--user-agent",
            help="Specify a custom user-agent string for HTTP-based scans",
        )
        self.parser.add_argument(
            "-e", "--exclude", type=self.parse_exclusions, help="Exclude specific IPs or ports from the scan"
        )
        self.parser.add_argument(
            "-b", "--banner", action="store_true", help="Enable service banner grabbing"
        )

        args = self.parser.parse_args()

        return vars(args)


    def parse_exclusions(self, value: str):
        if "," not in value: 
            return self.validate_exclusions(value)
        else:
            exclusions = value.split(',')
            modified_exclusions = []
            for e in exclusions:
                modified_exclusions.append(self.validate_exclusions(e))
            return modified_exclusions

    def validate_exclusions(self, value: str):
        try:
            if "." in value:
                ip = ipa.IPv4Address(value)
                return int(ip)
            else:
                e = int(value)
                if e > 65535 or e == 0:
                    raise ValueError
                else:
                    return e
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port exclusion")
        except ipa.AddressValueError as e:
            raise argparse.ArgumentTypeError(f"Invalid IP exclusion {e.args[0]}")


    def parse_ips(self, ips: str):
        if "-" not in ips:
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
                raise argparse.ArgumentTypeError(f"Invalid IP address range, {e.args[0]}")


    def parse_port_range(ports: str):

        delim = "," if "," in ports else "-" if "-" in ports else None
        try:
            if not delim:
                port = int(ports)
                if port < 1 or port > 65535:
                    raise ValueError
                return port
            else:
                start, end = map(int, ports.split(delim))
                if start > end or start == 0 or end > 65535:
                    raise ValueError
                return range(start, end + 1)

        except ValueError:
            if not delim:
                raise argparse.ArgumentTypeError(f"Invalid port range'{start} - {end}'")
            else:
                raise argparse.ArgumentTypeError(f"Invalid port: '{ports}'")
