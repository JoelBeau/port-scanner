import ipaddress as ipa
import socket

from port_scanner import config as conf
from port_scanner import errors


def parse_outputs(output):

    # If outputting to a file
    if "." in output:
        return (output, conf.OUTPUT_TO_FILE)

    # If just outputting to the terminal
    if output in conf.FORMAT_TYPES:
        return (output, conf.OUTPUT_TO_CONSOLE)

    raise errors.InvalidOutputFormatError(output)


def parse_exclusions(value: str):
    if "," not in value:
        return [validate_exclusions(value.strip())]
    else:
        exclusions = value.split(",")
        modified_exclusions = []
        for e in exclusions:
            modified_exclusions.append(validate_exclusions(e.strip()))
        return modified_exclusions


def validate_exclusions(value: str):
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
    except ValueError:
        raise errors.InvalidPortExclusionError(value)
    except ipa.AddressValueError:
        raise errors.InvalidIPExclusionError(value)


def parse_ips(ips: str):
    # Check if it's CIDR notation
    try:
        resolved_ip = ipa.IPv4Address(socket.gethostbyname(ips))
        return resolved_ip
    except socket.gaierror:
        if "/" in ips:
            try:
                network = ipa.IPv4Network(ips, strict=False)
            except ipa.NetmaskValueError:
                raise errors.InvalidCIDRError(ips)
            return list(network)
        # Not in CIDR notation
        elif "-" not in ips:
            try:
                int(ips)
                raise errors.InvalidIPError(ips)
            except ValueError:
                try:
                    ip = ipa.IPv4Address(ips)
                except ipa.AddressValueError:
                    try:
                        resolved_ip = ipa.IPv4Address(socket.gethostbyname(ips))
                        return resolved_ip
                    except socket.gaierror:
                        raise errors.InvalidIPError(ips)
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
            except ipa.AddressValueError:
                raise errors.InvalidIPRangeError(ips)


def parse_port_range(ports: str):
    delim = "," if "," in ports else "-" if "-" in ports else None

    if not delim:
        port = int(ports)
        if port < conf.MINIMUM_PORT or port > conf.MAXIMUM_PORT:
            raise errors.InvalidPortError(ports)
        return port
    else:
        start, end = map(int, ports.split(delim))
        if start > end or start == conf.PORT_NOT_ALLOWED or end > conf.MAXIMUM_PORT:
            raise errors.InvalidPortRangeError(ports)
        return range(start, end + 1)
