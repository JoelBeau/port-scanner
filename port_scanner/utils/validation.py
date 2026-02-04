import ipaddress as ipa
import os
import socket

from port_scanner import config as conf
from port_scanner import errors


def check_root_privileges():
    if os.geteuid() != 0:
        raise errors.RootPrivilegeRequiredError()

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
    """
    Accepts only:
    1) Single IPv4 address
    2) CIDR block
    3) Hostname (resolves to IPv4)
    4) IP range 
    """
    ips = ips.strip()

    # CIDR block
    if "/" in ips:
        try:
            network = ipa.IPv4Network(ips, strict=False)
            return list(network)
        except ipa.NetmaskValueError:
            raise errors.InvalidCIDRError(ips)

    # IP range (e.g., 192.168.1.1-192.168.1.10)
    if "-" in ips:
        try:
            ips_split = ips.split("-")
            start = int(ipa.IPv4Address(ips_split[0]))
            end = int(ipa.IPv4Address(ips_split[1]))
            # Validate each address in range
            for ip in range(start, end + 1):
                ip = ipa.IPv4Address(ip)
            return range(start, end + 1)
        except (ipa.AddressValueError, IndexError):
            raise errors.InvalidIPRangeError(ips)

    # Single IPv4 address
    try:
        return ipa.IPv4Address(ips)
    except ipa.AddressValueError:
        pass

    # Hostname
    try:
        resolved_ip = socket.gethostbyname(ips)
        return (ipa.IPv4Address(resolved_ip), ips)
    except (socket.gaierror, ipa.AddressValueError):
        raise errors.InvalidIPError(ips)


def parse_port_range(ports: str):
    delim = "," if "," in ports else "-" if "-" in ports else None

    if not delim:
        port = int(ports)
        if port < conf.MINIMUM_PORT or port > conf.MAXIMUM_PORT:
            raise errors.InvalidPortError(ports)
        return range(port, port + 1)
    elif delim == "-":
        start, end = map(int, ports.split(delim))
        if start > end or start == conf.PORT_NOT_ALLOWED or end > conf.MAXIMUM_PORT:
            raise errors.InvalidPortRangeError(ports)
        return range(start, end + 1)
    else:  # delim == ","
        port_list = []
        port_strs = ports.split(delim)
        for p_str in port_strs:
            p = int(p_str)
            if p < conf.MINIMUM_PORT or p > conf.MAXIMUM_PORT:
                raise errors.InvalidPortError(p_str)
            port_list.append(p)
        return port_list
