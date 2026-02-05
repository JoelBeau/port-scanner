"""Command-line argument validation and parsing.

Provides validation and parsing functions for all CLI arguments including
IPs, ports, ranges, CIDR blocks, and output formats.
"""

import ipaddress as ipa
import os
import socket

from port_scanner import config as conf
from port_scanner import errors


def check_root_privileges():
    """Verify that the program is running with root/administrator privileges.

    Raises:
        RootPrivilegeRequiredError: If not running as root.
    """
    if os.geteuid() != 0:
        raise errors.RootPrivilegeRequiredError()


def parse_outputs(output):
    """Parse and validate output format specification.

    Interprets output as either:
    - None (defaults to txt console output)
    - A format name (txt/json/csv) for console output
    - A file name with extension (e.g., results.json)
    - A file name without extension (defaults to .txt)

    Args:
        output (str | None): Output format name or file name.

    Returns:
        tuple: (format_or_path, is_file) where format_or_path is the format
               or file path, and is_file indicates file output.

    Raises:
        InvalidOutputFormatError: If format is not recognized.
    """

    if isinstance(output, tuple):
        return output

    output = output.strip()
    name, ext = os.path.splitext(output)
    ext = ext.lstrip(".")

    # If outputting to a file with explicit extension
    if ext:
        if ext not in conf.FORMAT_TYPES:
            raise errors.InvalidOutputFormatError(output)
        return (output, conf.OUTPUT_TO_FILE)

    # If just outputting to the terminal
    if output in conf.FORMAT_TYPES:
        return (output, conf.OUTPUT_TO_CONSOLE)

    # File name without extension defaults to .txt
    return (f"{output}.{conf.TEXT_FORMAT}", conf.OUTPUT_TO_FILE)


def parse_exclusions(value: str):
    """Parse comma-separated exclusion list of IPs and/or ports.

    Args:
        value (str): Comma-separated list of IPs or ports to exclude.

    Returns:
        list: List of excluded IP addresses (as integers) and port numbers.

    Raises:
        InvalidIPExclusionError: If an IP address is invalid.
        InvalidPortExclusionError: If a port is out of range.
    """
    if "," not in value:
        return [validate_exclusions(value.strip())]
    else:
        exclusions = value.split(",")
        modified_exclusions = []
        for e in exclusions:
            modified_exclusions.append(validate_exclusions(e.strip()))
        return modified_exclusions


def validate_exclusions(value: str):
    """Validate and parse a single exclusion value (IP or port).

    Args:
        value (str): Single IP address or port number as string.

    Returns:
        int or IPv4Address: IP address (as IPv4Address) or port number.

    Raises:
        InvalidIPExclusionError: If IP address is invalid.
        InvalidPortExclusionError: If port is out of range.
    """
    try:
        if "." in value:
            ip = ipa.IPv4Address(value)
            return ip
        else:
            p = int(value)
            if p > conf.MAXIMUM_PORT or p == conf.PORT_NOT_ALLOWED:
                raise ValueError
            else:
                return p
    except ipa.AddressValueError:
        raise errors.InvalidIPExclusionError(value)
    except ValueError:
        raise errors.InvalidPortExclusionError(value)


def parse_ips(ips: str):
    """Parse and validate IP address input in multiple formats.

    Accepts and normalizes:
    - Single IPv4 addresses
    - CIDR notation (e.g., 192.168.1.0/24)
    - Hostnames (resolved to IPv4)
    - IP ranges (e.g., 192.168.1.1-192.168.1.10)

    Args:
        ips (str): IP address specification.

    Returns:
        IPv4Address, IPv4Network, range, or tuple: Normalized target.

    Raises:
        InvalidIPError: If single IP address is invalid.
        InvalidCIDRError: If CIDR notation is invalid.
        InvalidIPRangeError: If IP range is invalid.
    """
    ips = ips.strip()

    # Hostname
    try:
        resolved_ip = socket.gethostbyname(ips)
        return (ipa.IPv4Address(resolved_ip), ips)
    except (socket.gaierror, ipa.AddressValueError):
        # CIDR block
        if "/" in ips:
            try:
                network = ipa.IPv4Network(ips, strict=False)
                return network
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
                    ipa.IPv4Address(ip)
                return range(start, end + 1)
            except (ipa.AddressValueError, IndexError):
                raise errors.InvalidIPRangeError(ips)

        # Single IPv4 address
        try:
            return ipa.IPv4Address(ips)
        except ipa.AddressValueError:
            raise errors.InvalidIPError(ips)


def parse_port_range(ports: str):
    """Parse and validate port range specification.

    Accepts port specifications in multiple formats:
    - Single port: "80"
    - Range: "1-1024"
    - List: "80,443,8080"

    Args:
        ports (str): Port specification string.

    Returns:
        range or list: Range object or list of port numbers.

    Raises:
        InvalidPortError: If a port is out of valid range (1-65535).
        InvalidPortRangeError: If range bounds are invalid or reversed.
    """
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
