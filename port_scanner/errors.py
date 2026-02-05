"""Custom exception classes for the port scanner.

Provides a hierarchy of domain-specific exceptions for different error scenarios:
- Network reachability errors
- Permission and privilege errors
- Argument validation errors (ports, IPs, ranges, formats)

All exceptions inherit from PortScannerError and provide formatted error messages.
"""

from argparse import ArgumentTypeError


class PortScannerError(Exception):
    """Base exception for port scanner.

    All port scanner exceptions inherit from this class, providing a consistent
    error message format prefixed with 'portscanner:'.
    """

    def __init__(self, message=None):
        self.message = self.message = f"portscanner: {message}"
        super().__init__(self.message)


class HostUnreachableError(PortScannerError, OSError):
    """Exception raised when a target host is not reachable.

    Indicates that a host could not be reached via ping or other network diagnostics.
    """

    def __init__(self, host):
        message = f"host {host} is not reachable"
        super().__init__(message)


class RootPrivilegeRequiredError(PortScannerError):
    """Exception raised when root/administrator privileges are required.

    Indicates that the scanner must be run with elevated privileges, typically
    for SYN scanning or other packet-based operations.
    """

    def __init__(self):
        message = "you don't have permission to run port scanner on this device"
        super().__init__(message)


# Argument type errors
class InvalidPortError(PortScannerError, ArgumentTypeError):
    """Exception raised when a port number is out of valid range.

    Valid ports are between 1 and 65535.
    """

    def __init__(self, port):
        message = f"port out of range: {port}"
        super().__init__(message)


class InvalidPortRangeError(PortScannerError, ArgumentTypeError):
    """Exception raised when a port range specification is invalid.

    Invalid ranges include reversed bounds, zero ports, or ports exceeding 65535.
    """

    def __init__(self, port_range, message=None):
        message = f"port range out of bounds: {port_range}"
        super().__init__(message)


class InvalidIPError(PortScannerError, ArgumentTypeError):
    """Exception raised when an IP address is invalid or malformed.

    Indicates that the provided IP address is not a valid IPv4 address.
    """

    def __init__(self, ip, message=None):
        message = f"invalid IP address specified: {ip}"
        if ip is None:
            message = "no IP address specified"
        super().__init__(message)


class InvalidIPRangeError(PortScannerError, ArgumentTypeError):
    """Exception raised when an IP range specification is invalid.

    Invalid ranges include reversed bounds or malformed IP addresses.
    """

    def __init__(self, ip_range, message=None):
        message = f"invalid IP range specified: {ip_range}"
        super().__init__(message)


class InvalidCIDRError(PortScannerError, ArgumentTypeError):
    """Exception raised when CIDR notation is invalid or malformed.

    Indicates that the provided CIDR block specification is not valid.
    """

    def __init__(self, cidr, message=None):
        message = f"invalid CIDR notation specified: {cidr}"
        super().__init__(message)


class InvalidPortExclusionError(PortScannerError, ArgumentTypeError):
    """Exception raised when a port exclusion value is invalid.

    Indicates that a port to exclude from scanning is out of valid range.
    """

    def __init__(self, exclusion, message=None):
        message = f"invalid port exclusion value specified: {exclusion}"
        super().__init__(message)


class InvalidIPExclusionError(PortScannerError, ArgumentTypeError):
    """Exception raised when an IP exclusion value is invalid.

    Indicates that an IP to exclude from scanning is invalid.
    """

    def __init__(self, exclusion, message=None):
        message = f"invalid IP exclusion value specified: {exclusion}"
        super().__init__(message)


class InvalidOutputFormatError(PortScannerError, ArgumentTypeError):
    """Exception raised when an output format specification is invalid.

    Valid formats are: txt, json, csv, or a valid file path.
    """

    def __init__(self, format, message=None):
        message = f"invalid output format specified: {format}"
        super().__init__(message)
