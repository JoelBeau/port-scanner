from argparse import ArgumentTypeError


class PortScannerError(Exception):
    """Base exception for port scanner"""

    def __init__(self, message=None):
        self.message = self.message = f"portscanner: {message}"
        super().__init__(self.message)


class HostUnreachableError(PortScannerError, OSError):
    """Host is not reachable"""

    def __init__(self, host):
        message = f"host {host} is not reachable"
        super().__init__(message)


class RootPrivilegeRequiredError(PortScannerError):
    """Permission denied error"""

    def __init__(self):
        message = "you don't have permission to run port scanner on this device"
        super().__init__(message)


# Argument type errors
class InvalidPortError(PortScannerError, ArgumentTypeError):
    """Invalid port or port range"""

    def __init__(self, port):
        message = f"port out of range: {port}"
        super().__init__(message)


class InvalidPortRangeError(PortScannerError, ArgumentTypeError):
    """Invalid port range specified"""

    def __init__(self, port_range, message=None):
        message = f"port range out of bounds: {port_range}"
        super().__init__(message)


class InvalidIPError(PortScannerError, ArgumentTypeError):
    """Invalid IP address"""

    def __init__(self, ip, message=None):
        message = f"invalid IP address specified: {ip}"
        if ip is None:
            message = "no IP address specified"
        super().__init__(message)


class InvalidIPRangeError(PortScannerError, ArgumentTypeError):
    """Invalid IP range"""

    def __init__(self, ip_range, message=None):
        message = f"invalid IP range specified: {ip_range}"
        super().__init__(message)


class InvalidCIDRError(PortScannerError, ArgumentTypeError):
    """Invalid CIDR notation"""

    def __init__(self, cidr, message=None):
        message = f"invalid CIDR notation specified: {cidr}"
        super().__init__(message)


class InvalidPortExclusionError(PortScannerError, ArgumentTypeError):
    """Invalid port exclusion value"""

    def __init__(self, exclusion, message=None):
        message = f"invalid port exclusion value specified: {exclusion}"
        super().__init__(message)


class InvalidIPExclusionError(PortScannerError, ArgumentTypeError):
    """Invalid IP exclusion value"""

    def __init__(self, exclusion, message=None):
        message = f"invalid IP exclusion value specified: {exclusion}"
        super().__init__(message)


class InvalidOutputFormatError(PortScannerError, ArgumentTypeError):
    """Invalid output format"""

    def __init__(self, format, message=None):
        message = f"invalid output format specified: {format}"
        super().__init__(message)
