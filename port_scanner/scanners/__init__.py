"""Scanner implementations for port scanning."""
from .tcp import TCPConnect
from .syn import SYNScan

# Scanner registry
SCANNER_CLASS = {
    "tcp": TCPConnect,
    "syn": SYNScan,
}