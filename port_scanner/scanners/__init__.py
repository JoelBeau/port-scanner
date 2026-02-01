"""Scanner implementations for port scanning."""
from .tcp import TCPConnect
from .syn import SYNScan

# Scanner registry
SCANNER_CLASSES = {
    "tcp": TCPConnect,
    "syn": SYNScan,
}