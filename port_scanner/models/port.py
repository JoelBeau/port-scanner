"""Port model representing a scanned port and its state.

Provides a data class for storing port scan results including status,
open/closed state, and optional service banner information.
"""


class Port:
    """Represents the scanning result of a single port on a host.

    Stores the state of a port scan including host, port number, status
    (open, closed, filtered), and optional service banner information.
    """

    def __init__(self, host, port, status, is_open=False):
        """Initialize a Port object with scan results.

        Args:
            host (str): Host IP or hostname.
            port (int): Port number scanned.
            status (str): Port status (OPEN, CLOSED, or FILTERED).
            is_open (bool, optional): Whether the port is open (default: False).
        """
        self._host = host
        self._port = port
        self._status = status
        self._is_open = is_open
        self._service_banner = None

    def check(self):
        """Check if the port is open.

        Returns:
            bool: True if port is open, False otherwise.
        """
        return self._is_open

    def get_port(self):
        """Get the port number.

        Returns:
            int: Port number.
        """
        return self._port

    def get_host(self):
        """Get the host IP or hostname.

        Returns:
            str: Host IP or hostname.
        """
        return self._host

    def get_status(self):
        """Get the port status.

        Returns:
            str: Port status (OPEN, CLOSED, or FILTERED).
        """
        return self._status

    def get_service_banner(self):
        """Get the service banner for the port.

        Returns:
            str or None: Service banner string or None if not retrieved.
        """
        return self._service_banner

    def set_service_banner(self, banner):
        """Set the service banner for the port.

        Args:
            banner (str): Service banner string to store.
        """
        self._service_banner = banner

    def __iter__(self):
        """Iterate over port data as a list.

        Yields:
            Iterable: List of [host, port, status, is_open, service_banner].
        """
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
        """Convert port data to dictionary format.

        Returns:
            dict: Dictionary with keys: host, port, status, is_open, service_banner.
        """
        return {
            "host": self._host,
            "port": self._port,
            "status": self._status,
            "is_open": self._is_open,
            "service_banner": self._service_banner if self._service_banner else "N/A",
        }

    def __str__(self):
        """String representation of the port scan result.

        Returns:
            str: Formatted string showing host, port, and status.
        """
        return f"{self._host}:{self._port} status: {self._status} "

    def __lt__(self, other):
        """Less-than comparison based on port number.

        Args:
            other (Port): Another Port object to compare against.
        Returns:
            bool: True if this port number is less than the other, False otherwise.
        """
        return self._port < other.get_port()
    