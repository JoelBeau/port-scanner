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
