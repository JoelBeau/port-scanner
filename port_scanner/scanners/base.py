import logging
import asyncio
import aiohttp

from scapy.all import conf as scapy_conf

from port_scanner.models.port import Port
from abc import ABC, abstractmethod

from typing import Optional
import port_scanner.config as conf

logger = logging.getLogger("port_scanner")

class Scan(ABC):
    """Abstract base class for port scanner implementations.

    Defines the interface for scanner implementations and provides shared
    functionality for banner grabbing (HTTP, SSH, and generic services).
    Each subclass must implement the scan_host method.
    """

    def __init__(self, host: str, hostname: str, **flags):
        """Initialize a scanner instance for a specific host.

        Args:
            host (str): Target IP address.
            hostname (str): Target hostname (if resolved).
            **flags: Scanning parameters including:
                - port: List/range of ports to scan
                - verbosity: Verbosity level (0-3)
                - retry: Number of retry attempts
                - timeout: Connection timeout in seconds
                - user_agent: Custom HTTP user-agent
                - exclude: List of ports/IPs to exclude
                - banner: Whether to grab service banners
        """
        self._host = host
        self._hostname = hostname
        self._ports = list(flags.get("port"))
        self._verbosity = flags.get("verbosity")
        self._retry = conf.DEFAULT_RETRY if flags.get("retry") is None else flags.get("retry")
        self._timeout = conf.DEFAULT_TIMEOUT if flags.get("timeout") is None else flags.get("timeout")
        self._user_agent = flags.get("user_agent")
        self._exclude = flags.get("exclude")
        self._banner = flags.get("banner")

        # Set scapy verbosity, dependent on verbosity passed in flags
        scapy_conf.verb = self._verbosity

        self._remove_excluded_ports()

    def get_host(self) -> str:
        """Get the display name for this host.

        Returns the hostname if available, otherwise the IP address.

        Returns:
            str: Hostname or IP address.
        """
        if self._hostname:
            return self._hostname
        return self._host
    def display_host(self) -> str:
        """Get formatted display string for the host.

        Returns hostname with IP address in parentheses if both are available,
        otherwise just the IP address.

        Returns:
            str: Formatted host display string.
        """
        if self._hostname:
            return f"{self._hostname} ({self._host})"
        return self._host

    def _remove_excluded_ports(self) -> None:
        """Filter out excluded ports from the scanning list.

        Removes any ports specified in the exclude list and logs the action.
        """
        if not self._exclude:
            return
        self._ports = [p for p in self._ports if p not in self._exclude]
        logger.info(f"Removed excluded ports from scan list for host {self._host}.")

    def verbosity_print(self, port_obj: Port) -> None:
        """Print port status message based on verbosity setting.

        Outputs a detailed message about the port status (open, closed, or filtered)
        for high-verbosity scanning output.

        Args:
            port_obj (Port): Port object containing scan result.
        """
        host = self._host
        status = port_obj.get_status()
        port = port_obj.get_port()

        if status == conf.FILTERED_PORT:
            print(
                f"FAILURE, port {port} on host {host} "
                "is being blocked by the host's firewall!"
            )
        elif status == conf.CLOSED_PORT:
            print(
                f"FAILURE, port {port} on host {host} "
                "is specifically closed from external connections!\n"
            )
        else:
            print(f"\nSUCCESS! Port {port} is open on {host}")

    @abstractmethod
    async def scan_host(self, port_list: list[Port]) -> None:
        """Scan all ports on the target host.

        Subclasses must implement this method to perform the actual port scanning
        and populate the port_list with Port objects. May optionally grab service
        banners if enabled.

        Args:
            port_list (list[Port]): List to populate with Port scan results.
        """
        pass

    async def grab_http_banner_aiohttp(self, port: int):
        """Fetch an HTTP/HTTPS banner using aiohttp.

        Performs a lightweight GET request and returns a compact banner string
        containing the HTTP status and common metadata headers (e.g., Server,
        X-Powered-By). This is intended for typical web ports and will not
        work for non-HTTP protocols (SSH, SMTP, etc.).

        Args:
            port (int): Target port to query.

        Returns:
            str | None: Banner string if available, otherwise None.

        Raises:
            None: Exceptions are caught internally and logged.
        """
        logger_message = f"Grabbing HTTP banner from {self._host}:{port}..."
        logger.info(logger_message)

        if self._verbosity == conf.MAX_VERBOSITY:
            print(logger_message)

        scheme = "http"

        if port in conf.HTTPS_PORTS:
            scheme = "https"

        logger.warning(f"Using scheme {scheme} for banner grabbing on port {port}.")

        domain = self._hostname if self._hostname else self._host
        logger.info(f"Using domain {domain} for http(s) banner grabbing on port {port}.")

        url = f"{scheme}://{domain}:{port}/"

        headers = {}
        if self._user_agent:
            headers["User-Agent"] = self._user_agent

        timeout_cfg = aiohttp.ClientTimeout(total=self._timeout)

        use_ssl = False

        if scheme == "https" and self._hostname is not None:
            use_ssl = True

        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg, connector=aiohttp.TCPConnector(ssl=use_ssl)) as session:

                logger.info(f"Sending {scheme.upper()} request to {url}...")

                async with session.get(
                    url, headers=headers, allow_redirects=True
                ) as resp:
                    logger.info(f"Received response from {url} with status {resp}")
                    server = resp.headers.get("Server")
                    powered = resp.headers.get("X-Powered-By")

                    # Read a tiny bit if needed
                    _ = await resp.content.read(200)

                    parts = [f"HTTP {resp.status}"]
                    if server:
                        parts.append(f"Server: {server}")
                    if powered:
                        parts.append(f"X-Powered-By: {powered}")
                    return " | ".join(parts)

        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            logger.error(
                f"{scheme} banner grab failed on {self._host}:{port} due to {e}"
            )
            return None

    async def grab_ssh_banner(
        self,
        port: int = 22,
    ) -> Optional[str]:
        """Fetch an SSH banner using a raw TCP connection.

        SSH servers typically send a banner line immediately after the
        connection is established. This method reads that line and returns it
        as a decoded string (e.g., 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3').

        Args:
            port (int, optional): SSH port to query (default: 22).

        Returns:
            str | None: Banner line if received, otherwise None.

        Raises:
            None: Exceptions are caught internally and logged.
        """
        logger_message = f"Grabbing SSH banner from {self._host}:{port}..."
        logger.info(logger_message)

        if self._verbosity == conf.MAX_VERBOSITY:
            print(logger_message)

        try:
            logger.info(f"Connecting to {self._host}:{port} for SSH banner grab...")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, port),
                timeout=self._timeout,
            )
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=self._timeout
                )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    logger.error(f"Error while closing writer: {e}")
                    pass

            banner = line.decode("utf-8", errors="ignore").strip()
            return banner

        except Exception as e:
            logger.error(f"SSH banner grab failed on {self._host}:{port} due to {e}")
            return None

    async def grab_service_banner(self, port: int) -> Optional[str]:
        """Perform a best-effort banner grab for non-HTTP services.

        Establishes a TCP connection and waits briefly for the server to send
        any initial data (useful for "speak-first" protocols). The response is
        decoded as UTF-8 with errors ignored.

        Args:
            port (int): Target port to query.

        Returns:
            str | None: Banner string if any data is received, otherwise None.

        Raises:
            None: Exceptions are caught internally and logged.
        """

        if self._verbosity == conf.MAX_VERBOSITY:
            print(f"Grabbing running service banner from {self._host}:{port}...")

        logger.info(f"Grabbing running service banner from {self._host}:{port}...")

        try:
            logger.info(f"Connecting to {self._host}:{port} for service banner grab...")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, port),
                timeout=self._timeout,
            )
            try:
                logger.info(
                    f"Waiting to read up to {conf.DEFAULT_READ_BYTES} bytes from {self._host}:{port}..."
                )
                data = await asyncio.wait_for(
                    reader.read(conf.DEFAULT_READ_BYTES), timeout=self._timeout
                )
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    logger.error(f"Error while closing writer: {e}")
                    pass

            if not data:
                return None

            logger.info(f"Received banner data from {self._host}:{port}: {data}")
            text = data.decode("utf-8", errors="ignore").strip()
            return text

        except Exception as e:
            logger.error(f"Service banner grab failed on {self._host}:{port} due to {e}")
            return None

    async def grab_banner_for_port(self, port: int) -> Optional[str]:
        """Select the appropriate banner-grabbing strategy for a port.

        Routes to SSH, HTTP(S), or generic TCP banner grabbing based on the
        port number.

        Args:
            port (int): Target port.

        Returns:
            str | None: Banner string if available, otherwise None.
        """
        if port == conf.SSH_PORT:
            return await self.grab_ssh_banner(port)
        if port in conf.ALL_HTTP_PORTS:
            return await self.grab_http_banner_aiohttp(port)
        return await self.grab_service_banner(port)

    async def _get_banners(
        self,
        port_objs: list[Port],
        concur: int = conf.DEFAULT_CONCURRENCY_FOR_BANNER_GRAB,
    ) -> None:
        """Fetch banners for open ports with bounded concurrency.

        Filters to open ports, then concurrently fetches banners using the
        appropriate strategy for each port. Updates Port objects in place
        with banner strings or a fallback message when unavailable.

        Args:
            port_objs (list[Port]): Port objects to evaluate and update.
            concur (int, optional): Maximum concurrent banner fetches.

        Returns:
            None
        """

        open_ports = [p for p in port_objs if p.check()]

        if self._verbosity >= conf.MEDIUM_VERBOSITY:
            print(f"\nStarting banner grabbing for {len(open_ports)} open ports...")

        logger.info(
            f"Starting banner grabbing for {len(open_ports)} open ports on host {self._host}. "
            f"Using concurrency of {concur}."
        )

        sem = asyncio.Semaphore(concur)

        async def one(pobj: Port) -> Port:
            if pobj.get_status() != conf.OPEN_PORT:
                return pobj
            async with sem:
                banner = await self.grab_banner_for_port(pobj.get_port())
            if banner:
                logger.info(
                    f"Retrieved banner for {self._host}:{pobj.get_port()}: {banner}"
                )
                pobj.set_service_banner(banner)
            if not banner:
                logger.warning(
                    f"Could not retrieve banner for {self._host}:{pobj.get_port()}"
                )
                pobj.set_service_banner("No banner retrieved")

        return await asyncio.gather(*(one(p) for p in open_ports))