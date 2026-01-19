import threading
import time
import asyncio
import aiohttp

from scapy.all import AsyncSniffer, send, conf as scapy_conf
from scapy.layers.inet import ICMP, IP, TCP, TCPerror

from utils.models import Port
from abc import ABC, abstractmethod

from typing import Optional
from utils.conf import logger
from utils.logger import setup_logger

import utils.conf as conf


class Scan(ABC):

    def __init__(
        self, host: str, verbosity: int = conf.DEFAULT_VERBOSITY, banner: bool = False
    ):
        self.host = host
        self.lock = threading.Lock()
        self.verbosity = verbosity
        self.banner = banner
        scapy_conf.verb = verbosity

    def verbosity_print(self, port_obj: Port):
        host = self.host
        status = port_obj.get_status()
        port = port_obj.get_port()

        if status == "FILTERED":
            print(
                f"FAILURE, port {port} on host {host} "
                "is being blocked by the host's firewall!"
            )
        elif status == "CLOSED":
            print(
                f"FAILURE, port {port} on host {host} "
                "is specifically closed from external connections!\n"
            )
        else:
            print(f"\nSUCCESS! Port {port} is open on {host}")

    @abstractmethod
    def scan_host(
        self, port_list, ports, timeout=1.5, retry=0, banner=False, verbose=False
    ):
        pass

    async def grab_http_banner_aiohttp(
        self,
        host: str,
        port: int,
        user_agent: Optional[str] = None,
    ):
        """
        HTTP/HTTPS banner via aiohttp: returns status + key headers (Server, X-Powered-By).
        Works for typical web ports; will NOT work for SSH, etc.
        """
        logger_message = f"Grabbing HTTP banner from {host}:{port}..."
        logger.info(logger_message)

        if self.verbosity == conf.MAX_VERBOSITY:
            print(logger_message)

        scheme = "http"

        if port in conf.HTTPS_PORTS:
            scheme = "https"

        logger.warning(f"Using scheme {scheme} for banner grabbing on port {port}.")

        url = f"{scheme}://{host}:{port}/"

        headers = {}
        if user_agent:
            headers["User-Agent"] = user_agent

        timeout_cfg = aiohttp.ClientTimeout(total=conf.DEFAULT_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:

                logger.info(f"Sending {scheme.upper()} request to {url}...")

                async with session.get(
                    url, headers=headers, allow_redirects=True
                ) as resp:
                    server = resp.headers.get("Server")
                    powered = resp.headers.get("X-Powered-By")

                    # read a tiny bit so some servers actually respond
                    _ = await resp.content.read(200)

                    parts = [f"HTTP {resp.status}"]
                    if server:
                        parts.append(f"Server: {server}")
                    if powered:
                        parts.append(f"X-Powered-By: {powered}")
                    return " | ".join(parts)

        except (asyncio.TimeoutError, aiohttp.ClientError) as e:
            logger.error(f"{scheme} banner grab failed on {host}:{port} due to {e}")
            return None

    async def grab_ssh_banner(
        self,
        host: str,
        port: int = 22,
    ) -> Optional[str]:
        """
        SSH banner via raw TCP. SSH servers usually speak first.
        Returns line like: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3'
        """
        logger_message = f"Grabbing SSH banner from {host}:{port}..."
        logger.info(logger_message)

        if self.verbosity == conf.MAX_VERBOSITY:
            print(logger_message)

        try:
            logger.info(f"Connecting to {host}:{port} for SSH banner grab...")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=conf.DEFAULT_TIMEOUT,
            )
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=conf.DEFAULT_TIMEOUT
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
            logger.error(f"SSH banner grab failed on {host}:{port} due to {e}")
            return None

    async def grab_service_banner(
        self,
        host: str,
        port: int,
        timeout: float = conf.DEFAULT_TIMEOUT,
        read_bytes: int = conf.DEFAULT_READ_BYTES,
    ) -> Optional[str]:
        """
        Best-effort service banner grab:
        - connects
        - waits briefly for the server to send something (for 'speak-first' protocols)
        """

        if self.verbosity == conf.MAX_VERBOSITY:
            print(f"Grabbing running service banner from {host}:{port}...")

        logger.info(f"Grabbing running service banner from {host}:{port}...")

        try:
            logger.info(f"Connecting to {host}:{port} for service banner grab...")
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            try:
                logger.info(
                    f"Waiting to read up to {read_bytes} bytes from {host}:{port}..."
                )
                data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    logger.error(f"Error while closing writer: {e}")
                    pass

            if not data:
                return None

            logger.info(f"Received banner data from {host}:{port}: {data}")
            text = data.decode("utf-8", errors="ignore").strip()
            return text

        except Exception as e:
            logger.error(f"Service banner grab failed on {host}:{port} due to {e}")
            return None

    async def grab_banner_for_port(self, host: str, port: int) -> Optional[str]:
        if port == 22:
            return await self.grab_ssh_banner(host, port)
        if port in conf.ALL_HTTP_PORTS:
            return await self.grab_http_banner_aiohttp(host, port)
        return await self.grab_service_banner(host, port)

    async def _get_banners(self, port_objs: list[Port], concur: int = conf.DEFAULT_CONCURRENCY_FOR_BANNER_GRAB) -> None:

        open_ports = [p for p in port_objs if p.check()]

        if self.verbosity >= conf.MEDIUM_VERBOSITY:
            print(f"\nStarting banner grabbing for {len(open_ports)} open ports...")

        logger.info(
            f"Starting banner grabbing for {len(open_ports)} open ports on host {self.host}. "
            f"Using concurrency of {concur}."
        )

        sem = asyncio.Semaphore(concur)

        async def one(pobj: Port) -> Port:
            if pobj.get_status() != "OPEN":
                return pobj
            async with sem:
                banner = await self.grab_banner_for_port(self.host, pobj.get_port())
            if banner:
                logger.info(
                    f"Retrieved banner for {self.host}:{pobj.get_port()}: {banner}"
                )
                pobj.set_banner(banner)
            if not banner:
                logger.warning(
                    f"Could not retrieve banner for {self.host}:{pobj.get_port()}"
                )
                pobj.set_banner("No banner retrieved")

        return await asyncio.gather(*(one(p) for p in open_ports))


class TCPConnect(Scan):

    async def _connect_one(self, port: int, timeout: float = 2) -> str:

        logger_message = f"Attempting to connect to {self.host} on port {port}..."
        logger.info(logger_message)

        if self.verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)

        try:
            conn = asyncio.open_connection(self.host, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()

            # ensure the writer is closed
            try:
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Error while closing writer: {e}")
                pass
            return "OPEN"
        except (ConnectionRefusedError, OSError) as e:
            if isinstance(e, ConnectionRefusedError):
                logger.warning(
                    f"Connection refused on {self.host}:{port} - port is CLOSED"
                )
                return "CLOSED"
            if getattr(e, "errno", None) in conf.ERRORNO_LIST:
                logger.warning(f"Connection failed on due to network error {e.errno}")
                return "FILTERED"
            logger.error(
                f"Connection to {self.host}:{port} failed due to packet drop or firewall"
            )
            return "FILTERED"
        except asyncio.TimeoutError:
            logger.warning(f"Connection to {self.host}:{port} failed due to timeout")
            return "FILTERED"

    async def _scan_batch_connect(
        self,
        port_list: list[Port],
        ports: range,
        timeout: float = conf.DEFAULT_TIMEOUT,
        concur: int = conf.DEFAULT_CONCURRENCY_FOR_SCANS,
        retry: int = 0,
    ) -> None:
        host = self.host
        sem = asyncio.Semaphore(concur)

        logger_message = (
            f"Starting TCP Connect scan on host {self.host} for ports in {ports} "
        )

        logger.info(logger_message)
        if ports.stop > conf.THRESHOLD_FOR_SLOW_SCAN:
            logger_message = f"Scanning more than {conf.THRESHOLD_FOR_SLOW_SCAN} ports may be slow."
            logger.warning(logger_message)
            print(logger_message)

        if self.verbosity >= conf.MINIMUM_VERBOSITY:
            print(logger_message)

        async def scan_port(port: int):
            # retry loop (avoid recursion)
            status = "FILTERED"

            for attempt in range(retry + 1):
                logger_message = (
                    f"Scanning port {port} on host {host}, attempt {attempt + 1}..."
                )
                logger.info(logger_message)

                if self.verbosity >= conf.MEDIUM_VERBOSITY:
                    print(logger_message)

                if attempt > 0:
                    logger_message = (
                        f"Retrying port {port} on host {host}, attempt {attempt + 1}..."
                    )
                    logger.warning(logger_message)
                    if self.verbosity == conf.MAX_VERBOSITY:
                        print(logger_message)

                async with sem:
                    logger.info(
                        f"Waiting for connection slot for port {port} on host {host}..."
                    )
                    status = await self._connect_one(port, timeout)
                if status == "OPEN":
                    break

            tested = Port(host, port, status, status == "OPEN")

            if self.verbosity == conf.MAX_VERBOSITY:
                self.verbosity_print(port_obj=tested)

            return tested

        tasks = [asyncio.create_task(scan_port(p)) for p in ports]

        logger.info(f"Waiting for scan tasks to complete for host {host}...")
        # gather results as they complete (keeps memory steady-ish)
        for t in asyncio.as_completed(tasks):
            port_list.append(await t)

    def scan_host(self, port_list, ports, timeout=conf.DEFAULT_TIMEOUT, retry=conf.DEFAULT_RETRY_COUNT) -> None:

        asyncio.run(self._scan_batch_connect(port_list, ports, timeout, concur=conf.DEFAULT_CONCURRENCY_FOR_SCANS, retry=retry))

        if self.banner:
            asyncio.run(self._get_banners(port_list))


class SYNScan(Scan):

    def __init__(self, host: str):
        super().__init__(host)

    def scan_batch(
        self,
        port_list: list[Port],
        ports: range,
        timeout: int = conf.DEFAULT_TIMEOUT,
    ):
        logger_message = f"There are no retries when using SYN scan."
        logger.info(logger_message)

        if self.verbosity >= conf.MINIMUM_VERBOSITY:
            print(logger_message)

        logger_message = (
            f"Starting SYN scan batch on host {self.host} for ports in {ports}."
        )
        logger.info(logger_message)

        if self.verbosity >= conf.MINIMUM_VERBOSITY:
            print(logger_message)

        host = self.host
        base_sport = 40000
        # map sport -> dport so we can correlate replies
        sport_map = {
            base_sport + i: p for i, p in enumerate(ports)
        }  # our_sport -> scanned_port

        logger.info(f"Preparing packets for SYN scan on host {host}...")
        pkts = [
            IP(dst=host) / TCP(sport=our_sport, dport=scanned_port, flags="S", seq=1000)
            for our_sport, scanned_port in sport_map.items()
        ]

        logger.info(f"Starting sniffer for SYN scan on host {host}...")
        sn = AsyncSniffer(
            iface="eth0", filter=f"tcp or icmp and src host {host}", store=True
        )

        logger_message = f"Sniffer started for SYN scan on host {host}."
        logger.info(logger_message)

        if self.verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)

        sn.start()

        # send all SYNs
        logger_message = f"Sending SYN packets to {host}..."
        logger.info(logger_message)
        if self.verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)
        send(pkts)

        logger_message = f"SYN packets sent to {host}, waiting for replies..."
        logger.info(logger_message)
        if self.verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)

        # Let replies arrive & capture them 
        time.sleep(timeout)
        replies = sn.stop()

        logger_message = f"Captured {len(replies)} replies from {host}."
        logger.info(logger_message)
        if self.verbosity >= conf.MAX_VERBOSITY:
            print(logger_message)

        status = {p: "FILTERED" for p in ports}
        seen = set()

        logger_message = f"Analyzing replies from {host}..."
        logger.info(logger_message)
        if self.verbosity >= conf.MAX_VERBOSITY:
            print(logger_message)

        for pkt in replies:
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                our_sport = int(tcp.dport)
                scanned_port = sport_map[our_sport]
                if scanned_port is None:
                    continue
                flags = tcp.flags
                if flags & 0x12 == 0x12:
                    status[scanned_port] = "OPEN"
                elif flags & 0x04:
                    status[scanned_port] = "CLOSED"
                seen.add(scanned_port)
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 3:
                icmp = pkt[ICMP]
                our_sport = icmp.sport
                scanned_port = sport_map[our_sport]
                status[scanned_port] = "FILTERED"
                seen.add(scanned_port)

        for p in ports:
            tested_port = Port(self.host, p, status[p], status[p] == "OPEN")
            port_list.append(tested_port)

    def _chunks(self, seq, size):
        logger.info(
            f"Splitting port list of length {len(seq)} into chunks of size {size} for SYN scan."
        )
        seq = list(seq)
        for i in range(0, len(seq), size):
            yield seq[i : i + size]
        
    def scan_host(self, port_list, ports, timeout=conf.DEFAULT_TIMEOUT) -> None:
        for chunk in self._chunks(ports, conf.SYN_SCAN_BATCH_SIZE):
            self.scan_batch(port_list, chunk, timeout)

        if self.banner:
            asyncio.run(self._get_banners(port_list))
