
import threading
import time
import asyncio
import aiohttp

from scapy.all import AsyncSniffer, send, conf
from scapy.layers.inet import ICMP, IP, TCP, TCPerror

from utils.models import Port
from abc import ABC, abstractmethod

from typing import Optional

import utils.constants as constants
from utils.logger import setup_logger

logger = setup_logger("scans_logger", "scanner.log")

class Scan(ABC):

    def __init__(self, host: str, verbose: bool = False):
        self.host = host
        self.lock = threading.Lock()
        self.verbose = verbose

    def verbosity_print(
        self, port: int = None, port_obj: Port = None, type: str = "result"
    ):

        host = self.host

        if type == "a":
            print(f"\nAiming to connect to {host} on port {port}...")
        else:
            status = port_obj.get_status()
            port = port_obj.get_port()
            if status == "FILTERED":
                print(
                    f"\nFAILURE, port {port} on host {host} is being blocked by the host's firewall!"
                )
            elif status == "CLOSED":
                print(
                    f"\nFAILURE, port {port} on host {host} is specifically close from external connections!"
                )
            else:
                print(f"\nSUCCESS! Port {port} is open on {host}")


    @abstractmethod
    def scan_host(
        self, port_list, ports, timeout=1.5, retry=0, banner=False, verbose=False
    ):
        pass

    async def grab_http_banner_aiohttp(self,
        host: str,
        port: int,
        user_agent: Optional[str] = None,
    ):
        """
        HTTP/HTTPS banner via aiohttp: returns status + key headers (Server, X-Powered-By).
        Works for typical web ports; will NOT work for SSH, etc.
        """
        scheme = "http"

        if port in constants.HTTPS_PORTS:
            scheme = "https"
        
        url = f"{scheme}://{host}:{port}/"

        headers = {}
        if user_agent:
            headers["User-Agent"] = user_agent

        timeout_cfg = aiohttp.ClientTimeout(total=constants.DEFAULT_TIMEOUT)

        try:
            async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
                async with session.get(url, headers=headers, allow_redirects=True) as resp:
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
            print(f"HTTP banner grab failed on {host}:{port} due to {e} error")
            return None


    async def grab_ssh_banner(self,
        host: str,
        port: int = 22,
    ) -> Optional[str]:
        """
        SSH banner via raw TCP. SSH servers usually speak first.
        Returns line like: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3'
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=constants.DEFAULT_TIMEOUT,
            )
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=constants.DEFAULT_TIMEOUT)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception as e:
                    print(f"Error while closing writer: {e}")

            banner = line.decode("utf-8", errors="ignore").strip()
            return banner or None

        except Exception as e:
            print(f"SSH banner grab failed on {host}:{port} due to {e}")
            return None


    async def grab_generic_banner(
        host: str,
        port: int,
        timeout: float = 2.0,
        read_bytes: int = 1024,
    ) -> Optional[str]:
        """
        Best-effort generic banner grab:
        - connects
        - waits briefly for the server to send something (for 'speak-first' protocols)
        Does NOT send protocol-specific handshakes.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            try:
                data = await asyncio.wait_for(reader.read(read_bytes), timeout=timeout)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

            if not data:
                return None

            text = data.decode("utf-8", errors="ignore").strip()
            return text

        except Exception as e:
            print(f"Generic banner grab failed on {host}:{port} due to {e}")
            return None

    async def grab_banner_for_port(self, host: str, port: int, verbose: int) -> Optional[str]:
        if port == 22:
            if verbose == constants.MAX_VERBOSITY:
                print(f"Grabbing SSH banner from {host}:{port}...")
            return await self.grab_ssh_banner(host, port)
        if port in (80, 443, 8080, 8443):
            return await self.grab_http_banner_aiohttp(host, port, user_agent="MyScanner/1.0")
        return await self.grab_generic_banner(host, port)

    async def get_banners(self, port_objs, concur: int = 50, verbose: bool = False):
        
        open_ports = [p for p in port_objs if p.check()]

        if verbose:
            print(f"\nStarting banner grabbing for {len(open_ports)} open ports...")

        sem = asyncio.Semaphore(concur)
        async def one(pobj):
            if pobj.get_status() != "OPEN":
                return pobj
            async with sem:
                banner = await self.grab_banner_for_port(self.host, pobj.get_port())
            if banner:
                pobj.set_banner(banner)
            if not banner:
                pobj.set_banner("No banner retrieved")

        return await asyncio.gather(*(one(p) for p in open_ports))
class TCPConnect(Scan):

    async def _connect_one(self, port: int, timeout: float = 2) -> str:
        try:
            conn = asyncio.open_connection(self.host, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()

            # ensure the writer is closed
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return "OPEN"
        except (ConnectionRefusedError, OSError) as e:
            if isinstance(e, ConnectionRefusedError):
                return "CLOSED"
            if getattr(e, "errno", None) in (113, 101, 110):
                return "FILTERED"
            return "FILTERED"
        except asyncio.TimeoutError:
            return "FILTERED"

    async def _scan_batch_connect(
        self,
        port_list,
        ports,
        timeout: float = 1.0,
        concur: int = 450,
        retry: int = 0,
        banner: bool = False,
    ):
        host = self.host
        sem = asyncio.Semaphore(concur)

        async def scan_port(port: int):
            if self.verbose:
                self.verbosity_print(port, type="a")

            # retry loop (avoid recursion)
            status = "FILTERED"

            for attempt in range(retry + 1):
                if self.verbose and attempt > 0:
                    print(f"Attempting retry {attempt} for port {port}...")

                async with sem:
                    status = await self._connect_one(port, timeout)
                if status == "OPEN":
                    break

            tested = Port(host, port, status, status == "OPEN")

            if tested.get_status() == "OPEN" and banner:
                # banner grabbing might be blocking; if so, offload to thread
                service = await asyncio.to_thread(self.get_running_service, tested)
                tested.set_banner(service)

            if self.verbose:
                self.verbosity_print(port_obj=tested)

            return tested

        tasks = [asyncio.create_task(scan_port(p)) for p in ports]

        # gather results as they complete (keeps memory steady-ish)
        for t in asyncio.as_completed(tasks):
            port_list.append(await t)
    
    def scan_host(self, port_list, ports, timeout=1.5, retry=0, banner=False):
        asyncio.run(
            self._scan_batch_connect(
                port_list, ports, timeout, concur=200, retry=retry, banner=banner
            )
        )

        if banner:
            asyncio.run(self.get_banners(port_list, concur=50))


class SYNScan(Scan):

    def __init__(self, host: str):
        super().__init__(host)

    def scan_batch(
        self,
        port_list: list[Port],
        ports: range,
        timeout: int = 2,
        retry: int = 0,
        verbose: bool = False,
    ):
        host = self.host
        base_sport = 40000
        # map sport -> dport so we can correlate replies
        sport_map = {
            base_sport + i: p for i, p in enumerate(ports)
        }  # our_sport -> scanned_port

        pkts = [
            IP(dst=host) / TCP(sport=our_sport, dport=scanned_port, flags="S", seq=1000)
            for our_sport, scanned_port in sport_map.items()
        ]

        conf.use_pcap = True

        sn = AsyncSniffer(
            iface="eth0", filter=f"tcp or icmp and src host {host}", store=True
        )
        sn.start()

        # send all SYNs
        send(pkts, verbose=3)

        # Let replies arrive & catpure them
        time.sleep(timeout)
        replies = sn.stop()

        print(f"Captured {len(replies)} replies")

        status = {p: "FILTERED" for p in ports}
        seen = set()

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

    def chunks(self, seq, size):
        logger.info(f"Splitting port list of length {len(seq)} into chunks of size {size} for SYN scan.")
        seq = list(seq)
        for i in range(0, len(seq), size):
            yield seq[i : i + size]

    def scan_host(
        self, port_list, ports, timeout=1.5, retry=0, banner=False, verbose=False
    ):
        for chunk in super().chunks(ports, 2000):
            self.scan_batch(port_list, chunk, timeout, retry, verbose)
        
        if banner:
            asyncio.run(self.get_banners(port_list, concur=50))
