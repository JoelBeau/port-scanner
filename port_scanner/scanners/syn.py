"""SYN port scanning implementation.

Provides SYN scanning (half-open scanning) using crafted TCP packets and
packet sniffing. Requires elevated privileges and Scapy packet handling.
"""

import asyncio
import time
import logging

import port_scanner.config as conf
from port_scanner.models.port import Port
from .base import Scan

from scapy.all import AsyncSniffer, send
from scapy.layers.inet import ICMP, IP, TCP

logger = logging.getLogger("port_scanner")


class SYNScan(Scan):
    """SYN scanner - performs half-open (SYN) scans.

    Sends crafted SYN packets and analyzes responses to determine port state.
    Does not complete TCP connections. Requires elevated privileges and
    packet-handling capabilities.
    """

    async def _scan_batch(self, port_list: list[Port], chunk_of_ports: list[int]):
        """
        Performs a SYN scan batch on a range of ports for a target host.

        This method conducts a TCP SYN scan (half-open scan) on multiple ports simultaneously
        by sending SYN packets and analyzing responses to determine port status. No retries
        are performed during SYN scanning.

        The method:
        1. Prepares SYN packets with sequential source ports mapped to destination ports
        2. Starts an async packet sniffer to capture replies
        3. Sends all SYN packets to the target host
        4. Waits for responses and captures them
        5. Analyzes TCP and ICMP replies to classify each port status
        6. Populates the port_list with Port objects containing scan results

        Port classifications are determined by TCP flags:
        - 0x12 (SYN-ACK): Port is OPEN
        - 0x04 (RST): Port is CLOSED
        - ICMP type 3 (Destination Unreachable): Port is FILTERED
        - No response: Port is FILTERED

        Args:
            port_list (list[Port]): List to append Port objects with scan results to
            chunk_of_ports (list[int]): List of port numbers to scan

        Returns:
            None (modifies port_list in place)
        """
        logger_message = f"There are no retries when using SYN scan."
        logger.info(logger_message)

        if self._verbosity >= conf.VerbosityLevel.MINIMUM:
            print(logger_message)

        logger_message = f"Starting SYN scan batch on host {self._host} for ports in {chunk_of_ports[0]} to {chunk_of_ports[-1]}."
        logger.info(logger_message)

        if self._verbosity >= conf.VerbosityLevel.MINIMUM:
            print(logger_message)

        base_sport = conf.BASE_SOURCE_PORT

        # Map source ports -> destination port so replies can be correlated
        sport_map = {base_sport + i: p for i, p in enumerate(chunk_of_ports)}

        logger.info(f"Preparing packets for SYN scan on host {self._host}...")
        pkts = [
            IP(dst=self._host)
            / TCP(sport=our_sport, dport=scanned_port, flags="S", seq=1000)
            for our_sport, scanned_port in sport_map.items()
        ]

        logger.info(f"Starting sniffer for SYN scan on host {self._host}...")
        sn = AsyncSniffer(
            iface=conf.IFACE,
            filter=f"(tcp or icmp) and src host {self._host}",
            store=True,
        )

        logger_message = f"Sniffer started for SYN scan on host {self._host}."
        logger.info(logger_message)

        if self._verbosity >= conf.VerbosityLevel.MEDIUM:
            print(logger_message)

        sn.start()

        # Send SYN packets
        logger_message = f"Sending SYN packets to {self._host}..."
        logger.info(logger_message)
        if self._verbosity >= conf.VerbosityLevel.MEDIUM:
            print(logger_message)
        send(pkts)

        logger_message = f"SYN packets sent to {self._host}, waiting for replies..."
        logger.info(logger_message)
        if self._verbosity >= conf.VerbosityLevel.MEDIUM:
            print(logger_message)

        # Let replies arrive & capture them
        await asyncio.sleep(self._timeout)

        replies = sn.stop()

        logger_message = f"Captured {len(replies)} replies from {self._host}."
        logger.info(logger_message)
        if self._verbosity >= conf.VerbosityLevel.MAXIMUM:
            print(logger_message)

        status = {p: conf.FILTERED_PORT for p in chunk_of_ports}
        seen = set()

        logger_message = f"Analyzing replies from {self._host}..."
        logger.info(logger_message)
        if self._verbosity >= conf.VerbosityLevel.MAXIMUM:
            print(logger_message)

        for pkt in replies:
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                our_sport = int(tcp.dport)
                scanned_port = sport_map.get(our_sport)
                if scanned_port is None:
                    continue

                # Only process first classification per scanned port
                if scanned_port in seen:
                    continue
                flags = tcp.flags
                logger.info(f"TCP flags for port {scanned_port}: {flags}")
                if flags & conf.SYN_ACK_FLAG == conf.SYN_ACK_FLAG:
                    status[scanned_port] = conf.OPEN_PORT
                elif flags & conf.RESET_FLAG:
                    status[scanned_port] = conf.CLOSED_PORT
                seen.add(scanned_port)
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == conf.ICMP_UNREACHABLE_TYPE:
                icmp = pkt[ICMP]
                our_sport = icmp.sport
                scanned_port = sport_map.get(our_sport)
                if scanned_port is None:
                    continue
                status[scanned_port] = conf.FILTERED_PORT
                seen.add(scanned_port)

        for p in chunk_of_ports:
            tested_port = Port(
                self.display_host(), p, status[p], status[p] == conf.OPEN_PORT
            )
            port_list.append(tested_port)

    def _chunk_list(self, seq: list[int], size: int):
        """Split a list into fixed-size chunks for batch processing.

        Generator that yields consecutive chunks of the input sequence.

        Args:
            seq (list[int]): List of port numbers to chunk.
            size (int): Size of each chunk.

        Yields:
            list: Chunks of port numbers of specified size.
        """
        logger.info(
            f"Splitting port list of length {len(seq)} into chunks of size {size} for SYN scan."
        )
        seq = list(seq)
        for i in range(0, len(seq), size):
            yield seq[i : i + size]

    async def scan_host(self, port_list: list[Port]) -> None:
        """Perform a complete SYN scan on the target host.

        Scans all ports using SYN packets sent in batches. Batches are executed
        concurrently, and results are appended to a shared list.
        Analyzes responses to determine port status and optionally grabs service
        banners from open ports.

        Args:
            port_list (list[Port]): List to populate with Port scan results.
        """

        async def _scan_batch_task(port_list: list[Port], chunk: range):
            await self._scan_batch(port_list, chunk)

        chunks = list(self._chunk_list(self._ports, conf.SYN_SCAN_BATCH_SIZE))
        logger.info(f"Created {len(chunks)} port chunks for SYN scan on host {self._host}.")

        logger.info(f"Created tasks for SYN scan on host {self._host}...")
        tasks = [
            asyncio.create_task(_scan_batch_task(port_list, chunk)) for chunk in chunks
        ]

        logger.info(f"Starting SYN scan on host {self._host} with {len(chunks)} batches...")
        await asyncio.gather(*tasks)

        if self._banner:
            await self._get_banners(port_list)
