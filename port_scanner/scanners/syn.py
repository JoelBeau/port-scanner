import time
import logging

import port_scanner.config as conf
from port_scanner.models.port import Port
from .base import Scan

from scapy.all import AsyncSniffer, send
from scapy.layers.inet import ICMP, IP, TCP

logger = logging.getLogger("port_scanner")

class SYNScan(Scan):

    def _scan_batch(self, port_list: list[Port], chunk_of_ports: list[int]):
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

        if self._verbosity >= conf.MINIMUM_VERBOSITY:
            print(logger_message)

        logger_message = f"Starting SYN scan batch on host {self._host} for ports in {chunk_of_ports[0]} to {chunk_of_ports[-1]}."
        logger.info(logger_message)

        if self._verbosity >= conf.MINIMUM_VERBOSITY:
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
            iface=conf.IFACE, filter=f"(tcp or icmp) and src host {self._host}", store=True
        )

        logger_message = f"Sniffer started for SYN scan on host {self._host}."
        logger.info(logger_message)

        if self._verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)

        sn.start()

        # Send SYN packets
        logger_message = f"Sending SYN packets to {self._host}..."
        logger.info(logger_message)
        if self._verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)
        send(pkts)

        logger_message = f"SYN packets sent to {self._host}, waiting for replies..."
        logger.info(logger_message)
        if self._verbosity >= conf.MEDIUM_VERBOSITY:
            print(logger_message)

        # Let replies arrive & capture them
        time.sleep(self._timeout)
        replies = sn.stop()

        logger_message = f"Captured {len(replies)} replies from {self._host}."
        logger.info(logger_message)
        if self._verbosity >= conf.MAX_VERBOSITY:
            print(logger_message)

        status = {p: conf.FILTERED_PORT for p in chunk_of_ports}
        seen = set()

        logger_message = f"Analyzing replies from {self._host}..."
        logger.info(logger_message)
        if self._verbosity >= conf.MAX_VERBOSITY:
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
            tested_port = Port(self.display_host(), p, status[p], status[p] == conf.OPEN_PORT)
            port_list.append(tested_port)

    def _chunks(self, seq: list[int], size: int):
        logger.info(
            f"Splitting port list of length {len(seq)} into chunks of size {size} for SYN scan."
        )
        seq = list(seq)
        for i in range(0, len(seq), size):
            yield seq[i : i + size]

    async def scan_host(self, port_list) -> None:
        for chunk in self._chunks(self._ports, conf.SYN_SCAN_BATCH_SIZE):
            self._scan_batch(port_list, chunk)

        if self._banner:
            await self._get_banners(port_list)

