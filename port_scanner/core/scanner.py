"""Orchestration of concurrent port scanning across multiple hosts.

Provides the main scanning pipeline that manages concurrent scanning of multiple
hosts with proper error handling and logging. Each host maintains isolated state
and respects global concurrency limits.
"""
import asyncio

from port_scanner.scanners import SCANNER_CLASSES
from port_scanner.models.port import Port
from port_scanner.utils import network
from port_scanner import config as conf
import port_scanner.errors as errors
import logging

logger = logging.getLogger("port_scanner")


async def scan(**flags):
    """Execute concurrent scanning across multiple target hosts.

    Orchestrates the scanning of one or more target hosts specified in flags.
    Creates a semaphore-based concurrency control to prevent overwhelming the
    system, and handles per-host errors gracefully.

    Args:
        **flags: Command-line argument dictionary containing:
            - target: Normalized target IP(s), CIDR, range, or hostname
            - verbosity: Verbosity level (0-3)
            - scan_type: Type of scan (tcp or syn)
            - exclude: List of IPs/ports to exclude
            - (other flags): Additional scanning parameters

    Returns:
        list: List of tuples (scanner, port_list) for each successfully scanned host,
              with None entries for unreachable or excluded hosts.
    """
    target, hostname = network.normalize_target(flags["target"])
    verbosity = flags["verbosity"]

    sem = asyncio.Semaphore(conf.DEFAULT_CONCURRENCY_FOR_SCANS)

    async def scan_single_host(host):
        try:
            network.is_reachable(host)
        except errors.HostUnreachableError as e:
            logger.error(e)
            if verbosity >= conf.VerbosityLevel.DEFAULT:
                print(e)
            return None

        if network.is_excluded(host, flags['exclude']):
            logger_message = f"host {host} is in exclusions, skipping..."
            if verbosity >= conf.VerbosityLevel.MINIMUM:
                print(logger_message)
            logger.warning(logger_message)
            return None

        async with sem:
            scan_type = flags["scan_type"]
            pscanner = SCANNER_CLASSES[scan_type](str(host), hostname, **flags)
            port_list: list[Port] = []

            logger_message = f"Scanning host {host} with {scan_type} scan..."
            logger.info(logger_message)
            if verbosity >= conf.VerbosityLevel.MINIMUM:
                print(logger_message)
            
            await pscanner.scan_host(port_list)
            return (pscanner, port_list)

    # Create tasks for all hosts
    tasks = [asyncio.create_task(scan_single_host(host)) for host in target]

    # Gather all results
    results = await asyncio.gather(*tasks)

    return results