import asyncio

from port_scanner.scanners import SCANNER_CLASSES
from port_scanner.models.port import Port
from port_scanner.utils import network
from port_scanner import config as conf
import port_scanner.errors as errors
import logging 

logger = logging.getLogger("port_scanner")

async def scan(**flags):
    target, hostname = network.normalize_target(flags["target"])
    verbosity = flags["verbosity"]

    sem = asyncio.Semaphore(conf.DEFAULT_CONCURRENCY_FOR_SCANS)

    async def scan_single_host(host):
        try:
            network.is_reachable(host)
        except errors.HostUnreachableError as e:
            logger.error(e)
            if verbosity >= conf.DEFAULT_VERBOSITY:
                print(e)
            return None

        if network.is_excluded(host, flags['exclude']):
            logger_message = f"host {host} is in exclusions, skipping..."
            if verbosity >= conf.MINIMUM_VERBOSITY:
                print(logger_message)
            logger.warning(logger_message)
            return None

        async with sem:
            scan_type = flags["scan_type"]
            pscanner = SCANNER_CLASSES[scan_type](str(host), hostname, **flags)
            port_list: list[Port] = []
            await pscanner.scan_host(port_list)
            return (pscanner, port_list)

    # Create tasks for all hosts
    tasks = [asyncio.create_task(scan_single_host(host)) for host in target]

    # Gather all results
    results = await asyncio.gather(*tasks)

    return results