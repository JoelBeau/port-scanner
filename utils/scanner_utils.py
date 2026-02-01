import os
import io
import csv
import json

import ipaddress as ipa

from dns.resolver import Answer

from tabulate import tabulate
from .models import Port
from utils.conf import logger
from utils import conf
from utils.scans import Scan

import asyncio


# Ensure ip is reachable
def is_reachable(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "0 received" in output else True

''' Normalize target into a list of IPs '''
def normalize_target(target):
    if isinstance(target, ipa.IPv4Network):
        return target.hosts()
    elif isinstance(target, range):
        return [ipa.IPv4Address(ip) for ip in target]
    return [target]

def is_excluded(ip: str, exclusions: list[str]):
    if not exclusions:
        return False
    return ip in exclusions

async def scan(**flags):
    target = normalize_target(flags["target"])
    verbosity = flags["verbosity"]

    sem = asyncio.Semaphore(conf.DEFAULT_CONCURRENCY_FOR_SCANS)

    async def scan_single_host(host):
        if not is_reachable(host):
            logger_message = f"host {host} is not reachable, skipping..."
            if verbosity >= conf.MINIMUM_VERBOSITY:
                print(logger_message)
            logger.error(logger_message)
            return None

        if is_excluded(host, flags['exclude']):
            logger_message = f"host {host} is in exclusions, skipping..."
            if verbosity >= conf.MINIMUM_VERBOSITY:
                print(logger_message)
            logger.warning(logger_message)
            return None

        async with sem:
            scan_type = flags["scan_type"]
            pscanner: Scan = conf.SCANNER_CLASSES[scan_type](str(host), **flags)
            port_list: list[Port] = []
            await pscanner.scan_host(port_list)
            return (pscanner, port_list)

    # Create tasks for all hosts
    tasks = [asyncio.create_task(scan_single_host(host)) for host in target]

    # Gather all results
    results = await asyncio.gather(*tasks)

    # Process and output results
    for result in results:
        if result is None:
            continue
        pscanner, port_list = result
        output_results(port_list, pscanner.get_host(), flags['output'])

def output_results(port_list: list[Port], host_ip: str, medium: tuple):
    port_list.sort(key=lambda x: x.get_port())

    # Medium is (format_or_path, is_file)
    format_type, is_file = medium

    # If writing to a file, build a per-host filename safely
    if is_file:
        base, ext = os.path.splitext(format_type)
        format_type = f"{base}-{host_ip}{ext}"

    # Determine the format keyword (txt/csv/json)
    fmt = (
        os.path.splitext(format_type)[1].lstrip(".").lower()
        if is_file
        else format_type.lower()
    )

    if fmt in ("text", "txt"):
        data = list(map(lambda p: list(p), port_list))
        headers = [
            "Host IP",
            "Port Tested",
            "Port Status",
            "Port Is Open",
            "Service Banner",
        ]
        results = tabulate(data, headers=headers, tablefmt="grid")

        if is_file:
            with open(format_type, "w") as f:
                f.write(results)
        else:
            print(results)

    elif fmt == "csv":
        data = list(map(lambda p: p.to_dict(), port_list))
        fieldnames = ["host", "port", "status", "is_open", "service_banner"]

        if is_file:
            with open(format_type, "w") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
        else:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            print(f"\n{buf.getvalue()}")

    elif fmt == "json":
        data = list(map(lambda p: p.to_dict(), port_list))
        json_obj = json.dumps(data, indent=5)

        if is_file:
            with open(format_type, "w") as jsonf:
                jsonf.write(json_obj)
        else:
            print(json_obj)
