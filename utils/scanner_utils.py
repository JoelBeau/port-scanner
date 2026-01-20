import socket
import os
import io
import csv
import json

import ipaddress as ipa
import threading

from tabulate import tabulate
from .models import Port
from utils.conf import logger
from utils import conf
from utils.scans import TCPConnect, SYNScan

# Ensure ip is reachable
def is_reachable(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "0 received" in output else True


def is_excluded(ip: str, exclusions: list[str]):
    if not exclusions:
        return False
    return ip in exclusions

def scan_one_host(**flags):

    host = flags["target"]
    port_list: list[Port] = []

    if type(host) is not ipa.IPv4Network:
        host = ipa.IPv4Address(host)
    if not is_reachable(host):
        logger.error(f"Host {host} is not reachable, exitting...")
        return
    if is_excluded(host, flags["exclude"]):
        logger_message = f"Host {host} is in exclusions, skipping..."
        if flags["verbosity"] >= conf.MINIMUM_VERBOSITY:
            print(logger_message)
        logger.warning(logger_message)
        return

    scan_type = flags["scan_type"]
    if scan_type == "tcp":
        pscanner = TCPConnect(str(host), **flags)
    else:
        pscanner = SYNScan(str(host), **flags)

    pscanner.scan_host(port_list)
    output_results(port_list, pscanner.get_host(), flags["output"])

def scan_multiple_hosts(**flags):
    hosts = flags["target"]
    scan_type = flags["scan_type"]
    exclusions = flags["exclude"]
    verbosity = flags["verbosity"]
    output = flags["output"]

    scanning_threads: list[threading.Thread] = []

    for host in hosts:
        port_list: list[Port] = []

        if type(hosts) is not ipa.IPv4Network:
            host = ipa.IPv4Address(host)
        if not is_reachable(host):
            logger.error(f"Host {host} is not reachable, skipping...")
            continue
        if is_excluded(host, exclusions):
            logger_message = f"Host {host} is in exclusions, skipping..."
            if verbosity >= conf.MINIMUM_VERBOSITY:
                print(logger_message)
            logger.warning(logger_message)
            continue

        if scan_type == "tcp":
            pscanner = TCPConnect(str(host), **flags)
        else:
            pscanner = SYNScan(str(host), **flags)

        t = threading.Thread(target=pscanner.scan_host, args=(port_list,))
        scanning_threads.append((t, port_list, pscanner))
        t.start()

    for t, port_list, pscanner in scanning_threads:
        t.join()
        output_results(port_list, pscanner.get_host(), output)

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
        os.path.splitext(format_type)[1].lstrip(".").lower() if is_file else format_type.lower()
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
