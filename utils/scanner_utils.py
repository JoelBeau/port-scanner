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

# Get ip of specified host
def get_ip(host: str):
    return socket.gethostbyname(host)

# Ensure ip is reachable
def is_reachable(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "not known" in output else True

def scan_multiple_hosts(**flags):
    hosts = flags["target"]
    scan_type = flags["scan_type"]
    exclusions = flags["exclude"]
    verbosity = flags["verbose"]

    scanning_threads: list[threading.Thread] = []

    for host in hosts:
        port_list: list[Port] = []

        if type(hosts) is not ipa.IPv4Network:
            host = ipa.IPv4Address(host)
        if not is_reachable(host):
            logger.warning(f"Host {host} is not reachable, skipping...")
            continue
        if host in exclusions:
            logger_message = f"Host {host} is in exclusions, skipping..."
            if verbosity >= conf.MINIMUM_VERBOSITY:
                print(logger_message)
            logger.info(logger_message)
            continue

        args = set()
        if scan_type == "tcp":
            pscanner = TCPConnect(str(host), flags)
        else:
            pscanner = SYNScan(str(host), flags)

        t = threading.Thread(target=pscanner.scan_host, args=args)
        scanning_threads.append((t, port_list, pscanner))
        t.start()

    for t, port_list, pscanner in scanning_threads:
        t.join()
        output(port_list, pscanner.output_medium)




# Skeleton for outputing results
def output(port_list: list[Port], medium: tuple):

    formattype, file = medium

    if 'text' or 'txt' in formattype:

        data = list(map(lambda p: list(p), port_list))

        headers = ["Host IP", "Port Tested", "Port Status", "Port Is Open", "Port Banner"]

        results = tabulate(data, headers=headers, tablefmt="grid")

        if file:
            with open(formattype, 'w') as f:
                f.write(results)
        else:
            print(results)

    if "csv" in formattype:

        data = list(map(lambda p: p.to_dict(), port_list))

        fieldnames = ["host", "port", "status", "is_open", "banner"]

        if medium.endswith(".csv"):
            with open(formattype, 'w') as csvf:
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

            print(f"\n{output.getvalue()}")

    if "json" in formattype:

        data = list(map(lambda p: p.to_dict(), port_list))

        json_obj = json.dumps(data,indent=5)

         # Check if medium is a file name (contains a file extension)
        if file:  # If medium is a file name
            with open(formattype, "w") as jsonf:
                jsonf.write(json_obj)
        else:  # Output to terminal
            print(json_obj)