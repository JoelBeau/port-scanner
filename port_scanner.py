import os
import argparse

import threading
import ipaddress as ipa
import socket
import asyncio
import time

from utils.models import Port, Arguements
from utils.scanner_utils import output
from utils.scans import Scan, TCPConnect, SYNScan

from concurrent.futures import ThreadPoolExecutor


# # Initialize arguments class and get the cli arguements
flags = Arguements().args

ips = flags["target"]
ports = flags["port"]
stype = flags["scan_type"]
verbose = flags["verbose"]
out = flags["output"]
retry = flags["retry"]
agent = flags["user_agent"]
exclusions = flags["exclude"]
banner = flags["banner"]

print(flags)

if isinstance(ips, range):

    for ip in ips:
        ip = str(ipa.IPv4Address(ip))
        if exclusions:
            if ip not in exclusions:
                print(ip)
        else:
            print(ip)

port_list: list[Port] = []

scanning_threads: list[threading.Thread] = []

cse3320_ip = socket.gethostbyname("cse3320.org")
cse4380_ip = socket.gethostbyname("cse4380.org")

tcp_scan = TCPConnect(cse3320_ip, True)
syn_scan = SYNScan(cse3320_ip)

ports = range(1, 81)

s = time.time()

# for ip in [cse3320_ip, cse4380_ip]:
#     syn_scan = SYNScan(ip)
    
#     t = threading.Thread(target=syn_scan.scan_host, args=(port_list, ports, 1.5, retry, banner, verbose))
#     scanning_threads.append(t)
#     t.start()

# for t in scanning_threads:
#     t.join()
tcp_scan.scan_host(port_list, ports)


# Sort and print the results
port_list.sort(key=lambda x: x.get_port())
for p in port_list:
    print(p, p.get_banner())
print(len(port_list))

e = time.time()
print(f"Scanning completed in {e - s}")

