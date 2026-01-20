import os
import argparse

import threading
import ipaddress as ipa
import socket
import asyncio
import time

from utils.models import Port, Arguements
from utils.scanner_utils import scan_multiple_hosts, scan_one_host
from utils.scans import Scan, TCPConnect, SYNScan


# # Initialize arguments class and get the cli arguements
flags = Arguements().args

print(flags)

port_list: list[Port] = []

scanning_threads: list[threading.Thread] = []

cse3320_ip = socket.gethostbyname("cse3320.org")
cse4380_ip = socket.gethostbyname("cse4380.org")

# tcp_scan = TCPConnect(cse3320_ip)
syn_scan = SYNScan(cse3320_ip, **flags)

flags["port"] = range(1, 80)
flags["banner"] = True
flags['scan_type'] = 'syn'

# s = time.time()

print(flags['exclude'])

scan_one_host(**flags)

# syn_scan.scan_host(port_list)


# # Sort and print the results
# port_list.sort(key=lambda x: x.get_port())
# for p in port_list:
#     print(p, p.get_banner())
# print(len(port_list))

# e = time.time()
# print(f"Scanning completed in {e - s}")

