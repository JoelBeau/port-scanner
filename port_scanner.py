import os
import argparse

import threading
import ipaddress as ipa
import socket

from utils.models import Port, Arguements
from utils.scanner_utils import output
from utils.scans import Scan, TCPConnect, SYNScan

from concurrent.futures import ThreadPoolExecutor


MAX_THREADS = 4799

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

tcp_scan = TCPConnect(cse3320_ip)
syn_scan = SYNScan(cse3320_ip).scan

def syn_scan_wrapper(port):
    syn_scan(port_list, port, timeout=2,verbose=True)

with ThreadPoolExecutor(max_workers=500) as exe:
    exe.map(syn_scan_wrapper, ports)

# syn_scan(port_list, 22, timeout=2, banner=True, verbose=True)
# syn_scan(port_list, 80, timeout=2, verbose=True)

# output(port_list, medium=out)


# Test the first 50 ports
for p in ports:
    thread = threading.Thread(
        target=syn_scan, args=(port_list, p, 2, 0, False, True)
    )
    scanning_threads.append(thread)
    thread.start()

for t in scanning_threads:
    t.join()

# port_list.sort(key=lambda x: x.get_port())

# for p in port_list:
#     # if p.check():
#     print(p)
