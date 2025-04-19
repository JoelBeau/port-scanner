import os
import argparse

import threading
import ipaddress as ipa
import socket
import time

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

# ports = range(1,81)

# def syn_scan_wrapper(port):
#     syn_scan(port_list, port, timeout=2,verbose=True)

# with ThreadPoolExecutor(max_workers=500) as exe:
#     exe.map(syn_scan_wrapper, ports)

# syn_scan(port_list, 22, timeout=2, banner=True, verbose=True)
# syn_scan(port_list, 80, timeout=2, verbose=True)

# output(port_list, medium=out)

# Define the batch size (number of ports per thread)
ports = range(1,65535)
BATCH_SIZE = 10

# Split the ports into batches
port_batches = [ports[i:i + BATCH_SIZE] for i in range(0, len(ports), BATCH_SIZE)]

# Function to scan a batch of ports
def scan_batch(port_list, batch):
    for port in batch:
        syn_scan(port_list, port, 2, 0, False, True)

# Create and start threads for each batch
for batch in port_batches:
    thread = threading.Thread(target=scan_batch, args=(port_list, batch))
    scanning_threads.append(thread)
    thread.start()

# Wait for all threads to finish
for t in scanning_threads:
    t.join()


# for p in ports:
#     thread = threading.Thread(
#         target=syn_scan, args=(port_list, p, 2, 0, False, True)
#     )
#     scanning_threads.append(thread)
#     thread.start()

# for t in scanning_threads:
#     t.join()


# Sort and print the results
port_list.sort(key=lambda x: x.get_port())
for p in port_list:
    print(p)
print(len(port_list))
