import os
import argparse

import threading
import ipaddress as ipa
import socket
import asyncio

from utils.models import Port, Arguements
from utils.scanner_utils import output
from utils.scans import Scan, TCPConnect, SYNScan

from concurrent.futures import ThreadPoolExecutor


MAX_THREADS = 4800

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

ports = range(1, 20000)

def syn_scan_wrapper(port):
    syn_scan(port_list, port, timeout=0.1,verbose=True)

async def scan_host(ports, concur=7000):
    q = asyncio.Queue()
    for p in ports:
        q.put_nowait(p)

    async def worker():
        while True:
            try:
                port = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await asyncio.to_thread(syn_scan_wrapper, port)
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concur)]
    await q.join()
    await asyncio.gather(*workers)
    return port_list

asyncio.run(scan_host(ports))
# Sort and print the results
port_list.sort(key=lambda x: x.get_port())
for p in port_list:
    print(p)
print(len(port_list))
