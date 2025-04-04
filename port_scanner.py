import os
import argparse

import socket
import threading
import ipaddress as ipa

from utils.models import Port, Arguements
from utils.network_utils import get_host_mac
from utils.scans import TCPConnect, SYNScan
from scapy.all import sr1
from scapy.layers.inet import ICMP, IP, TCP, Ether


MAX_THREADS = 4799

# Initialize arguments class and get the cli arguements
flags = Arguements().args

print(flags)

# Test arguements ensuring it works
r = flags['target']
e = flags["exclude"]
type = flags["scan_type"]

print(r)
print(e)
print(type)

# Ensure's ip range is right and the exclusions are right
for ip in r:
    if ip not in e:
        print(ipa.IPv4Address(ip))

port_list: list[Port] = []

scanning_threads: list[threading.Thread] = []

cse3320_ip = socket.gethostbyname("cse3320.org")

tcp_scan = TCPConnect(cse3320_ip).scan
syn_scan = SYNScan(cse3320_ip).scan

# Test the first 50 ports
for p in range(1, 50):
    thread = threading.Thread(
        target=syn_scan, args=(port_list, str(cse3320_ip), p, 5)
    )
    scanning_threads.append(thread)
    thread.start()

for t in scanning_threads:
    t.join()

port_list.sort(key=lambda x: x.get_port())

for p in port_list:
    # if p.check():
    print(p)
