import os
import argparse

import socket
import threading
import ipaddress as ipa
from arguements import Arguements

from port import Port
from scapy.all import sr1
from scapy.layers.inet import ICMP, IP, TCP, Ether

MAX_THREADS = 4799

# Mutex
lock = threading.Lock()


# Get ip of specified host
def get_ip(host: str):
    return socket.gethostbyname(host)


# Get mac Address of given ipaddress
def get_host_mac(ip):
    return os.popen("curl -s ifconfig.me | arp -n | grep :").read().split()[2]


# Ensure ip is reachable
def check_ip(ip):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "not known" in output else True


# Thread function for TCP connect scan
def tcp_connect_scan(port_list: list[Port], host: str, port: int, timeout: int):

    is_open = False
    status = None

    # Creates a socket denoting which IP protocol to be used and the type of port to open i.e. TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    # Tries to connect to the specified host and port, if successful, sets the is_open variable to true, if it doesn't & an error arrises, nothing is changed
    try:
        s.connect((host, port))
        is_open = True
        status = "OPEN"
    except socket.timeout and OSError as e:
        if type(e) == OSError:
            if e.errno == 113:
                status = "FILTERED"
        else:
            # If it is a timeout error, then that also means firewall is blocking it
            status = "FILTERED"
    except ConnectionRefusedError:
        # If connection is refused, this means port is closed
        status = "CLOSED"
    finally:
        s.close()

    # With the mutex lock, append the port to the port list
    with lock:
        port_list.append(Port(host, port, status, is_open))


def syn_scan(port_list: list[Port], host: str, port: int, timeout: int = None):

    # Ether layer for the packet
    eth_layer = Ether(dst=get_host_mac(host).upper())

    # Create IP layer for SYN packet
    ip_layer = IP(dst=host)

    # Create TCP layer with SYN flag set
    tcp_layer = TCP(dport=port, flags="S", sport=12345)

    # Stack the layers on top of eachother
    packet = ip_layer / tcp_layer

    # Sends packet an returns answer
    response = sr1(packet, timeout=timeout)

    tested_port = None

    if response:
        if response.haslayer(TCP):
            # Get tcp flags from the packet response
            tcp_flags = response[TCP].flags
            if tcp_flags == "SA":
                tested_port = Port(host, port, "OPEN", True)
            if tcp_flags == "AR":
                tested_port = Port(host, port, "CLOSED", False)
        if response.haslayer(ICMP):
            r_code = response[ICMP].code
            if "prohibited" in r_code:
                tested_port = Port(host, port, "FILTERED", False)
    else:
        # If no response, then port is filtered
        tested_port = Port(host, port, "FILTERED", False)

    with lock:
        if tested_port:
            port_list.append(tested_port)
        else:
            port_list.append(Port(host, port, "UNKNOWN", False))

 
flags = Arguements()

# print(flags)

# r = flags['target']
# e = flags["exclude"]

# for ip in r:
#     if ip not in e:
#         print(ipa.IPv4Address(ip))

# port_list: list[Port] = []

# scanning_threads: list[threading.Thread] = []

# cse3320_ip = socket.gethostbyname("cse3320.org")

# # Test the first 50 ports
# for p in range(1, 4799):
#     thread = threading.Thread(
#         target=tcp_connect_scan, args=(port_list, str(cse3320_ip), p, 5)
#     )
#     scanning_threads.append(thread)
#     thread.start()

# for t in scanning_threads:
#     t.join()

# port_list.sort(key=lambda x: x.get_port())

# for p in port_list:
#     # if p.check():
#     print(p)
