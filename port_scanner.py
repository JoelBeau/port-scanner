import socket
import threading
import ipaddress
import textwrap
from port import Port

lock = threading.Lock()

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
        status = 'OPEN'
    except socket.timeout:
        status = 'FILTERED'
    except ConnectionRefusedError:
        status = 'CLOSED'
    finally:
        s.close()

    # With the mutex lock, append the port to the port list
    with lock:
        port_list.append(Port(host, port, status, is_open))

def syn_scan(port_list: list[Port], host: str, port: int):
    is_open = False

    s= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_TCP, socket.IP_HDRINCL, 1)

    ip_header  = b'\x45\x00\x00\x28'  # Version, IHL, Type of Service | Total Length
    ip_header += b'\xab\xcd\x00\x00'  # Identification | Flags, Fragment Offset
    ip_header += b'\x40\x06\xa6\xec'  # TTL, Protocol | Header Checksum

def convert_ip_to_hex(host: str):
    hex_val = hex(int(ipaddress.IPv4Address('127.0.0.1')))[2:]

    for val in textwrap.wrap(hex_val,2):
        print(val)


port_list: list[Port] = []
scanning_threads: list[threading.Thread] = []

for p in range(1, 50):
    thread = threading.Thread(target=tcp_connect_scan, args=(port_list, "127.0.0.1", p, 5))
    scanning_threads.append(thread)
    thread.start()

for t in scanning_threads:
    t.join()

port_list.sort(key=lambda x: x.get_port())

for p in port_list:
    print(p)
