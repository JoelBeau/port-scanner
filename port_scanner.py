import socket
import threading
import ipaddress
import textwrap
from port import Port

lock = threading.Lock()

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)


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
    except socket.timeout:
        status = "FILTERED"
    except ConnectionRefusedError:
        status = "CLOSED"
    finally:
        s.close()

    # With the mutex lock, append the port to the port list
    with lock:
        port_list.append(Port(host, port, status, is_open))


def syn_scan(port_list: list[Port], host: str, port: int):
    is_open = False

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_TCP, socket.IP_HDRINCL, 1)

    # Bind to source socket randomly, store to add in tcp_header
    s.bind((str(ip), 0))
    source_port = s.getsockname()[1]

    # Build the ip_header
    """
    - Add the:
      - the version (4 -> ipv4), IHL (Internet Header length) 
      - Length of the IP header ToS (Type of Service, modernly called DSCP & ECN) (0, default)
      - the Total Length of the packet we are sending (i.e. header + payload )
    """
    ip_header = b"\x45\x00\x00\x28"  # (IP Version, IHL), Type of Service, Total Length

    # Now provide: 
    # Provide identification of the packet (unqiue identifier)
    # Provide any flags (i.e. Don't Fragment, More Fragments) & fragmenetation offset
    # since we are sending a single small SYN packet, both of these are 0 (there are no fragmented packets to follow)
    ip_header += b"\xab\xcd\x00\x00"  # Identification | Flags, Fragment Offset

    # Finally we provide the:
    # TTL (Time To Live) meaning the max hops (routers the packet can go through before it is discarded)
    # Protocol in this case it is the TCP protocol, which is registered as 6 by the IANA
    # Finally add the Header checksum (just all hex added up to ensure integrity of the header)
    ip_header += b"\x40\x06\xa6\xec"  # TTL, Protocol | Header Checksum

    # Now we build the tcp payload

    # First we add the
    # Convert source ip and destination ip to bytes and add them to the tcp_payload for the packet
    tcp_payload = socket.inet_aton(str(ip))
    tcp_payload += socket.inet_aton(host)


port_list: list[Port] = []
scanning_threads: list[threading.Thread] = []

# Test the first 50 ports
for p in range(1, 50):
    thread = threading.Thread(target=tcp_connect_scan, args=(port_list, str(ip), p, 5))
    scanning_threads.append(thread)
    thread.start()

for t in scanning_threads:
    t.join()

port_list.sort(key=lambda x: x.get_port())

for p in port_list:
    print(p)
