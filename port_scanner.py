import socket
import threading
import struct
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

    '''
    Build the ip_header
    Add the:
        - the version (4 -> ipv4), IHL (Internet Header length) 
        - Length of the IP header ToS (Type of Service, modernly called DSCP & ECN) (0, default)
        - the Total Length of the packet we are sending (i.e. header + payload )
    '''
    ip_header = b"\x45\x00\x00\x28"  # (IP Version, IHL), Type of Service, Total Length

    '''
    Now provide:
        - Identification of the packet (unique identifier).
        - Flags (e.g., Don't Fragment, More Fragments) and fragmentation offset.
        - Since we are sending a single small SYN packet, both of these are 0 
        (there are no fragmented packets to follow).
    '''
    ip_header += b"\xab\xcd\x00\x00"  # Identification | Flags, Fragment Offset

    '''
    Finally we provide the:
        - TTL (Time To Live) meaning the max hops (routers the packet can go through before it is discarded)
        - Protocol in this case it is the TCP protocol, which is registered as 6 by the IANA
        - Finally add the Header checksum (just all hex added up to ensure integrity of the header)
    ''' 
    ip_header += b"\x40\x06\xa6\xec"  # TTL, Protocol | Header Checksum

    # 
    '''
    Now we build the tcp_header:
    
    Add the:
        - First we add the source ip and destination ip
        - Convert source ip and destination ip to bytes and add them to the tcp_header for the packet
    '''

    tcp_header = socket.inet_aton(str(ip))
    tcp_header += socket.inet_aton(host)

    '''
    Now provide:
        - Source port (where the packet is coming from on the source machine)
        - Desitnation port (where the packet is going to on the destination machine)
        - But we have to convert them to bytes (struct.pack), make sure it is big endian (!) and specify the size of the port # (H == 16)
    '''
    tcp_header += struct.pack("!H", source_port)
    tcp_header += struct.pack("!H", port)

    '''
    Then provide the:
        - Squence number (meaning the step in the handshake we are) since it is a SYN packet, it is 0 (it will increment when we get it back)
        - Acknowledgement # -> Since this is a SYN packet, hence we are not recieving any data, this value is 0 too.
    '''
    tcp_header += b"\x00\x00\x00\x00" # Sequence #
    tcp_header += b"\x00\x00\x00\x00" # Acknowledgment

    '''
    Then provide the:
        - Data Offset & reserved (nothing reserved) -> the offset from the header to the actual data that is being sent in this case it is going to be the length of the header (5 = 5*4 = 20 bytes, standard TCP header)
        - Our Flags: since we are sending a SYN packet and nothing else we need to set the SYN bit to 1 (000000000010\x02)
        - Window size -> This denotes how much data we are willing to accept before the destination machine must wait for an ACK package from us.
        - Choose 28944 bytes (doesn't really matter we are just sending a SYN packet and then seeing if we get a SYN/ACK back)
    '''
    tcp_header += b"\x50\x02\x71\x10"  # Data Offset, Reserved, Flags | Window Size

    '''
    Finally we provide the:
        - Checksum of the TCP header, which we need to calculate
        - Urgent pointer -> only used when the URG flag is set (in flags), since it is not, this value is also 0
    '''
    tcp_header += b"\x00\x00"


def calculate_checksum(data: bytes):
    """
    Calculate the checksum for the given data.
    :param data: The data (pseudo-header + TCP header) as bytes.
    :return: The checksum as an integer.
    """
    checksum = 0
    # Process the data in 16-bit chunks
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[
                i + 1
            ]  # Combine two bytes into one 16-bit word
        else:
            word = data[i] << 8  # Handle the case where the length is odd
        checksum += word
    print(hex(checksum))
    checksum = (checksum & 0xFFFF) + (checksum >> 16)  # Add carry bits

    # One's complement of the result
    return ~checksum & 0xFFFF

data1 = b"\x00\x00\x00\x06" 
data1 = b"\x0a\x0a\x0a\x02"  # Source Address
data1 += b"\x0a\x0a\x0a\x01"  # Destination Address

data = b"\x30\x39\x00\x50"  # Source Port | Destination Port
data += b"\x00\x00\x00\x00"  # Sequence Number
data += b"\x00\x00\x00\x00"  # Acknowledgement Number 
data += b"\x50\x02\x71\x10"  # Data Offset, Reserved, Flags | Window Size
data += b"\x00\x00\x00\x00"  # Checksum (0 in calc) | urgent pointer

data1 += struct.pack("!H", len(data))

# data += b"\x02"

# Calculate the checksum
tcp_checksum = calculate_checksum(data1 + data)
hex_values = [
    0x0006,       # Protocol
    0x0a0a, 0x0a02,  # Source IP: 10.10.10.2
    0x0a0a, 0x0a01,  # Destination IP: 10.10.10.1
    0x0014,       # TCP length (20 bytes)
    0x3039, 0x0050,  # Source + Destination Ports: 1234 and 80
    0x0000, 0x0000,  # Sequence Number
    0x0000, 0x0000,  # Acknowledgement Number
    0x5002, 0x7110,  # Data Offset/Flags and Window Size
    0x0000, 0x0000   # Checksum + Urgent Pointer (set to 0 for calculation)
]

test = sum(hex_values)
test = (test & 0xFFFF) + (test >> 16)  # Add carry bits

# One's complement of the result
test = ~test & 0xFFFF

print(hex(test))


# port_list: list[Port] = []
# scanning_threads: list[threading.Thread] = []

# # Test the first 50 ports
# for p in range(1, 50):
#     thread = threading.Thread(target=tcp_connect_scan, args=(port_list, str(ip), p, 5))
#     scanning_threads.append(thread)
#     thread.start()

# for t in scanning_threads:
#     t.join()

# port_list.sort(key=lambda x: x.get_port())

# for p in port_list:
#     print(p)
