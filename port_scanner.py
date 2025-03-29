import socket
import threading
import time
import struct
from port import Port

# Mutex
lock = threading.Lock()

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't send data, just figures out the best local IP to reach 8.8.8.8
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

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

def listen_for_syn_ack(source_port: int, timeout: int = 5) -> bool:
    """
    Listen for a SYN/ACK response to the SYN packet.
    :param source_port: The source port used in the SYN packet.
    :param timeout: Timeout in seconds to wait for a response.
    :return: True if a SYN/ACK is received, False otherwise.
    """
    try:
        # Create a raw socket to listen for incoming packets
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_socket.settimeout(timeout)

        while True:
            # Receive packets
            packet, _ = recv_socket.recvfrom(65535)

            # Extract TCP header (next 20 bytes)
            tcp_header = packet[20:40]

            # Unpack the TCP header
            tcp_fields = struct.unpack("!HHLLBBHHH", tcp_header)
            dest_port = tcp_fields[1]  # Destination port
            flags = tcp_fields[5]      # TCP flags

            # Check if the packet is for our source port and has SYN/ACK flags
            if dest_port == source_port and flags & 0x12 == 0x12:  # SYN (0x02) + ACK (0x10)
                return "OPEN"

            if dest_port == source_port and flags & 0x14 == 0x14: # ACK (0x10) + RST (0X04)
                return "CLOSED"
            
    except socket.timeout:
        return "FILTERED"


def syn_scan(port_list: list[Port], host: str, port: int):
    is_open = False

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # randomport to include in the SYN packet
    source_port = 1234

    """
    Build the ip_header
    Add the:
        - the version (4 -> ipv4), IHL (Internet Header length) 
        - Length of the IP header ToS (Type of Service, modernly called DSCP & ECN) (0, default)
        - the Total Length of the packet we are sending (i.e. header + payload )

    Then the:
        - Identification of the packet (unique identifier).
        - Flags (e.g., Don't Fragment, More Fragments) and fragmentation offset.
        - Since we are sending a single small SYN packet, both of these are 0 
        (there are no fragmented packets to follow).

    Finally we provide the:
        - TTL (Time To Live) meaning the max hops (routers the packet can go through before it is discarded)
        - Protocol in this case it is the TCP protocol, which is registered as 6 by the IANA
        - Finally add the Header checksum (just all hex added up to ensure integrity of the header)
    """
    ip_header = b"\x45\x00\x00\x28"  # (IP Version, IHL), Type of Service, Total Length
    ip_header += b"\xab\xcd\x00\x00"  # Identification | Flags, Fragment Offset
    ip_header += b"\x40\x06\xa6\xec"  # TTL, Protocol | Header Checksum

    #
    """
    Now we build the tcp_header:
    
    Add the:
        - First we add the source ip and destination ip
        - Convert source ip and destination ip to bytes and add them to the tcp_header for the packet

    Then the:
        - Source port (where the packet is coming from on the source machine)
        - Desitnation port (where the packet is going to on the destination machine)
        - But we have to convert them to bytes (struct.pack), make sure it is big endian (!) and specify the size of the port # (H == 16)
    
    Then provide the:
        - Squence number (meaning the step in the handshake we are) since it is a SYN packet, it is 0 (it will increment when we get it back)
        - Acknowledgement # -> Since this is a SYN packet, hence we are not recieving any data, this value is 0 too.
    
    Then provide the:
        - Data Offset & reserved (nothing reserved) -> the offset from the header to the actual data that is being sent in this case it is going to be the length of the header (5 = 5*4 = 20 bytes, standard TCP header)
        - Our Flags: since we are sending a SYN packet and nothing else we need to set the SYN bit to 1 (000000000010\x02)
        - Window size -> This denotes how much data we are willing to accept before the destination machine must wait for an ACK package from us.
        - Choose 28944 bytes (doesn't really matter we are just sending a SYN packet and then seeing if we get a SYN/ACK back)

    Finally we provide the:
        - Checksum of the TCP header, which we need to calculate
        - Urgent pointer -> only used when the URG flag is set (in flags), since it is not, this value is also 0
    
    """
    # Create a pseudo header for the checksum
    pseudo_header = b"\x00\x06"

    # Add the source_ip and host
    tcp_header = socket.inet_aton(str(ip_add))
    tcp_header += socket.inet_aton(host)

    # Add the source & dest port to the header
    pseudo_header += tcp_header

    # Store the ports for later access
    source_port_b = struct.pack("!H", source_port)
    dest_port_b = struct.pack("!H", port)

    # Add the ports to the tcp_header
    tcp_header += source_port_b + dest_port_b

    # Add them to "data" for calculating the checksum as well
    tcp_data = source_port_b + dest_port_b

    # Store the squence # and acknowledgement in on variable (since they are both 0-d out)
    squence_n_ack = b"\x00\x00\x00\x00"

    tcp_header += squence_n_ack  # Sequence #
    tcp_header += squence_n_ack  # Acknowledgment

    # Add them to the data variable as well.
    tcp_data += squence_n_ack
    tcp_data += squence_n_ack

    # Put data offset, reserved, flags & ws in a variable
    offset_reserved_flags_ws = b"\x50\x02\x71\x10"
    tcp_header += offset_reserved_flags_ws  # Data Offset, Reserved, Flags | Window Size

    # Add to tcp data for checksum
    tcp_data += offset_reserved_flags_ws

    # Add the checksum (0 in calc) and the urgent pointer (0 as well) to the data to be calculated for the checksum
    tcp_data += b"\x00\x00\x00\x00"

    # Add the length of the TCP to the pseudo header
    pseudo_header += struct.pack("!H", len(tcp_data))

    # Claculate the checksum
    tcp_checksum = calculate_checksum(pseudo_header + tcp_data)

    # Add the checksum
    tcp_header += struct.pack("!H", tcp_checksum)
    tcp_header += b"\x00\x00"

    packet = ip_header + tcp_header

    s.sendto(packet, (host, 0))

    # Listen for a SYN/ACK response
    status = listen_for_syn_ack(source_port)

    is_open = True if status == "OPEN" else False

    with lock:
        port_list.append(Port(host, port, status, is_open))

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

    while checksum > 0xFFFF:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement of the result
    return ~checksum & 0xFFFF

# Get host ip
ip_add = get_ip()

port_list: list[Port] = []

scanning_threads: list[threading.Thread] = []

cse3320_ip = socket.gethostbyname("cse3320.org")
print(cse3320_ip)

syn_scan(port_list, str(cse3320_ip), 22)

# # Test the first 50 ports
# for p in range(1,10):
#     thread = threading.Thread(target=syn_scan, args=(port_list, str(cse3320_ip), p))
#     scanning_threads.append(thread)
#     thread.start()
    
# for t in scanning_threads:
#     t.join()

# port_list.sort(key=lambda x: x.get_port())

for p in port_list:
    print(p)
