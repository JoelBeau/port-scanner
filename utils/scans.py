import socket
import threading

from utils.models import Port
from abc import ABC, abstractmethod

from scapy.all import sr1, conf
from scapy.layers.inet import ICMP, IP, TCP, Ether
from utils.network_utils import get_host_mac


class Scan(ABC):

    def __init__(self, host: str):
        self.host = host
        self.lock = threading.Lock()

    @abstractmethod
    def scan(self, port_list: list[Port], host: str, port: str, timeout: int):
        pass


class TCPConnect(Scan):

    def scan(self, port_list: list[Port], host: str, port: str, timeout: int):
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
        with self.lock:
            port_list.append(Port(host, port, status, is_open))


class SYNScan(Scan):

    def scan(self, port_list: list[Port], host: str, port: str, timeout: int):
        conf.verb = 0
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
                if r_code == 10:
                    tested_port = Port(host, port, "FILTERED", False)
        else:
            # If no response, then port is filtered
            tested_port = Port(host, port, "FILTERED", False)

        with self.lock:
            if tested_port:
                port_list.append(tested_port)
            else:
                port_list.append(Port(host, port, "UNKNOWN", False))
