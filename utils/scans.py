import socket
import threading

import requests

from utils.models import Port
from abc import ABC, abstractmethod

from scapy.all import sr1, conf
from scapy.layers.inet import ICMP, IP, TCP, Ether
from utils.scanner_utils import get_mac


class Scan(ABC):

    def __init__(self, host: str):
        self.host = host
        self.lock = threading.Lock()

    @abstractmethod
    def scan(
        self,
        port_list: list[Port],
        port: int,
        timeout: int,
        rety: int = 0,
        verbose: bool = False,
    ):
        pass

    def verbosity_print(
        self, port: int = None, port_obj: Port = None, type: str = "result"
    ):

        host = self.host

        if type == "a":
            print(f"\nAiming to connect to {host} on port {port}...")
        else:
            status = port_obj.get_status()
            port = port_obj.get_port()
            if status == "FILTERED":
                print(
                    f"\nFAILURE, port {port} on host {host} is being blocked by the host's firewall!"
                )
            elif status == "CLOSED":
                print(
                    f"\nFAILURE, port {port} on host {host} is specifically close from external connections!"
                )
            else:
                print(f"\nSUCCESS! Port {port} is open on {host}")


class TCPConnect(Scan):

    def scan(
        self,
        port_list: list[Port],
        port: int,
        timeout: int,
        user_agent=None,
        retry: int = 0,
        verbose: bool = False,
    ):
        is_open = False
        status = None

        http_ports = [80, 443]

        host = self.host

        # If verbosity is enabled, print
        if verbose:
            self.verbosity_print(port, type="a")

        # Check if port is an http port if not proceed with raw sockets
        if port not in http_ports:
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
        else:
            # if the port is a http port, make an https request
            try:
                protocol = "http" if port == 80 else "https"
                url = f"{protocol}://{host}:{port}/"

                headers = {}

                if user_agent:
                    headers["User-Agent"] = user_agent

                response = requests.get(url, headers=headers, timeout=2).text

                # If there is text in the response, then that connection succeeded
                if response:
                    status = "OPEN"

            # If there is a TimeoutError, then the host has some sort of firewall blocking access to that port
            except requests.exceptions.ConnectTimeout:
                status = "FILTERED"
            # If there is a ConnectionError, then the host has explicitly closed that port
            except requests.exceptions.ConnectionError:
                status = "CLOSED"

        # If the port connection fails, and the rety flag is set with x, then recursively try until retries runs out or connection succeeds
        if status == "CLOSED" or status == "FILTERED":
            if retry > 0:
                retry -= 1
                self.scan(port_list, port, timeout, user_agent, retry, verbose)
                return
        tested_port = Port(self.host, port, status, is_open)
        
        # If the rety count is at 0, add the tested_port to its 
        if retry == 0:
            if verbose:
                self.verbosity_print(port_obj=tested_port)
            # With the mutex lock, append the port to the port list
            with self.lock:
                port_list.append(tested_port)


class SYNScan(Scan):

    def scan(
        self,
        port_list: list[Port],
        port: int,
        timeout: int,
        retry: int = 0,
        verbose: bool = False,
    ):

        # If verbose is not set, then supress scapy's INFO prints
        if not verbose:
            conf.verb = 0

        if verbose:
            self.verbosity_print(port, type="a")

        # Set the host value to the super classes host
        host = self.host

        # Ether layer for the packet
        # eth_layer = Ether(dst=get_mac(host).upper())

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

        # Get the status of the tested port
        port_status = tested_port.get_status()

        # If the status is closed or filtered and the rety amount is > 0, recursevily try until connection succeeds or number of retries runs out
        if port_status == "CLOSED" or port_status == "FILTERED":
            if retry > 0:
                retry -= 1
                self.scan(port_list, port, timeout, retry, verbose)
                return

        # If the retry amount is 0 and verbosity is enabled call verbosity print func
        if retry == 0:
            if verbose:
                self.verbosity_print(port_obj=tested_port)

            # With the mutex, append the port to the port list
            with self.lock:
                if tested_port:
                    port_list.append(tested_port)
                else:
                    port_list.append(Port(host, port, "UNKNOWN", False))
