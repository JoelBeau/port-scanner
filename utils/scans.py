from random import randint
import socket
import threading

import requests

from utils.models import Port
from abc import ABC, abstractmethod

from scapy.all import srp, conf
from scapy.layers.inet import ICMP, IP, TCP, Ether
from .scanner_utils import get_mac, get_gateway_mac


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

    # Gets banner service on open port
    def get_running_service(self, port_obj: Port):

        port = port_obj.get_port()

        try:
            socket.setdefaulttimeout(2)
            s = socket.socket()
            s.connect((self.host, port))
            banner = s.recv(1024).decode("utf-8").strip()
        except Exception as e:
            banner = f"Unable to get running service on port {port} due to {e.args}"
        finally:
            s.close()

        return banner if banner else "No service to be found on open port"


class TCPConnect(Scan):

    def scan(
        self,
        port_list: list[Port],
        port: int,
        timeout: int,
        user_agent=None,
        retry: int = 0,
        banner: bool = False,
        verbose: bool = False,
    ):
        status = None
        tested_port = None

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

        # Determine if the port is open based on the status
        is_open = True if status == "OPEN" else False

        # Create port object of the port we just tested
        tested_port = Port(self.host, port, status, is_open)

        # If the port is open and the banner flag has been enabled, get the banner and add it to the object
        if tested_port.get_status() == "OPEN":
            if banner:
                service = self.get_running_service(tested_port)
                tested_port.set_banner(service)

        # After doing any retries, if verbose, print and add to list else just print
        if verbose:
            self.verbosity_print(port_obj=tested_port)
        # With the mutex lock, append the port to the port list
        with self.lock:
            port_list.append(tested_port)


class SYNScan(Scan):

    def __init__(self, host: str):
        super().__init__(host)
        self.gateway_mac = get_gateway_mac()
        self.host_mac = get_mac()
        self.sport = 1025

    def scan(
        self,
        port_list: list[Port],
        port: int,
        timeout: int = 2,
        retry: int = 0,
        banner: bool = False,
        verbose: bool = False
    ):

        # If verbose is not set, then supress scapy's INFO prints
        if not verbose:
            conf.verb = 0

        if verbose:
            self.verbosity_print(port, type="a")

        # Set the host value to the super classes host
        host = self.host

        # Ether layer for the packet
        eth_layer = Ether(dst=self.gateway_mac, src=self.host_mac)
        # Create IP layer for SYN packet
        ip_layer = IP(dst=host)

        # Create TCP layer with SYN flag set
        tcp_layer = TCP(dport=port, flags="S", sport=self.sport)

        self.sport += 1

        # Stack the layers on top of eachother
        packet = eth_layer / ip_layer / tcp_layer

        # Sends packet an returns answer
        response = srp(packet, iface="eth0", timeout=timeout)

        # Get the first response from the packet
        sndrcv = response[0]

        # Get the first packet in the response
        try:
            _, rcv = sndrcv[0]
        except IndexError:
            print(
                f"\nFAILURE, unable to get response from host {host} on port {port}!"
            )
            print(sndrcv.show())
            return

        status = None

        if rcv:
            if rcv.haslayer(TCP):
                # Get tcp flags from the packet response
                tcp_flags = rcv[TCP].flags
                if tcp_flags == "SA":
                    status = "OPEN"
                if tcp_flags == "AR":
                    status = "CLOSED"
            if rcv.haslayer(ICMP):
                r_code = rcv[ICMP].code
                if r_code == 10:
                    status = "FILTERED"
        else:
            # If no response, then port is filtered
            status = "FILTERED"

        # If the status is closed or filtered and the rety amount is > 0, recursevily try until connection succeeds or number of retries runs out
        if status == "CLOSED" or status == "FILTERED":
            if retry > 0:
                retry -= 1
                self.scan(port_list, port, timeout, retry, verbose)
                return

        # Determine if the port is open based on the status
        is_open = True if status == "OPEN" else False

        # Create port object of the port we just tested
        tested_port = Port(self.host, port, status, is_open)

        # If the port is open and the banner flag has been enabled, get the banner and add it to the object
        if tested_port.get_status() == "OPEN":
            if banner:
                service = self.get_running_service(tested_port)
                tested_port.set_banner(service)

        # After any retries, if verbosity is enabled print and add to list else just add to list
        if verbose:
            self.verbosity_print(port_obj=tested_port)

        # With the mutex, append the port to the port list
        with self.lock:
            port_list.append(tested_port)
