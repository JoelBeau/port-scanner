import socket
import os

class Port:

    def __init__(self, host, port, status, is_open=False):
        self.__host = host
        self.__port = port
        self.__status = status
        self.__is_open = is_open

    def check(self):
        return self.__is_open

    def get_port(self):
        return self.__port

    def get_host(self):
        return self.__host

    def get_status(self):
        return self.__status

    def __str__(self):
        return f"{self.__host}:{self.__port} status: {self.__status} "

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
