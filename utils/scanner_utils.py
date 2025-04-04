import socket
import os
from models import Port

# Get ip of specified host
def get_ip(host: str):
    return socket.gethostbyname(host)


# Get mac Address of given ipaddress
def get_mac(ip: str):
    return os.popen(f"curl -s ifconfig.me | arp -n {ip} | grep :").read().split()[2]


# Ensure ip is reachable
def check_ip(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "not known" in output else True

# Gets banner service on open port
def get_banner(ip: str, port: int, user_agent=False):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode("utf-8")
    except:
        return None
    finally:
        s.close()

    return banner if banner else "No service to be found on open port"

# Skeleton for outputing results
def output(port_list: list[Port], format="text"):
    pass
    

