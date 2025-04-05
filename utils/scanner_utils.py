import socket
import os
import pandas
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



# Skeleton for outputing results
def output(port_list: list[Port], format):
    
    if format == "text":
        pd = pandas.DataFrame()

        for p in port_list:

            pd["host-ip"] = p.get_host()
            pd["port-tested"] = p.get_port()
            pd["port-status"] = p.get_status()
            pd["port-is-open"] = p.check()
            pd["port-banner"] = p.get_banner()
        
    

