import socket
import os
import csv

from tabulate import tabulate

from .models import Port


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
def output(port_list: list[Port], medium="plain text"):

    if "text" or "txt" in medium:
        data = list (
            map(
                lambda p: list(p),
                port_list
            )
        )
        
        headers = ["Host IP", "Port Test", "Port Status", "Port Is Open", "Port Banner"]

        results = tabulate(data, headers=headers, tablefmt="grid")

        if os.path.basename(medium):
            with open(medium, "w") as f:
                f.write(results)
        else:
            print(results)

    if "csv" in medium:
        
        data = list (
            map(
                lambda p: vars(p),
                port_list
            )
        )
        
        if os.path.basename(medium):
            
        field_names = ['host', 'port', 'status', 'is_open', 'banner']




        


