import socket
import os
import io
import csv
import json

from scapy.layers.inet import Ether

from tabulate import tabulate
from .models import Port


# Get ip of specified host
def get_ip(host: str):
    return socket.gethostbyname(host)

# Ensure ip is reachable
def check_ip(ip: str):
    output = os.popen(f"ping {ip} -c 4").read()
    return False if "not known" in output else True

# Skeleton for outputing results
def output(port_list: list[Port], medium: tuple):

    formattype, file = medium

    if 'text' or 'txt' in formattype:

        data = list(map(lambda p: list(p), port_list))

        headers = ["Host IP", "Port Test", "Port Status", "Port Is Open", "Port Banner"]

        results = tabulate(data, headers=headers, tablefmt="grid")

        if file:
            with open(formattype, 'w') as f:
                f.write(results)
        else:
            print(results)

    if "csv" in formattype:

        data = list(map(lambda p: p.to_dict(), port_list))

        fieldnames = ["host", "port", "status", "is_open", "banner"]

        if medium.endswith(".csv"):
            with open(formattype, 'w') as csvf:
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
        else:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

            print(f"\n{output.getvalue()}")

    if "json" in formattype:

        data = list(map(lambda p: p.to_dict(), port_list))

        json_obj = json.dumps(data,indent=5)

         # Check if medium is a file name (contains a file extension)
        if file:  # If medium is a file name
            with open(formattype, "w") as jsonf:
                jsonf.write(json_obj)
        else:  # Output to terminal
            print(json_obj)