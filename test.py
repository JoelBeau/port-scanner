from scapy.all import IP, TCP, srp, conf, arping, get_if_hwaddr
from scapy.layers.inet import ICMP, Ether
import socket
import os
import requests
# Test using scapy package

# Get mac Address of given ipaddress
def get_host_mac():
    return os.popen("curl -s ifconfig.me | arp -n | grep :").read().split()[2]

def get_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        banner = s.recv(1024).decode("utf-8")
        return banner
    except:
        return None
    finally:
        s.close()

port = 22

cse3320_ip = socket.gethostbyname("cse3320.org")

def get_gateway_mac():
    gw_ip = conf.route.route(cse3320_ip)[2]  # or use your target IP
    ans, _ = arping(gw_ip, timeout=2, verbose=False)
    for _, rcv in ans:
        return rcv[Ether].src
    return None

iface = "eth0"  # or "wlan0" or whatever interface you're using
mac_address = get_if_hwaddr(iface)

print(f"Your MAC address on {iface} is: {mac_address}")

gateway_mac = get_gateway_mac()
print("Gateway MAC Address: ", gateway_mac)

# print("f2:3c:91:37:3a:7b".upper())
eth_layer = Ether(dst=gateway_mac)

ip_layer =  IP(dst=cse3320_ip)
tcp_layer = TCP(dport=port, flags="S", sport=12345, seq=1000)

packet = eth_layer / ip_layer / tcp_layer

print(packet.show())

conf.verb = 3
response = srp(packet, iface="eth0")

sndrcv = response[0]

_, rcv = sndrcv[0]

print(rcv.show())

# if response and response.haslayer(TCP) and response[TCP].flags == "SA":
#     # banner = get_banner(cse3320_ip, port).strip()
#     # print("Banner: ", banner)
#     print("Received SYN/ACK!")
# else:
#     print("No SYN/ACK received.")

# # mac = os.popen("curl -s ifconfig.me | arp -n | grep :").read()
# # print(get_host_mac())

# user_agent = "Mozilla/5.0"

# port = 80

# try:
#     protocol = "http" if port == 80 else "https"
#     url = f"{protocol}://127.0.0.1:{80}/"

#     headers = {}

#     if user_agent:
#         headers["User-Agent"] = user_agent

#     response = requests.get(url, headers=headers, timeout=2)

#     print(response.text)
# except requests.exceptions.ConnectionError as e:
#     print(f"Error: {e}")

# print(conf.route)