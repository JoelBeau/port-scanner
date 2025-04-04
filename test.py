from scapy.all import IP, TCP, sr1, Ether
from scapy.layers.inet import ICMP
import socket
import os
# Test using scapy package

# Get mac Address of given ipaddress
def get_host_mac():
    return os.popen("curl -s ifconfig.me | arp -n | grep :").read().split()[2]

def get_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode("utf-8") + b'\r\n\r\n')
        return s.recv(1024).decode("utf-8")
    except:
        return None

port = 22

cse3320_ip = socket.gethostbyname("cse3320.org")

# print("f2:3c:91:37:3a:7b".upper())

# eth_layer = Ether(dst="f2:3c:91:37:3a:7b".upper())

ip_layer =  IP(dst=cse3320_ip)
tcp_layer = TCP(dport=port, flags="S", sport=12345, seq=1000)

packet = ip_layer / tcp_layer

response = sr1(packet, timeout=2, verbose=0)
print(response.show())
 
if response and response.haslayer(TCP) and response[TCP].flags == "SA":
    banner = get_banner(cse3320_ip, port).strip()
    print("Banner: ", banner)
    print("Received SYN/ACK!")
else:
    print("No SYN/ACK received.")

mac = os.popen("curl -s ifconfig.me | arp -n | grep :").read()
print(get_host_mac())