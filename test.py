from scapy.all import IP, TCP, sr1, Ether
from scapy.layers.inet import ICMP
import socket
# Test using scapy package

port = 3306

cse3320_ip = socket.gethostbyname("cse3320.org")

ip_layer =  IP(dst=cse3320_ip)
tcp_layer = TCP(dport=port, flags="S", sport=12345, seq=1000)

packet = ip_layer / tcp_layer

response = sr1(packet, timeout=2, verbose=0)
print(response.show())
 
if response and response.haslayer(TCP) and response[TCP].flags == "AR":
    print("Received ACK/RST!")
else:
    print("No ACK/RST received.")