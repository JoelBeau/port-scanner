import socket
import os

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

# Gets banner service on open port
def get_banner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        s.send(b'GET / HTTP/1.1\r\nHost: ' + ip.encode("utf-8") + b'\r\n\r\n')
        return s.recv(1024).decode("utf-8")
    except:
        return None

