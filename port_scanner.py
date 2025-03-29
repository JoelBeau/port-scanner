import socket
from port import Port

def tcp_connect_scan(port_list: list[Port], host: str, port: int):

    is_open = False
    # Creates a socket denoting which IP protocol to be used and the type of port to open i.e. TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Tries to connect to the specified host and port, if successful, sets the is_open variable to true, if it doesn't & an error arrises, nothing is changed
    try:
        s.connect((host, port))
        is_open = True
    except socket.error as e:
        pass
    finally:
        s.close()

    port_list.append(Port(host, port, is_open))

port_list: list[Port] = []

for p in range(0, 50):
    print(f"Scanning port: {p}")
    tcp_connect_scan(port_list, '127.0.0.1', p)

open_ports = [p if p.check() else None for p in port_list]
port_list.sort(key=lambda x: x.get_port())

for p in port_list:
    print(p)
