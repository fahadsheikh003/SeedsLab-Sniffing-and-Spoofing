# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.3: (Sniffing and Spoofing)

from scapy.all import *

from scapy.all import *

def print_pkt(pkt):
    if pkt[2].type == 8: 
        src = pkt[1].src
        dst = pkt[1].dst
        id = pkt[2].id
        seq = pkt[2].seq
        load = pkt[3].load

        icmp = ICMP(type=0, id=id, seq=seq)
        ip = IP(src=dst, dst=src)
        p = ip/icmp/load
        send(p, verbose=0)

        print(f"Source: {src}", f"Destination: {dst}", "Handled!", sep="\n", end="\n\n")

pkt = sniff(iface='enp0s3', filter='icmp', prn=print_pkt)
