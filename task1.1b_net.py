# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.1 B: (Packet Sniffing of a specific Network)

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='enp0s3', filter='net 128.230.0.0/16', prn=print_pkt)