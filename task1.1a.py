# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.1 A: (Packet Sniffing)

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='enp0s3', filter='icmp', prn=print_pkt)