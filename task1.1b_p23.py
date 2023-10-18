# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.1 B: (Port 23 Packet Sniffing)

from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='enp0s3', filter='tcp dst port 23 and src host 192.168.2.5', prn=print_pkt)