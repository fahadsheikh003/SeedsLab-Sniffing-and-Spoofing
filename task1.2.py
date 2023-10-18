# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.2: (Packet Spoofing)

from scapy.all import *

total_packets = 2

a = IP()
a.src = '192.168.2.5'
a.dst = '192.168.2.7'
b = ICMP()
p = a/b

send(p, count=total_packets)