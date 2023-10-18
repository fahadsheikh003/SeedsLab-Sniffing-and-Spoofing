# Name: Abdullah Hussain Alwadie
# ID: 438160459
# Task 1.3: (TraceRoute)

from scapy.all import *

destination = input("Enter Destination IP Address: ")

icmp = ICMP()

count = 1
while True:
	a = IP(dst=destination, ttl=count)
	res = sr1(a/icmp, timeout=10, verbose=0)

	if res is None:
		print(f"AT {count}: Request timed out.")
		break
	elif res.type == 0:
		print(f"AT {count}: {res.src}")
		break
	else:
		print(f"AT {count}: {res.src}")

	count += 1
