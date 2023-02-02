from scapy.all import *

def print_arp_table():
	#Create an empty dictionary to store the ARP table
	arp_table = {}
	#Send an ARP request to every IP address in the range "192.168.1.0/24" and collect the responses
	ans, unans = arping("192.168.1.0/24")
	# Iterate over the responses
	for s,r in ans:
	# Extract the source IP address and MACaddress from the received packet
		src_ip = r.psrc
		src_mac = r.hwsrc
	
	#Add the mapping of IP address to MACaddress to the dictionary
		arp_table[src_ip] = src_mac
		
	#Print the ARP table
	print(arp_table)
	
# Call the function to print the ARP table
	
print_arp_table()
