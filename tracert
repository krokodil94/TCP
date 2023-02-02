from scapy.all import * 

def traceroute ( dst_ip, max_hops):
	# Set the initial TTL value
	ttl = 1
	
	# Create an empty list to store the routers
	routers = []
	
	while ttl <= max_hops:
		# Send an ICMP Echo Request with the current TTL value
		pkt = IP(dst=dst_ip,ttl=ttl)/ICMP()
		# Try to send the packet and receive a response
		try:
			response = sr1(pkt,verbose=0, timeout=5)
		except TimeoutError:
			# If a TImeoutError is raised, set the response to None
			response = None
		
		# Check if we received a response
		if response is not None:
			# Extract the source IP address from the response
			src_ip = response.src
			# Add the source IP address to the list of routers
			routers.append(src_ip)
				
			# Print the source IP address
			print(src_ip)
			# If we reached the destination, stop the loop
			if src_ip == dst_ip:
				break
		else:
			# If we didn't receive a response, add a "*" to the list of routers
			routers.append("*")
	
			
		
			
		# Increase the TTL value for the next iteration
		ttl += 1
		
	# Print the list of routers
	print(routers)
	
# Set the destination IP address
dst_ip = "8.8.8.8"
# Set the maximum number of hops
max_hops = 30
# Perform the traceroute
traceroute(dst_ip, max_hops)
