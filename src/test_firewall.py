from scapy.all import IP, send

# Define target IPs for testing
whitelist_ip = "192.168.1.4"
blacklist_ip = "192.168.1.2"  # This IP should be in the blacklist

# Define the source IP address
source_ip = "192.168.1.2"
  # This is the IP you want to simulate sending from

# Create IP packets with a specified source IP
whitelist_packet = IP(src=whitelist_ip, dst=whitelist_ip)
blacklist_packet = IP(src=source_ip, dst=blacklist_ip)

# Send packets
print(f"Sending packet from {source_ip} to whitelist IP: {whitelist_ip}")
send(whitelist_packet, count=5)

print(f"Sending packet from {source_ip} to blacklist IP: {blacklist_ip}")
send(blacklist_packet, count=5) 