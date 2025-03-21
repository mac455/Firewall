from scapy.all import IP, TCP, UDP, ICMP, send

# Define the target IP address (your firewall's IP)
target_ip = "192.168.1.1"

# Create TCP, UDP, and ICMP packets
tcp_packet = IP(dst=target_ip)/TCP(dport=80)
udp_packet = IP(dst=target_ip)/UDP(dport=80)
icmp_packet = IP(dst=target_ip)/ICMP()

# Send TCP packet
print(f"Sending TCP packet to {target_ip}")
send(tcp_packet, count=5)

# Send UDP packet
print(f"Sending UDP packet to {target_ip}")
send(udp_packet, count=5)

# Send ICMP packet
print(f"Sending ICMP packet to {target_ip}")
send(icmp_packet, count=5) 