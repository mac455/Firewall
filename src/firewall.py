import os 
import time
from collections import defaultdict 
from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
from cryptography.fernet import Fernet
from dotenv import load_dotenv

from modules.packet_analyser import PacketAnalyzer
from modules.logger import Logger
from modules.rate_limiter import RateLimiter
from modules.ip_manager import IPManager

# Load environment variables from .env file
load_dotenv()

# Retrieve the encryption key from the environment
key = os.getenv('ENCRYPTION_KEY')
cipher_suite = Fernet(key)

#Block limit for packet transfer amount 
THRESHOLD = 40 
print(f"THRESHOLD:{THRESHOLD}, ")

# Define rate limit parameters (rate at which packets are recieved from a single IP address)
RATE_LIMIT = 100  # Maximum packets per minute
rate_limit_window = 60  # Time window in seconds

# Track packet counts and timestamps for rate limiting using a defaultdictionary
packet_counts = defaultdict(lambda: {'count': 0, 'start_time': time.time()})

def read_ip_file(filename): 
    with open(filename, "r") as file: 
        ips = [line.strip() for line in file]
    return set(ips)

#Check if a packet contain Nimda worm signature, return signature if true otherwise returns false.

def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80: # Check if it has TCP layer and check destination port
        payload = packet[TCP].payload
        return "GET/scripts/root.exe" in str(payload)
    return 

# Define a single log file path
log_file_path = "logs/firewall_log.txt"

# Initialize the database
conn = sqlite3.connect('firewall_logs.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        src_mac TEXT,
        dst_ip TEXT,
        dst_mac TEXT,
        protocol TEXT,
        packet_size INTEGER,
        message TEXT
    )
''')
conn.commit()

# Modify the log_event function to encrypt the message
def log_event(message, src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size):
    encrypted_message = cipher_suite.encrypt(message.encode())
    cursor.execute('''
        INSERT INTO logs (timestamp, src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size, message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()), src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size, encrypted_message))
    conn.commit()

# Example function to decrypt and read logs
def read_logs():
    cursor.execute("SELECT * FROM logs")
    rows = cursor.fetchall()
    for row in rows:
        decrypted_message = cipher_suite.decrypt(row[-1]).decode()
        print(row[:-1] + (decrypted_message,))

class Firewall:
    def __init__(self):
        # Load environment variables
        load_dotenv()
        encryption_key = os.getenv('ENCRYPTION_KEY')
        
        # Initialize components
        self.packet_analyzer = PacketAnalyzer()
        self.logger = Logger('firewall_logs.db', encryption_key.encode())
        self.rate_limiter = RateLimiter(rate_limit=100, window_seconds=60)
        self.ip_manager = IPManager(
            whitelist={"192.168.1.4", "192.168.1.5"},
            blacklist={"192.168.1.2", "192.168.1.3"}
        )

    def packet_callback(self, packet):
        """Process each packet"""
        try:
            if not packet.haslayer(IP):
                return

            # Safely extract packet information
            src_ip = packet[IP].src if packet.haslayer(IP) else None
            dst_ip = packet[IP].dst if packet.haslayer(IP) else None
            src_mac = packet.src if hasattr(packet, 'src') else None
            dst_mac = packet.dst if hasattr(packet, 'dst') else None
            packet_size = len(packet) if packet else 0
            
            # Skip processing if we couldn't get the basic information
            if not all([src_ip, dst_ip, src_mac, dst_mac]):
                return

            protocol = self.packet_analyzer.get_protocol(packet)

            # Check whitelist first
            if self.ip_manager.is_whitelisted(src_ip):
                print(f"Packet from {src_ip} is whitelisted")
                return

            # Check blacklist
            if self.ip_manager.is_blacklisted(src_ip):
                print(f"Packet from {src_ip} is blacklisted")
                self.logger.log_event(
                    f"Blacklisted IP detected: {src_ip}",
                    src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size
                )
                return

            # Check for known attack signatures first
            signature_match = self.packet_analyzer.check_signatures(packet)
            if signature_match:
                signature_name, matched_content = signature_match
                print(f"ALERT: Detected {signature_name} attack pattern from {src_ip}")
                print(f"Logging event: SECURITY ALERT - {signature_name} attack detected: {matched_content}")
                self.logger.log_event(
                    f"SECURITY ALERT - {signature_name} attack detected: {matched_content}",
                    src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size
                )
                self.ip_manager.block_ip(src_ip)
                return

            # Check for Nimda worm
            if self.packet_analyzer.is_nimda_worm(packet):
                print(f"Blocking Nimda source IP: {src_ip}")
                self.logger.log_event(
                    f"Blocked Nimda worm attempt",
                    src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size
                )
                self.ip_manager.block_ip(src_ip)
                return

            # Check rate limiting
            if self.rate_limiter.is_rate_limited(src_ip):
                print(f"Rate limit exceeded for IP: {src_ip}")
                self.logger.log_event(
                    f"Rate limit exceeded",
                    src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size
                )
                self.ip_manager.block_ip(src_ip)
                return

            # Block UDP traffic
            if protocol == "UDP":
                print(f"Blocking UDP packet from {src_ip}")
                self.logger.log_event(
                    f"Blocked UDP packet",
                    src_ip, src_mac, dst_ip, dst_mac, protocol, packet_size
                )
                return

        except Exception as e:
            print(f"Error processing packet: {e}")
            return  # Skip this packet if there's an error

    def start(self, packet_count=None):
        """Start the firewall"""
        print("Firewall started. Monitoring network traffic...")
        try:
            sniff(
                filter="ip",
                prn=self.packet_callback,
                count=packet_count,
                store=0  # Don't store packets in memory
            )
        except KeyboardInterrupt:
            print("\nFirewall stopped by user")
        except Exception as e:
            print(f"Error: {e}")
        
if __name__ == "__main__":
    firewall = Firewall()
    firewall.start(packet_count=1000)