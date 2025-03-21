from scapy.all import IP, TCP, UDP, ICMP
from typing import Optional, Tuple, Dict

class PacketAnalyzer:
    def __init__(self):
        # Initialize signatures dictionary with more comprehensive patterns
        self.signatures = {
            # Log4j Exploitation Attempts
            "Log4j_RCE": ["${jndi:ldap", "${jndi:dns", "${jndi:rmi"],
            "Log4j_Lookup": ["${lower:", "${upper:", "${env:"],
            
            # SQL Injection Patterns
            "SQL_Injection": [
                "UNION SELECT",
                "OR '1'='1'",
                "DROP TABLE",
                "1=1--",
                "' OR '",
                "admin'--",
                "EXEC xp_"
            ],
            
            # Cross-Site Scripting (XSS)
            "XSS": [
                "<script>",
                "javascript:",
                "onerror=",
                "onload=",
                "eval(",
                "alert(",
                "<img src='x'"
            ],
            
            # Directory Traversal
            "Dir_Traversal": [
                "../../../",
                "..\\..\\",
                "/..",
                "%2e%2e"
            ],
            
            # Remote Code Execution
            "RCE": [
                "eval(base64_decode",
                "system($_",
                "exec($_",
                "shell_exec",
                "passthru"
            ],
            
            # Common Malware Communication
            "Malware": [
                "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0;)",
                ".php?ip=",
                "POST /gate.php",
                "cmd.exe",
                "powershell -enc"
            ]
        }

    def check_signatures(self, packet) -> Optional[Tuple[str, str]]:
        """Check if packet matches any known malicious signatures"""
        if packet.haslayer(TCP):
            try:
                # Get the payload as string, handle both string and bytes
                payload = packet[TCP].payload
                payload_str = str(payload)
                
                # Check all signatures regardless of port
                for attack_type, patterns in self.signatures.items():
                    for pattern in patterns:
                        if pattern.lower() in payload_str.lower():
                            return (attack_type, pattern)
                            
            except Exception as e:
                print(f"Error processing packet payload: {e}")
                
        return None

    def get_protocol(self, packet) -> str:
        """Determine the protocol of the packet"""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "OTHER"

    def is_nimda_worm(self, packet) -> bool:
        """Check if packet contains Nimda worm signature"""
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
            payload = packet[TCP].payload
            return "GET/scripts/root.exe" in str(payload)
        return False 