from typing import Set, List

class IPManager:
    def __init__(self, whitelist: Set[str] = None, blacklist: Set[str] = None):
        """Initialize IP manager with optional whitelist and blacklist"""
        self.whitelist = whitelist or set()
        self.blacklist = blacklist or set()
        self.blocked_ips = set()

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted"""
        return ip in self.whitelist

    def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is blacklisted"""
        return ip in self.blacklist

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked"""
        return ip in self.blocked_ips

    def block_ip(self, ip: str):
        """Add an IP to the blocked list"""
        self.blocked_ips.add(ip)

    def unblock_ip(self, ip: str):
        """Remove an IP from the blocked list"""
        self.blocked_ips.discard(ip)

    def add_to_whitelist(self, ip: str):
        """Add an IP to the whitelist"""
        self.whitelist.add(ip)
        self.blocked_ips.discard(ip)
        self.blacklist.discard(ip)

    def add_to_blacklist(self, ip: str):
        """Add an IP to the blacklist"""
        self.blacklist.add(ip)
        self.whitelist.discard(ip)
        self.block_ip(ip)

    def load_ips_from_file(self, filename: str) -> List[str]:
        """Read IP addresses from a file"""
        try:
            with open(filename, "r") as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(f"Warning: IP list file {filename} not found")
            return []
        except Exception as e:
            print(f"Error reading IP list file {filename}: {e}")
            return []

    def load_whitelist_from_file(self, filename: str):
        """Load whitelist IPs from a file"""
        ips = self.load_ips_from_file(filename)
        self.whitelist.update(ips)

    def load_blacklist_from_file(self, filename: str):
        """Load blacklist IPs from a file"""
        ips = self.load_ips_from_file(filename)
        self.blacklist.update(ips)
        self.blocked_ips.update(ips)

    def save_lists_to_files(self, whitelist_file: str = None, blacklist_file: str = None):
        """Save current IP lists to files"""
        if whitelist_file:
            with open(whitelist_file, 'w') as f:
                for ip in self.whitelist:
                    f.write(f"{ip}\n")
        
        if blacklist_file:
            with open(blacklist_file, 'w') as f:
                for ip in self.blacklist:
                    f.write(f"{ip}\n") 