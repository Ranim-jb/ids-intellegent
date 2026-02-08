import threading
import time

class PreventionSystem:
    def __init__(self):
        self.blacklist = set()
        self.blacklist_file = 'data/blacklist.txt'
        self.lock = threading.Lock()
        self.load_blacklist()
    
    def load_blacklist(self):
        """Load blacklist from file"""
        try:
            with open(self.blacklist_file, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.blacklist.add(ip)
        except FileNotFoundError:
            pass
    
    def save_blacklist(self):
        """Save blacklist to file"""
        with self.lock:
            with open(self.blacklist_file, 'w') as f:
                for ip in self.blacklist:
                    f.write(f"{ip}\n")
    
    def block_ip(self, ip):
        """Block an IP address"""
        with self.lock:
            if ip not in self.blacklist:
                self.blacklist.add(ip)
                self.save_blacklist()
                print(f"[*] IP {ip} added to blacklist")
                
                # In a real implementation, you would add iptables rules here
                # self.add_iptables_rule(ip)
                
                return True
        return False
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        with self.lock:
            if ip in self.blacklist:
                self.blacklist.remove(ip)
                self.save_blacklist()
                print(f"[*] IP {ip} removed from blacklist")
                
                # In a real implementation, you would remove iptables rules here
                # self.remove_iptables_rule(ip)
                
                return True
        return False
    
    def is_blocked(self, ip):
        """Check if IP is blocked"""
        return ip in self.blacklist
    
    def get_blacklist(self):
        """Get all blocked IPs"""
        return list(self.blacklist)
