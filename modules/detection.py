import time
from collections import defaultdict

class DetectionEngine:
    def __init__(self):
        self.syn_count = defaultdict(int)
        self.arp_table = {}
        self.udp_count = defaultdict(int)
        self.port_scan_threshold = 10
        self.time_window = 5  # seconds
        self.port_access = {}
        
    def detect(self, packet, features):
        # Check for SYN Flood
        if self.detect_syn_flood(packet, features):
            return "SYN Flood"
            
        # Check for Port Scan
        if self.detect_port_scan(packet, features):
            return "Port Scan"
            
        # Check for ARP Spoofing
        if self.detect_arp_spoofing(packet, features):
            return "ARP Spoofing"
            
        # Check for UDP Flood
        if self.detect_udp_flood(packet, features):
            return "UDP Flood"
            
        return None
    
    def detect_syn_flood(self, packet, features):
        if packet.haslayer('TCP'):
            flags = packet['TCP'].flags
            if flags == 'S':  # SYN flag
                src_ip = features.get('src_ip')
                if src_ip:
                    current_time = time.time()
                    self.syn_count[src_ip] = (self.syn_count.get(src_ip, (0, current_time))[0] + 1, current_time)
                    
                    # Clean old entries
                    to_remove = []
                    for ip, (count, timestamp) in list(self.syn_count.items()):
                        if current_time - timestamp > self.time_window:
                            to_remove.append(ip)
                    
                    for ip in to_remove:
                        del self.syn_count[ip]
                    
                    # Check threshold
                    if self.syn_count[src_ip][0] > 100:  # Threshold
                        return True
        return False
    
    def detect_port_scan(self, packet, features):
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            src_ip = features.get('src_ip')
            dst_port = features.get('dst_port')
            
            if src_ip and dst_port:
                if src_ip in self.port_access:
                    if len(self.port_access[src_ip]) > self.port_scan_threshold:
                        return True
                    self.port_access[src_ip].add(dst_port)
                else:
                    self.port_access[src_ip] = {dst_port}
                
        return False
    
    def detect_arp_spoofing(self, packet, features):
        if packet.haslayer('ARP'):
            src_ip = packet['ARP'].psrc
            src_mac = packet['ARP'].hwsrc
            
            if src_ip in self.arp_table:
                if self.arp_table[src_ip] != src_mac:
                    return True
            else:
                self.arp_table[src_ip] = src_mac
                
        return False
    
    def detect_udp_flood(self, packet, features):
        if packet.haslayer('UDP'):
            src_ip = features.get('src_ip')
            if src_ip:
                current_time = time.time()
                self.udp_count[src_ip] = (self.udp_count.get(src_ip, (0, current_time))[0] + 1, current_time)
                
                # Clean old entries
                to_remove = [ip for ip, (count, timestamp) in self.udp_count.items() 
                           if current_time - timestamp > self.time_window]
                
                for ip in to_remove:
                    del self.udp_count[ip]
                
                # Check threshold
                if self.udp_count[src_ip][0] > 500:  # Threshold
                    return True
        return False
