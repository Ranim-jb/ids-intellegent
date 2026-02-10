# Import time module for timestamp operations
import time
# Import defaultdict for automatic key initialization
from collections import defaultdict

# Rule-based attack detection engine class
class DetectionEngine:
    def __init__(self):
        # Dictionary to track SYN packet counts per IP (ip -> (count, timestamp))
        self.syn_count = defaultdict(int)
        # Dictionary to store ARP table mappings (ip -> mac)
        self.arp_table = {}
        # Dictionary to track UDP packet counts per IP (ip -> (count, timestamp))
        self.udp_count = defaultdict(int)
        # Threshold for port scan detection (number of ports accessed)
        self.port_scan_threshold = 10
        # Time window for rate-based detection (seconds)
        self.time_window = 5  # seconds
        # Dictionary to track ports accessed by each IP (ip -> set of ports)
        self.port_access = {}

    def detect(self, packet, features):
        """Main detection method that checks for various attack types"""
        # Check for SYN Flood attack
        if self.detect_syn_flood(packet, features):
            return "SYN Flood"

        # Check for Port Scan attack
        if self.detect_port_scan(packet, features):
            return "Port Scan"

        # Check for ARP Spoofing attack
        if self.detect_arp_spoofing(packet, features):
            return "ARP Spoofing"

        # Check for UDP Flood attack
        if self.detect_udp_flood(packet, features):
            return "UDP Flood"

        # No attack detected
        return None

    def detect_syn_flood(self, packet, features):
        """Detect SYN flood attacks by monitoring SYN packet rate"""
        # Check if packet is TCP with SYN flag
        if packet.haslayer('TCP'):
            flags = packet['TCP'].flags
            if flags == 'S':  # SYN flag set
                src_ip = features.get('src_ip')
                if src_ip:
                    current_time = time.time()
                    # Update SYN count for this IP (count, timestamp)
                    self.syn_count[src_ip] = (self.syn_count.get(src_ip, (0, current_time))[0] + 1, current_time)

                    # Remove old entries outside time window
                    to_remove = []
                    for ip, (count, timestamp) in list(self.syn_count.items()):
                        if current_time - timestamp > self.time_window:
                            to_remove.append(ip)

                    for ip in to_remove:
                        del self.syn_count[ip]

                    # Check if SYN count exceeds threshold
                    if self.syn_count[src_ip][0] > 5:  # Threshold for SYN flood (lowered for testing)
                        return True
        return False

    def detect_port_scan(self, packet, features):
        """Detect port scanning by monitoring unique ports accessed by IP"""
        # Check if packet is TCP or UDP
        if packet.haslayer('TCP') or packet.haslayer('UDP'):
            src_ip = features.get('src_ip')
            dst_port = features.get('dst_port')

            if src_ip and dst_port:
                # Track ports accessed by this IP
                if src_ip in self.port_access:
                    # Check if port scan threshold exceeded
                    if len(self.port_access[src_ip]) > self.port_scan_threshold:
                        return True
                    # Add new port to set
                    self.port_access[src_ip].add(dst_port)
                else:
                    # Initialize port set for new IP
                    self.port_access[src_ip] = {dst_port}

        return False

    def detect_arp_spoofing(self, packet, features):
        """Detect ARP spoofing by checking for IP-MAC address conflicts"""
        # Check if packet is ARP
        if packet.haslayer('ARP'):
            src_ip = packet['ARP'].psrc  # Source IP in ARP packet
            src_mac = packet['ARP'].hwsrc  # Source MAC in ARP packet

            # Check if IP is already in ARP table
            if src_ip in self.arp_table:
                # If MAC address changed, it's spoofing
                if self.arp_table[src_ip] != src_mac:
                    return True
            else:
                # Add new IP-MAC mapping
                self.arp_table[src_ip] = src_mac

        return False

    def detect_udp_flood(self, packet, features):
        """Detect UDP flood attacks by monitoring UDP packet rate"""
        # Check if packet is UDP
        if packet.haslayer('UDP'):
            src_ip = features.get('src_ip')
            if src_ip:
                current_time = time.time()
                # Update UDP count for this IP (count, timestamp)
                self.udp_count[src_ip] = (self.udp_count.get(src_ip, (0, current_time))[0] + 1, current_time)

                # Remove old entries outside time window
                to_remove = [ip for ip, (count, timestamp) in self.udp_count.items()
                           if current_time - timestamp > self.time_window]

                for ip in to_remove:
                    del self.udp_count[ip]

                # Check if UDP count exceeds threshold
                if self.udp_count[src_ip][0] > 500:  # Threshold for UDP flood
                    return True
        return False
