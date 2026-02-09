# Import Scapy modules for packet creation and manipulation
from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, ICMP, send, sr1, sniff, get_if_list, RandIP, RandShort
# Import time module for delays and timing
import time
# Import random module for generating random values
import random
# Import socket module for network operations
import socket

def get_local_ip():
    """Get the local machine's IP address by connecting to external host"""
    try:
        # Create UDP socket to connect to Google DNS
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to external host
        local_ip = s.getsockname()[0]  # Get local IP from socket
        s.close()  # Close socket
        return local_ip
    except:
        return "127.0.0.1"  # Fallback to localhost

def get_local_interface():
    """Get local network interface for packet capture"""
    try:
        # Get list of available network interfaces
        interfaces = get_if_list()
        # Filter out loopback interfaces
        for iface in interfaces:
            if 'loopback' not in iface.lower():
                return iface
        # Return first interface if no non-loopback found
        return interfaces[0] if interfaces else None
    except:
        return None

def tcp_syn_flood(target_ip, target_port=80, count=20):
    """Send multiple TCP SYN packets to simulate SYN flood attack"""
    print(f"[*] Sending {count} TCP SYN packets to {target_ip}:{target_port}")

    sent_count = 0
    # Send specified number of SYN packets
    for i in range(count):
        try:
            # Generate random source port
            src_port = random.randint(1024, 65535)
            # Create TCP SYN packet
            packet = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
            send(packet, verbose=0)  # Send packet without verbose output
            sent_count += 1
            print(f"  [+] TCP SYN #{i+1} sent (sport: {src_port})")
            time.sleep(0.1)  # Short delay between packets

        except Exception as e:
            print(f"  [-] Error sending SYN #{i+1}: {e}")

    print(f"[+] SYN Flood completed: {sent_count}/{count} packets sent")

def tcp_port_scan(target_ip, ports=None):
    """Scan multiple ports to simulate port scanning attack"""
    # Default ports to scan if none specified
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]

    print(f"[*] Scanning {len(ports)} ports on {target_ip}")

    open_ports = []
    # Scan each port
    for port in ports:
        try:
            # Create TCP SYN packet for port scan
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2, verbose=0)  # Send and wait for response

            if response and response.haslayer(TCP):
                if response[TCP].flags == "SA":  # SYN-ACK received
                    print(f"  [+] Port {port}: OPEN")
                    open_ports.append(port)
                elif response[TCP].flags == "RA":  # RST-ACK received
                    print(f"  [-] Port {port}: CLOSED")
                else:
                    print(f"  [?] Port {port}: Unexpected response")
            else:
                print(f"  [?] Port {port}: No response (filtered?)")

            time.sleep(0.1)  # Delay between port scans

        except Exception as e:
            print(f"  [!] Error scanning port {port}: {e}")

    print(f"[+] Port scan completed. Open ports: {open_ports}")

def tcp_anomalous_traffic(target_ip, count=15):
    """Send TCP packets with anomalous flag combinations"""
    print(f"[*] Sending {count} anomalous TCP packets to {target_ip}")

    # Define anomalous TCP flag combinations
    anomalous_flags = ["FPU", "UPF", "SPU", "APU", "RPU", "CPU", "IPU", "EPU"]

    sent_count = 0
    # Send anomalous packets
    for i in range(count):
        try:
            # Randomly select anomalous flags and ports
            flags = random.choice(anomalous_flags)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 21, 25, 53])

            # Create packet with anomalous flags
            packet = IP(dst=target_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] Anomalous TCP packet #{i+1} sent (flags: {flags}, dport: {dst_port})")
            time.sleep(0.1)

        except Exception as e:
            print(f"  [-] Error sending anomalous packet #{i+1}: {e}")

    print(f"[+] Anomalous traffic completed: {sent_count}/{count} packets sent")

def udp_flood(target_ip, target_port=53, count=25):
    """Send multiple UDP packets to simulate UDP flood attack"""
    print(f"[*] Sending {count} UDP packets to {target_ip}:{target_port}")

    sent_count = 0
    # Send UDP packets rapidly
    for i in range(count):
        try:
            # Random source port
            src_port = random.randint(1024, 65535)
            # Create UDP packet
            packet = IP(dst=target_ip)/UDP(sport=src_port, dport=target_port)
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] UDP packet #{i+1} sent (sport: {src_port})")
            time.sleep(0.05)  # Very short delay for flood simulation

        except Exception as e:
            print(f"  [-] Error sending UDP #{i+1}: {e}")

    print(f"[+] UDP Flood completed: {sent_count}/{count} packets sent")

def udp_amplification_attack(target_ip, count=10):
    """Simulate UDP amplification attack patterns"""
    print(f"[*] Simulating UDP amplification attack to {target_ip}")

    # Common ports vulnerable to amplification attacks
    amp_ports = [53, 123, 1900, 5353]  # DNS, NTP, SSDP, mDNS

    sent_count = 0
    # Send packets to amplification ports
    for i in range(count):
        try:
            # Random source port
            src_port = random.randint(1024, 65535)
            # Random amplification port
            dst_port = random.choice(amp_ports)

            # Large payload to simulate amplification
            payload = b"A" * random.randint(100, 500)
            packet = IP(dst=target_ip)/UDP(sport=src_port, dport=dst_port)/payload
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] UDP amp packet #{i+1} sent (dport: {dst_port}, size: {len(payload)})")
            time.sleep(0.1)

        except Exception as e:
            print(f"  [-] Error sending UDP amp #{i+1}: {e}")

    print(f"[+] UDP amplification simulation completed: {sent_count}/{count} packets sent")

def arp_spoofing(target_ip, spoof_ip, count=8):
    """Send ARP spoofing packets to simulate ARP poisoning"""
    print(f"[*] Sending {count} ARP spoofing packets")

    sent_count = 0
    # Send ARP reply packets with spoofed source IP
    for i in range(count):
        try:
            # Create ARP reply packet (op=2) with spoofed source IP
            packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=RandIP()._fix())
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] ARP spoofing packet #{i+1} sent (spoofing {spoof_ip} -> {target_ip})")
            time.sleep(0.2)  # Longer delay for ARP packets

        except Exception as e:
            print(f"  [-] Error sending ARP #{i+1}: {e}")

    print(f"[+] ARP spoofing completed: {sent_count}/{count} packets sent")

def dns_query(dns_server="8.8.8.8", domains=None, count=5):
    """Send DNS query packets to simulate DNS traffic"""
    # Default domains if none specified
    if domains is None:
        domains = ["example.com", "google.com", "facebook.com", "amazon.com", "microsoft.com"]

    print(f"[*] Sending DNS query packets to {dns_server}")

    sent_count = 0
    # Send DNS queries for each domain
    for domain in domains:
        for i in range(count):
            try:
                # Create DNS query packet
                packet = IP(dst=dns_server)/UDP(dport=53, sport=RandShort())/DNS(rd=1, qd=DNSQR(qname=domain))
                send(packet, verbose=0)
                sent_count += 1
                print(f"  [+] DNS query #{i+1} for {domain} sent")
                time.sleep(0.1)

            except Exception as e:
                print(f"  [-] Error sending DNS query for {domain}: {e}")

    print(f"[+] DNS queries completed: {sent_count} packets sent")

def icmp_flood(target_ip, count=15):
    """Send ICMP echo request flood to simulate ping flood"""
    print(f"[*] Sending {count} ICMP echo requests to {target_ip}")

    sent_count = 0
    # Send ICMP echo requests rapidly
    for i in range(count):
        try:
            # Create ICMP echo request packet
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] ICMP echo #{i+1} sent")
            time.sleep(0.05)  # Short delay for flood

        except Exception as e:
            print(f"  [-] Error sending ICMP #{i+1}: {e}")

    print(f"[+] ICMP flood completed: {sent_count}/{count} packets sent")

def mixed_attack_simulation(target_ip, duration=30):
    """Simulate a mixed attack scenario with multiple attack types"""
    print(f"[*] Starting mixed attack simulation for {duration} seconds")

    start_time = time.time()
    attack_count = 0

    # Continue sending attacks for specified duration
    while time.time() - start_time < duration:
        try:
            # Randomly select attack type
            attack_type = random.choice(['syn', 'udp', 'arp', 'icmp'])

            # Create packet based on attack type
            if attack_type == 'syn':
                port = random.choice([80, 443, 22, 21])
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            elif attack_type == 'udp':
                port = random.choice([53, 123, 1900])
                packet = IP(dst=target_ip)/UDP(dport=port)
            elif attack_type == 'arp':
                packet = ARP(op=2, pdst=target_ip, psrc=RandIP()._fix())
            elif attack_type == 'icmp':
                packet = IP(dst=target_ip)/ICMP()

            send(packet, verbose=0)
            attack_count += 1

            # Progress update every 10 packets
            if attack_count % 10 == 0:
                print(f"  [+] {attack_count} mixed attack packets sent...")

            time.sleep(0.1)  # Delay between packets

        except Exception as e:
            print(f"  [-] Error in mixed attack: {e}")
            time.sleep(0.1)

    print(f"[+] Mixed attack simulation completed: {attack_count} packets sent in {duration}s")

# Main execution block
if __name__ == "__main__":
    print("="*70)
    print("Enhanced Multi-Protocol Attack Testing Tool (Using Scapy)")
    print("="*70)
    print("[!] Note: Requires root/admin privileges")
    print("[!] NOTE: On Windows, packets must be sent to accessible network IPs")
    print("[!] This tool generates test traffic for IDPS evaluation\n")

    # Auto-detect local IP address
    LOCAL_IP = get_local_ip()
    TARGET_IP = LOCAL_IP  # Send packets to ourselves for IDPS testing
    DNS_SERVER = "8.8.8.8"  # Public DNS server

    print(f"[*] Local IP detected: {LOCAL_IP}")
    print(f"[*] Target IP: {TARGET_IP} (sending to self for IDPS testing)")
    print(f"[*] DNS Server: {DNS_SERVER}")
    print(f"[*] Interface: {get_local_interface()}\n")

    # Phase 1: TCP SYN Flood Attack
    print("\n" + "="*50)
    print("PHASE 1: TCP SYN FLOOD ATTACK")
    print("="*50)
    tcp_syn_flood(TARGET_IP, 80, 15)
    time.sleep(2)  # Pause between phases

    # Phase 2: TCP Port Scan
    print("\n" + "="*50)
    print("PHASE 2: TCP PORT SCAN")
    print("="*50)
    tcp_port_scan(TARGET_IP, [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995])
    time.sleep(2)

    # Phase 3: TCP Anomalous Traffic
    print("\n" + "="*50)
    print("PHASE 3: TCP ANOMALOUS TRAFFIC")
    print("="*50)
    tcp_anomalous_traffic(TARGET_IP, 12)
    time.sleep(2)

    # Phase 4: UDP Flood Attack
    print("\n" + "="*50)
    print("PHASE 4: UDP FLOOD ATTACK")
    print("="*50)
    udp_flood(TARGET_IP, 53, 20)
    time.sleep(2)

    # Phase 5: UDP Amplification Attack
    print("\n" + "="*50)
    print("PHASE 5: UDP AMPLIFICATION ATTACK")
    print("="*50)
    udp_amplification_attack(TARGET_IP, 8)
    time.sleep(2)

    # Phase 6: ARP Spoofing Attack
    print("\n" + "="*50)
    print("PHASE 6: ARP SPOOFING ATTACK")
    print("="*50)
    arp_spoofing(TARGET_IP, LOCAL_IP, 6)
    time.sleep(2)

    # Phase 7: ICMP Flood Attack
    print("\n" + "="*50)
    print("PHASE 7: ICMP FLOOD ATTACK")
    print("="*50)
    icmp_flood(TARGET_IP, 12)
    time.sleep(2)

    # Phase 8: DNS Query Traffic
    print("\n" + "="*50)
    print("PHASE 8: DNS QUERY TRAFFIC")
    print("="*50)
    dns_query(DNS_SERVER, ["example.com", "google.com", "facebook.com", "amazon.com"], 3)
    time.sleep(2)

    # Phase 9: Mixed Attack Simulation
    print("\n" + "="*50)
    print("PHASE 9: MIXED ATTACK SIMULATION (15 seconds)")
    print("="*50)
    mixed_attack_simulation(TARGET_IP, 15)

    # Completion message
    print("\n" + "="*70)
    print("[✓] ENHANCED MULTI-PROTOCOL ATTACK TESTING COMPLETED")
    print("[✓] Check the IDPS dashboard to review detection results")
    print("[✓] Look for attack alerts, statistics updates, and blocked IPs")
    print("="*70)
from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, ICMP, send, sr1, sniff, get_if_list, RandIP, RandShort
import time
import random
import socket

def get_local_ip():
    """Get the local machine's IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

def get_local_interface():
    """Get local network interface for packet capture"""
    try:
        interfaces = get_if_list()
        # Filter loopback
        for iface in interfaces:
            if 'loopback' not in iface.lower():
                return iface
        return interfaces[0] if interfaces else None
    except:
        return None

def tcp_syn_flood(target_ip, target_port=80, count=20):
    """Send multiple TCP SYN packets (simulating SYN flood)"""
    print(f"[*] Sending {count} TCP SYN packets to {target_ip}:{target_port}")

    sent_count = 0
    for i in range(count):
        try:
            # Create raw TCP SYN packet with random source port
            src_port = random.randint(1024, 65535)
            packet = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags="S")
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] TCP SYN #{i+1} sent (sport: {src_port})")
            time.sleep(0.1)  # Faster for flood simulation

        except Exception as e:
            print(f"  [-] Error sending SYN #{i+1}: {e}")

    print(f"[+] SYN Flood completed: {sent_count}/{count} packets sent")

def tcp_port_scan(target_ip, ports=None):
    """Scan multiple ports (simulating port scan)"""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080]

    print(f"[*] Scanning {len(ports)} ports on {target_ip}")

    open_ports = []
    for port in ports:
        try:
            # Create TCP SYN packet
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=2, verbose=0)

            if response and response.haslayer(TCP):
                if response[TCP].flags == "SA":  # SYN-ACK
                    print(f"  [+] Port {port}: OPEN")
                    open_ports.append(port)
                elif response[TCP].flags == "RA":  # RST-ACK
                    print(f"  [-] Port {port}: CLOSED")
                else:
                    print(f"  [?] Port {port}: Unexpected response")
            else:
                print(f"  [?] Port {port}: No response (filtered?)")

            time.sleep(0.1)

        except Exception as e:
            print(f"  [!] Error scanning port {port}: {e}")

    print(f"[+] Port scan completed. Open ports: {open_ports}")

def tcp_anomalous_traffic(target_ip, count=15):
    """Send anomalous TCP traffic patterns"""
    print(f"[*] Sending {count} anomalous TCP packets to {target_ip}")

    anomalous_flags = ["FPU", "UPF", "SPU", "APU", "RPU", "CPU", "IPU", "EPU"]

    sent_count = 0
    for i in range(count):
        try:
            flags = random.choice(anomalous_flags)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 21, 25, 53])

            packet = IP(dst=target_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] Anomalous TCP packet #{i+1} sent (flags: {flags}, dport: {dst_port})")
            time.sleep(0.1)

        except Exception as e:
            print(f"  [-] Error sending anomalous packet #{i+1}: {e}")

    print(f"[+] Anomalous traffic completed: {sent_count}/{count} packets sent")

def udp_flood(target_ip, target_port=53, count=25):
    """Send multiple UDP packets (simulating UDP flood)"""
    print(f"[*] Sending {count} UDP packets to {target_ip}:{target_port}")

    sent_count = 0
    for i in range(count):
        try:
            src_port = random.randint(1024, 65535)
            packet = IP(dst=target_ip)/UDP(sport=src_port, dport=target_port)
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] UDP packet #{i+1} sent (sport: {src_port})")
            time.sleep(0.05)  # Very fast for flood

        except Exception as e:
            print(f"  [-] Error sending UDP #{i+1}: {e}")

    print(f"[+] UDP Flood completed: {sent_count}/{count} packets sent")

def udp_amplification_attack(target_ip, count=10):
    """Simulate UDP amplification attack patterns"""
    print(f"[*] Simulating UDP amplification attack to {target_ip}")

    # Common amplification ports
    amp_ports = [53, 123, 1900, 5353]  # DNS, NTP, SSDP, mDNS

    sent_count = 0
    for i in range(count):
        try:
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(amp_ports)

            # Large payload to simulate amplification
            payload = b"A" * random.randint(100, 500)
            packet = IP(dst=target_ip)/UDP(sport=src_port, dport=dst_port)/payload
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] UDP amp packet #{i+1} sent (dport: {dst_port}, size: {len(payload)})")
            time.sleep(0.1)

        except Exception as e:
            print(f"  [-] Error sending UDP amp #{i+1}: {e}")

    print(f"[+] UDP amplification simulation completed: {sent_count}/{count} packets sent")

def arp_spoofing(target_ip, spoof_ip, count=8):
    """Send ARP spoofing packets"""
    print(f"[*] Sending {count} ARP spoofing packets")

    sent_count = 0
    for i in range(count):
        try:
            # Create ARP reply packet (op=2)
            packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwsrc=RandIP()._fix())
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] ARP spoofing packet #{i+1} sent (spoofing {spoof_ip} -> {target_ip})")
            time.sleep(0.2)

        except Exception as e:
            print(f"  [-] Error sending ARP #{i+1}: {e}")

    print(f"[+] ARP spoofing completed: {sent_count}/{count} packets sent")

def dns_query(dns_server="8.8.8.8", domains=None, count=5):
    """Send DNS query packets"""
    if domains is None:
        domains = ["example.com", "google.com", "facebook.com", "amazon.com", "microsoft.com"]

    print(f"[*] Sending DNS query packets to {dns_server}")

    sent_count = 0
    for domain in domains:
        for i in range(count):
            try:
                # Create DNS query packet
                packet = IP(dst=dns_server)/UDP(dport=53, sport=RandShort())/DNS(rd=1, qd=DNSQR(qname=domain))
                send(packet, verbose=0)
                sent_count += 1
                print(f"  [+] DNS query #{i+1} for {domain} sent")
                time.sleep(0.1)

            except Exception as e:
                print(f"  [-] Error sending DNS query for {domain}: {e}")

    print(f"[+] DNS queries completed: {sent_count} packets sent")

def icmp_flood(target_ip, count=15):
    """Send ICMP echo request flood"""
    print(f"[*] Sending {count} ICMP echo requests to {target_ip}")

    sent_count = 0
    for i in range(count):
        try:
            # Create ICMP echo request
            packet = IP(dst=target_ip)/ICMP()
            send(packet, verbose=0)
            sent_count += 1
            print(f"  [+] ICMP echo #{i+1} sent")
            time.sleep(0.05)

        except Exception as e:
            print(f"  [-] Error sending ICMP #{i+1}: {e}")

    print(f"[+] ICMP flood completed: {sent_count}/{count} packets sent")

def mixed_attack_simulation(target_ip, duration=30):
    """Simulate a mixed attack scenario for a specified duration"""
    print(f"[*] Starting mixed attack simulation for {duration} seconds")

    start_time = time.time()
    attack_count = 0

    while time.time() - start_time < duration:
        try:
            attack_type = random.choice(['syn', 'udp', 'arp', 'icmp'])

            if attack_type == 'syn':
                port = random.choice([80, 443, 22, 21])
                packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            elif attack_type == 'udp':
                port = random.choice([53, 123, 1900])
                packet = IP(dst=target_ip)/UDP(dport=port)
            elif attack_type == 'arp':
                packet = ARP(op=2, pdst=target_ip, psrc=RandIP()._fix())
            elif attack_type == 'icmp':
                packet = IP(dst=target_ip)/ICMP()

            send(packet, verbose=0)
            attack_count += 1

            if attack_count % 10 == 0:
                print(f"  [+] {attack_count} mixed attack packets sent...")

            time.sleep(0.1)

        except Exception as e:
            print(f"  [-] Error in mixed attack: {e}")
            time.sleep(0.1)

    print(f"[+] Mixed attack simulation completed: {attack_count} packets sent in {duration}s")

if __name__ == "__main__":
    print("="*70)
    print("Enhanced Multi-Protocol Attack Testing Tool (Using Scapy)")
    print("="*70)
    print("[!] Note: Requires root/admin privileges")
    print("[!] NOTE: On Windows, packets must be sent to accessible network IPs")
    print("[!] This tool generates test traffic for IDPS evaluation\n")

    # Auto-detect local IP
    LOCAL_IP = get_local_ip()
    TARGET_IP = LOCAL_IP  # Send to ourselves for testing
    DNS_SERVER = "8.8.8.8"

    print(f"[*] Local IP detected: {LOCAL_IP}")
    print(f"[*] Target IP: {TARGET_IP} (sending to self for IDPS testing)")
    print(f"[*] DNS Server: {DNS_SERVER}")
    print(f"[*] Interface: {get_local_interface()}\n")

    # Test 1: TCP SYN Flood
    print("\n" + "="*50)
    print("PHASE 1: TCP SYN FLOOD ATTACK")
    print("="*50)
    tcp_syn_flood(TARGET_IP, 80, 15)
    time.sleep(2)

    # Test 2: TCP Port Scan
    print("\n" + "="*50)
    print("PHASE 2: TCP PORT SCAN")
    print("="*50)
    tcp_port_scan(TARGET_IP, [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995])
    time.sleep(2)

    # Test 3: TCP Anomalous Traffic
    print("\n" + "="*50)
    print("PHASE 3: TCP ANOMALOUS TRAFFIC")
    print("="*50)
    tcp_anomalous_traffic(TARGET_IP, 12)
    time.sleep(2)

    # Test 4: UDP Flood
    print("\n" + "="*50)
    print("PHASE 4: UDP FLOOD ATTACK")
    print("="*50)
    udp_flood(TARGET_IP, 53, 20)
    time.sleep(2)

    # Test 5: UDP Amplification
    print("\n" + "="*50)
    print("PHASE 5: UDP AMPLIFICATION ATTACK")
    print("="*50)
    udp_amplification_attack(TARGET_IP, 8)
    time.sleep(2)

    # Test 6: ARP Spoofing
    print("\n" + "="*50)
    print("PHASE 6: ARP SPOOFING ATTACK")
    print("="*50)
    arp_spoofing(TARGET_IP, LOCAL_IP, 6)
    time.sleep(2)

    # Test 7: ICMP Flood
    print("\n" + "="*50)
    print("PHASE 7: ICMP FLOOD ATTACK")
    print("="*50)
    icmp_flood(TARGET_IP, 12)
    time.sleep(2)

    # Test 8: DNS Queries
    print("\n" + "="*50)
    print("PHASE 8: DNS QUERY TRAFFIC")
    print("="*50)
    dns_query(DNS_SERVER, ["example.com", "google.com", "facebook.com", "amazon.com"], 3)
    time.sleep(2)

    # Test 9: Mixed Attack Simulation
    print("\n" + "="*50)
    print("PHASE 9: MIXED ATTACK SIMULATION (15 seconds)")
    print("="*50)
    mixed_attack_simulation(TARGET_IP, 15)

    print("\n" + "="*70)
    print("[✓] ENHANCED MULTI-PROTOCOL ATTACK TESTING COMPLETED")
    print("[✓] Check the IDPS dashboard to review detection results")
    print("[✓] Look for attack alerts, statistics updates, and blocked IPs")
    print("="*70)
