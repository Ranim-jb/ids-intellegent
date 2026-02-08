from scapy.all import IP, TCP, UDP, ARP, DNS, DNSQR, send, sr1, sniff, get_if_list
import time

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

def tcp_syn_flood(target_ip="192.168.1.1", target_port=80, count=10):
    """Send multiple TCP SYN packets (simulating SYN flood)"""
    print(f"[*] Sending {count} TCP SYN packets to {target_ip}:{target_port}")
    
    for i in range(count):
        try:
            # Create raw TCP SYN packet using Scapy
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            send(packet, verbose=0)
            print(f"  [+] TCP SYN #{i+1} sent to {target_ip}:{target_port}")
            time.sleep(0.2)
            
        except Exception as e:
            print(f"  [-] Error sending SYN: {e}")

def tcp_port_scan(target_ip="192.168.1.1", ports=[80, 443, 22, 21, 25]):
    """Scan multiple ports (simulating port scan with Scapy)"""
    print(f"[*] Scanning ports on {target_ip} using Scapy")
    
    for port in ports:
        try:
            # Create TCP SYN packet
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            
            if response:
                if response.haslayer(TCP):
                    if response[TCP].flags == "SA":
                        print(f"  [+] Port {port}: OPEN")
                    elif response[TCP].flags == "RA":
                        print(f"  [-] Port {port}: CLOSED")
            else:
                print(f"  [?] Port {port}: No response")
            
            time.sleep(0.2)
            
        except Exception as e:
            print(f"  [!] Error scanning port {port}: {e}")

def tcp_anomalous_traffic(target_ip="192.168.1.1", count=10):
    """Send anomalous TCP traffic patterns"""
    print(f"[*] Sending {count} anomalous TCP packets to {target_ip}")
    
    for i in range(count):
        try:
            # Send packets with various suspicious flags
            packet = IP(dst=target_ip)/TCP(dport=80, flags="FPU")  # Suspicious flag combination
            send(packet, verbose=0)
            print(f"  [+] Anomalous TCP packet #{i+1} sent (flags: FPU)")
            time.sleep(0.2)
            
        except Exception as e:
            print(f"  [-] Error sending anomalous packet: {e}")

def udp_flood(target_ip="192.168.1.1", target_port=53, count=10):
    """Send multiple UDP packets (simulating UDP flood)"""
    print(f"[*] Sending {count} UDP packets to {target_ip}:{target_port}")
    
    for i in range(count):
        try:
            # Create UDP packet
            packet = IP(dst=target_ip)/UDP(dport=target_port, sport=12345)
            send(packet, verbose=0)
            print(f"  [+] UDP packet #{i+1} sent to {target_ip}:{target_port}")
            time.sleep(0.2)
            
        except Exception as e:
            print(f"  [-] Error sending UDP: {e}")

def arp_spoofing(target_ip="192.168.1.1", spoof_ip="192.168.1.254", count=5):
    """Send ARP spoofing packets"""
    print(f"[*] Sending {count} ARP spoofing packets")
    
    for i in range(count):
        try:
            # Create ARP packet (reply - op=2)
            packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
            send(packet, verbose=0)
            print(f"  [+] ARP spoofing packet #{i+1} sent (spoofing {spoof_ip} to {target_ip})")
            time.sleep(0.2)
            
        except Exception as e:
            print(f"  [-] Error sending ARP: {e}")

def dns_query(dns_server="8.8.8.8", domains=["example.com", "google.com", "facebook.com"], count=3):
    """Send DNS query packets"""
    print(f"[*] Sending DNS query packets to {dns_server}")
    
    for domain in domains:
        for i in range(count):
            try:
                # Create DNS query packet
                packet = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                send(packet, verbose=0)
                print(f"  [+] DNS query #{i+1} for {domain} sent to {dns_server}")
                time.sleep(0.2)
                
            except Exception as e:
                print(f"  [-] Error sending DNS query: {e}")

if __name__ == "__main__":
    print("="*60)
    print("Multi-Protocol Attack Testing Tool (Using Scapy)")
    print("="*60)
    print("[!] Note: Requires root/admin privileges")
    print("[!] NOTE: On Windows, packets must be sent to accessible network IPs")
    print("[!] Trying to send packets to your machine IP...\n")
    
    # Configuration - IMPORTANT: Use the IP of this machine or another accessible IP
    TARGET_IP = "192.168.1.39"  # Your machine IP - packets should be captured here
    LOCAL_IP = "192.168.1.39"   # Your IP for ARP spoofing
    DNS_SERVER = "8.8.8.8"      # Public DNS server
    
    print(f"[*] Target IP: {TARGET_IP}")
    print(f"[*] Local IP: {LOCAL_IP}")
    print(f"[*] DNS Server: {DNS_SERVER}\n")
    
    # Test 1: TCP SYN Flood
    print("\n--- TCP TESTING ---")
    print("[*] Sending TCP SYN packets...")
    tcp_syn_flood(TARGET_IP, 80, 5)
    print()
    
    # Test 2: TCP Port Scan
    print("[*] Performing TCP port scan...")
    tcp_port_scan(TARGET_IP, [21, 22, 23, 80, 443, 8080, 8888])
    print()
    
    # Test 3: TCP Anomalous Traffic
    print("[*] Sending TCP anomalous traffic...")
    tcp_anomalous_traffic(TARGET_IP, 5)
    print()
    
    # Test 4: UDP Flood
    print("\n--- UDP TESTING ---")
    print("[*] Sending UDP packets...")
    udp_flood(TARGET_IP, 53, 5)
    print()
    
    # Test 5: ARP Spoofing
    print("\n--- ARP TESTING ---")
    print("[*] Sending ARP spoofing packets...")
    arp_spoofing(TARGET_IP, LOCAL_IP, 5)
    print()
    
    # Test 6: DNS Queries
    print("\n--- DNS TESTING ---")
    print("[*] Sending DNS query packets...")
    dns_query(DNS_SERVER, ["example.com", "google.com", "facebook.com"], 2)
    
    print("\n" + "="*60)
    print("[*] Multi-protocol attack testing completed")
    print("[*] Check the IDPS UI to see if packets were captured")
    print("="*60)