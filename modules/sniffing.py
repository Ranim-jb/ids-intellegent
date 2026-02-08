from scapy.all import sniff, get_if_list, get_working_if
import threading
import platform

class PacketSniffer:
    def __init__(self, interface=None):
        self.interface = interface
        self.sniffing = False
        
    def list_interfaces(self):
        """List all available network interfaces"""
        try:
            interfaces = get_if_list()
            print("\n[*] Available network interfaces:")
            for i, iface in enumerate(interfaces):
                print(f"  [{i}] {iface}")
            return interfaces
        except Exception as e:
            print(f"[!] Error listing interfaces: {e}")
            return []
        
    def get_default_interface(self):
        """Get the working network interface"""
        try:
            # Try to get the working interface
            working_iface = get_working_if()
            if working_iface:
                print(f"[*] Working interface detected: {working_iface}")
                return working_iface
            
            interfaces = get_if_list()
            print(f"[*] Available interfaces: {interfaces}")
            
            if not interfaces:
                print("[!] No interfaces found!")
                return None
            
            # Filter out loopback
            non_loopback = [iface for iface in interfaces if 'loopback' not in iface.lower()]
            
            if non_loopback:
                selected = non_loopback[0]
                print(f"[*] Selected interface: {selected}")
                return selected
            else:
                print(f"[*] Using first available interface: {interfaces[0]}")
                return interfaces[0]
                
        except Exception as e:
            print(f"[!] Error getting interface: {e}")
            return None
        
    def start_sniffing(self, callback):
        self.sniffing = True
        interface = self.interface or self.get_default_interface()
        
        if not interface:
            print("[!] No network interface found!")
            print("[!] IMPORTANT: Run as Administrator to enable packet sniffing!")
            self.list_interfaces()
            self.sniffing = False
            return
            
        print(f"[*] Starting packet sniffing on interface: {interface}")
        print("[*] Waiting for packets...")
        print("[*] Make sure test_tcp.py uses YOUR LOCAL IP address as TARGET_IP!")
        
        packet_count = 0
        
        def packet_handler(packet):
            nonlocal packet_count
            if self.sniffing:
                try:
                    packet_count += 1
                    print(f"[DEBUG SNIFFER] Packet #{packet_count} received")
                    if packet_count % 1 == 1:  # Print every packet
                        print(f"[DEBUG SNIFFER] Calling callback for packet #{packet_count}")
                    callback(packet)
                    print(f"[DEBUG SNIFFER] Callback completed for packet #{packet_count}")
                except Exception as e:
                    print(f"[!] Error in packet callback: {e}")
        
        try:
            # Continuous sniffing
            while self.sniffing:
                try:
                    print(f"[*] Sniffing on {interface}...")
                    sniff(iface=interface,
                          prn=packet_handler, 
                          store=False,
                          stop_filter=lambda x: not self.sniffing,
                          timeout=2)
                except PermissionError:
                    print("[!] ERROR: Permission denied! You need to run as Administrator!")
                    self.sniffing = False
                    break
                except OSError as ose:
                    print(f"[!] OS Error: {ose}")
                    print("[!] Make sure you're running as Administrator on Windows!")
                    self.sniffing = False
                    break
                except Exception as e:
                    if self.sniffing:
                        print(f"[!] Sniff error: {e}")
                        threading.Event().wait(1)
                        
        except KeyboardInterrupt:
            print("[*] Sniffing interrupted")
            self.sniffing = False
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
            self.sniffing = False
    
    def stop_sniffing(self):
        self.sniffing = False
        print("[*] Stopping packet sniffing")