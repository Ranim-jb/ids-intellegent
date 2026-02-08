import platform
import subprocess
import re
from scapy.all import get_if_list

def get_available_interfaces():
    """Get available network interfaces based on OS"""
    interfaces = []
    
    try:
        # Use scapy to get interface list
        scapy_interfaces = get_if_list()
        interfaces = list(scapy_interfaces)
        
        if not interfaces:
            # Fallback for Windows
            if platform.system() == "Windows":
                interfaces = get_windows_interfaces()
            elif platform.system() == "Linux":
                interfaces = ["eth0", "wlan0", "lo"]
            elif platform.system() == "Darwin":  # macOS
                interfaces = ["en0", "en1", "lo0"]
                
    except Exception as e:
        print(f"[!] Error getting interfaces: {e}")
        interfaces = ["eth0", "wlan0", "lo"]  # Default fallback
    
    return interfaces

def get_windows_interfaces():
    """Get network interfaces on Windows"""
    interfaces = []
    
    try:
        # Use ipconfig to get interface names on Windows
        result = subprocess.run(['ipconfig'], capture_output=True, text=True)
        
        # Parse interface names from ipconfig output
        lines = result.stdout.split('\n')
        current_interface = None
        
        for line in lines:
            # Look for adapter names
            if 'adapter' in line.lower() and ':' in line:
                # Extract adapter name
                adapter_name = line.split(':')[0].strip()
                interfaces.append(adapter_name)
                
    except Exception as e:
        print(f"[!] Error getting Windows interfaces: {e}")
    
    # Add common Windows interface patterns
    if not interfaces:
        interfaces = [
            "Ethernet",
            "Wi-Fi", 
            "Local Area Connection",
            "Wireless Network Connection"
        ]
    
    return interfaces

def get_default_interface():
    """Get default network interface"""
    interfaces = get_available_interfaces()
    
    if interfaces:
        # Prefer Ethernet/Wi-Fi interfaces
        for iface in interfaces:
            iface_lower = iface.lower()
            if 'ethernet' in iface_lower or 'eth' in iface_lower:
                return iface
            if 'wi-fi' in iface_lower or 'wlan' in iface_lower or 'wireless' in iface_lower:
                return iface
        
        # Return the first available interface
        return interfaces[0]
    
    return "eth0"  # Final fallback