# Import Flask web framework for creating the web application
from flask import Flask, render_template, jsonify, request, send_file
# Import Flask-SocketIO for real-time WebSocket communication
from flask_socketio import SocketIO, emit
# Import custom modules for IDPS functionality
from modules.sniffing import PacketSniffer  # Packet capture module
from modules.detection import DetectionEngine  # Attack detection rules
from modules.ml_model import MLModel  # Machine learning model for anomaly detection
from modules.prevention import PreventionSystem  # IP blocking and prevention
from modules.logger import Logger  # Logging system for events
from modules.utils import get_available_interfaces  # Network interface utilities
# Import threading for concurrent packet sniffing
import threading
# Import time for timestamps and delays
import time
# Import json for data serialization
import json
# Import socket for network operations
import socket
# Import traceback for error debugging
import traceback

# Create Flask application instance
app = Flask(__name__)
# Set secret key for session management and security
app.config['SECRET_KEY'] = 'ids-secret-key-2023'
# Initialize SocketIO with CORS enabled for all origins and threading mode for Windows compatibility
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global variables for packet sniffing management
sniffer = None  # PacketSniffer instance
sniffer_thread = None  # Thread for running sniffer
is_sniffing = False  # Flag to track sniffing status
logger = Logger()  # Logger instance for event logging
prevention = PreventionSystem()  # IP blocking system
ml_model = MLModel()  # Machine learning model for anomaly detection

# Global data structures to store detection results
detected_attacks = []  # List of detected attacks with timestamps and details
traffic_data = {  # Real-time traffic statistics
    'total_packets': 0,  # Total packets captured
    'tcp': 0,  # TCP packet count
    'udp': 0,  # UDP packet count
    'arp': 0,  # ARP packet count
    'dns': 0,  # DNS packet count
    'attacks': 0  # Total detected attacks
}

# Main IDPS manager class that coordinates packet processing and attack detection
class IDPSManager:
    def __init__(self):
        # Initialize the detection engine for rule-based attack detection
        self.detection_engine = DetectionEngine()

    # Main packet processing method called for each captured packet
    def process_packet(self, packet):
        # Access global variables for traffic statistics and attack storage
        global traffic_data, detected_attacks

        # Debug logging to track packet processing
        print(f"[DEBUG] process_packet called - Packet received")

        try:
            # Increment total packet counter
            traffic_data['total_packets'] += 1
            print(f"[DEBUG] Total packets: {traffic_data['total_packets']}")

            # Count different packet types (using separate if statements to count all types)
            if packet.haslayer('TCP'):
                traffic_data['tcp'] += 1
                print(f"[+] TCP packet captured (Total: {traffic_data['tcp']})")

            if packet.haslayer('UDP'):
                traffic_data['udp'] += 1
                print(f"[+] UDP packet captured (Total: {traffic_data['udp']})")

            if packet.haslayer('ARP'):
                traffic_data['arp'] += 1
                print(f"[+] ARP packet captured (Total: {traffic_data['arp']})")

            # Check for DNS traffic (UDP port 53)
            try:
                if packet.haslayer('UDP'):
                    dport = packet['UDP'].dport  # Destination port
                    sport = packet['UDP'].sport  # Source port
                    if dport == 53 or sport == 53:  # DNS port
                        traffic_data['dns'] += 1
                        print(f"[+] DNS packet captured (Total: {traffic_data['dns']})")
            except:
                pass  # Skip if UDP layer access fails

            # Broadcast updated statistics to all connected WebSocket clients
            print(f"[DEBUG] Broadcasting stats: {traffic_data}")
            socketio.server.emit('stats_updated', traffic_data, namespace='/')

            # Extract packet features for analysis
            features = self.extract_packet_features(packet)

            # First, try rule-based detection
            attack_type = self.detection_engine.detect(packet, features)

            # If no attack detected by rules, try machine learning detection
            if not attack_type and features:
                attack_type = ml_model.predict(features)

            # If an attack is detected
            if attack_type:
                # Increment attack counter
                traffic_data['attacks'] += 1
                # Get source IP from packet features
                src_ip = features.get('src_ip', 'Unknown')

                # Log the attack event
                logger.log_event(attack_type, src_ip, features)

                # Add the attacking IP to the prevention system (blocking)
                prevention.block_ip(src_ip)

                # Create attack data structure for storage and display
                attack_data = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),  # Current timestamp
                    'type': attack_type,  # Type of attack detected
                    'src_ip': src_ip,  # Source IP of the attack
                    'details': json.dumps(features)  # Packet details as JSON string
                }
                # Add to detected attacks list
                detected_attacks.append(attack_data)

                # Send real-time notification to WebSocket clients
                socketio.server.emit('new_attack', attack_data, namespace='/')

                # Maintain only the last 100 attacks to prevent memory issues
                if len(detected_attacks) > 100:
                    detected_attacks.pop(0)  # Remove oldest attack

        except Exception as e:
            # Log any errors during packet processing
            print(f"[!] Error processing packet: {e}")
            traceback.print_exc()  # Print full traceback for debugging

    # Extract features from packet for analysis and machine learning
    def extract_packet_features(self, packet):
        features = {}  # Dictionary to store extracted features
        try:
            # Extract IP layer features
            if packet.haslayer('IP'):
                features['src_ip'] = packet['IP'].src  # Source IP address
                features['dst_ip'] = packet['IP'].dst  # Destination IP address
                features['protocol'] = packet['IP'].proto  # Protocol number

            # Extract TCP layer features
            if packet.haslayer('TCP'):
                features['src_port'] = packet['TCP'].sport  # Source port
                features['dst_port'] = packet['TCP'].dport  # Destination port
                features['flags'] = packet['TCP'].flags  # TCP flags (SYN, ACK, etc.)

            # Extract UDP layer features
            if packet.haslayer('UDP'):
                features['src_port'] = packet['UDP'].sport  # Source port
                features['dst_port'] = packet['UDP'].dport  # Destination port

            # Extract ARP layer features
            if packet.haslayer('ARP'):
                features['op'] = packet['ARP'].op  # ARP operation (request/reply)
                features['src_mac'] = packet['ARP'].hwsrc  # Source MAC address

        except:
            pass  # Skip if feature extraction fails

        return features

# Create an instance of the IDPSManager to handle packet processing
manager = IDPSManager()

# Flask route for the main dashboard page
@app.route('/')
def index():
    # Render the main HTML template for the IDPS dashboard
    return render_template('index.html')

# API endpoint to start packet sniffing (POST request)
@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    # Access global variables for sniffer management
    global sniffer, sniffer_thread, is_sniffing

    # Check if sniffing is not already active
    if not is_sniffing:
        # Get interface from request (default to 'eth0')
        interface = request.json.get('interface', 'eth0')
        # Create new PacketSniffer instance
        sniffer = PacketSniffer()
        # Create daemon thread for sniffing to avoid blocking main thread
        sniffer_thread = threading.Thread(target=sniffer.start_sniffing,
                                         args=(manager.process_packet,))
        sniffer_thread.daemon = True
        # Start the sniffing thread
        sniffer_thread.start()
        # Update sniffing status
        is_sniffing = True

        # Log the status change
        print(f"[*] Sniffing started - is_sniffing: {is_sniffing}")

        # Notify all connected WebSocket clients about status change
        socketio.server.emit('status_changed', {'is_sniffing': True}, namespace='/')

        # Return success response
        return jsonify({'status': 'success', 'message': 'Sniffing started', 'is_sniffing': is_sniffing})

    # Return error if already sniffing
    return jsonify({'status': 'error', 'message': 'Already sniffing'})

# API endpoint to stop packet sniffing (POST request)
@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    # Access global sniffing status
    global is_sniffing

    # Check if sniffing is active and sniffer exists
    if is_sniffing and sniffer:
        # Stop the sniffer
        sniffer.stop_sniffing()
        # Update status
        is_sniffing = False

        # Log the status change
        print(f"[*] Sniffing stopped - is_sniffing: {is_sniffing}")

        # Notify WebSocket clients about status change
        socketio.server.emit('status_changed', {'is_sniffing': False}, namespace='/')

        # Return success response
        return jsonify({'status': 'success', 'message': 'Sniffing stopped', 'is_sniffing': is_sniffing})

    # Return error if not sniffing
    return jsonify({'status': 'error', 'message': 'Not sniffing'})

# API endpoint to get current traffic statistics (GET request)
@app.route('/get_stats')
def get_stats():
    # Create copy of traffic data and add sniffing status
    stats = dict(traffic_data)
    stats['is_sniffing'] = is_sniffing
    # Return statistics as JSON
    return jsonify(stats)

# API endpoint to get list of detected attacks (GET request)
@app.route('/get_attacks')
def get_attacks():
    # Return last 20 detected attacks as JSON
    return jsonify(detected_attacks[-20:])

# API endpoint to get available network interfaces (GET request)
@app.route('/get_interfaces')
def get_interfaces():
    # Import Scapy's interface listing function
    from scapy.all import get_if_list
    try:
        # Get list of network interfaces
        interfaces = get_if_list()
        # Return interfaces with success status
        return jsonify({'interfaces': interfaces, 'status': 'success'})
    except Exception as e:
        # Return error if interface listing fails
        return jsonify({'error': str(e), 'status': 'error'})

# API endpoint to get current IP blacklist (GET request)
@app.route('/get_blacklist')
def get_blacklist():
    # Return current blacklist from prevention system
    return jsonify(prevention.get_blacklist())

# API endpoint to add IP to blacklist (POST request)
@app.route('/add_to_blacklist', methods=['POST'])
def add_to_blacklist():
    # Get IP address from request JSON
    ip = request.json.get('ip')
    if ip:
        # Add IP to prevention system's blacklist
        prevention.block_ip(ip)
        # Return success response
        return jsonify({'status': 'success'})
    # Return error if no IP provided
    return jsonify({'status': 'error'})

# API endpoint to remove IP from blacklist (POST request)
@app.route('/remove_from_blacklist', methods=['POST'])
def remove_from_blacklist():
    # Get IP address from request JSON
    ip = request.json.get('ip')
    if ip:
        # Remove IP from prevention system's blacklist
        prevention.unblock_ip(ip)
        # Return success response
        return jsonify({'status': 'success'})
    # Return error if no IP provided
    return jsonify({'status': 'error'})

# API endpoint to export logs as file download (GET request)
@app.route('/export_logs')
def export_logs():
    # Define log file path
    log_file = 'logs/ids.log'
    # Send log file as attachment for download
    return send_file(log_file, as_attachment=True)

# Debug endpoint to check IDPS system status (GET request)
@app.route('/debug/status')
def debug_status():
    """Debug endpoint to check IDPS status"""
    # Return comprehensive system status information
    return jsonify({
        'is_sniffing': is_sniffing,  # Current sniffing status
        'total_packets': traffic_data['total_packets'],  # Total packets captured
        'tcp_packets': traffic_data['tcp'],  # TCP packet count
        'udp_packets': traffic_data['udp'],  # UDP packet count
        'arp_packets': traffic_data['arp'],  # ARP packet count
        'dns_packets': traffic_data['dns'],  # DNS packet count
        'detected_attacks': traffic_data['attacks'],  # Total attacks detected
        'sniffer_thread_alive': sniffer_thread.is_alive() if sniffer_thread else False  # Thread status
    })

# API endpoint to get local machine IP address (GET request)
@app.route('/get_local_ip')
def get_local_ip():
    """Get the machine's local IP address"""
    try:
        # Create UDP socket to connect to external host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to Google DNS
        local_ip = s.getsockname()[0]  # Get local IP from socket
        s.close()  # Close socket
        # Return local IP with success status
        return jsonify({'local_ip': local_ip, 'status': 'success'})
    except Exception as e:
        # Return error if IP detection fails
        return jsonify({'error': str(e), 'status': 'error'})

# API endpoint to train machine learning model (POST request)
@app.route('/train_model', methods=['POST'])
def train_model():
    try:
        # Train the ML model
        ml_model.train_model()
        # Return success response
        return jsonify({'status': 'success', 'message': 'Model trained successfully'})
    except Exception as e:
        # Return error if training fails
        return jsonify({'status': 'error', 'message': str(e)})

# Main application entry point
if __name__ == '__main__':
    # Load machine learning model on application startup
    ml_model.load_model()
    # Run Flask-SocketIO server with debug mode enabled
    # Disable reloader to avoid issues with threading on Windows
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=False)
