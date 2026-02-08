from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
from modules.sniffing import PacketSniffer
from modules.detection import DetectionEngine
from modules.ml_model import MLModel
from modules.prevention import PreventionSystem
from modules.logger import Logger
from modules.utils import get_available_interfaces
import threading
import time
import json
import socket
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids-secret-key-2023'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global instances
sniffer = None
sniffer_thread = None
is_sniffing = False
logger = Logger()
prevention = PreventionSystem()
ml_model = MLModel()

# Store detected attacks
detected_attacks = []
traffic_data = {
    'total_packets': 0,
    'tcp': 0,
    'udp': 0,
    'arp': 0,
    'dns': 0,
    'attacks': 0
}

class IDPSManager:
    def __init__(self):
        self.detection_engine = DetectionEngine()
        
    def process_packet(self, packet):
        global traffic_data, detected_attacks
        
        print(f"[DEBUG] process_packet called - Packet received")
        
        try:
            # Update traffic stats
            traffic_data['total_packets'] += 1
            print(f"[DEBUG] Total packets: {traffic_data['total_packets']}")
            
            # Count packet types (use if for all, not elif)
            if packet.haslayer('TCP'):
                traffic_data['tcp'] += 1
                print(f"[+] TCP packet captured (Total: {traffic_data['tcp']})")
            
            if packet.haslayer('UDP'):
                traffic_data['udp'] += 1
                print(f"[+] UDP packet captured (Total: {traffic_data['udp']})")
            
            if packet.haslayer('ARP'):
                traffic_data['arp'] += 1
                print(f"[+] ARP packet captured (Total: {traffic_data['arp']})")
            
            # Check for DNS (UDP port 53)
            try:
                if packet.haslayer('UDP'):
                    dport = packet['UDP'].dport
                    sport = packet['UDP'].sport
                    if dport == 53 or sport == 53:
                        traffic_data['dns'] += 1
                        print(f"[+] DNS packet captured (Total: {traffic_data['dns']})")
            except:
                pass
            
            # Broadcast stats update immediately
            print(f"[DEBUG] Broadcasting stats: {traffic_data}")
            socketio.server.emit('stats_updated', traffic_data, namespace='/')
            
            # Extract features
            features = self.extract_packet_features(packet)
            
            # Rule-based detection
            attack_type = self.detection_engine.detect(packet, features)
            
            # ML-based detection
            if not attack_type and features:
                attack_type = ml_model.predict(features)
            
            if attack_type:
                traffic_data['attacks'] += 1
                src_ip = features.get('src_ip', 'Unknown')
                
                # Log the attack
                logger.log_event(attack_type, src_ip, features)
                
                # Add to prevention system
                prevention.block_ip(src_ip)
                
                # Add to detected attacks list
                attack_data = {
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'type': attack_type,
                    'src_ip': src_ip,
                    'details': json.dumps(features)
                }
                detected_attacks.append(attack_data)
                
                # Send real-time update via WebSocket
                socketio.server.emit('new_attack', attack_data, namespace='/')
                
                # Keep only last 100 attacks
                if len(detected_attacks) > 100:
                    detected_attacks.pop(0)
        
        except Exception as e:
            print(f"[!] Error processing packet: {e}")
            traceback.print_exc()
    
    def extract_packet_features(self, packet):
        # Extract features for ML model
        features = {}
        try:
            if packet.haslayer('IP'):
                features['src_ip'] = packet['IP'].src
                features['dst_ip'] = packet['IP'].dst
                features['protocol'] = packet['IP'].proto
                
            if packet.haslayer('TCP'):
                features['src_port'] = packet['TCP'].sport
                features['dst_port'] = packet['TCP'].dport
                features['flags'] = packet['TCP'].flags
                
            if packet.haslayer('UDP'):
                features['src_port'] = packet['UDP'].sport
                features['dst_port'] = packet['UDP'].dport
                
            if packet.haslayer('ARP'):
                features['op'] = packet['ARP'].op
                features['src_mac'] = packet['ARP'].hwsrc
                
        except:
            pass
            
        return features

# Initialize manager
manager = IDPSManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    global sniffer, sniffer_thread, is_sniffing
    
    if not is_sniffing:
        interface = request.json.get('interface', 'eth0')
        sniffer = PacketSniffer()
        sniffer_thread = threading.Thread(target=sniffer.start_sniffing, 
                                         args=(manager.process_packet,))
        sniffer_thread.daemon = True
        sniffer_thread.start()
        is_sniffing = True
        
        # Log status
        print(f"[*] Sniffing started - is_sniffing: {is_sniffing}")
        
        # Emit status using socketio server object
        socketio.server.emit('status_changed', {'is_sniffing': True}, namespace='/')
        
        return jsonify({'status': 'success', 'message': 'Sniffing started', 'is_sniffing': is_sniffing})
    
    return jsonify({'status': 'error', 'message': 'Already sniffing'})

@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    global is_sniffing
    
    if is_sniffing and sniffer:
        sniffer.stop_sniffing()
        is_sniffing = False
        
        # Log status
        print(f"[*] Sniffing stopped - is_sniffing: {is_sniffing}")
        
        # Emit status using socketio server object
        socketio.server.emit('status_changed', {'is_sniffing': False}, namespace='/')
        
        return jsonify({'status': 'success', 'message': 'Sniffing stopped', 'is_sniffing': is_sniffing})
    
    return jsonify({'status': 'error', 'message': 'Not sniffing'})

@app.route('/get_stats')
def get_stats():
    # Return current stats including sniffing status
    stats = dict(traffic_data)
    stats['is_sniffing'] = is_sniffing
    return jsonify(stats)

@app.route('/get_attacks')
def get_attacks():
    return jsonify(detected_attacks[-20:])  # Return last 20 attacks

@app.route('/get_interfaces')
def get_interfaces():
    from scapy.all import get_if_list
    try:
        interfaces = get_if_list()
        return jsonify({'interfaces': interfaces, 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})

@app.route('/get_blacklist')
def get_blacklist():
    return jsonify(prevention.get_blacklist())

@app.route('/add_to_blacklist', methods=['POST'])
def add_to_blacklist():
    ip = request.json.get('ip')
    if ip:
        prevention.block_ip(ip)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'})

@app.route('/remove_from_blacklist', methods=['POST'])
def remove_from_blacklist():
    ip = request.json.get('ip')
    if ip:
        prevention.unblock_ip(ip)
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error'})

@app.route('/export_logs')
def export_logs():
    log_file = 'logs/ids.log'
    return send_file(log_file, as_attachment=True)

@app.route('/debug/status')
def debug_status():
    """Debug endpoint to check IDPS status"""
    return jsonify({
        'is_sniffing': is_sniffing,
        'total_packets': traffic_data['total_packets'],
        'tcp_packets': traffic_data['tcp'],
        'udp_packets': traffic_data['udp'],
        'arp_packets': traffic_data['arp'],
        'dns_packets': traffic_data['dns'],
        'detected_attacks': traffic_data['attacks'],
        'sniffer_thread_alive': sniffer_thread.is_alive() if sniffer_thread else False
    })

@app.route('/get_local_ip')
def get_local_ip():
    """Get the machine's local IP address"""
    try:
        # Connect to an external host to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return jsonify({'local_ip': local_ip, 'status': 'success'})
    except Exception as e:
        return jsonify({'error': str(e), 'status': 'error'})

@app.route('/train_model', methods=['POST'])
def train_model():
    try:
        ml_model.train_model()
        return jsonify({'status': 'success', 'message': 'Model trained successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    # Load ML model on startup
    ml_model.load_model()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
