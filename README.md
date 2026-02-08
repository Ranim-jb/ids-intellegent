# IDPS - Intrusion Detection & Prevention System

A Flask-based web application for real-time network intrusion detection and prevention.

## Features
- Real-time packet sniffing using Scapy
- Detection of SYN Flood, Port Scan, ARP Spoofing, UDP Flood attacks
- Machine Learning-based anomaly detection (Random Forest)
- Web-based dashboard with real-time updates
- IP blacklisting and automatic blocking
- Comprehensive logging system
- Export functionality for logs

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ids-flask-app
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create required directories:
```bash
mkdir -p logs data/models
```

4. Run the application:
```bash
# On Linux/Mac (requires root for packet sniffing)
sudo python app.py

# On Windows (run as Administrator)
python app.py
```

## Usage

1. Open your browser and navigate to `http://localhost:5000`
2. Click "Start Sniffing" to begin monitoring network traffic
3. View real-time statistics and detected attacks on the dashboard
4. Manage blacklisted IPs from the interface
5. Export logs when needed

## Project Structure
```
ids-flask-app/
├── app.py              # Main Flask application
├── modules/           # Core IDPS modules
│   ├── sniffing.py   # Packet sniffing
│   ├── detection.py  # Attack detection rules
│   ├── ml_model.py   # ML model training/prediction
│   ├── prevention.py # IP blocking system
│   └── logger.py     # Logging system
├── templates/        # HTML templates
├── static/          # CSS/JS assets
├── logs/            # Log files
└── data/            # Models and blacklists
```

## Technologies Used
- Flask - Web framework
- Scapy - Packet manipulation
- scikit-learn - Machine Learning
- Socket.IO - Real-time updates
- JavaScript - Frontend interactivity

## Security Notes
- Requires administrative/root privileges for packet sniffing
- The ML model uses synthetic data for demonstration
- In production, train with real network data
- Implement proper authentication for web interface
- Use HTTPS in production

## License
MIT License
