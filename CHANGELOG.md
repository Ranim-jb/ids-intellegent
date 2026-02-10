# IDPS System Changelog

## Latest Updates

### Authentication System
- ✅ Added Flask-Login for user authentication
- ✅ Created login page with modern UI
- ✅ Protected all dashboard routes with `@login_required` decorator
- ✅ Added logout functionality
- ✅ Default credentials: `admin` / `admin123`

### Blacklist Management
- ✅ Fixed add/remove IP buttons functionality
- ✅ All blacklisted IPs are now displayed in the table
- ✅ Real-time updates via WebSocket when IPs are added/removed
- ✅ Persistent storage in `data/blacklist.txt`

### Attacks Display
- ✅ Changed attacks table to show ALL attacks (removed 20-attack limit)
- ✅ Removed 100-attack storage limit in backend
- ✅ All detected attacks are now stored and displayed

### Dynamic Charts
- ✅ Added Chart.js library for data visualization
- ✅ **Traffic Overview Chart**: Line chart showing total packets over time
- ✅ **Protocol Distribution Chart**: Doughnut chart showing TCP/UDP/ARP/DNS distribution
- ✅ Real-time chart updates with WebSocket data
- ✅ Charts maintain last 20 data points for traffic history

### UI Improvements
- ✅ Added logout button in dashboard header
- ✅ Improved header layout with flexbox
- ✅ Added charts section above attacks/blacklist tables
- ✅ Responsive design maintained

## Installation

1. Install new dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Access the application:
- Navigate to `http://localhost:5000`
- Login with username: `admin`, password: `admin123`

## Features

### Login System
- Secure authentication required to access dashboard
- Session management with Flask-Login
- Password hashing with Werkzeug

### Real-time Monitoring
- Live packet capture and analysis
- WebSocket-based real-time updates
- Dynamic charts updating every 5 seconds

### Attack Detection
- Rule-based detection (SYN Flood, Port Scan, ARP Spoofing, UDP Flood)
- Machine learning-based anomaly detection
- Complete attack history with no limits

### IP Blacklist Management
- Add/remove IPs manually
- Automatic blocking of attacking IPs
- Persistent blacklist storage
- Real-time synchronization across all clients

## Technical Details

### New Dependencies
- `Flask-Login==0.6.2` - User authentication and session management

### Modified Files
- `app.py` - Added authentication routes and decorators
- `templates/login.html` - New login page
- `templates/index.html` - Added logout button and charts
- `static/css/style.css` - Added charts section styling
- `static/js/script.js` - Added Chart.js integration and removed attack limits
- `modules/prevention.py` - Cleaned up duplicate test IP initialization
- `requirements.txt` - Added Flask-Login dependency

### Security Notes
- Change default admin password in production
- Consider using environment variables for credentials
- Implement rate limiting for login attempts
- Use HTTPS in production environment
