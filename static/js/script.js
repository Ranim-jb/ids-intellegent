document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    const exportBtn = document.getElementById('exportBtn');
    const trainBtn = document.getElementById('trainBtn');
    const addIpBtn = document.getElementById('addIpBtn');
    const ipInput = document.getElementById('ipInput');
    
    // Stats elements
    const totalPacketsEl = document.getElementById('totalPackets');
    const tcpPacketsEl = document.getElementById('tcpPackets');
    const udpPacketsEl = document.getElementById('udpPackets');
    const arpPacketsEl = document.getElementById('arpPackets');
    const dnsPacketsEl = document.getElementById('dnsPackets');
    const attacksEl = document.getElementById('attacks');
    
    // Tables
    const attacksTable = document.getElementById('attacksTable');
    const blacklistTable = document.getElementById('blacklistTable');
    
    // Packet counter
    let packetNumber = 0;
    
    // Status indicator
    const statusIndicator = document.querySelector('.status-indicator');
    const statusText = document.getElementById('statusText');
    
    // WebSocket connection
    const socket = io();
    
    // Event Listeners
    startBtn.addEventListener('click', startSniffing);
    stopBtn.addEventListener('click', stopSniffing);
    exportBtn.addEventListener('click', exportLogs);
    trainBtn.addEventListener('click', trainModel);
    addIpBtn.addEventListener('click', addToBlacklist);
    
    // WebSocket events
    socket.on('connect', function() {
        console.log('Connected to WebSocket server');
        updateStats();  // Get initial stats
    });
    
    socket.on('status_changed', function(data) {
        console.log('Status changed:', data);
        setStatusActive(data.is_sniffing);
    });
    
    socket.on('stats_updated', function(data) {
        console.log('Stats updated:', data);
        totalPacketsEl.textContent = data.total_packets;
        tcpPacketsEl.textContent = data.tcp;
        udpPacketsEl.textContent = data.udp;
        arpPacketsEl.textContent = data.arp;
        dnsPacketsEl.textContent = data.dns;
        attacksEl.textContent = data.attacks;
    });
    
    socket.on('new_attack', function(data) {
        console.log('New attack detected:', data);
        addAttackToTable(data);
        updateStats();
    });
    
    // Initialize
    updateStats();
    updateBlacklist();
    
    // Functions
    function startSniffing() {
        fetch('/start_sniffing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ interface: 'eth0' })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                setStatusActive(true);
                showNotification('Sniffing started successfully', 'success');
            } else {
                showNotification(data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showNotification('Failed to start sniffing', 'error');
        });
    }
    
    function stopSniffing() {
        fetch('/stop_sniffing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                setStatusActive(false);
                showNotification('Sniffing stopped', 'success');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
    
    function exportLogs() {
        window.open('/export_logs', '_blank');
        showNotification('Logs exported successfully', 'success');
    }
    
    function trainModel() {
        fetch('/train_model', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                showNotification(data.message, 'success');
            } else {
                showNotification(data.message, 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
    
    function addToBlacklist() {
        const ip = ipInput.value.trim();
        if (!ip || !isValidIP(ip)) {
            showNotification('Please enter a valid IP address', 'error');
            return;
        }
        
        fetch('/add_to_blacklist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                ipInput.value = '';
                updateBlacklist();
                showNotification('IP added to blacklist', 'success');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
    
    function removeFromBlacklist(ip) {
        fetch('/remove_from_blacklist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(() => {
            updateBlacklist();
            showNotification('IP removed from blacklist', 'success');
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
    
    function updateStats() {
        fetch('/get_stats')
            .then(response => response.json())
            .then(data => {
                totalPacketsEl.textContent = data.total_packets;
                tcpPacketsEl.textContent = data.tcp;
                udpPacketsEl.textContent = data.udp;
                arpPacketsEl.textContent = data.arp;
                dnsPacketsEl.textContent = data.dns;
                attacksEl.textContent = data.attacks;
                
                // Also sync status from backend
                if (data.is_sniffing !== undefined) {
                    setStatusActive(data.is_sniffing);
                }
            });
    }
    
    function updateAttacks() {
        fetch('/get_attacks')
            .then(response => response.json())
            .then(attacks => {
                attacksTable.innerHTML = `
                    <tr>
                        <th>Packet #</th>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Source IP</th>
                        <th>Details</th>
                    </tr>
                `;
                
                // Set packet number based on current table rows
                packetNumber = attacks.length;
                
                attacks.forEach((attack, index) => {
                    const row = attacksTable.insertRow();
                    row.className = 'real-time-update';
                    
                    const packetCell = row.insertCell();
                    const timeCell = row.insertCell();
                    const typeCell = row.insertCell();
                    const ipCell = row.insertCell();
                    const detailsCell = row.insertCell();
                    
                    packetCell.textContent = index + 1;
                    packetCell.className = 'packet-number';
                    timeCell.textContent = attack.timestamp;
                    typeCell.textContent = attack.type;
                    typeCell.className = getAttackClass(attack.type);
                    ipCell.innerHTML = `<span class="ip-badge">${attack.src_ip}</span>`;
                    detailsCell.textContent = attack.details || 'No details';
                    
                    // Remove highlight animation after 1 second
                    setTimeout(() => {
                        row.classList.remove('real-time-update');
                    }, 1000);
                });
            });
    }
    
    function updateBlacklist() {
        fetch('/get_blacklist')
            .then(response => response.json())
            .then(ips => {
                blacklistTable.innerHTML = `
                    <tr>
                        <th>IP Address</th>
                        <th>Action</th>
                    </tr>
                `;
                
                ips.forEach(ip => {
                    const row = blacklistTable.insertRow();
                    const ipCell = row.insertCell();
                    const actionCell = row.insertCell();
                    
                    ipCell.innerHTML = `<span class="ip-badge">${ip}</span>`;
                    actionCell.innerHTML = `
                        <span class="remove-ip" onclick="removeFromBlacklist('${ip}')">
                            <i class="fas fa-trash"></i> Remove
                        </span>
                    `;
                });
            });
    }
    
    function addAttackToTable(attack) {
        packetNumber++;
        const row = attacksTable.insertRow();
        row.className = 'real-time-update';
        
        const packetCell = row.insertCell();
        const timeCell = row.insertCell();
        const typeCell = row.insertCell();
        const ipCell = row.insertCell();
        const detailsCell = row.insertCell();
        
        packetCell.textContent = packetNumber;
        packetCell.className = 'packet-number';
        timeCell.textContent = attack.timestamp;
        typeCell.textContent = attack.type;
        typeCell.className = getAttackClass(attack.type);
        ipCell.innerHTML = `<span class="ip-badge">${attack.src_ip}</span>`;
        detailsCell.textContent = attack.details || 'No details';
        
        // Remove old rows if more than 20
        if (attacksTable.rows.length > 21) {
            attacksTable.deleteRow(1);
        }
        
        // Remove highlight animation
        setTimeout(() => {
            row.classList.remove('real-time-update');
        }, 1000);
    }
    
    function getAttackClass(attackType) {
        const classMap = {
            'SYN Flood': 'attack-syn',
            'Port Scan': 'attack-port',
            'ARP Spoofing': 'attack-arp',
            'UDP Flood': 'attack-udp',
            'ML Detected Attack': 'attack-ml'
        };
        return classMap[attackType] || '';
    }
    
    function setStatusActive(active) {
        if (active) {
            statusIndicator.classList.remove('status-inactive');
            statusIndicator.classList.add('status-active');
            statusText.textContent = 'Active';
        } else {
            statusIndicator.classList.remove('status-active');
            statusIndicator.classList.add('status-inactive');
            statusText.textContent = 'Inactive';
        }
    }
    
    function isValidIP(ip) {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) return false;
        
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }
    
    function showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 25px;
            background: ${type === 'success' ? '#28a745' : '#dc3545'};
            color: white;
            border-radius: 8px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            z-index: 1000;
            animation: slideIn 0.3s ease;
        `;
        
        document.body.appendChild(notification);
        
        // Remove after 3 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }
    
    // Add CSS for notifications
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
    
    // Auto-update stats every 5 seconds
    setInterval(updateStats, 5000);
    setInterval(updateAttacks, 10000);
    setInterval(updateBlacklist, 15000);
    
    // Make removeFromBlacklist globally available
    window.removeFromBlacklist = removeFromBlacklist;
});
