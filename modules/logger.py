import logging
import time
from datetime import datetime

class Logger:
    def __init__(self):
        self.log_file = 'logs/ids.log'
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('IDS')
    
    def log_event(self, attack_type, src_ip, details=None):
        """Log security event"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = f"ATTACK: {attack_type} - Source IP: {src_ip}"
        
        if details:
            message += f" - Details: {details}"
        
        self.logger.info(message)
        
        # Also write to console
        print(f"[!] {message}")
        
        return timestamp
