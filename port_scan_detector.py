import psutil
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Set, Deque, Tuple
from utils.signal_relay import SignalRelay

class PortScanDetector:
    """Detects potential port scanning activity by monitoring connection patterns."""
    
    def __init__(self, signal_relay: SignalRelay):
        self.signal_relay = signal_relay
        # Track connection attempts per IP
        self.ip_port_history: Dict[str, Deque[Tuple[int, datetime]]] = defaultdict(lambda: deque(maxlen=100))
        # Window size for detection (in seconds)
        self.time_window = 30  # Reduced window to avoid long-lasting alerts
        # Threshold for number of unique ports in time window
        self.port_threshold = 25  # Increased threshold for normal IPs
        # Higher threshold for localhost
        self.localhost_threshold = 50
        # Common ports that are frequently scanned
        self.common_ports = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080}
        # Track currently detected scanners
        self.active_scanners: Dict[str, Dict] = {}
        # Track alert cooldowns
        self.alert_cooldowns: Dict[str, float] = {}

    def check_port_scan(self) -> None:
        """
        Check for potential port scanning activity by analyzing connection patterns.
        """
        try:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(seconds=self.time_window)
            
            # Get current connections
            connections = psutil.net_connections()
            
            # Process each connection
            for conn in connections:
                if not conn.raddr:  # Skip if no remote address
                    continue
                    
                remote_ip = conn.raddr[0]
                remote_port = conn.raddr[1] if len(conn.raddr) > 1 else 0
                
                # Add to history
                self.ip_port_history[remote_ip].append((remote_port, current_time))
                
                # Analyze this IP's recent activity
                recent_ports = set()
                common_port_hits = 0
                
                # Look at recent history for this IP
                for port, timestamp in self.ip_port_history[remote_ip]:
                    if timestamp >= cutoff_time:
                        recent_ports.add(port)
                        if port in self.common_ports:
                            common_port_hits += 1
                
                # Check if criteria for port scan are met
                unique_ports = len(recent_ports)
                
                # Use higher threshold for localhost
                threshold = self.localhost_threshold if remote_ip in ('127.0.0.1', 'localhost') else self.port_threshold
                
                # Check cooldown
                current_time_ts = current_time.timestamp()
                cooldown_expired = remote_ip not in self.alert_cooldowns or \
                                 (current_time_ts - self.alert_cooldowns.get(remote_ip, 0)) > 60
                
                if unique_ports >= threshold and cooldown_expired:
                    scan_info = {
                        'ip': remote_ip,
                        'unique_ports': unique_ports,
                        'common_ports_hit': common_port_hits,
                        'first_seen': current_time,
                        'last_seen': current_time
                    }
                    
                    # Update cooldown timestamp
                    self.alert_cooldowns[remote_ip] = current_time_ts
                    
                    # If this is a new scanner or updated info for existing scanner
                    if remote_ip not in self.active_scanners or \
                       self.active_scanners[remote_ip]['unique_ports'] != unique_ports:
                        self.active_scanners[remote_ip] = scan_info
                        
                        # Calculate score based on port activity
                        score = min(1.0, unique_ports / 100.0)  # Normalize score between 0 and 1
                        if common_port_hits > 0:
                            score += min(0.5, common_port_hits / 10.0)  # Bonus for hitting common ports
                        
                        # Skip if score is too low or IP is unknown
                        if score < 0.3 or remote_ip == 'Unknown':
                            continue
                        
                        # Only emit for non-localhost or very aggressive localhost scans
                        if remote_ip not in ('127.0.0.1', 'localhost') or unique_ports >= self.localhost_threshold:
                            scan_info['score'] = score
                            # Emit port scan signal
                            self.signal_relay.port_scan_signal.emit(scan_info)
                            # Also emit alert
                            self.signal_relay.alert_signal.emit(
                                f"Port scan detected from {remote_ip} - "
                                f"Score: {score:.2f} - "
                                f"Accessed {unique_ports} unique ports ({common_port_hits} common ports)"
                            )
            
            # Clean up old scanners
            self._cleanup_old_scanners(cutoff_time)
            
        except Exception as e:
            print(f"Error in port scan detection: {str(e)}")

    def _cleanup_old_scanners(self, cutoff_time: datetime) -> None:
        """Remove scanners that haven't been active recently."""
        to_remove = []
        for ip in self.active_scanners:
            if not any(ts >= cutoff_time for _, ts in self.ip_port_history[ip]):
                to_remove.append(ip)
        
        for ip in to_remove:
            del self.active_scanners[ip]
            del self.ip_port_history[ip]

    def get_active_scanners(self) -> Dict[str, Dict]:
        """Return information about currently active port scanners."""
        return self.active_scanners.copy()
