import psutil
import time
from typing import Tuple, List, Dict, Any
from collections import deque
from utils.signal_relay import SignalRelay
from utils.constants import HISTORY_SIZE
from datetime import datetime, timedelta

class NetworkMonitor:
    """Monitors network traffic and maintains history."""
    
    def __init__(self, signal_relay: SignalRelay):
        self.signal_relay = signal_relay
        self.history = []
        self.prev_bytes_sent = 0
        self.prev_bytes_recv = 0
        self.prev_time = time.time()
        self.active_connections: Dict[str, Dict[str, Any]] = {}

    def get_network_stats(self) -> Tuple[int, int, int, int]:
        """Get current network statistics."""
        try:
            # Get network counters
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate rates
            time_delta = current_time - self.prev_time
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv
            
            # Avoid division by zero
            if time_delta > 0:
                sent_rate = (bytes_sent - self.prev_bytes_sent) / time_delta
                recv_rate = (bytes_recv - self.prev_bytes_recv) / time_delta
            else:
                sent_rate = 0
                recv_rate = 0
            
            # Update connection tracking
            self.update_active_connections()
            
            # Get packet and connection counts
            try:
                connections = psutil.net_connections()
                packet_rate = len(connections)
                conn_count = sum(1 for conn in connections if conn.status == 'ESTABLISHED')
            except Exception:
                packet_rate = 0
                conn_count = 0
            
            # Update previous values
            self.prev_bytes_sent = bytes_sent
            self.prev_bytes_recv = bytes_recv
            self.prev_time = current_time
            
            # Update history
            stats = [sent_rate, recv_rate, packet_rate, conn_count]
            self.update_history(stats)
            
            return sent_rate, recv_rate, packet_rate, conn_count
            
        except Exception as e:
            self.signal_relay.log_signal.emit(f"Error getting network stats: {str(e)}")
            return 0, 0, 0, 0

    def update_active_connections(self):
        """Update the list of active network connections."""
        try:
            current_time = datetime.now()
            current_time_str = current_time.isoformat()
            
            # Get current connections
            connections = psutil.net_connections()
            current_ips = set()
            new_connections = {}
            
            # First pass: collect all current connections
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    current_ips.add(ip)
                    
                    if ip not in new_connections:
                        # New connection or first occurrence
                        new_connections[ip] = {
                            'count': 1,
                            'first_seen': current_time_str if ip not in self.active_connections 
                                        else self.active_connections[ip]['first_seen'],
                            'last_seen': current_time_str
                        }
                    else:
                        # Increment count for existing connection
                        new_connections[ip]['count'] += 1
            
            # Second pass: copy over any recent connections that are no longer active
            cutoff_time = current_time - timedelta(minutes=5)
            cutoff_time_str = cutoff_time.isoformat()
            
            for ip, data in self.active_connections.items():
                if ip not in new_connections and data['last_seen'] > cutoff_time_str:
                    new_connections[ip] = data
            
            # Update the active connections with the new state
            self.active_connections = new_connections
            
        except Exception as e:
            self.signal_relay.log_signal.emit(f"Error updating connections: {str(e)}")

    def get_active_connections(self) -> Dict[str, Dict[str, Any]]:
        """Get the dictionary of active connections."""
        return self.active_connections

    def update_history(self, stats):
        """Update monitoring history."""
        self.history.append(stats)
        if len(self.history) > HISTORY_SIZE:
            self.history.pop(0)

    def get_history(self) -> List[List[int]]:
        """Get monitoring history."""
        return list(self.history)

    def reset(self):
        """Reset the monitor state."""
        self.history.clear()
        self.prev_bytes_sent = 0
        self.prev_bytes_recv = 0
        self.prev_time = time.time()
        self.active_connections.clear()

    @staticmethod
    def format_bytes(size: int) -> str:
        """Format byte size to human readable format."""
        try:
            size = float(size)
            if size < 1024:
                return f"{size:.0f} B/s"
            elif size < 1024**2:
                return f"{size/1024:.2f} KB/s"
            elif size < 1024**3:
                return f"{size/1024**2:.2f} MB/s"
            else:
                return f"{size/1024**3:.2f} GB/s"
        except (ValueError, TypeError):
            return "0 B/s" 