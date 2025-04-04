import threading
import time
from typing import Optional
from port_scan_detector import PortScanDetector
from utils.signal_relay import SignalRelay

class PortScanMonitor:
    """Manages port scan detection in a separate thread."""
    
    def __init__(self, signal_relay: SignalRelay):
        self.signal_relay = signal_relay
        self.detector = PortScanDetector(signal_relay)
        self.monitoring_thread: Optional[threading.Thread] = None
        self.should_stop = threading.Event()
    
    def start_monitoring(self):
        """Start the port scan monitoring thread."""
        if self.monitoring_thread is None or not self.monitoring_thread.is_alive():
            self.should_stop.clear()
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop the port scan monitoring thread."""
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.should_stop.set()
            self.monitoring_thread.join(timeout=5.0)
            self.monitoring_thread = None
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread."""
        while not self.should_stop.is_set():
            try:
                # Check for port scans
                self.detector.check_port_scan()
                
                # Get current scanners for UI update
                scanners = self.detector.get_active_scanners()
                if scanners:
                    # Convert each scanner to string format
                    for ip, info in scanners.items():
                        scan_str = f"{ip}|{info.get('score', 0.0):.2f}|{info.get('unique_ports', 0)}|{info.get('common_ports_hit', 0)}"
                        self.signal_relay.port_scan_signal.emit(scan_str)
                
                # Sleep briefly to avoid excessive CPU usage
                time.sleep(1.0)
                
            except Exception as e:
                # Use log_signal directly
                self.signal_relay.log_signal.emit(
                    f"Error in port scan monitoring: {str(e)}"
                )
                # Sleep a bit longer on error to avoid spam
                time.sleep(5.0)
