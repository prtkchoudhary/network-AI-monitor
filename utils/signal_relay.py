from PyQt5.QtCore import QObject, pyqtSignal

class SignalRelay(QObject):
    """Handles signal communication between different components of the application."""
    
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)
    data_signal = pyqtSignal(list)  # For network connection data updates
    port_scan_signal = pyqtSignal(str)  # For port scan updates (using string format)
    anomaly_signal = pyqtSignal(list)  # For DDoS detection data