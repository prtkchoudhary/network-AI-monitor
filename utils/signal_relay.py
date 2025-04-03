from PyQt5.QtCore import QObject, pyqtSignal

class SignalRelay(QObject):
    """Handles signal communication between different components of the application."""
    
    log_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)
    data_signal = pyqtSignal(object)  # For network connection data updates 