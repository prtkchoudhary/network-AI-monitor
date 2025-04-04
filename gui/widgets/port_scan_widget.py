from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel,
                           QFrame)
from PyQt5.QtCore import Qt
from .port_scan_table import PortScanTable

class PortScanWidget(QWidget):
    """Widget container for port scan monitoring."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the widget UI."""
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Port Scan Monitor")
        header.setStyleSheet("""
            QLabel {
                color: #ECF0F1;
                font-size: 16px;
                font-weight: bold;
                padding: 5px;
            }
        """)
        layout.addWidget(header)
        
        # Add separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet("background-color: #34495E;")
        layout.addWidget(line)
        
        # Add table
        self.scan_table = PortScanTable()
        layout.addWidget(self.scan_table)
        
        # Set layout properties
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
    def update_scanner(self, ip: str, scanner_info: dict):
        """Update the display with new scanner information."""
        self.scan_table.update_scanner(ip, scanner_info)
        
    def remove_scanner(self, ip: str):
        """Remove a scanner from the display."""
        self.scan_table.remove_scanner(ip)
