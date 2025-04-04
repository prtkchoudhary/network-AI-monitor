from PyQt5.QtWidgets import QSplitter, QWidget, QVBoxLayout
from PyQt5.QtCore import Qt, pyqtSignal

from .main_window import NetworkMonitorGUI
from .widgets.port_scan_widget import PortScanWidget
from port_scan_monitor import PortScanMonitor

class EnhancedMonitorGUI(NetworkMonitorGUI):
    """Enhanced version of NetworkMonitorGUI with port scan detection."""
    
    def __init__(self):
        # Initialize base GUI
        super().__init__()
        
        # Add port scan components
        self.port_scan_widget = PortScanWidget()
        self.port_scan_monitor = PortScanMonitor(self.signal_relay)
        
        # Connect port scan signal
        self.signal_relay.port_scan_signal.connect(self.update_port_scan_display)
        
        # Integrate port scan widget into UI
        self._integrate_port_scan_widget()
        
    def _integrate_port_scan_widget(self):
        """Integrate the port scan widget into the main window."""
        # Find the main content area (assuming it's the central widget)
        central_widget = self.centralWidget()
        if isinstance(central_widget, QWidget):
            # Create a splitter for the existing content and port scan widget
            layout = central_widget.layout()
            if layout is not None:
                # Remove all widgets from the layout
                while layout.count():
                    item = layout.takeAt(0)
                    if item.widget():
                        widget = item.widget()
                        layout.removeWidget(widget)
                        
                # Create horizontal splitter
                splitter = QSplitter(Qt.Horizontal)
                
                # Add existing content to left side
                left_widget = QWidget()
                left_layout = QVBoxLayout(left_widget)
                while layout.count():
                    left_layout.addWidget(layout.takeAt(0).widget())
                splitter.addWidget(left_widget)
                
                # Add port scan widget to right side
                splitter.addWidget(self.port_scan_widget)
                
                # Set initial sizes (70% main content, 30% port scan)
                splitter.setStretchFactor(0, 70)
                splitter.setStretchFactor(1, 30)
                
                # Add splitter to main layout
                layout.addWidget(splitter)
    
    def update_port_scan_display(self, scanners: dict):
        """Update the port scan display with current scanner information."""
        for ip, info in scanners.items():
            self.port_scan_widget.update_scanner(ip, info)
    
    def start_monitoring(self):
        """Override to also start port scan monitoring."""
        super().start_monitoring()
        self.port_scan_monitor.start_monitoring()
    
    def stop_monitoring(self):
        """Override to also stop port scan monitoring."""
        super().stop_monitoring()
        self.port_scan_monitor.stop_monitoring()
    
    def closeEvent(self, event):
        """Override to ensure port scan monitoring is stopped."""
        self.port_scan_monitor.stop_monitoring()
        super().closeEvent(event)
