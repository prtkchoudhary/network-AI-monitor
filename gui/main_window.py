import sys
import threading
import time
import numpy as np
from PyQt5.QtWidgets import (QMainWindow, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QWidget, QFrame, QTextEdit, QMessageBox,
                           QApplication, QSplitter, QSizePolicy)
from PyQt5.QtGui import QColor, QFont, QIcon, QPalette
from PyQt5.QtCore import QTimer, Qt, QCoreApplication, QSize
import pyqtgraph as pg
from datetime import datetime

from utils.signal_relay import SignalRelay
from utils.constants import (
    GLOBAL_BG_COLOR, SIDEBAR_BG_COLOR, BUTTON_COLORS,
    MONITORING_INTERVAL, HISTORY_SIZE, FONT_FAMILY,
    FONT_SIZES, GRAPH_COLORS, SIDEBAR_WIDTH, GRAPH_HEIGHT,
    LOG_HEIGHT, BUTTON_HEIGHT, SPACING, MARGIN
)
from network_monitor import NetworkMonitor
from ddos_detector import DDoSDetector
from gui.widgets.anomaly_table import AnomalyTable
from gui.widgets.network_map import NetworkMap

class NetworkMonitorGUI(QMainWindow):
    """Main window for the Network Monitor application."""
    
    def __init__(self):
        super().__init__()
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle("AI-Powered Network Monitor with DDoS Detection")
        
        # Set window size
        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)
        
        # Set application-wide style
        self.setStyleSheet(f"""
            QWidget {{
                font-family: {FONT_FAMILY};
                background-color: {GLOBAL_BG_COLOR};
                color: #FFFFFF;
            }}
        """)
        
        # Initialize state
        self.monitoring = False
        self.ddos_monitoring_thread = None
        self.sent_data = np.zeros(HISTORY_SIZE)
        self.recv_data = np.zeros(HISTORY_SIZE)
        self.data_index = 0
        
        # Create log view first
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setStyleSheet("""
            QTextEdit {
                background-color: #2C3E50;
                color: #ECF0F1;
                border: none;
                border-radius: 5px;
            }
        """)
        
        try:
            # Initialize components
            self.signal_relay = SignalRelay()
            self.network_monitor = NetworkMonitor(self.signal_relay)
            self.ddos_detector = DDoSDetector(self.signal_relay)
            
            # Setup UI
            self.initUI()
            
            # Connect signals
            self.signal_relay.log_signal.connect(self.log_message)
            self.signal_relay.alert_signal.connect(self.show_alert)
            
            # Setup timer
            self.timer = QTimer()
            self.timer.timeout.connect(self.monitor_network)
        except Exception as e:
            QMessageBox.critical(
                self,
                "Initialization Error",
                f"Failed to initialize the application: {str(e)}\nPlease check your system requirements and try again."
            )
            self.close()

    def initUI(self):
        """Initialize the user interface."""
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Add control buttons at the top
        control_layout = self.setup_controls()
        layout.addLayout(control_layout)
        
        # Create horizontal splitter for main content
        main_splitter = QSplitter(Qt.Horizontal)
        
        # Left panel (Map and Graph)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Create vertical splitter for map and graph
        left_splitter = QSplitter(Qt.Vertical)
        
        # Add network map
        self.network_map = NetworkMap(self.signal_relay)
        left_splitter.addWidget(self.network_map)
        
        # Create graph panel
        graph_panel = QWidget()
        graph_layout = QVBoxLayout(graph_panel)
        
        # Traffic display
        traffic_layout = QHBoxLayout()
        self.sent_value = QLabel("Sent: 0 B/s")
        self.recv_value = QLabel("Received: 0 B/s")
        traffic_layout.addWidget(self.sent_value)
        traffic_layout.addWidget(self.recv_value)
        graph_layout.addLayout(traffic_layout)
        
        # Add traffic graph
        self.setup_graph()
        graph_layout.addWidget(self.graph_widget)
        
        left_splitter.addWidget(graph_panel)
        
        # Set initial splitter sizes (60% map, 40% graph)
        left_splitter.setSizes([600, 400])
        
        left_layout.addWidget(left_splitter)
        left_panel.setLayout(left_layout)
        
        # Right panel (Table and Log)
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Add anomaly table
        self.anomaly_table = AnomalyTable()
        right_layout.addWidget(self.anomaly_table)
        
        # Add log view
        right_layout.addWidget(self.log_view)
        
        right_panel.setLayout(right_layout)
        
        # Add panels to splitter
        main_splitter.addWidget(left_panel)
        main_splitter.addWidget(right_panel)
        
        # Set initial splitter sizes (60% left, 40% right)
        main_splitter.setSizes([800, 600])
        
        # Add splitter to main layout
        layout.addWidget(main_splitter)
        
        # Set window properties
        self.setGeometry(100, 100, 1400, 900)
        self.setWindowTitle("AI-Powered Network Monitor")

    def setup_controls(self):
        """Setup control buttons."""
        control_layout = QHBoxLayout()
        
        # Start button
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.setStyleSheet(f"background-color: {BUTTON_COLORS['start']}; color: white;")
        self.start_button.clicked.connect(self.start_monitoring)
        
        # Stop button
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.setStyleSheet(f"background-color: {BUTTON_COLORS['stop']}; color: white;")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        
        # Reset button
        self.reset_button = QPushButton("Reset")
        self.reset_button.setStyleSheet(f"background-color: {BUTTON_COLORS['reset']}; color: white;")
        self.reset_button.clicked.connect(self.reset_monitoring)
        
        # Block IPs button
        self.block_button = QPushButton("Block Suspicious IPs")
        self.block_button.setStyleSheet(f"background-color: {BUTTON_COLORS['block']}; color: white;")
        self.block_button.clicked.connect(self.block_suspicious_ips)
        
        # Refresh Map button
        self.map_button = QPushButton("Refresh Map")
        self.map_button.setStyleSheet(f"background-color: {BUTTON_COLORS['settings']}; color: white;")
        self.map_button.clicked.connect(self.refresh_map)
        
        # Add buttons to layout
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.reset_button)
        control_layout.addWidget(self.block_button)
        control_layout.addWidget(self.map_button)
        
        return control_layout

    def setup_graph(self):
        """Setup the network traffic graph."""
        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setBackground(GRAPH_COLORS['grid'])
        self.graph_widget.setTitle("Network Traffic Monitor", 
                                color=GRAPH_COLORS['text'], 
                                size=FONT_SIZES['subtitle'])
        self.graph_widget.setLabel("left", "Speed (Bytes per Second)", 
                                color=GRAPH_COLORS['text'])
        self.graph_widget.setLabel("bottom", "Time", 
                                color=GRAPH_COLORS['text'])
        self.graph_widget.showGrid(x=True, y=True, alpha=0.3)
        self.graph_widget.addLegend()
        
        # Set graph style
        self.graph_widget.setStyleSheet(f"""
            QWidget {{
                background-color: {GRAPH_COLORS['grid']};
                border-radius: 8px;
            }}
        """)

        # Create x-axis data array
        self.time_data = np.arange(HISTORY_SIZE)
        
        # Initialize curves with proper scaling
        self.sent_curve = self.graph_widget.plot(
            self.time_data,
            self.sent_data,
            pen=pg.mkPen(color=GRAPH_COLORS['sent'], width=2), 
            name="Bytes Sent"
        )
        self.recv_curve = self.graph_widget.plot(
            self.time_data,
            self.recv_data,
            pen=pg.mkPen(color=GRAPH_COLORS['received'], width=2), 
            name="Bytes Received"
        )
        self.anomaly_curve = self.graph_widget.plot(
            pen=None, 
            symbol='o', 
            symbolSize=8, 
            symbolBrush=QColor(GRAPH_COLORS['anomaly']), 
            name="Anomalies"
        )

        # Set view range and scaling
        self.graph_widget.setYRange(0, 1000000)  # Initial y-range (will auto-adjust)
        self.graph_widget.setXRange(0, HISTORY_SIZE)  # Show full history window
        self.graph_widget.enableAutoRange(axis='y')  # Enable auto-ranging for y-axis

    def show_settings(self):
        """Show settings dialog."""
        # TODO: Implement settings dialog
        QMessageBox.information(
            self,
            "Settings",
            "Settings dialog will be implemented in the next version."
        )

    def log_message(self, message):
        """Handle log messages with filtering."""
        # Only log critical messages and alerts
        if any(key in message for key in [
            "⚠ DDoS Alert",
            "🚫 Blocked",
            "Error",
            "Warning",
            "❌",
            "Fatal"
        ]):
            self.log_view.append(message)
            # Auto-scroll to bottom for important messages
            self.log_view.verticalScrollBar().setValue(
                self.log_view.verticalScrollBar().maximum()
            )

    def show_alert(self, message):
        """Show alert messages."""
        QMessageBox.warning(self, "Network Security Alert", message)

    def refresh_map(self):
        """Refresh the network map."""
        if hasattr(self, 'network_map'):
            self.network_map.refresh_map()

    def monitor_network(self):
        """Monitor network traffic and update UI."""
        try:
            # Get network stats (returns tuple of sent_rate, recv_rate, packet_rate, conn_count)
            sent_rate, recv_rate, packet_rate, conn_count = self.network_monitor.get_network_stats()
            
            # Update traffic display
            self.update_traffic_display(sent_rate, recv_rate, packet_rate, conn_count)
            
            # Update graph
            self.update_graph_data(sent_rate, recv_rate)
            
            # Update map with new connections
            active_connections = self.network_monitor.get_active_connections()
            for ip, conn_data in active_connections.items():
                self.network_map.add_connection(ip, conn_data)
            
        except Exception as e:
            self.log_message(f"Error monitoring network: {str(e)}")

    def update_traffic_display(self, sent_rate, recv_rate, packet_rate, conn_count):
        """Update the traffic display labels."""
        try:
            # Format rates for display
            sent_text = self.network_monitor.format_bytes(sent_rate)
            recv_text = self.network_monitor.format_bytes(recv_rate)
            
            # Update labels
            self.sent_value.setText(f"Sent: {sent_text}")
            self.recv_value.setText(f"Received: {recv_text}")
            
            # Add to history
            self.sent_data[:-1] = self.sent_data[1:]
            self.sent_data[-1] = sent_rate
            
            self.recv_data[:-1] = self.recv_data[1:]
            self.recv_data[-1] = recv_rate
            
            # Increment data index
            self.data_index += 1
            
        except Exception as e:
            self.log_message(f"Error updating traffic display: {str(e)}")
            
    def update_graph_data(self, sent_rate, recv_rate):
        """Update the network traffic graph."""
        try:
            # Update the main traffic curves
            self.sent_curve.setData(self.time_data, self.sent_data)
            self.recv_curve.setData(self.time_data, self.recv_data)
            
            # Handle anomaly plotting
            if hasattr(self, 'ddos_detector') and self.ddos_detector.anomalies:
                try:
                    x_vals = []
                    y_vals = []
                    
                    # Calculate the window range
                    window_start = self.data_index - HISTORY_SIZE
                    
                    # Process each anomaly and adjust its position
                    for idx, data in self.ddos_detector.anomalies:
                        # Calculate relative position in current window
                        relative_pos = HISTORY_SIZE - (self.data_index - idx)
                        
                        # Only plot if the anomaly is within the visible window
                        if 0 <= relative_pos < HISTORY_SIZE:
                            x_vals.append(relative_pos)
                            if isinstance(data, (list, tuple)) and len(data) > 0:
                                y_vals.append(float(data[0]))  # Use sent_rate for y-value
                    
                    if x_vals and y_vals:
                        self.anomaly_curve.setData(x_vals, y_vals)
                    else:
                        self.anomaly_curve.setData([], [])
                        
                except Exception as e:
                    self.log_message(f"Error plotting anomalies: {str(e)}")
                    self.anomaly_curve.setData([], [])
            else:
                self.anomaly_curve.setData([], [])

            # Auto-scale y-axis based on current data
            if np.max(self.recv_data) > 0 or np.max(self.sent_data) > 0:
                max_val = max(np.max(self.recv_data), np.max(self.sent_data))
                self.graph_widget.setYRange(0, max_val * 1.1)  # Add 10% padding
                
        except Exception as e:
            self.log_message(f"Error updating graph: {str(e)}")
            self.sent_curve.setData([])
            self.recv_curve.setData([])
            self.anomaly_curve.setData([], [])

    def reset_monitoring(self):
        """Reset all monitoring data and UI."""
        # Reset table
        self.anomaly_table.reset()
        
        # Reset data arrays and index
        self.sent_data = np.zeros(HISTORY_SIZE)
        self.recv_data = np.zeros(HISTORY_SIZE)
        self.data_index = 0  # Reset global index
        
        # Reset components
        if hasattr(self, 'network_monitor'):
            self.network_monitor.reset()
        if hasattr(self, 'ddos_detector'):
            self.ddos_detector.reset()
            self.ddos_detector.anomalies = []
        
        # Reset graph
        self.sent_curve.setData(self.time_data, self.sent_data)
        self.recv_curve.setData(self.time_data, self.recv_data)
        self.anomaly_curve.setData([], [])
        
        # Reset UI elements
        self.log_view.clear()
        self.sent_value.setText("Sent: 0 B/s")
        self.recv_value.setText("Received: 0 B/s")
        
        # Clear map data
        self.network_map.clear_data()
        
        self.log_message("Monitoring reset")

    def block_suspicious_ips(self):
        """Block suspicious IPs."""
        self.ddos_detector.detect_and_block_suspicious_ips()

    def start_monitoring(self):
        """Start network monitoring."""
        try:
            self.monitoring = True
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            # Start the monitoring timer
            self.timer.start(MONITORING_INTERVAL)
            
            # Start DDoS detection thread
            self.ddos_monitoring_thread = threading.Thread(target=self.run_ddos_detection)
            self.ddos_monitoring_thread.daemon = True
            self.ddos_monitoring_thread.start()
            
            self.log_message("Monitoring started")
            
        except Exception as e:
            self.log_message(f"Error starting monitoring: {str(e)}")

    def stop_monitoring(self):
        """Stop network monitoring."""
        try:
            self.monitoring = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            
            # Stop the monitoring timer
            self.timer.stop()
            
            # Wait for DDoS detection thread to finish
            if self.ddos_monitoring_thread:
                self.ddos_monitoring_thread.join()
            
            self.log_message("Monitoring stopped")
            
        except Exception as e:
            self.log_message(f"Error stopping monitoring: {str(e)}")

    def run_ddos_detection(self):
        """Run DDoS detection in a separate thread."""
        try:
            self.ddos_detector.running = True
            while self.monitoring:
                try:
                    # Get current network stats
                    sent_rate, recv_rate, packet_rate, conn_count = self.network_monitor.get_network_stats()
                    history = self.network_monitor.get_history()
                    
                    # Run detection
                    result = self.ddos_detector.detect_ddos(history)
                    
                    if result:
                        # Format anomaly data for the table
                        anomaly_data = {
                            'sent': sent_rate,
                            'recv': recv_rate,
                            'packets': packet_rate,
                            'connections': conn_count,
                            'timestamp': time.time()
                        }
                        
                        # Add to table in the main thread
                        self.add_anomaly_to_table(anomaly_data)
                        
                        # Log the alert
                        self.signal_relay.log_signal.emit(
                            f"⚠ DDoS Alert: Abnormal traffic detected! "
                            f"Packets: {packet_rate}, Connections: {conn_count}"
                        )
                    
                    time.sleep(2)
                except Exception as e:
                    self.log_message(f"Error in DDoS detection: {str(e)}")
                    time.sleep(2)  # Wait before retrying
        except Exception as e:
            self.log_message(f"Fatal error in DDoS detection thread: {str(e)}")
            self.stop_monitoring()

    def add_anomaly_to_table(self, anomaly_data):
        """Add anomaly to table from the main thread."""
        try:
            # Create formatted anomaly data
            formatted_data = [
                anomaly_data['sent'],
                anomaly_data['recv'],
                anomaly_data['packets'],
                anomaly_data['connections']
            ]
            
            # Add to table
            self.anomaly_table.add_anomaly(formatted_data)
            
            # Update graph anomalies with current time index
            if hasattr(self, 'ddos_detector'):
                # Store the actual data index with the anomaly
                self.ddos_detector.anomalies.append((self.data_index, formatted_data))
                
                # Keep only anomalies within the visible window
                window_start = self.data_index - HISTORY_SIZE
                self.ddos_detector.anomalies = [
                    (idx, data) for idx, data in self.ddos_detector.anomalies 
                    if idx > window_start
                ]
        
        except Exception as e:
            self.log_message(f"Error adding anomaly to table: {str(e)}")

    def closeEvent(self, event):
        """Handle application closure."""
        try:
            reply = QMessageBox.question(
                self, 'Close Confirmation', 
                "Are you sure you want to exit the Network Monitor?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                self.stop_monitoring()
                if hasattr(self, 'network_map'):
                    self.network_map.close()
                QCoreApplication.instance().quit()
                event.accept()
            else:
                event.ignore()
        except Exception as e:
            self.log_message(f"Error during application closure: {str(e)}")
            event.accept()  # Force close if there's an error

    def handle_anomaly(self, anomaly_data):
        """Handle detected anomalies by updating the UI and logging."""
        try:
            # Format anomaly data
            if isinstance(anomaly_data, list):
                for anomaly in anomaly_data:
                    self.handle_single_anomaly(anomaly)
            else:
                self.handle_single_anomaly(anomaly_data)
                
        except Exception as e:
            print(f"Error handling anomaly batch: {str(e)}")
            
    def handle_single_anomaly(self, anomaly):
        """Handle a single anomaly event."""
        try:
            # Create formatted anomaly data
            formatted_anomaly = {}
            
            if isinstance(anomaly, dict):
                formatted_anomaly = anomaly.copy()
            elif isinstance(anomaly, (float, int)):
                formatted_anomaly = {
                    'ip': 'System',
                    'score': float(anomaly),
                    'type': 'Anomaly Score'
                }
            else:
                formatted_anomaly = {
                    'ip': str(anomaly),
                    'score': 1.0,
                    'type': 'Unknown'
                }
            
            # Add anomaly to table
            if hasattr(self, 'anomaly_table'):
                self.anomaly_table.add_anomaly(formatted_anomaly)
            
            # Log the anomaly
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] ANOMALY DETECTED - "
            log_message += f"IP: {formatted_anomaly.get('ip', 'Unknown')}, "
            log_message += f"Type: {formatted_anomaly.get('type', 'Unknown')}, "
            log_message += f"Score: {formatted_anomaly.get('score', 0):.3f}"
            self.log_message(log_message)
            
            # Update threat data in map
            if hasattr(self, 'network_map'):
                self.network_map.update_threat_data(
                    formatted_anomaly.get('ip', 'Unknown'),
                    {
                        'threat_level': 'High' if formatted_anomaly.get('score', 0) > 0.7 else 'Medium',
                        'score': formatted_anomaly.get('score', 0)
                    }
                )
                
        except Exception as e:
            print(f"Error handling single anomaly: {str(e)}") 