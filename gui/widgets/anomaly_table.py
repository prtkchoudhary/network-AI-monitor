from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt
import time
from datetime import datetime
from PyQt5.QtGui import QColor

class AnomalyTable(QTableWidget):
    """Custom table widget for displaying network anomalies."""
    
    def __init__(self):
        super().__init__()
        self.max_rows = 100  # Maximum number of rows to keep
        self.setup_table()
        self.row_count = 0

    def setup_table(self):
        """Initialize the table structure."""
        self.setColumnCount(3)
        self.setHorizontalHeaderLabels(["#", "Timestamp", "Anomaly Details"])
        
        # Style the table
        self.setStyleSheet("""
            QTableWidget {
                background-color: #2C3E50;
                color: #ECF0F1;
                gridline-color: #34495E;
                border-radius: 5px;
            }
            QHeaderView::section {
                background-color: #34495E;
                color: #ECF0F1;
                padding: 5px;
                border: none;
                font-weight: bold;
                font-size: 11px;
                text-transform: uppercase;
            }
            QTableWidget::item {
                padding: 5px;
                border: 1px solid #34495E;
            }
            QTableWidget::item:selected {
                background-color: #2980B9;
            }
        """)
        
        # Set column stretching
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)  # Index column
        header.setSectionResizeMode(1, QHeaderView.Fixed)  # Timestamp column
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Details column
        
        # Set column widths
        self.setColumnWidth(0, 50)  # Index column
        self.setColumnWidth(1, 180)  # Timestamp column
        
        # Hide vertical header
        self.verticalHeader().setVisible(False)
        
        # Set selection behavior
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)

    def add_anomaly(self, anomaly_data):
        """Add a new anomaly to the table."""
        try:
            # Create timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Format anomaly details based on type
            if isinstance(anomaly_data, dict):
                details = f"IP: {anomaly_data.get('ip', 'Unknown')} | "
                details += f"Score: {anomaly_data.get('score', 0.0):.3f} | "
                details += f"Type: {anomaly_data.get('type', 'Unknown')}"
            elif isinstance(anomaly_data, (float, int)):
                details = f"Anomaly Score: {float(anomaly_data):.3f}"
            else:
                details = str(anomaly_data)

            # Insert at the beginning of the table
            self.insertRow(0)
            
            # Add items
            self.setItem(0, 0, QTableWidgetItem(str(self.row_count + 1)))
            self.setItem(0, 1, QTableWidgetItem(timestamp))
            self.setItem(0, 2, QTableWidgetItem(details))
            
            # Update row count
            self.row_count += 1
            
            # Color code high scores
            if isinstance(anomaly_data, dict) and anomaly_data.get('score', 0) > 0.7:
                for col in range(self.columnCount()):
                    self.item(0, col).setBackground(QColor(255, 200, 200))
            
            # Trim table if it exceeds maximum rows
            while self.rowCount() > self.max_rows:
                self.removeRow(self.rowCount() - 1)
                
        except Exception as e:
            print(f"Error adding anomaly to table: {str(e)}")

    def reset(self):
        """Clear all entries from the table."""
        self.setRowCount(0)
        self.row_count = 0

    @staticmethod
    def format_bytes(size):
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
            return str(size) 