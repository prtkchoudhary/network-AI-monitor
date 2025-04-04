from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt
from datetime import datetime

class PortScanTable(QTableWidget):
    """Widget to display detected port scan attempts."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Initialize the table UI."""
        # Set columns
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels([
            'Source IP',
            'Unique Ports',
            'Common Ports Hit',
            'Last Seen'
        ])
        
        # Set table properties
        self.setShowGrid(True)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        
        # Style
        self.setStyleSheet("""
            QTableWidget {
                background-color: #2C3E50;
                color: #ECF0F1;
                gridline-color: #34495E;
                border: none;
                border-radius: 5px;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3498DB;
            }
            QHeaderView::section {
                background-color: #34495E;
                color: #ECF0F1;
                padding: 5px;
                border: none;
            }
        """)
    
    def update_scanner(self, ip: str, scanner_info: dict):
        """Update or add a scanner entry to the table."""
        # Check if IP already exists in table
        items = self.findItems(ip, Qt.MatchExactly)
        row = items[0].row() if items else -1
        
        # Format the timestamp
        last_seen = scanner_info['last_seen']
        if isinstance(last_seen, str):
            last_seen = datetime.fromisoformat(last_seen)
        timestamp = last_seen.strftime('%Y-%m-%d %H:%M:%S')
        
        if row == -1:
            # Add new row
            row = self.rowCount()
            self.insertRow(row)
        
        # Update row data
        self.setItem(row, 0, QTableWidgetItem(ip))
        self.setItem(row, 1, QTableWidgetItem(str(scanner_info['unique_ports'])))
        self.setItem(row, 2, QTableWidgetItem(str(scanner_info['common_ports_hit'])))
        self.setItem(row, 3, QTableWidgetItem(timestamp))
        
        # Ensure the new row is visible
        self.scrollToItem(self.item(row, 0))
    
    def remove_scanner(self, ip: str):
        """Remove a scanner entry from the table."""
        items = self.findItems(ip, Qt.MatchExactly)
        if items:
            self.removeRow(items[0].row())
