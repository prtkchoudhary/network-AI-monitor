"""Shared constants used throughout the application."""

# UI Constants
GLOBAL_BG_COLOR = "#1a1f2c"  # Darker background
SIDEBAR_BG_COLOR = "#232b3a"  # Slightly lighter than global
BUTTON_COLORS = {
    "start": "#2ecc71",     # Emerald
    "stop": "#e74c3c",      # Red
    "reset": "#f39c12",     # Orange
    "block": "#9b59b6",     # Purple
    "settings": "#3498db"   # Blue
}

# Typography
FONT_FAMILY = "'Segoe UI', 'Roboto', sans-serif"
FONT_SIZES = {
    "title": "24px",
    "subtitle": "20px",
    "body": "14px",
    "small": "12px"
}

# Monitoring Constants
HISTORY_SIZE = 100
ANOMALY_THRESHOLD = 2
MONITORING_INTERVAL = 1000  # ms

# ML Model Parameters
ISOLATION_FOREST_CONTAMINATION = 0.01
SVM_NU = 0.01
LOF_NEIGHBORS = 30

# DDoS Detection Configuration
DETECTION_MODES = {
    "BASIC": "basic",      # Basic threshold-based detection
    "ML": "ml",           # Machine learning-based detection
    "HYBRID": "hybrid"    # Combined approach
}

BASELINE_WINDOW_SIZE = 3600  # 1 hour of data for baseline calculation
UPDATE_INTERVAL = 300        # Update baseline every 5 minutes
MIN_SAMPLES_FOR_ML = 100     # Minimum samples needed for ML detection

# Adaptive Thresholds (multipliers for standard deviation)
ADAPTIVE_THRESHOLD_CONFIG = {
    "BASELINE_MULTIPLIER": 2.5,     # Multiplier for standard deviation
    "MIN_THRESHOLD_BYTES": 500_000, # Minimum bytes/sec threshold (500KB/s)
    "MIN_THRESHOLD_PACKETS": 1000,  # Minimum packets/sec threshold
    "MIN_THRESHOLD_CONNS": 50,      # Minimum connections threshold
    "LEARNING_RATE": 0.1           # Rate at which baseline updates
}

# Logging Configuration
LOG_LEVELS = {
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40
}

# Table Columns
ANOMALY_TABLE_COLUMNS = ["#", "Timestamp", "Anomaly Details"]

# Graph Colors
GRAPH_COLORS = {
    "sent": "#e74c3c",      # Red
    "received": "#3498db",  # Blue
    "anomaly": "#f1c40f",   # Yellow
    "grid": "#2c3e50",      # Dark Blue
    "text": "#ecf0f1"       # Light Grey
}

# Layout Constants
SIDEBAR_WIDTH = 300
GRAPH_HEIGHT = 400
LOG_HEIGHT = 150
BUTTON_HEIGHT = 40
SPACING = 10
MARGIN = 15

# Map Configuration
MAP_UPDATE_INTERVAL = 30000  # Update map every 30 seconds
MAP_CONFIG = {
    "TILE_LAYER": "cartodbdark_matter",
    "ATTRIBUTION": "Map tiles by CartoDB",
    "HIGH_CONN_THRESHOLD": 100,
    "COLORS": {
        "normal": "#4a9eff",      # Bright blue
        "high_traffic": "#ffa500", # Orange
        "threat": "#ff2b2b",      # Bright red
        "home": "#00ff00",        # Bright green
        "connection": "#6b7280"    # Cool grey
    }
} 