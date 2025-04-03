from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import Qt, QUrl, QTimer
import folium
from folium.plugins import MarkerCluster
import requests
from typing import Dict, Tuple, Optional
import os
import tempfile
from datetime import datetime
import time
from utils.constants import MAP_CONFIG
import json
from utils.signal_relay import SignalRelay

class NetworkMap(QWidget):
    def __init__(self, signal_relay: SignalRelay):
        super().__init__()
        self.signal_relay = signal_relay
        
        # Initialize attributes
        self.home_location = None
        self.map = None
        self.current_map_file = None
        self.connections = {}
        self.threat_data = {}
        self.request_queue = []
        self.marker_cluster = None
        
        # Setup UI components
        self.setup_ui()
        
        # Initialize state
        self.last_update = 0
        self.update_interval = 30  # Update every 30 seconds
        self.connection_data = {}
        self.geo_cache = {}
        self.last_geo_request = 0
        self.geo_rate_limit = 1.0  # One request per second
        
        # Load cached data
        self.load_geo_cache()
        
        # Get home location
        self.get_home_location()
        
        # Create initial map
        self.create_map()
        
        # Connect signals
        self.signal_relay.data_signal.connect(self.update_connection_data)
        self.signal_relay.alert_signal.connect(self.handle_alert)
        
    def setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Control panel
        control_panel = QHBoxLayout()
        
        # View type selector
        self.view_selector = QComboBox()
        self.view_selector.addItems(["All Connections", "Threats Only"])
        self.view_selector.currentTextChanged.connect(self.refresh_map)
        
        # Refresh button
        self.refresh_btn = QPushButton("Refresh Map")
        self.refresh_btn.clicked.connect(self.refresh_map)
        
        # Add controls to panel
        control_panel.addWidget(self.view_selector)
        control_panel.addWidget(self.refresh_btn)
        control_panel.addStretch()
        
        # Map view
        self.web_view = QWebEngineView()
        self.web_view.setMinimumHeight(400)
        
        # Add everything to main layout
        layout.addLayout(control_panel)
        layout.addWidget(self.web_view)
        
    def get_home_location(self):
        """Get the home network location."""
        if self.home_location:
            return self.home_location
            
        try:
            # First try to load from cache
            if os.path.exists('home_location.json'):
                with open('home_location.json', 'r') as f:
                    data = json.load(f)
                    if 'lat' in data and 'lon' in data:
                        self.home_location = (data['lat'], data['lon'])
                        return self.home_location
            
            # If not in cache, get from API
            response = requests.get('https://ipapi.co/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                lat = data.get('latitude')
                lon = data.get('longitude')
                if lat is not None and lon is not None:
                    self.home_location = (float(lat), float(lon))
                    # Cache the location
                    with open('home_location.json', 'w') as f:
                        json.dump({'lat': lat, 'lon': lon}, f)
                    return self.home_location
        except Exception as e:
            print(f"Error getting home location: {str(e)}")
        
        # Default to a central location if home location cannot be determined
        self.home_location = (20, 0)  # More central default location
        return self.home_location
        
    def load_geo_cache(self):
        """Load cached IP locations from file."""
        try:
            if os.path.exists('ip_locations.json'):
                with open('ip_locations.json', 'r') as f:
                    self.geo_cache = json.load(f)
        except Exception as e:
            print(f"Error loading geo cache: {str(e)}")
            
    def save_geo_cache(self):
        """Save IP locations cache to file."""
        try:
            with open('ip_locations.json', 'w') as f:
                json.dump(self.geo_cache, f)
        except Exception as e:
            print(f"Error saving geo cache: {str(e)}")
            
    def process_geo_queue(self):
        """Process queued geolocation requests."""
        if not self.request_queue:
            return
            
        current_time = time.time()
        if current_time - self.last_geolocation_request < 1.0:
            return
            
        ip = self.request_queue.pop(0)
        location = self._fetch_ip_location(ip)
        if location:
            self.geo_cache[ip] = location
            self.save_geo_cache()
            self.refresh_map()
            
    def _fetch_ip_location(self, ip: str) -> Optional[Tuple[float, float]]:
        """Internal method to fetch IP location from API."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            self.last_geolocation_request = time.time()
            
            if response.status_code == 200:
                data = response.json()
                lat = data.get('latitude')
                lon = data.get('longitude')
                if lat is not None and lon is not None:
                    return (float(lat), float(lon))
        except Exception as e:
            print(f"Error getting location for IP {ip}: {str(e)}")
        return None
        
    def get_ip_location(self, ip: str) -> Optional[Tuple[float, float]]:
        """Get location for an IP address with caching and rate limiting."""
        # Return cached location if available
        if ip in self.geo_cache:
            return self.geo_cache[ip]
            
        # Skip private IPs
        if ip.startswith(('10.', '172.', '192.168.', '127.')):
            return None
            
        # Queue the request if not already queued
        if ip not in self.request_queue:
            self.request_queue.append(ip)
            
        return None
        
    def create_map(self):
        """Create the base map."""
        if not self.map:
            # Create map centered on home location
            self.map = folium.Map(
                location=self.home_location,
                zoom_start=3,
                tiles=MAP_CONFIG['TILE_LAYER'],
                attr=MAP_CONFIG['ATTRIBUTION']
            )
            
            # Add marker cluster
            self.marker_cluster = MarkerCluster().add_to(self.map)
            
            # Add home marker
            folium.CircleMarker(
                location=self.home_location,
                radius=8,
                color=MAP_CONFIG['COLORS']['home'],
                fill=True,
                popup='Home Network'
            ).add_to(self.map)
        
    def draw_connection(self, target_location, is_threat=False):
        """Draw a connection line from home to target."""
        if not self.map:
            return
            
        # Style based on threat status
        color = MAP_CONFIG['COLORS']['threat'] if is_threat else MAP_CONFIG['COLORS']['normal']
        weight = 3 if is_threat else 2
        
        # Draw line
        folium.PolyLine(
            [self.home_location, target_location],
            color=color,
            weight=weight,
            opacity=0.8
        ).add_to(self.map)
        
    def refresh_map(self):
        """Refresh the map with current connections."""
        current_time = time.time()
        if current_time - self.last_update < 30:  # Only update every 30 seconds
            return
            
        self.last_update = current_time
        
        # Create new map
        self.map = None
        self.create_map()
        
        # Add connections
        threats_only = self.view_selector.currentText() == "Threats Only"
        
        for ip, conn_data in self.connections.items():
            # Skip if we're only showing threats and this isn't one
            if threats_only and ip not in self.threat_data:
                continue
                
            location = self.get_ip_location(ip)
            if location:
                # Add connection marker
                color = MAP_CONFIG['COLORS']['threat'] if ip in self.threat_data else MAP_CONFIG['COLORS']['normal']
                popup_html = f"""
                    <div style='font-family: Arial, sans-serif; min-width: 200px;'>
                        <h4 style='margin: 0; color: #ecf0f1;'>Connection Details</h4>
                        <hr style='margin: 5px 0;'>
                        <p><b>IP:</b> {ip}</p>
                        <p><b>Connections:</b> {conn_data.get('count', 0)}</p>
                        <p><b>First Seen:</b> {conn_data.get('first_seen', 'Unknown')}</p>
                        <p><b>Last Seen:</b> {conn_data.get('last_seen', 'Unknown')}</p>
                        {'<p style="color: red;"><b>⚠️ Threat Detected</b></p>' if ip in self.threat_data else ''}
                    </div>
                """
                
                # Add marker to cluster
                folium.CircleMarker(
                    location=location,
                    radius=6,
                    color=color,
                    fill=True,
                    popup=popup_html,
                    tooltip=f"IP: {ip}"
                ).add_to(self.marker_cluster)
                
                # Draw connection line
                self.draw_connection(location, is_threat=ip in self.threat_data)
        
        # Save and display
        self.save_and_display()
        
    def update_connection_data(self, data):
        """Update connection data and refresh map if needed."""
        if isinstance(data, dict):
            for ip, conn_info in data.items():
                self.connections[ip] = conn_info
            self.refresh_map()
            
    def handle_alert(self, message):
        """Handle alert messages."""
        # Currently just refreshes the map when an alert is received
        self.refresh_map()
        
    def save_and_display(self):
        """Save the map to a temporary file and display it."""
        try:
            # Clean up old file
            if self.current_map_file and os.path.exists(self.current_map_file):
                try:
                    os.remove(self.current_map_file)
                except:
                    pass
            
            # Create new temporary file
            fd, path = tempfile.mkstemp(suffix='.html')
            os.close(fd)
            
            # Save map
            self.map.save(path)
            self.current_map_file = path
            
            # Load in web view
            self.web_view.setUrl(QUrl.fromLocalFile(path))
            
        except Exception as e:
            print(f"Error saving/displaying map: {str(e)}")
            
    def add_connection(self, ip: str, connection_data: dict):
        """Add or update a connection."""
        self.connections[ip] = connection_data
        self.refresh_map()
        
    def update_threat_data(self, ip: str, threat_data: dict):
        """Update threat data for an IP."""
        self.threat_data[ip] = threat_data
        self.refresh_map()
        
    def clear_data(self):
        """Clear all data and refresh map."""
        self.connections.clear()
        self.threat_data.clear()
        self.map = None
        self.create_map()
        
    def closeEvent(self, event):
        """Clean up temporary files on close."""
        if self.current_map_file and os.path.exists(self.current_map_file):
            try:
                os.remove(self.current_map_file)
            except:
                pass
        super().closeEvent(event) 