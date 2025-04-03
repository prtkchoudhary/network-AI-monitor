import ipaddress
import socket
import subprocess
import sys
from typing import Optional

class IPAnalyzer:
    """Handles IP address analysis and blocking functionality."""
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if an IP address is private."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or 
                ip_obj.is_loopback or 
                ip_obj.is_reserved or 
                ip_obj.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def geolocate_ip(ip: str) -> str:
        """Basic IP geolocation (placeholder)."""
        try:
            hostname = socket.gethostbyaddr(ip)
            return hostname[0]
        except (socket.herror, socket.gaierror):
            return "Unknown"

    @staticmethod
    def get_ip_reputation(ip: str) -> bool:
        """Basic IP reputation check (mock implementation)."""
        suspicious_patterns = [
            'bot', 'crawler', 'spam', 'malware', 'attack', 'hack'
        ]
        
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            return any(pattern in hostname for pattern in suspicious_patterns)
        except (socket.herror, socket.gaierror):
            return False

    @staticmethod
    def block_ip(ip: str) -> Optional[str]:
        """Block an IP using system firewall."""
        try:
            if sys.platform.startswith('linux'):
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            elif sys.platform == 'darwin':  # macOS
                subprocess.run(['sudo', 'pfctl', '-t', 'blocked', '-T', 'add', ip], check=True)
            elif sys.platform == 'win32':  # Windows
                subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 
                              f'name=Block {ip}', 'dir=in', 
                              f'action=block', f'remoteip={ip}'], check=True)
            return None
        except subprocess.CalledProcessError as e:
            return f"Error blocking IP {ip}: {e}" 