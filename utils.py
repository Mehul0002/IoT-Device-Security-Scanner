# utils.py - Helper functions for the IoT Device Security Scanner
# This module contains utility functions used across the application

import socket
import ipaddress
import random

def get_local_ip():
    """
    Get the local IP address of the machine.
    This is used to determine the network range for scanning.
    """
    try:
        # Create a socket to connect to an external server to get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Google's DNS server
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error getting local IP: {e}")
        return "127.0.0.1"  # Fallback to localhost

def get_network_range(ip):
    """
    Given an IP address, return the network range (e.g., 192.168.1.0/24).
    Assumes a /24 subnet for simplicity.
    """
    try:
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(network)
    except Exception as e:
        print(f"Error calculating network range: {e}")
        return "192.168.1.0/24"  # Default fallback

def simulate_firmware_check(device_ip):
    """
    Simulate a firmware version check.
    In a real scenario, this would query the device or use known databases.
    Returns: 'Up-to-date', 'Outdated', or 'Unknown'
    """
    # Simulate based on IP (for demo purposes)
    if int(device_ip.split('.')[-1]) % 3 == 0:
        return 'Outdated'
    elif int(device_ip.split('.')[-1]) % 3 == 1:
        return 'Up-to-date'
    else:
        return 'Unknown'

def check_default_passwords(device_ip):
    """
    Simulate checking for default passwords.
    In a real scenario, this would attempt login with common defaults (ethically).
    Returns: True if vulnerable (default password found), False otherwise.
    """
    # Simulate vulnerability based on IP
    return int(device_ip.split('.')[-1]) % 5 == 0  # Every 5th IP is vulnerable

def is_risky_port(port):
    """
    Check if a port is considered risky.
    Risky ports: 21 (FTP), 23 (Telnet), 80 (HTTP), 443 (HTTPS), 1883 (MQTT), 8883 (MQTT SSL)
    """
    risky_ports = [21, 23, 80, 443, 1883, 8883]
    return port in risky_ports

def get_service_name(port):
    """
    Get a service name based on port number.
    This is a simplified mapping; in reality, use nmap or similar.
    """
    port_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        80: 'HTTP',
        443: 'HTTPS',
        1883: 'MQTT',
        8883: 'MQTT SSL'
    }
    return port_services.get(port, 'Unknown')

def get_security_status(vulnerabilities):
    """
    Determine overall security status based on vulnerabilities found.
    Returns: 'Safe', 'Warning', 'Critical'
    """
    if not vulnerabilities:
        return 'Safe'
    elif any(v['severity'] == 'Critical' for v in vulnerabilities):
        return 'Critical'
    else:
        return 'Warning'

def get_status_color(status):
    """
    Get color code for security status.
    Returns hex color codes for GUI display.
    """
    colors = {
        'Safe': '#00FF00',      # Green
        'Warning': '#FFFF00',   # Yellow
        'Critical': '#FF0000'   # Red
    }
    return colors.get(status, '#FFFFFF')  # White for unknown

def format_vulnerabilities(vulns):
    """
    Format vulnerabilities list for display.
    Returns a string summary.
    """
    if not vulns:
        return "No vulnerabilities detected"
    return "\n".join([f"- {v['type']}: {v['description']}" for v in vulns])
