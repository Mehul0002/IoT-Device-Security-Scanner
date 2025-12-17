# scanner.py - Network scanning logic for IoT Device Security Scanner
# This module handles device discovery and basic security checks using Nmap

import nmap
import socket
from utils import is_risky_port, get_service_name, simulate_firmware_check, check_default_passwords

class IoTScanner:
    def __init__(self):
        """
        Initialize the scanner with Nmap.
        """
        self.nm = nmap.PortScanner()

    def scan_network(self, network_range, progress_callback=None):
        """
        Scan the specified network range for devices.
        Returns a list of discovered devices with basic info.
        """
        devices = []
        try:
            # Perform a ping scan to discover hosts
            self.nm.scan(hosts=network_range, arguments='-sn')

            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    device = {
                        'ip': host,
                        'mac': self.nm[host]['addresses'].get('mac', 'Unknown'),
                        'hostname': self.nm[host].hostname() or 'Unknown',
                        'state': self.nm[host].state()
                    }
                    devices.append(device)

                    if progress_callback:
                        progress_callback(len(devices))

        except Exception as e:
            print(f"Error during network scan: {e}")

        return devices

    def scan_device_ports(self, device_ip, progress_callback=None):
        """
        Scan open ports on a specific device.
        Returns a list of open ports with service info.
        """
        ports = []
        try:
            # Scan common ports (you can adjust the range)
            self.nm.scan(device_ip, '1-1024', arguments='-T4 -A')

            if device_ip in self.nm.all_hosts():
                for proto in self.nm[device_ip].all_protocols():
                    lport = self.nm[device_ip][proto].keys()
                    for port in lport:
                        port_info = {
                            'port': port,
                            'protocol': proto,
                            'state': self.nm[device_ip][proto][port]['state'],
                            'service': self.nm[device_ip][proto][port].get('name', 'Unknown'),
                            'risky': is_risky_port(port)
                        }
                        ports.append(port_info)

        except Exception as e:
            print(f"Error scanning ports for {device_ip}: {e}")

        return ports

    def perform_security_checks(self, device_ip, ports):
        """
        Perform security checks on a device based on discovered ports and simulated checks.
        Returns a list of vulnerabilities found.
        """
        vulnerabilities = []

        # Check for outdated firmware (simulated)
        firmware_status = simulate_firmware_check(device_ip)
        if firmware_status == 'Outdated':
            vulnerabilities.append({
                'type': 'Outdated Firmware',
                'description': 'Device firmware appears to be outdated',
                'severity': 'Warning'
            })

        # Check for default passwords (simulated)
        if check_default_passwords(device_ip):
            vulnerabilities.append({
                'type': 'Weak/Default Password',
                'description': 'Device may be using default or weak credentials',
                'severity': 'Critical'
            })

        # Check for open risky ports
        risky_ports = [p for p in ports if p['risky'] and p['state'] == 'open']
        if risky_ports:
            for port in risky_ports:
                vulnerabilities.append({
                    'type': 'Open Risky Port',
                    'description': f"Port {port['port']} ({get_service_name(port['port'])}) is open",
                    'severity': 'Warning'
                })

        # Check for vulnerable services
        vulnerable_services = ['telnet', 'ftp', 'http']  # Simplified list
        for port in ports:
            if port['state'] == 'open' and port['service'].lower() in vulnerable_services:
                vulnerabilities.append({
                    'type': 'Vulnerable Service',
                    'description': f"Potentially insecure service '{port['service']}' running on port {port['port']}",
                    'severity': 'Critical'
                })

        return vulnerabilities

    def scan_device_comprehensive(self, device_ip, progress_callback=None):
        """
        Perform a comprehensive scan on a single device.
        Returns device info, ports, and vulnerabilities.
        """
        device_info = {
            'ip': device_ip,
            'mac': 'Unknown',  # Would need additional scan for MAC
            'hostname': 'Unknown',  # Would need additional scan for hostname
            'ports': [],
            'vulnerabilities': []
        }

        # Scan ports
        device_info['ports'] = self.scan_device_ports(device_ip, progress_callback)

        # Perform security checks
        device_info['vulnerabilities'] = self.perform_security_checks(device_ip, device_info['ports'])

        return device_info
