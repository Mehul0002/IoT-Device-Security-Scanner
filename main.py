# main.py - Main GUI application for IoT Device Security Scanner
# This module contains the Tkinter-based GUI and orchestrates the scanning process

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from scanner import IoTScanner
from mqtt_checker import MQTTChecker
from utils import get_local_ip, get_network_range, get_security_status, get_status_color, format_vulnerabilities

class IoTScannerGUI:
    def __init__(self, root):
        """
        Initialize the GUI application.
        """
        self.root = root
        self.root.title("IoT Device Security Scanner")
        self.root.geometry("900x700")

        # Initialize scanner components
        self.scanner = IoTScanner()
        self.mqtt_checker = MQTTChecker()

        # Variables for GUI elements
        self.network_range_var = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.devices = []
        self.scan_results = {}

        # Set default network range
        local_ip = get_local_ip()
        default_range = get_network_range(local_ip)
        self.network_range_var.set(default_range)

        self.setup_gui()

    def setup_gui(self):
        """
        Set up the GUI components.
        """
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Network range input
        ttk.Label(main_frame, text="Network Range:").grid(row=0, column=0, sticky=tk.W, pady=5)
        network_entry = ttk.Entry(main_frame, textvariable=self.network_range_var, width=30)
        network_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)

        # Scan button
        self.scan_button = ttk.Button(main_frame, text="Scan Network", command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=10, pady=5)

        # Progress bar
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)

        # Results treeview
        columns = ('IP', 'MAC', 'Hostname', 'Status', 'Vulnerabilities')
        self.results_tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=15)
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=150)

        # Add scrollbar to treeview
        tree_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=tree_scrollbar.set)
        self.results_tree.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        tree_scrollbar.grid(row=2, column=2, sticky=(tk.N, tk.S))

        # Details panel
        details_frame = ttk.LabelFrame(main_frame, text="Device Details", padding="10")
        details_frame.grid(row=2, column=3, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))

        self.details_text = scrolledtext.ScrolledText(details_frame, width=40, height=15)
        self.details_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Bind treeview selection event
        self.results_tree.bind('<<TreeviewSelect>>', self.on_device_select)

        # Configure grid weights for resizing
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)

    def start_scan(self):
        """
        Start the network scanning process in a separate thread.
        """
        network_range = self.network_range_var.get()
        if not network_range:
            messagebox.showerror("Error", "Please enter a network range.")
            return

        # Disable scan button and reset progress
        self.scan_button.config(state='disabled')
        self.progress_var.set(0)
        self.results_tree.delete(*self.results_tree.get_children())
        self.details_text.delete('1.0', tk.END)

        # Start scanning in a thread
        scan_thread = threading.Thread(target=self.perform_scan, args=(network_range,))
        scan_thread.start()

    def perform_scan(self, network_range):
        """
        Perform the actual scanning process.
        """
        try:
            # Step 1: Discover devices
            self.devices = self.scanner.scan_network(network_range, self.update_progress)

            # Step 2: Scan each device for vulnerabilities
            total_devices = len(self.devices)
            for i, device in enumerate(self.devices):
                device_ip = device['ip']

                # Perform comprehensive scan
                device_results = self.scanner.scan_device_comprehensive(device_ip)

                # Check MQTT security
                mqtt_results = self.mqtt_checker.check_device_mqtt(device_ip)

                # Combine results
                combined_vulns = device_results['vulnerabilities'] + mqtt_results.get('vulnerabilities', [])
                status = get_security_status(combined_vulns)

                # Store results
                self.scan_results[device_ip] = {
                    'device': device,
                    'ports': device_results['ports'],
                    'vulnerabilities': combined_vulns,
                    'mqtt': mqtt_results,
                    'status': status
                }

                # Update GUI
                self.root.after(0, self.add_device_to_tree, device, status, combined_vulns)
                self.update_progress((i + 1) / total_devices * 100)

            # Final progress update
            self.update_progress(100)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"An error occurred during scanning: {str(e)}"))

        finally:
            # Re-enable scan button
            self.root.after(0, lambda: self.scan_button.config(state='normal'))

    def update_progress(self, value):
        """
        Update the progress bar.
        """
        self.root.after(0, lambda: self.progress_var.set(value))

    def add_device_to_tree(self, device, status, vulnerabilities):
        """
        Add a device to the results treeview.
        """
        vuln_count = len(vulnerabilities)
        self.results_tree.insert('', 'end', values=(
            device['ip'],
            device['mac'],
            device['hostname'],
            status,
            f"{vuln_count} vulnerabilities"
        ), tags=(status,))

        # Configure tag colors
        self.results_tree.tag_configure('Safe', background='#E8F5E8')
        self.results_tree.tag_configure('Warning', background='#FFF9C4')
        self.results_tree.tag_configure('Critical', background='#FFCDD2')

    def on_device_select(self, event):
        """
        Handle device selection in the treeview.
        """
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            device_ip = item['values'][0]

            if device_ip in self.scan_results:
                results = self.scan_results[device_ip]
                self.display_device_details(results)

    def display_device_details(self, results):
        """
        Display detailed information about the selected device.
        """
        self.details_text.delete('1.0', tk.END)

        device = results['device']
        status = results['status']
        vulnerabilities = results['vulnerabilities']
        ports = results['ports']
        mqtt = results['mqtt']

        details = f"Device IP: {device['ip']}\n"
        details += f"MAC Address: {device['mac']}\n"
        details += f"Hostname: {device['hostname']}\n"
        details += f"Security Status: {status}\n\n"

        details += "Open Ports:\n"
        for port in ports:
            if port['state'] == 'open':
                details += f"  - Port {port['port']} ({port['protocol']}): {port['service']}"
                if port['risky']:
                    details += " [RISKY]"
                details += "\n"

        details += "\nMQTT Security:\n"
        if mqtt['connection_success']:
            details += "  - Connection: Successful\n"
            details += f"  - Anonymous Access: {'Allowed' if mqtt['anonymous_access'] else 'Not Allowed'}\n"
            if mqtt['default_topics_accessible']:
                details += f"  - Accessible Topics: {', '.join(mqtt['default_topics_accessible'])}\n"
        else:
            details += "  - Connection: Failed\n"

        details += "\nVulnerabilities:\n"
        if vulnerabilities:
            for vuln in vulnerabilities:
                details += f"  - {vuln['type']} ({vuln['severity']}): {vuln['description']}\n"
        else:
            details += "  - No vulnerabilities detected\n"

        self.details_text.insert('1.0', details)

def main():
    """
    Main function to run the application.
    """
    root = tk.Tk()
    app = IoTScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
