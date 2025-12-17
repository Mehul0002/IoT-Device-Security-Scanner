# mqtt_checker.py - MQTT security checks for IoT Device Security Scanner
# This module handles MQTT broker security assessments

import paho.mqtt.client as mqtt
import time
import threading

class MQTTChecker:
    def __init__(self, timeout=5):
        """
        Initialize the MQTT checker with a timeout for connections.
        """
        self.timeout = timeout
        self.results = {}

    def on_connect(self, client, userdata, flags, rc):
        """
        Callback when the client connects to the MQTT broker.
        """
        if rc == 0:
            self.results['connection_success'] = True
            self.results['anonymous_access'] = True  # If connected without auth, anonymous is allowed
        else:
            self.results['connection_success'] = False
            self.results['anonymous_access'] = False

    def on_message(self, client, userdata, message):
        """
        Callback when a message is received (for subscription tests).
        """
        pass  # We don't need to process messages for security checks

    def check_mqtt_security(self, broker_ip, port=1883):
        """
        Perform security checks on an MQTT broker.
        Returns a dictionary with security assessment results.
        """
        self.results = {
            'broker_ip': broker_ip,
            'port': port,
            'connection_success': False,
            'anonymous_access': False,
            'default_topics_accessible': [],
            'vulnerabilities': []
        }

        # Create MQTT client
        client = mqtt.Client()
        client.on_connect = self.on_connect
        client.on_message = self.on_message

        try:
            # Attempt to connect without authentication
            client.connect(broker_ip, port, self.timeout)
            client.loop_start()
            time.sleep(2)  # Wait for connection

            if self.results['connection_success']:
                # Check access to default topics
                default_topics = ['#', 'test', 'home/#']
                for topic in default_topics:
                    try:
                        result, mid = client.subscribe(topic)
                        if result == 0:  # Subscription successful
                            self.results['default_topics_accessible'].append(topic)
                        time.sleep(0.5)  # Brief pause between subscriptions
                    except Exception as e:
                        print(f"Error subscribing to {topic}: {e}")

                # If anonymous access and default topics are accessible, flag as vulnerable
                if self.results['anonymous_access'] and self.results['default_topics_accessible']:
                    self.results['vulnerabilities'].append({
                        'type': 'Anonymous MQTT Access',
                        'description': 'MQTT broker allows anonymous connections and access to default topics',
                        'severity': 'Critical'
                    })

            client.loop_stop()
            client.disconnect()

        except Exception as e:
            print(f"Error connecting to MQTT broker {broker_ip}:{port}: {e}")
            self.results['vulnerabilities'].append({
                'type': 'Connection Error',
                'description': f'Unable to connect to MQTT broker: {str(e)}',
                'severity': 'Info'
            })

        return self.results

    def check_device_mqtt(self, device_ip):
        """
        Check MQTT security for a specific device IP.
        Assumes MQTT on default port 1883.
        """
        return self.check_mqtt_security(device_ip, 1883)

    def check_multiple_devices(self, device_ips, progress_callback=None):
        """
        Check MQTT security for multiple devices.
        Runs checks in parallel using threads.
        """
        results = {}
        threads = []

        def check_device(ip):
            results[ip] = self.check_device_mqtt(ip)
            if progress_callback:
                progress_callback()

        for ip in device_ips:
            thread = threading.Thread(target=check_device, args=(ip,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        return results
