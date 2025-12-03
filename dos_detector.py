#!/usr/bin/env python3
"""
DoS Detection Tool - Network Traffic Pattern Monitor
Detects potential denial-of-service attacks by monitoring traffic patterns
"""

import time
import threading
import logging
import json
import yaml
from collections import defaultdict, deque
from datetime import datetime, timedelta
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
import psutil


class TrafficMonitor:
    """Monitor network traffic and collect statistics"""
    
    def __init__(self, config):
        self.config = config
        self.running = False
        self.capture_thread = None
        
        # Traffic statistics
        self.packet_counts = defaultdict(lambda: deque(maxlen=config['thresholds']['time_window']))
        self.traffic_volume = defaultdict(lambda: deque(maxlen=config['thresholds']['time_window']))
        self.connections = defaultdict(set)
        self.connection_rates = defaultdict(lambda: deque(maxlen=config['thresholds']['time_window']))
        
        # Timestamp tracking
        self.timestamps = defaultdict(deque)
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config['alerts']['log_file']),
                logging.StreamHandler() if self.config['alerts']['console_output'] else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def packet_handler(self, packet):
        """Handle captured packets and update statistics"""
        if not packet.haslayer(IP):
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = time.time()
        
        # Update packet counts
        self.packet_counts[src_ip].append(timestamp)
        self.timestamps[src_ip].append(timestamp)
        
        # Update traffic volume
        packet_size = len(packet)
        self.traffic_volume[src_ip].append((timestamp, packet_size))
        
        # Track connections for TCP packets
        if packet.haslayer(TCP):
            connection_key = f"{src_ip}:{packet[TCP].sport}->{dst_ip}:{packet[TCP].dport}"
            self.connections[src_ip].add(connection_key)
            self.connection_rates[src_ip].append(timestamp)
    
    def start_monitoring(self):
        """Start network traffic monitoring"""
        self.running = True
        interface = self.config['network']['interface']
        capture_filter = self.config['network']['capture_filter']
        
        self.logger.info(f"Starting traffic monitoring on interface: {interface}")
        
        def capture_packets():
            try:
                sniff(iface=interface, prn=self.packet_handler, 
                      filter=capture_filter, stop_filter=lambda x: not self.running)
            except Exception as e:
                self.logger.error(f"Packet capture error: {e}")
        
        self.capture_thread = threading.Thread(target=capture_packets, daemon=True)
        self.capture_thread.start()
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        self.logger.info("Traffic monitoring stopped")


class DoSDetector:
    """Main DoS detection engine"""
    
    def __init__(self, config_file='config.yaml'):
        self.config = self.load_config(config_file)
        self.monitor = TrafficMonitor(self.config)
        self.alerts = defaultdict(lambda: {'last_alert': 0, 'count': 0})
        
        # Statistical baselines
        self.baseline_pps = 0
        self.baseline_bps = 0
        self.baseline_connections = 0
        self.baseline_established = False
        
    def load_config(self, config_file):
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            'network': {'interface': 'any', 'capture_filter': 'ip'},
            'thresholds': {
                'max_pps_per_ip': 1000, 'max_pps_total': 10000,
                'max_connections_per_ip': 100, 'max_connection_rate': 50,
                'max_bps_per_ip': 1048576, 'max_bps_total': 10485760,
                'time_window': 10, 'detection_window': 60
            },
            'alerts': {'log_file': 'dos_alerts.log', 'console_output': True, 'alert_cooldown': 300},
            'patterns': {'enable_statistical_analysis': True, 'enable_behavioral_analysis': True, 'anomaly_threshold': 2.0}
        }
    
    def calculate_rates(self, ip_address):
        """Calculate traffic rates for a specific IP"""
        current_time = time.time()
        time_window = self.config['thresholds']['time_window']
        
        # Packets per second
        packets = [t for t in self.monitor.timestamps[ip_address] if current_time - t <= time_window]
        pps = len(packets) / time_window if time_window > 0 else 0
        
        # Bytes per second
        traffic = [(t, size) for t, size in self.monitor.traffic_volume[ip_address] 
                  if current_time - t <= time_window]
        bps = sum(size for t, size in traffic) / time_window if time_window > 0 else 0
        
        # Connection rate
        connections = [t for t in self.monitor.connection_rates[ip_address] 
                      if current_time - t <= time_window]
        connection_rate = len(connections) / time_window if time_window > 0 else 0
        
        # Active connections
        active_connections = len(self.monitor.connections[ip_address])
        
        return pps, bps, connection_rate, active_connections
    
    def detect_anomalies(self, ip_address, pps, bps, connection_rate, active_connections):
        """Detect traffic anomalies for a specific IP"""
        alerts = []
        thresholds = self.config['thresholds']
        
        # Check packet rate threshold
        if pps > thresholds['max_pps_per_ip']:
            alerts.append(f"High packet rate: {pps:.2f} pps (threshold: {thresholds['max_pps_per_ip']})")
        
        # Check traffic volume threshold
        if bps > thresholds['max_bps_per_ip']:
            alerts.append(f"High traffic volume: {bps:.2f} B/s (threshold: {thresholds['max_bps_per_ip']})")
        
        # Check connection rate threshold
        if connection_rate > thresholds['max_connection_rate']:
            alerts.append(f"High connection rate: {connection_rate:.2f} conn/s (threshold: {thresholds['max_connection_rate']})")
        
        # Check connection count threshold
        if active_connections > thresholds['max_connections_per_ip']:
            alerts.append(f"High connection count: {active_connections} (threshold: {thresholds['max_connections_per_ip']})")
        
        # Statistical anomaly detection
        if self.config['patterns']['enable_statistical_analysis'] and self.baseline_established:
            if self.detect_statistical_anomaly(ip_address, pps, bps, connection_rate):
                alerts.append("Statistical anomaly detected")
        
        return alerts
    
    def detect_statistical_anomaly(self, ip_address, pps, bps, connection_rate):
        """Detect statistical anomalies using baseline comparison"""
        anomaly_threshold = self.config['patterns']['anomaly_threshold']
        
        # Calculate z-scores
        pps_z = (pps - self.baseline_pps) / (self.baseline_pps * 0.1) if self.baseline_pps > 0 else 0
        bps_z = (bps - self.baseline_bps) / (self.baseline_bps * 0.1) if self.baseline_bps > 0 else 0
        conn_z = (connection_rate - self.baseline_connections) / (self.baseline_connections * 0.1) if self.baseline_connections > 0 else 0
        
        return any(abs(z) > anomaly_threshold for z in [pps_z, bps_z, conn_z])
    
    def establish_baseline(self):
        """Establish baseline traffic patterns"""
        self.monitor.logger.info("Establishing traffic baseline...")
        time.sleep(30)  # Collect baseline data for 30 seconds
        
        # Calculate baseline averages
        total_pps = 0
        total_bps = 0
        total_connections = 0
        ip_count = len(self.monitor.timestamps)
        
        if ip_count > 0:
            for ip in self.monitor.timestamps:
                pps, bps, conn_rate, _ = self.calculate_rates(ip)
                total_pps += pps
                total_bps += bps
                total_connections += conn_rate
            
            self.baseline_pps = total_pps / ip_count
            self.baseline_bps = total_bps / ip_count
            self.baseline_connections = total_connections / ip_count
            self.baseline_established = True
            
            self.monitor.logger.info(f"Baseline established - PPS: {self.baseline_pps:.2f}, BPS: {self.baseline_bps:.2f}, Connections: {self.baseline_connections:.2f}")
    
    def send_alert(self, ip_address, alerts):
        """Send security alert"""
        current_time = time.time()
        alert_cooldown = self.config['alerts']['alert_cooldown']
        
        # Check cooldown period
        if current_time - self.alerts[ip_address]['last_alert'] < alert_cooldown:
            self.alerts[ip_address]['count'] += 1
            return
        
        # Log alert
        alert_msg = f"DoS ALERT - IP: {ip_address} | {' | '.join(alerts)}"
        self.monitor.logger.warning(alert_msg)
        
        # Update alert tracking
        self.alerts[ip_address]['last_alert'] = current_time
        self.alerts[ip_address]['count'] = 1
    
    def run_detection(self):
        """Main detection loop"""
        self.monitor.start_monitoring()
        
        try:
            # Establish baseline after initial monitoring period
            baseline_thread = threading.Thread(target=self.establish_baseline, daemon=True)
            baseline_thread.start()
            
            self.monitor.logger.info("DoS detection engine started")
            
            while True:
                time.sleep(5)  # Check every 5 seconds
                
                current_time = time.time()
                suspicious_ips = []
                
                # Monitor all active IPs
                for ip_address in list(self.monitor.timestamps.keys()):
                    pps, bps, connection_rate, active_connections = self.calculate_rates(ip_address)
                    
                    # Clean up old connections
                    self.monitor.connections[ip_address] = {
                        conn for conn in self.monitor.connections[ip_address] 
                        if current_time - self.monitor.timestamps[ip_address][-1] <= 60
                    }
                    
                    # Detect anomalies
                    alerts = self.detect_anomalies(ip_address, pps, bps, connection_rate, active_connections)
                    
                    if alerts:
                        suspicious_ips.append((ip_address, alerts))
                        self.send_alert(ip_address, alerts)
                
                # Log summary if suspicious activity detected
                if suspicious_ips:
                    self.monitor.logger.info(f"Detected suspicious activity from {len(suspicious_ips)} IP addresses")
                
        except KeyboardInterrupt:
            self.monitor.logger.info("Shutting down DoS detection...")
        finally:
            self.monitor.stop_monitoring()


def main():
    """Main entry point"""
    print("DoS Detection Tool - Network Traffic Pattern Monitor")
    print("=" * 50)
    
    try:
        detector = DoSDetector()
        detector.run_detection()
    except Exception as e:
        print(f"Error: {e}")
        logging.error(f"Application error: {e}")


if __name__ == "__main__":
    main()
