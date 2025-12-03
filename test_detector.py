#!/usr/bin/env python3
"""
Test script for DoS Detection Tool
Simulates various attack patterns to test detection capabilities
"""

import time
import threading
import random
from collections import defaultdict
import yaml
from dos_detector import DoSDetector, TrafficMonitor


class TrafficSimulator:
    """Simulate various traffic patterns for testing"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.running = False
        
    def simulate_normal_traffic(self, duration=60):
        """Simulate normal network traffic"""
        print(f"Simulating normal traffic for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Simulate packets from multiple IPs with normal rates
            for ip in [f"192.168.1.{i}" for i in range(10, 20)]:
                # Normal packet rate (10-50 pps)
                packets = random.randint(10, 50)
                for _ in range(packets):
                    self._simulate_packet(ip, random.randint(64, 1500))
                
            time.sleep(1)
    
    def simulate_syn_flood(self, target_ip="192.168.1.100", duration=30):
        """Simulate SYN flood attack"""
        print(f"Simulating SYN flood attack for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # High packet rate from single IP
            for _ in range(2000):  # 2000 pps
                self._simulate_packet("10.0.0.100", 64, syn=True)
            
            time.sleep(1)
    
    def simulate_udp_flood(self, target_ip="192.168.1.100", duration=30):
        """Simulate UDP flood attack"""
        print(f"Simulating UDP flood attack for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # High volume UDP packets
            for _ in range(1000):  # 1000 pps
                self._simulate_packet("10.0.0.101", 1400, udp=True)
            
            time.sleep(1)
    
    def simulate_connection_exhaustion(self, target_ip="192.168.1.100", duration=30):
        """Simulate connection exhaustion attack"""
        print(f"Simulating connection exhaustion attack for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Many connections from single IP
            for port in range(1000, 2000):
                self._simulate_connection("10.0.0.102", target_ip, port)
            
            time.sleep(1)
    
    def simulate_slowloris(self, target_ip="192.168.1.100", duration=30):
        """Simulate slowloris attack"""
        print(f"Simulating slowloris attack for {duration} seconds...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Slow, incomplete connections
            for _ in range(100):
                self._simulate_connection("10.0.0.103", target_ip, 80, incomplete=True)
            
            time.sleep(5)
    
    def _simulate_packet(self, src_ip, size, syn=False, udp=False):
        """Simulate a single packet"""
        timestamp = time.time()
        
        # Update packet counts
        self.monitor.packet_counts[src_ip].append(timestamp)
        self.monitor.timestamps[src_ip].append(timestamp)
        
        # Update traffic volume
        self.monitor.traffic_volume[src_ip].append((timestamp, size))
        
        # Simulate connections for TCP
        if not udp:
            connection_key = f"{src_ip}:80->192.168.1.100:80"
            self.monitor.connections[src_ip].add(connection_key)
            if syn:
                self.monitor.connection_rates[src_ip].append(timestamp)
    
    def _simulate_connection(self, src_ip, dst_ip, port, incomplete=False):
        """Simulate a connection"""
        timestamp = time.time()
        connection_key = f"{src_ip}:{port}->{dst_ip}:{port}"
        
        self.monitor.connections[src_ip].add(connection_key)
        self.monitor.connection_rates[src_ip].append(timestamp)
        
        if not incomplete:
            # Complete connection
            self.monitor.packet_counts[src_ip].append(timestamp)
            self.monitor.timestamps[src_ip].append(timestamp)
            self.monitor.traffic_volume[src_ip].append((timestamp, 64))


def run_tests():
    """Run comprehensive tests"""
    print("DoS Detection Tool - Test Suite")
    print("=" * 40)
    
    # Create test configuration
    test_config = {
        'network': {'interface': 'any', 'capture_filter': 'ip'},
        'thresholds': {
            'max_pps_per_ip': 500,  # Lower threshold for testing
            'max_pps_total': 5000,
            'max_connections_per_ip': 50,
            'max_connection_rate': 25,
            'max_bps_per_ip': 500000,
            'max_bps_total': 5000000,
            'time_window': 5,  # Shorter window for faster testing
            'detection_window': 30
        },
        'alerts': {'log_file': 'test_alerts.log', 'console_output': True, 'alert_cooldown': 10},
        'patterns': {'enable_statistical_analysis': True, 'enable_behavioral_analysis': True, 'anomaly_threshold': 1.5}
    }
    
    # Initialize detector with test config
    detector = DoSDetector()
    detector.config = test_config
    detector.monitor = TrafficMonitor(test_config)
    
    # Create simulator
    simulator = TrafficSimulator(detector.monitor)
    
    print("\n1. Testing normal traffic patterns...")
    simulator.simulate_normal_traffic(10)
    
    print("\n2. Testing SYN flood detection...")
    simulator.simulate_syn_flood(duration=10)
    
    print("\n3. Testing UDP flood detection...")
    simulator.simulate_udp_flood(duration=10)
    
    print("\n4. Testing connection exhaustion detection...")
    simulator.simulate_connection_exhaustion(duration=10)
    
    print("\n5. Testing slowloris detection...")
    simulator.simulate_slowloris(duration=10)
    
    print("\nTest suite completed!")
    print(f"Check 'test_alerts.log' for detection results")


def benchmark_detector():
    """Benchmark detector performance"""
    print("DoS Detection Tool - Performance Benchmark")
    print("=" * 45)
    
    detector = DoSDetector()
    simulator = TrafficSimulator(detector.monitor)
    
    # Test with increasing load
    loads = [100, 500, 1000, 2000, 5000]
    
    for load in loads:
        print(f"\nTesting with {load} packets per second...")
        
        start_time = time.time()
        
        # Simulate traffic
        for _ in range(load):
            simulator._simulate_packet(f"192.168.1.{random.randint(1, 255)}", random.randint(64, 1500))
        
        # Run detection
        for ip in list(detector.monitor.timestamps.keys())[:10]:  # Test first 10 IPs
            detector.calculate_rates(ip)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"Processing time: {processing_time:.4f} seconds")
        print(f"Throughput: {load/processing_time:.2f} packets/second")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "benchmark":
        benchmark_detector()
    else:
        run_tests()
