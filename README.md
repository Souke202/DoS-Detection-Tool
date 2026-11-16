# DoS Detection Tool

A network traffic pattern monitoring tool designed to detect potential denial-of-service (DoS) attacks by analyzing network traffic patterns and identifying suspicious behavior.

## Features

- **Real-time Traffic Monitoring**: Captures and analyzes network packets using Scapy
- **Pattern Analysis**: Detects anomalies in traffic patterns using statistical analysis
- **Configurable Thresholds**: Customizable detection thresholds for different attack vectors
- **Alert System**: Automated alerting with cooldown periods to prevent alert fatigue
- **Baseline Establishment**: Learns normal traffic patterns for better anomaly detection
- **Multi-protocol Support**: Monitors TCP, UDP, and ICMP traffic
- **Logging**: Comprehensive logging with both file and console output

## Detection Capabilities

The tool detects various types of DoS attacks:

1. **High Packet Rate Attacks**: SYN floods, UDP floods
2. **High Volume Attacks**: Bandwidth exhaustion attacks
3. **Connection-based Attacks**: Connection exhaustion, slowloris
4. **Statistical Anomalies**: Deviations from established baselines

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. On Linux/Mac, you may need admin privileges for packet capture:
   ```bash
   sudo python3 dos_detector.py
   ```

## Configuration

Edit `config.yaml` to customize detection thresholds and monitoring settings:

### Network Settings
- `interface`: Network interface to monitor (use "any" for all interfaces)
- `capture_filter`: BPF filter for packet capture

### Detection Thresholds
- `max_pps_per_ip`: Maximum packets per second from single IP
- `max_pps_total`: Maximum total packets per second
- `max_connections_per_ip`: Maximum concurrent connections per IP
- `max_connection_rate`: New connections per second per IP
- `max_bps_per_ip`: Maximum bytes per second per IP
- `max_bps_total`: Maximum total bytes per second

### Alert Settings
- `log_file`: File for alert logs
- `console_output`: Enable/disable console alerts
- `alert_cooldown`: Minimum seconds between alerts for same IP

## Usage

Run the detector with default configuration:
```bash
python3 dos_detector.py
```

Run with custom configuration:
```bash
python3 dos_detector.py custom_config.yaml
```

In VS Code, select **Run DoS Detection Tool** in the Run and Debug configuration
list, then choose **Run Without Debugging** (Ctrl+F5). This runs the Python
entry point; the YAML extension is for YAML editing and validation, not running
the application.

## How It Works

1. **Traffic Capture**: Uses Scapy to capture network packets in real-time
2. **Statistical Analysis**: Maintains rolling windows of traffic metrics
3. **Baseline Establishment**: Learns normal traffic patterns over time
4. **Anomaly Detection**: Compares current traffic against thresholds and baselines
5. **Alert Generation**: Triggers alerts when suspicious patterns are detected

## Architecture

- **TrafficMonitor**: Handles packet capture and basic statistics
- **DoSDetector**: Main detection engine with analysis algorithms
- **Configuration**: YAML-based configuration system
- **Alerting**: Cooldown-based alert system to prevent spam

## Requirements

- Python 3.7+
- Scapy (for packet capture)
- NumPy (for statistical calculations)
- PSUtil (for system monitoring)
- PyYAML (for configuration parsing)
- Matplotlib (for optional visualization)

## Security Considerations

- Requires elevated privileges for packet capture
- Logs sensitive network information
- Should be deployed in controlled environments
- Regular review of detection thresholds recommended

## Troubleshooting

### Permission Denied Errors
On Linux/Mac, run with sudo:
```bash
sudo python3 dos_detector.py
```

### Network Interface Issues
Check available interfaces:
```bash
python3 -c "from scapy.all import get_if_list; print(get_if_list())"
```

On Windows, install [Npcap](https://npcap.com/#download) to enable packet
capture, then set `network.interface` in `config.yaml` to the adapter name
(for example, `Wi-Fi`). The `any` interface value is for Linux/macOS, not
Windows.

### High False Positives
Adjust thresholds in `config.yaml` based on your network's normal traffic patterns.

## License

This tool is for educational and security research purposes. Use responsibly and in compliance with applicable laws and regulations.

## Contributing

Feel free to submit issues and enhancement requests to improve the detection capabilities.
