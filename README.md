# Intrusion-Detection
-Overview
This project is a host-based intrusion detection system designed to monitor system and network activity in order to identify suspicious or potentially malicious behavior. It focuses on detecting common attack patterns such as reconnaissance activity and brute-force login attempts through structured analysis of event data.
Features
Detects repeated suspicious activity within defined time windows
Identifies brute-force authentication attempts
Flags reconnaissance behavior indicative of port scanning
Generates real-time alerts for detected anomalies
Logs detected events for later review and analysis
-How It Works
The system analyzes activity events over configurable time intervals and applies threshold-based detection logic to identify abnormal behavior patterns. When suspicious activity exceeds defined limits within a specific time window, the system triggers alerts and records the event for auditing purposes.
-Technologies Used
Python
File I/O
Time-based analysis
Security monitoring logic
-Use Cases
Monitoring system activity for early signs of intrusion
Detecting unauthorized access attempts
Learning foundational intrusion detection techniques
Demonstrating defensive cybersecurity concepts
-Usage
Run the detection script.
The system continuously evaluates activity data.
Alerts are generated when suspicious behavior is detected.
Logged events can be reviewed for further analysis.
