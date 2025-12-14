## Overview
This project is a host-based intrusion detection system that monitors system and network activity to detect suspicious or potentially malicious behavior. It focuses on identifying patterns such as reconnaissance activity and brute-force login attempts through structured analysis of event data.

## Features
- Detects repeated suspicious activity within defined time windows  
- Identifies brute-force authentication attempts  
- Flags reconnaissance behavior such as port scanning  
- Generates real-time alerts for detected anomalies  
- Logs events for further review and auditing  

## How It Works
The system analyzes activity events over configurable time intervals and applies threshold-based logic to identify abnormal behavior patterns. When suspicious activity exceeds predefined thresholds within a specific time window, alerts are triggered and logged for monitoring purposes.

## Technologies Used
- Python  
- File I/O  
- Time-window based analysis  
- Security monitoring logic  

## Usage
1. Run the main detection script.  
2. The system continuously evaluates activity data.  
3. Alerts are generated when suspicious behavior is detected.  
4. Review logged events for analysis.
