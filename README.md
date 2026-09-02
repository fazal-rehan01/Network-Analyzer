# Zeek Forensics Analysis

This repository contains forensic analysis tools and simulated network traffic for detecting malicious activities using Zeek logs.

## Files Included

- **analyze_logs.py**: Automated analysis script for Zeek logs
- **generate_traffic.py**: Packet generation script using Scapy
- **conn.log**: Zeek connection logs
- **dns.log**: Zeek DNS logs
- **packet_filter.log**: Zeek packet filter logs
- **evidence_capture.pcap**: Generated packet capture file

## Features

- TCP SYN port scanning detection
- HTTP cleartext credential exfiltration analysis
- DNS tunneling/exfiltration detection

## Usage

### Generate Packet Capture
```bash
python3 generate_traffic.py
