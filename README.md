# Python Cybersecurity Project: Network Tracking using Wireshark and Google Maps

## Project Overview
This project demonstrates how to visualize network traffic by capturing data with Wireshark, processing it using Python to extract and geolocate IP addresses, and mapping the results on Google Maps. It provides a clear geographic view of network connections, helping cybersecurity professionals track suspicious or malicious sources effectively.

## Description
Network tracking is essential for understanding and responding to cyber threats. Using this project, you capture real-time network traffic, translate IP addresses into geographic coordinates using GeoLite2, and create map visualizations for easier analysis of attacker origins or suspicious patterns.

## Real-World Examples
- **Target Breach (2013):** Network tracking revealed attacker lateral movement via a third-party.
- **Maersk NotPetya Attack (2017):** Mapping infection routes helped manage the global impact.
- **Equifax Breach (2017):** Traffic analysis exposed international data exfiltration.
- **Boeing Ransomware (2023):** Network forensic mapping identified ransomware pathways and mitigated damage.

## Technologies Used
- Wireshark (network capture)
- Python (data processing with pyshark/scapy)
- GeoLite2 City database (IP geolocation)
- Google Maps (visualization)

## Usage Summary
- Capture network traffic with Wireshark
- Parse `.pcap` captures in Python to extract IPs and geolocate them
- Plot geographic data using Google Maps for visual analysis

## Prevention Tips
- Continuous monitoring and analysis of network traffic  
- Network segmentation to limit attack spread  
- Regular patching and updating of systems  
- Automated alerts on suspicious or foreign IP connections  
- Integration with firewalls and IDS for layered defense and many other things


