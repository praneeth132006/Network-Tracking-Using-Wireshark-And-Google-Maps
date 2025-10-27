
# Network Tracking using Wireshark and Google Maps

## Overview

This project demonstrates how to parse and geolocate network packets captured by Wireshark, visualize them on Google Maps using KML, and understand the methods and security context behind each step. The explanations below detail every part of the code, show its relevance in modern cybersecurity, feature real-world attack case studies, and recommend prevention best practices.

***

## Table of Contents

- [Project Purpose](#project-purpose)
- [Code Breakdown](#code-breakdown)
    - [Imports](#imports)
    - [GeoIP Database Initialization](#geoip-database-initialization)
    - [KML String Builder Function](#kml-string-builder-function)
    - [Packet Plotting Function](#packet-plotting-function)
    - [Main Routine](#main-routine)
    - [Script Entry Point](#script-entry-point)
- [Real-World Incident Examples](#real-world-incident-examples)
- [Security and Prevention Tips](#security-and-prevention-tips)
- [Additional Resources](#additional-resources)
- [References](#references)

***

## Project Purpose

Network forensics is vital in cybersecurity for tracing malicious activity, identifying data exfiltration pathways, and supporting incident response. By extracting and visualizing IP traffic from raw packet captures, analysts can rapidly spot suspicious routes, attacker locations, and compromise patterns.

***

## Code Breakdown

### Imports

```python
import dpkt
import socket
import pygeoip
```

- **dpkt:**
Parses binary packet data from pcap files (the format used by Wireshark), handling Ethernet, IP, TCP, and more.
- **socket:**
Converts raw byte-form IP addresses into readable strings.
- **pygeoip:**
Interfaces with a geolocation database to map IPs to their physical (longitude/latitude) locations.

***

### GeoIP Database Initialization

```python
gi = pygeoip.GeoIP('GeoLiteCity.dat')
```

- **Purpose:**
Loads the `GeoLiteCity.dat` database (obtained from MaxMind) to support fast IP-to-location lookups.
- **Importance:**
Mapping IPs geographically is crucial when tracing attack origins, botnet nodes, or exfiltration paths, helping pinpoint compromised systems.

***

### KML String Builder Function

```python
def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name('192.168.0.8')
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
        kml = (
            '<Placemark>\n'
            '<name>%s</name>\n'
            '<extrude>1</extrude>\n'
            '<tessellate>1</tessellate>\n'
            '<styleUrl>#transBluePoly</styleUrl>\n'
            '<LineString>\n'
            '<coordinates>%6f,%6f\n%6f,%6f</coordinates>\n'
            '</LineString>\n'
            '</Placemark>\n'
        )%(dstip, dstlongitude, dstlatitude, srclongitude, srclatitude)
        return kml
    except:
        return ''
```

- **Function:**
Creates one KML placemark for each network connection, describing a line from the source to the destination IP.
- **GeoIP Lookups:**
Finds the geo-location (longitude/latitude) for each public IP from the database.
- **Error Handling:**
Uses try/except to ensure processing continues if a lookup fails or the IP is not in the database.
- **KML Format:**
KML (Keyhole Markup Language) is used by Google Earth/Maps to visualize spatial data.
- **Customization:**
The source IP is hardcoded (for demo purposes)—in advanced implementations, this should dynamically take srcip as input.

***

### Packet Plotting Function

```python
def plotIPs(pcap):
    kmlPts = ''
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            KML = retKML(dst, src)
            kmlPts = kmlPts + KML
        except:
            pass
    return kmlPts
```

- **Functionality:**
Iterates over all packets, decodes layers to extract source and destination IPs, and generates the corresponding KML for each connection.
- **Resilience:**
Skips malformed or non-IP packets (e.g., ARP frames), ensuring robustness for diverse capture files.
- **Integration:**
Aggregates all results into one KML data block for easy visual import.

***

### Main Routine

```python
def main():
    f = open('mac_data.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">' \
                '<LineStyle>' \
                '<width>1.5</width>' \
                '<color>501400E6</color>' \
                '</LineStyle>' \
                '</Style>'
    kmlfooter = '</Document>\n</kml>\n'
    kmldoc=kmlheader+plotIPs(pcap)+kmlfooter
    print(kmldoc)
```

- **File Handling:**
Opens the capture file as bytes (necessary for pcap processing).
- **Header/Footer:**
Prepares the full KML document, including styles (like line color and thickness) for improved readability in Google Earth/Maps.
- **Final Output:**
Concatenates the header, all plotted connections, and the footer, then prints for file redirection or immediate copy to visualization tools.

***

### Script Entry Point

```python
if __name__ == '__main__':
    main()
```

- **Standard Python Practice:**
Ensures the script runs its main logic only when directly executed, allowing for module imports elsewhere.

***

## Real-World Incident Examples

### 1. 2014 JP Morgan Chase Breach

- Attackers exploited networking weaknesses, leading to massive data theft. Forensics used similar IP geolocation and packet tracking to visualize attacker paths through infrastructure.


### 2. 2017 WannaCry Ransomware

- Tracked by packet captures and mapped geopolitically to show spread worldwide, helping governments pinpoint outbreaks and coordinate response.


### 3. 2018 Iranian Cyber-Espionage

- Security researchers traced IPs from European institutions back to Iranian operators using similar geo-mapping techniques, supporting nation-state attribution.


### 4. 2020 SolarWinds Attack

- Packet capture analysis with geo-mapping showed global reach and infection chain, aiding in rapid response and remediation across organizations.

***

## Security and Prevention Tips

- **Sanitize Inputs:**
Validate all IPs and handle exceptions gracefully to avoid data loss or script crashes.
- **Keep Databases Updated:**
Regularly update GeoIP databases to prevent misattribution errors during attacks.
- **Network Segmentation:**
Restrict unnecessary connections between network zones, limiting attacker mobility and traffic visualization scope.
- **Automated Alerts:**
Combine IP mapping with SIEM monitoring to flag abnormal geo-locations.
- **Traffic Encryption:**
Encrypt sensitive internal traffic so that even if PCAP files leak, no confidential data is exposed.
- **Role-Based Access:**
Limit packet capture and analysis to trusted, trained administrators to prevent misuse by adversaries.
- **Update Tools:**
Frequently update Python libraries and dependencies (`dpkt`, `pygeoip`, etc.) to avoid vulnerabilities in the codebase.
- **Legal Compliance:**
Ensure use of geo-mapping tools adheres to all applicable privacy and legal standards (GDPR, etc.).

***

## Additional Resources

- **Wireshark Documentation:** Packet capture and analysis guide.
- **MaxMind GeoIP:** Updated geolocation datasets and usage.
- **KML Reference:** Official documentation for Google Maps/Earth integration.
- **dpkt Docs:** Deep dive into Python packet parsing.

***

## References

- Standard network security documentation, library guides, and professional cybersecurity resources.
- Incident reports from major cybersecurity news outlets and forensic analysis write-ups.
- Security best practices as published by SANS, NIST, and cybersecurity authorities.


