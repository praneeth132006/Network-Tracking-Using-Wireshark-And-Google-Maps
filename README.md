# Network Tracking Using Wireshark and Google Maps

## Project Overview

This project enables you to capture network traffic with Wireshark, process that data using Python scripts, and visualize geolocated IP addresses both on Google Maps (KML output) and as an interactive HTML dashboard. These combined visual and tabular outputs help administrators or cybersecurity professionals quickly analyze network activity and investigate sources.

***

## Features

- Capture network packets and flows with Wireshark
- Extract, parse, and geo-locate source IPs from PCAP with Python and GeoLiteCity
- Generate KML files viewable in Google Maps ([Google My Maps](https://www.google.com/maps/d/))
- Produce a full-featured HTML dashboard report for interactive data exploration
- Displays comprehensive statistics: total packets, flows, unique IPs, countries, and processing time

***

## Technologies Used

- **Wireshark:** Network packet capture ([Download Wireshark](https://www.wireshark.org/download.html))
- **Python 3:** Scripting for packet parsing, IP geolocation, and report generation
- **GeoLiteCity Database:** Translates IPs to locations
- **Google Maps/My Maps:** Show KML visualizations
- **HTML Dashboard:** Rich analytics and filtering
- **Python Libraries:** `dpkt`, `pygeoip`, `simplekml`

***

## System Requirements

- Windows, Linux, or macOS with Python 3.x
- Wireshark for packet capture
- GeoLiteCity database file, placed in your project directory
- Internet connection for Google Maps and dashboard visualization

***

## Installation and Setup

1. **Install Wireshark:**
[Wireshark Download](https://www.wireshark.org/download.html)
2. **Install Python 3 and libraries:**

```bash
pip install dpkt pygeoip simplekml
```

3. **Download GeoLiteCity Database:**
Download from MaxMind or a reliable source, and place it in your project folder.
4. **Capture Network Traffic:**
Start Wireshark, record traffic, then save as a `.pcap` file.
5. **Run the Python Script for Analysis:**

```bash
python main.py path_to_capture.pcap
```

This creates both a KML file for Google Maps and an HTML dashboard.
6. **Visualize KML File:**
Upload the generated `.kml` file to [Google My Maps](https://www.google.com/maps/d/) to inspect network locations spatially.
7. **Open the HTML Dashboard:**
Open `traffic2_report.html` in your browser to view and interact with dashboard analytics, filter/search traffic, and explore detailed tables with geo-annotations.

***

## Usage Example

```bash
python main.py capture.pcap
```

- Then open the `.kml` file on Google Maps, and `traffic2_report.html` in your browser for analytics.

***

## Output Files Overview

- **KML File:** Plot IP geolocations graphically on Google Maps; inspect global network flows interactively.
- **traffic2_report.html:**
    - Interactive dashboard with summary statistics, search/filter capability, sortable tables showing timestamps, IP addresses, ports, protocols, services, and locations. Useful for investigations and presentations.

***

## Best Practices and Precautions

- Disable any VPNs while capturing, or IP geolocations may be inaccurate.
- Only use public IPs for location mapping; internal/private IPs will not resolve meaningfully.
- Consider administrative privileges to ensure Wireshark can access all interfaces.

***

## Contribution

Contributions are welcomed! Fork this repository, enhance the code, and submit a pull request. Please write clear commit messages and add/update documentation as needed.


