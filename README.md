

# Network Tracking Using Wireshark and Google Maps

## Project Overview

This project demonstrates the use of Wireshark to capture network traffic data and visualize the geolocation of the source IP addresses on Google Maps. It leverages Python scripting to process PCAP files captured by Wireshark, translate IP addresses to geographic coordinates using geo-IP databases, and plot these points on a Google Maps interface with KML files.

The primary goal is to provide an insightful way of analyzing network traffic visually, which can aid network administrators and cybersecurity professionals in monitoring and locating network sources effectively.

***

## Features

- Capture network traffic using Wireshark.
- Extract and parse network packet data, including IP addresses and timestamps.
- Use GeoLiteCity or similar geo-IP databases to convert IP addresses into latitude and longitude.
- Generate KML files compatible with Google Maps to plot traffic sources on a map.
- Provide a clear geographic visualization of network activity.

***

## Technologies Used

- **Wireshark:** Network packet capture and analysis tool.
- **Python 3:** Scripting language for data processing and KML generation.
- **GeoLiteCity Database:** For IP to geolocation mapping.
- **Google Maps:** Visual interface to display network traffic locations.
- Python libraries such as `dpkt`, `pygeoip`, `simplekml`, and others for packet parsing and KML handling.

***

## System Requirements

- Operating System: Windows, Linux, or macOS
- Python 3.x installed
- Wireshark installed and configured to capture network traffic
- GeoLiteCity database files downloaded and placed in the project directory
- Internet connection for Google Maps visualization

***

## Installation and Setup

### Step 1: Install Wireshark

Download and install Wireshark from the official website: [Wireshark Download](https://www.wireshark.org/download.html)

### Step 2: Install Python and Required Libraries

Make sure Python 3 is installed. Then install necessary Python libraries via pip:

```bash
pip install dpkt pygeoip simplekml
```


### Step 3: Download GeoLiteCity Database

Download the GeoLiteCity database from an official or trusted source and place it in the project directory for IP geolocation.

### Step 4: Capture Network Traffic

Launch Wireshark, start capturing traffic on the desired network interface, and save the capture as a PCAP file.

### Step 5: Run the Python Script

Run the provided Python script (`main.py`) with the saved PCAP file as input. The script will process the data and generate a KML file.

```bash
python main.py path_to_capture.pcap
```


### Step 6: Visualize on Google Maps

Upload or open the generated KML file using Google My Maps [Google My Maps](https://www.google.com/maps/d/) to visualize network traffic locations.

***

## Usage Example

```bash
python main.py capture.pcap
```

After running, open the output KML file in Google Maps and explore the visualized network traffic points.

***

## Project Structure

- `main.py` — Main Python script for parsing PCAP and generating KML.
- `GeoLiteCity.dat` — GeoIP database file for IP to location translation.
- `README.md` — Project documentation.
- Any other dependencies or scripts

***

## Challenges Faced

- Parsing PCAP files reliably across different network interfaces.
- Accurate geolocation mapping of IP addresses.
- Handling a large volume of network packets efficiently.
- Generating precise KML output compatible with Google Maps.


***
## Precausions 
- Make sure that VPNs are turned off
- Should use pulic ip instead of private ip address

***

## Contributing

Contributions are welcome! Feel free to fork the repository, make improvements, and submit pull requests. Please follow the existing code style and provide clear documentation.
