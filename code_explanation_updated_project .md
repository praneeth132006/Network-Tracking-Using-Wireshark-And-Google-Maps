## 1. Importing Required Modules

```python
import dpkt
import socket
import pygeoip
import argparse
import time
from collections import defaultdict
from datetime import datetime
```

- **dpkt:** A library to parse network pcap files containing captured packets.
- **socket:** Provides low-level network interfaces, used here for IP-to-hostname conversions and IP formatting.
- **pygeoip:** Allows querying of an IP geolocation database to get city, country, lat/long for IP addresses.
- **argparse:** For handling command-line arguments (not fully shown in snippet but likely for user input).
- **time:** For measuring performance/timing.
- **defaultdict:** Enhances Python dictionaries with default values automatically created on first access.
- **datetime:** For converting timestamps to human-readable forms.

***

## 2. Loading GeoIP Database and Configuring IP

```python
gi = pygeoip.GeoIP('GeoLiteCity.dat')
MY_PUBLIC_IP = '182.66.218.121'
```

- Using the GeoLiteCity database (a local file), the code creates an object `gi` to query IP geolocation data.
- `MY_PUBLIC_IP` variable stores the external IP address of the machine/network running the analysis. This is used to reference your own traffic flows.

***

## 3. Protocol Colors and Port Mappings

```python
PROTOCOL_COLORS = {
    'HTTP': ('501400E6', [80, 8080]),
    'HTTPS': ('501400E6', [443, 8443]),
    'SSH': ('500000FF', [^22]),
    'DNS': ('5000FF00', [^53]),
    'FTP': ('50FF00FF', [20, 21]),
    'DEFAULT': ('50FFFF00', [])
}
```

- This dictionary assigns colors (in KML color notation) and known port numbers to important protocols.
- Colors help visualize traffic types distinctly on maps or visual reports.
- The `DEFAULT` entry is a fallback for unknown protocols.

***

## 4. Domain to Service Mapping

```python
DOMAIN_SERVICES = {
    'youtube': 'YouTube',
    'googlevideo': 'YouTube',
    'amazon': 'Amazon',
    'aws': 'Amazon AWS',
    'facebook': 'Facebook',
    'fbcdn': 'Facebook',
    'google': 'Google',
    'twitter': 'Twitter',
    'netflix': 'Netflix',
    'cloudflare': 'Cloudflare CDN',
    'akamai': 'Akamai CDN',
    'instagram': 'Instagram',
    'whatsapp': 'WhatsApp',
    'reddit': 'Reddit',
    'github': 'GitHub',
    'stackoverflow': 'StackOverflow'
}
```

- Maps well-known domain keywords to human-readable service names.
- Helps identify traffic by hostname/domain lookup during packet analysis.

***

## 5. NetworkAnalyzer Class Initialization

```python
class NetworkAnalyzer:
    def __init__(self, pcap_file, protocol_filter=None):
        self.pcap_file = pcap_file
        self.protocol_filter = protocol_filter
        self.stats = {
            'total_packets': 0,
            'src_ips': set(),
            'dst_ips': set(),
            'countries': set(),
            'destinations': defaultdict(int),
            'protocol_counts': defaultdict(int),
            'port_services': defaultdict(int)
        }
        self.connections = []
        try:
            self.my_geo = gi.record_by_name(MY_PUBLIC_IP)
            if not self.my_geo:
                self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946,
                               'city': 'Bangalore', 'country_name': 'India'}
        except:
            self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946,
                           'city': 'Bangalore', 'country_name': 'India'}
```



The `NetworkAnalyzer` class is designed to analyze network traffic captured in a PCAP file. The constructor method (`__init__`) initializes the class instance with configuration settings and prepares the data structures to hold analysis results.



### Constructor Signature

```

def __init__(self, pcap_file, protocol_filter=None):

```

- **pcap_file**: The path or filename of the packet capture (PCAP) file to be analyzed.
- **protocol_filter**: An optional parameter to specify a particular protocol (e.g., "tcp", "udp") to filter the analysis. If omitted or `None`, all protocols are considered.



### Instance Variable Initialization

```

self.pcap_file = pcap_file
self.protocol_filter = protocol_filter

```
- Stores the file path and filter choice as instance variables to be used by other methods in the class.



### Statistics Dictionary Setup

```

self.stats = {
'total_packets': 0,
'src_ips': set(),
'dst_ips': set(),
'countries': set(),
'destinations': defaultdict(int),
'protocol_counts': defaultdict(int),
'port_services': defaultdict(int)
}

```

- `self.stats` is a dictionary designed to accumulate detailed analytics throughout the packet processing.
- Keys explained:
  - **total_packets**: Counts the number of packets processed.
  - **src_ips**: A `set` holding every unique source IP address found.
  - **dst_ips**: A `set` for all unique destination IP addresses.
  - **countries**: Set of country names discovered via geolocation of destination IPs.
  - **destinations**: A `defaultdict(int)` counting total connections to each destination IP.
  - **protocol_counts**: Counts how often each protocol (TCP, UDP, ICMP, etc.) appears.
  - **port_services**: Counts occurrences of each destination port number used.

*Using sets ensures uniqueness; defaultdicts simplify counting by automatically initializing missing keys to zero.*



### Connections List Initialization

```

self.connections = []

```

- Prepares an empty list to store dictionaries representing each network connection with fields like IP addresses, ports, timestamp, protocol, service name, and geolocation.
- Accumulates detailed per-connection data for reporting and visualization.



### Own IP Geolocation Lookup with Fallback

```

try:
self.my_geo = gi.record_by_name(MY_PUBLIC_IP)
if not self.my_geo:
self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946,
'city': 'Bangalore', 'country_name': 'India'}
except:
self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946,
'city': 'Bangalore', 'country_name': 'India'}

```

- Attempts to retrieve geographic details for the user’s public IP address using the GeoIP database.
- The geo info includes latitude, longitude, city, and country.
- If the lookup fails or returns `None` (e.g., absence of data or lookup error), a default location is assigned (Bangalore, India).
- This fallback ensures the program runs robustly even if geolocation data is missing or inaccessible.



---

## 6. Service Identification by IP or Port

```python
def identify_service(self, ip, port):
    try:
        hostname = socket.gethostbyaddr(ip)[^0].lower()
        for domain, service in DOMAIN_SERVICES.items():
            if domain in hostname:
                return service
    except:
        pass
    for service, (_, ports) in PROTOCOL_COLORS.items():
        if service != 'DEFAULT' and port in ports:
            return service
    return 'Unknown'
```

- Tries to resolve the IP address to a hostname.
- Checks if any known domain keyword is in the hostname, returns mapped service name if so.
- If DNS resolution fails, it falls back to mapping based on well-known port numbers.
- Returns `'Unknown'` if no match found.

***

## 7. KML Style Selection Based on Port

```python
def get_style_for_port(self, port):
    for service, (color, ports) in PROTOCOL_COLORS.items():
        if port in ports:
            return service.lower() + 'Style', color
    return 'defaultStyle', PROTOCOL_COLORS['DEFAULT'][^1]
```

- For visualization with KML (Google Earth), returns styling (name and color) based on port number.
- Falls back to default style if port unknown.

***

## 8. Packet Capture File Analysis

```python
def analyze_pcap(self):
    start_time = time.time()
    with open(self.pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            self.stats['total_packets'] += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                # Filter by protocol if specified
                protocol = self.get_protocol_name(ip)
                if self.protocol_filter and protocol.lower() != self.protocol_filter.lower():
                    continue
                self.stats['protocol_counts'][protocol] += 1

                # Extract ports for TCP/UDP
                src_port = dst_port = 0
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
                self.stats['port_services'][dst_port] += 1

                # Update IP stats
                self.stats['src_ips'].add(src)
                self.stats['dst_ips'].add(dst)
                self.stats['destinations'][dst] += 1

                # Get destination geo info
                try:
                    dst_geo = gi.record_by_name(dst)
                    if dst_geo:
                        country = dst_geo.get('country_name', 'Unknown')
                        self.stats['countries'].add(country)

                        service = self.identify_service(dst, dst_port)

                        self.connections.append({
                            'timestamp': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
                            'src': src,
                            'dst': dst,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'protocol': protocol,
                            'service': service,
                            'country': country,
                            'city': dst_geo.get('city', 'Unknown'),
                            'lat': dst_geo['latitude'],
                            'lon': dst_geo['longitude']
                        })
                except:
                    pass
            except:
                continue
    self.stats['processing_time'] = time.time() - start_time
    return self.connections
```





### Packet Capture File Analysis - Detailed Code Explanation

#### Function Definition and Initialization

```python
def analyze_pcap(self):
```

Defines a method `analyze_pcap` that belongs to a class (indicated by `self`). This method will process and analyze network packet capture files.

```python
    start_time = time.time()
```

Records the current system time in seconds since epoch. This serves as a benchmark to measure how long the PCAP analysis takes, which is useful for performance monitoring and optimization.

```python
    with open(self.pcap_file, 'rb') as f:
```

Opens the PCAP file specified in `self.pcap_file` in read-binary mode (`'rb'`). The `with` statement ensures proper file handling by automatically closing the file when done, even if errors occur. Binary mode is required because PCAP files contain raw binary data, not text.

```python
        pcap = dpkt.pcap.Reader(f)
```

Creates a dpkt PCAP reader object that will parse the binary PCAP file. The `dpkt` library provides specialized tools for dissecting network protocols, and the Reader class handles the PCAP file format structure.

### Main Packet Processing Loop

```python
        for ts, buf in pcap:
```

Iterates through each packet in the PCAP file. For each packet, `ts` contains the timestamp (when the packet was captured), and `buf` contains the raw packet data (bytes).

```python
            self.stats['total_packets'] += 1
```

Increments a counter tracking the total number of packets processed. This statistics dictionary (`self.stats`) maintains various metrics about the packet capture.

```python
            try:
```

Begins an exception handling block. Since packet data can be malformed or incomplete, this prevents the entire analysis from crashing if a single packet has issues.

### Ethernet and IP Layer Processing

```python
                eth = dpkt.ethernet.Ethernet(buf)
```

Parses the raw packet buffer as an Ethernet frame. This extracts Layer 2 (Data Link Layer) information including MAC addresses and the protocol type of the encapsulated data.

```python
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
```

Checks if the data payload of the Ethernet frame is an IP packet. If it's not (e.g., ARP, IPv6, or other protocols), the `continue` statement skips to the next packet. This filter focuses analysis on IPv4 traffic only.

```python
                ip = eth.data
```

Assigns the IP packet (Layer 3 - Network Layer) to the variable `ip` for easier access and manipulation.

```python
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
```

Converts the source and destination IP addresses from binary format (4 bytes) to human-readable dotted-decimal notation (e.g., "192.168.1.1"). The `inet_ntoa` function stands for "Internet Network to ASCII".

### Protocol Filtering

```python
                # Filter by protocol if specified
                protocol = self.get_protocol_name(ip)
```

Calls a helper method `get_protocol_name` to identify the transport layer protocol (TCP, UDP, ICMP, etc.) from the IP packet. This extracts the protocol type from the IP header.

```python
                if self.protocol_filter and protocol.lower() != self.protocol_filter.lower():
                    continue
```

If a protocol filter was specified (e.g., only analyze TCP traffic), this checks if the current packet's protocol matches. Case-insensitive comparison is performed using `.lower()`. If there's no match, the packet is skipped.

```python
                self.stats['protocol_counts'][protocol] += 1
```

Updates statistics by incrementing the count for this specific protocol type. This creates a distribution showing which protocols are most prevalent in the capture.

### Port Extraction

```python
                # Extract ports for TCP/UDP
                src_port = dst_port = 0
```

Initializes both source and destination port variables to 0. This default value is used for protocols that don't have port numbers (like ICMP).

```python
                if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
```

Checks if the transport layer protocol is either TCP or UDP, as only these protocols use port numbers. The tuple `(dpkt.tcp.TCP, dpkt.udp.UDP)` allows checking for either type.

```python
                    src_port = ip.data.sport
                    dst_port = ip.data.dport
```

Extracts the source port (`sport`) and destination port (`dport`) from the transport layer header. Ports identify specific services or applications (e.g., port 80 for HTTP, port 443 for HTTPS).

```python
                self.stats['port_services'][dst_port] += 1
```

Tracks which destination ports are being accessed most frequently. This helps identify what services are being used (web servers, DNS, SSH, etc.).

### IP Address Tracking

```python
                # Update IP stats
                self.stats['src_ips'].add(src)
                self.stats['dst_ips'].add(dst)
```

Adds the source and destination IPs to sets, which automatically maintain unique values only. This tracks how many distinct hosts are communicating in the packet capture.

```python
                self.stats['destinations'][dst] += 1
```

Counts how many times each destination IP appears. This helps identify which destinations receive the most traffic, potentially revealing primary servers or targets.

### Geolocation Processing

```python
                # Get destination geo info
                try:
```

Begins a nested try-except block specifically for geolocation lookup, which may fail for private/local IPs or if the database doesn't have information.

```python
                    dst_geo = gi.record_by_name(dst)
```

Queries the GeoIP database (`gi`, likely GeoLiteCity) to retrieve geographical information for the destination IP address. This returns a dictionary with location data.

```python
                    if dst_geo:
```

Checks if geolocation data was found. Some IPs (private ranges, localhost) won't have geo information.

```python
                        country = dst_geo.get('country_name', 'Unknown')
```

Safely retrieves the country name from the geo record. The `.get()` method returns 'Unknown' if the key doesn't exist, preventing KeyError exceptions.

```python
                        self.stats['countries'].add(country)
```

Adds the country to a set tracking all unique countries that appear as destinations in the traffic.

```python
                        service = self.identify_service(dst, dst_port)
```

Calls a helper method to identify what service or application the connection is targeting, based on the destination IP and port combination.

### Connection Record Creation

```python
                        self.connections.append({
```

Begins building a dictionary that represents a complete connection record, which will be added to the `self.connections` list.

```python
                            'timestamp': datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S'),
```

Converts the Unix timestamp to a human-readable datetime string in the format "2025-11-08 16:45:30". This makes timestamps easier to read in reports.

```python
                            'src': src,
                            'dst': dst,
```

Stores the source and destination IP addresses in their readable string format.

```python
                            'src_port': src_port,
                            'dst_port': dst_port,
```

Records the port numbers used in the connection, which identify the specific services being accessed.

```python
                            'protocol': protocol,
```

Stores the protocol type (TCP, UDP, etc.) for this connection.

```python
                            'service': service,
```

Includes the identified service name (e.g., "HTTP", "HTTPS", "DNS") based on port and other heuristics.

```python
                            'country': country,
                            'city': dst_geo.get('city', 'Unknown'),
```

Records the destination's country and city, providing geographical context for where traffic is going.

```python
                            'lat': dst_geo['latitude'],
                            'lon': dst_geo['longitude']
```

Stores the geographical coordinates (latitude and longitude) which can be used for mapping network traffic on visualizations like Google Earth KML files.

```python
                        })
```

Closes the dictionary definition and appends it to the connections list.

### Error Handling

```python
                except:
                    pass
```

Catches any exceptions during geolocation processing and silently continues. This prevents the analysis from stopping if geo lookup fails for some IPs.

```python
            except:
                continue
```

Outer exception handler catches any errors during packet parsing (malformed packets, unsupported protocols, etc.) and continues processing the next packet.

## Finalization

```python
    self.stats['processing_time'] = time.time() - start_time
```

Calculates total processing time by subtracting the start time from the current time, storing it in statistics for performance analysis.

```python
    return self.connections
```

Returns the list of all analyzed connections, which can be used for generating reports, creating visualizations, or further analysis.

























### Summary


- Opens the pcap file and reads packets one by one.
- Parses Ethernet frames, then checks if they contain IP packets.
- Converts source and destination IPs from byte to string format.
- Optionally filters packets by protocol type.
- Extracts source and destination ports for TCP and UDP.
- Updates various statistics on sources, destinations, protocols, ports, and countries.
- Looks up geographic info for each destination IP and records connection details with timestamp, IPs, ports, protocol, service, and geolocation.
- Returns all connection details after processing and records total time taken.

***

### 9. Protocol Detection Helper

```python
def get_protocol_name(self, ip):
    if isinstance(ip.data, dpkt.tcp.TCP):
        return 'TCP'
    elif isinstance(ip.data, dpkt.udp.UDP):
        return 'UDP'
    elif isinstance(ip.data, dpkt.icmp.ICMP):
        return 'ICMP'
    return 'Other'
```

- Determines protocol type by checking internal packet data type.
- Useful for protocol-based filtering and statistics.

***

### 10. Generating Human-Readable Analysis Reports

```python
def generate_statistics_report(self):
    report = f"""
{'='*60}
NETWORK TRAFFIC ANALYSIS REPORT
{'='*60}
SOURCE INFORMATION:
Your IP: {MY_PUBLIC_IP}
Location: {self.my_geo.get('city', 'Unknown')}, {self.my_geo.get('country_name', 'Unknown')}
OVERVIEW:
Total Packets Analyzed: {self.stats['total_packets']:,}
Unique Source IPs: {len(self.stats['src_ips'])}
Unique Destination IPs: {len(self.stats['dst_ips'])}
Countries Detected: {len(self.stats['countries'])}
Processing Time: {self.stats['processing_time']:.2f} seconds
PROTOCOL DISTRIBUTION:
"""
    for proto, count in sorted(self.stats['protocol_counts'].items(), key=lambda x: x[^1], reverse=True):
        report += f" {proto}: {count:,} packets\n"
    report += "\nTOP 10 DESTINATION IPs:\n"
    for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[^1], reverse=True)[:10]:
        report += f" {ip}: {count} connections\n"
    report += "\nTOP SERVICES/PORTS:\n"
    for port, count in sorted(self.stats['port_services'].items(), key=lambda x: x[^1], reverse=True)[:10]:
        service = self.identify_service('', port)
        report += f" Port {port} ({service}): {count} connections\n"
    report += "\nCOUNTRIES DETECTED:\n"
    for country in sorted(self.stats['countries']):
        report += f" - {country}\n"
    report += f"\n{'='*60}\n"
    with open('traffic2_statistics.txt', 'w') as f:
        f.write(report)
    print(report)
    return report
```

- Creates a formatted multiline string report with:
    - Basic source info,
    - Total packets,
    - Unique IP counts,
    - Countries observed,
    - Protocol distribution,
    - Top destination IPs by number of connections,
    - Top ports with service names,
    - Countries observed in traffic.
- Writes this report to a file and prints it.

***

### 11. KML File Generation for Visualization (start)

```python
def generate_kml(self):
    styles = ''
    for service, (color, _) in PROTOCOL_COLORS.items():
        style_id = service.lower() + 'Style'
        styles += f"""
        <Style id="{style_id}">
            <LineStyle><color>{color}</color><width>4</width></LineStyle>
            <PolyStyle><color>{color}</color></PolyStyle>
        </Style>
        """
    # (Further code to generate KML placemarks for each recorded connection goes here.)
```

- Builds XML style tags for each protocol based on color.
- These styles are later referenced in the KML file used for mapping connections in tools like Google Earth.
- The full KML generation includes placemarks plotting source and destination geolocations for each connection but is partially shown.

***

## Summary

This project is a comprehensive network traffic analyzer that processes pcap files to:

- Count and categorize packets by IP, protocol, ports.
- Resolve IP addresses to geo-locations.
- Associate traffic with known services/domains.
- Produce detailed text reports on traffic statistics.
- Generate KML visualization files to map traffic flows geographically with protocol-based color coding.



