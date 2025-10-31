

# Network Tracking Project Using Google Maps and Wireshark

## Overview

This Python project parses network traffic data from a Wireshark `.pcap` file, extracts IP addresses from the packets, locates their geographic coordinates using a GeoIP database, and generates a KML file for visualization of network paths on Google Maps.

***

## Libraries Used

- **dpkt**: A fast, simple packet creation/parsing library for Python used to read `.pcap` files.
- **socket**: Provides utilities for networking, here used to convert raw IP bytes to human-readable IP addresses.
- **pygeoip**: Used to perform IP geolocation lookups against a GeoIP database (`GeoLiteCity.dat`), which maps IP addresses to geographic locations (latitude \& longitude).

***

## Code Explanation

### Import Statements

```python
import dpkt
import socket
import pygeoip
```

- **dpkt**: Reads and processes captured packet data.
- **socket**: Converts binary IP addresses to dotted-decimal format.
- **pygeoip**: Retrieves geolocation info for IPs.


### Initialize GeoIP Database

```python
gi = pygeoip.GeoIP('GeoLiteCity.dat')
```

- Loads MaxMind’s free `GeoLiteCity` database for IP-to-location mapping.
- Essential for converting IP addresses to geographic coordinates for map visualization.


### `main()` Function

```python
def main():
    f = open('demo3.pcap', 'rb')
    pcap = dpkt.pcap.Reader(f)
```

- Opens the `.pcap` file `demo3.pcap` in binary mode for reading network packet data.
- `dpkt.pcap.Reader` prepares the file for packet iteration.

```python
    kmlheader = '<?xml version="1.0" encoding="UTF-8"?> \n<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n'\
    '<Style id="transBluePoly">' \
    '<LineStyle>' \
    '<width>1.5</width>' \
    '<color>501400E6</color>' \
    '</LineStyle>' \
    '</Style>'
```

- KML file header with XML declaration, namespace, and a style block defining a translucent blue line.
- This style will visually represent the network paths in Google Earth or Google Maps.

```python
    kmlfooter = '</Document>\n</kml>\n'
```

- Closes required KML tags.

```python
    kmldoc=kmlheader+plotIPs(pcap)+kmlfooter
    print(kmldoc)
```

- Combines the header, generated KML points/paths from `plotIPs()`, and footer into the full KML document.
- Prints the KML document content for review/debug.

```python
    f = open('file.kml', 'w')
    f.write(kmldoc)
    f.close()
```

- Saves the KML output to `file.kml` for use with Google Maps or Earth.

***

### `plotIPs()` Function

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

- Iterates over each packet in the `.pcap` file.
- Converts raw packet bytes into an Ethernet frame (`dpkt.ethernet.Ethernet`).
- Extracts IP layer (`ip = eth.data`).
- Converts source (`ip.src`) and destination (`ip.dst`) IP addresses from binary to string using `socket.inet_ntoa()`.
- Calls `retKML()` to generate KML for the source-destination IP pair.
- Adds generated KML snippet to the cumulative string.
- Ignores any packets that cause exceptions (e.g., non-IP packets).

***

### `retKML()` Function

```python
def retKML(dstip, srcip):
    dst = gi.record_by_name(dstip)
    src = gi.record_by_name('182.66.218.121')
    try:
        dstlongitude = dst['longitude']
        dstlatitude = dst['latitude']
        srclongitude = src['longitude']
        srclatitude = src['latitude']
```

- Performs geolocation lookup for the destination IP using the GeoIP database.
- Note: source IP geolocation is hardcoded to `'182.66.218.121'` (can be improved by passing `srcip` instead).
- Extracts latitude and longitude for both IPs.

```python
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

- Generates a KML `<Placemark>` element representing a line between the destination and source coordinates.
- Uses previously defined blue line style.
- If any geolocation fails, returns empty string to skip invalid points.

***

### Script Entry Point

```python
if __name__ == '__main__':
    main()
```

- Standard practice to run the `main()` function when the script is executed directly (not imported).

***



## Terminal Commands to Run

```shell
python your_script_name.py
```

- Replace `your_script_name.py` with the filename of your script.

***

## Key Vocabulary

- **PCAP (Packet Capture):** File format to save network packet data.
- **KML (Keyhole Markup Language):** XML-based format for geographic visualization.
- **GeoIP:** Method to map IP addresses to geographic locations.
- **Placemark:** A point or line feature in KML for map annotations.
- **Extrude and Tessellate in KML:** Visual effects to enhance line rendering in 3D maps.



