import dpkt
import socket
import pygeoip
import argparse
import time
from collections import defaultdict
from datetime import datetime

gi = pygeoip.GeoIP('GeoLiteCity.dat')

# Your public IP address (source)
MY_PUBLIC_IP = '182.66.218.121'

# Protocol colors and port mappings
PROTOCOL_COLORS = {
    'HTTP': ('501400E6', [80, 8080]),  # Blue
    'HTTPS': ('501400E6', [443, 8443]),  # Blue
    'SSH': ('500000FF', [22]),  # Red
    'DNS': ('5000FF00', [53]),  # Green
    'FTP': ('50FF00FF', [20, 21]),  # Magenta
    'DEFAULT': ('50FFFF00', [])  # Yellow
}

# Domain to service mapping
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
        
        # Get your own geolocation
        try:
            self.my_geo = gi.record_by_name(MY_PUBLIC_IP)
            if not self.my_geo:
                self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946, 
                              'city': 'Bangalore', 'country_name': 'India'}
        except:
            self.my_geo = {'latitude': 12.9716, 'longitude': 77.5946, 
                          'city': 'Bangalore', 'country_name': 'India'}

    def identify_service(self, ip, port):
        """Identify service based on IP or port"""
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            for domain, service in DOMAIN_SERVICES.items():
                if domain in hostname:
                    return service
        except:
            pass
        
        # Check port-based services
        for service, (_, ports) in PROTOCOL_COLORS.items():
            if service != 'DEFAULT' and port in ports:
                return service
        return 'Unknown'

    def get_style_for_port(self, port):
        """Get KML style based on port"""
        for service, (color, ports) in PROTOCOL_COLORS.items():
            if port in ports:
                return service.lower() + 'Style', color
        return 'defaultStyle', PROTOCOL_COLORS['DEFAULT'][1]

    def analyze_pcap(self):
        """Main analysis function"""
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
                    
                    # Protocol filtering
                    protocol = self.get_protocol_name(ip)
                    if self.protocol_filter and protocol.lower() != self.protocol_filter.lower():
                        continue
                    
                    self.stats['protocol_counts'][protocol] += 1
                    
                    # Extract ports
                    src_port = dst_port = 0
                    if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                        self.stats['port_services'][dst_port] += 1
                    
                    # Update statistics
                    self.stats['src_ips'].add(src)
                    self.stats['dst_ips'].add(dst)
                    self.stats['destinations'][dst] += 1
                    
                    # Get geolocation (no caching)
                    try:
                        dst_geo = gi.record_by_name(dst)
                        if dst_geo:
                            country = dst_geo.get('country_name', 'Unknown')
                            self.stats['countries'].add(country)
                            
                            # Identify service
                            service = self.identify_service(dst, dst_port)
                            
                            # Store connection info
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

    def get_protocol_name(self, ip):
        """Get protocol name from IP packet"""
        if isinstance(ip.data, dpkt.tcp.TCP):
            return 'TCP'
        elif isinstance(ip.data, dpkt.udp.UDP):
            return 'UDP'
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            return 'ICMP'
        return 'Other'

    def generate_statistics_report(self):
        """Generate and save statistics report"""
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
        for proto, count in sorted(self.stats['protocol_counts'].items(), key=lambda x: x[1], reverse=True):
            report += f"  {proto}: {count:,} packets\n"

        report += "\nTOP 10 DESTINATION IPs:\n"
        for ip, count in sorted(self.stats['destinations'].items(), key=lambda x: x[1], reverse=True)[:10]:
            report += f"  {ip}: {count} connections\n"

        report += "\nTOP SERVICES/PORTS:\n"
        for port, count in sorted(self.stats['port_services'].items(), key=lambda x: x[1], reverse=True)[:10]:
            service = self.identify_service('', port)
            report += f"  Port {port} ({service}): {count} connections\n"

        report += "\nCOUNTRIES DETECTED:\n"
        for country in sorted(self.stats['countries']):
            report += f"  - {country}\n"

        report += f"\n{'='*60}\n"

        # Save to file
        with open('traffic2_statistics.txt', 'w') as f:
            f.write(report)
        
        print(report)
        return report

    def generate_kml(self):
        """Generate KML file with enhanced features"""
        # Generate style definitions
        styles = ''
        for service, (color, _) in PROTOCOL_COLORS.items():
            style_id = service.lower() + 'Style'
            styles += f"""
    <Style id="{style_id}">
        <LineStyle>
            <width>1.5</width>
            <color>{color}</color>
        </LineStyle>
    </Style>"""

        header = f'''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
    <name>Network Traffic Geolocation - {MY_PUBLIC_IP}</name>{styles}
'''
        
        placemarks = ''
        for conn in self.connections:
            style_id, _ = self.get_style_for_port(conn['dst_port'])
            
            description = f"""
Service: {conn['service']}
Protocol: {conn['protocol']}
Timestamp: {conn['timestamp']}
Source: {conn['src']}:{conn['src_port']} ({self.my_geo.get('city', 'Unknown')}, {self.my_geo.get('country_name', 'Unknown')})
Destination: {conn['dst']}:{conn['dst_port']} ({conn['city']}, {conn['country']})
"""
            
            placemarks += f'''
    <Placemark>
        <name>{conn['service']} - {conn['country']}</name>
        <description><![CDATA[{description}]]></description>
        <styleUrl>#{style_id}</styleUrl>
        <LineString>
            <extrude>1</extrude>
            <tessellate>1</tessellate>
            <coordinates>
                {self.my_geo['longitude']},{self.my_geo['latitude']},0
                {conn['lon']},{conn['lat']},0
            </coordinates>
        </LineString>
    </Placemark>'''

        footer = '\n</Document>\n</kml>'
        
        kml_content = header + placemarks + footer
        with open('traffic2_map.kml', 'w') as f:
            f.write(kml_content)
        
        print(f"📍 KML map generated with lines from {self.my_geo.get('city', 'Your location')} to destinations")
        return kml_content

    def generate_html_report(self):
        """Generate interactive HTML report"""
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Network Traffic Analysis - {MY_PUBLIC_IP}</title>
    <meta charset="UTF-8">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }}
        .stat-card .label {{
            color: #666;
            font-size: 0.9em;
        }}
        .controls {{
            padding: 20px 30px;
            background: white;
            border-bottom: 2px solid #eee;
        }}
        #searchBox {{
            width: 100%;
            max-width: 500px;
            padding: 12px 20px;
            border: 2px solid #ddd;
            border-radius: 25px;
            font-size: 16px;
            transition: all 0.3s;
        }}
        #searchBox:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 10px rgba(102, 126, 234, 0.3);
        }}
        .table-container {{
            padding: 30px;
            overflow-x: auto;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
        }}
        th {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            cursor: pointer;
            user-select: none;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        th:hover {{
            background: linear-gradient(135deg, #764ba2 0%, #667eea 100%);
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #eee;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .protocol {{
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
        }}
        .TCP {{
            background: #e3f2fd;
            color: #1976d2;
        }}
        .UDP {{
            background: #f3e5f5;
            color: #7b1fa2;
        }}
        .ICMP {{
            background: #fff3e0;
            color: #f57c00;
        }}
        .service {{
            background: #e8f5e9;
            color: #2e7d32;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            display: inline-block;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 2px solid #eee;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 Network Traffic Analysis</h1>
            <p>Source IP: {MY_PUBLIC_IP} | Location: {self.my_geo.get('city', 'Unknown')}, {self.my_geo.get('country_name', 'Unknown')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">Total Packets</div>
                <div class="number">{self.stats['total_packets']:,}</div>
            </div>
            <div class="stat-card">
                <div class="label">Connections</div>
                <div class="number">{len(self.connections)}</div>
            </div>
            <div class="stat-card">
                <div class="label">Unique IPs</div>
                <div class="number">{len(self.stats['dst_ips'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Countries</div>
                <div class="number">{len(self.stats['countries'])}</div>
            </div>
            <div class="stat-card">
                <div class="label">Processing Time</div>
                <div class="number">{self.stats['processing_time']:.2f}s</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" id="searchBox" placeholder="🔍 Search by IP, service, country, or any keyword...">
        </div>
        
        <div class="table-container">
            <table id="dataTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Timestamp ▼</th>
                        <th onclick="sortTable(1)">Source IP</th>
                        <th onclick="sortTable(2)">Destination IP</th>
                        <th onclick="sortTable(3)">Ports</th>
                        <th onclick="sortTable(4)">Protocol</th>
                        <th onclick="sortTable(5)">Service</th>
                        <th onclick="sortTable(6)">Location</th>
                    </tr>
                </thead>
                <tbody>
'''
        
        for conn in self.connections:
            html += f'''
                    <tr>
                        <td>{conn['timestamp']}</td>
                        <td>{conn['src']}</td>
                        <td>{conn['dst']}</td>
                        <td>{conn['src_port']} → {conn['dst_port']}</td>
                        <td><span class="protocol {conn['protocol']}">{conn['protocol']}</span></td>
                        <td><span class="service">{conn['service']}</span></td>
                        <td>{conn['city']}, {conn['country']}</td>
                    </tr>'''

        html += '''
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            Generated by Network Traffic Analyzer | All times in local timezone
        </div>
    </div>
    
    <script>
        // Search functionality
        document.getElementById('searchBox').addEventListener('keyup', function() {
            const filter = this.value.toLowerCase();
            const rows = document.querySelectorAll('#dataTable tbody tr');
            let visibleCount = 0;
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(filter)) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
        });

        // Sort functionality
        function sortTable(col) {
            const table = document.getElementById('dataTable');
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            const isAsc = table.dataset.sortCol == col && table.dataset.sortDir == 'asc';
            
            rows.sort((a, b) => {
                const aVal = a.cells[col].textContent.trim();
                const bVal = b.cells[col].textContent.trim();
                return isAsc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
            });
            
            rows.forEach(row => table.querySelector('tbody').appendChild(row));
            table.dataset.sortCol = col;
            table.dataset.sortDir = isAsc ? 'desc' : 'asc';
        }
    </script>
</body>
</html>'''
        
        with open('traffic2_report.html', 'w') as f:
            f.write(html)
        
        return html

def main():
    parser = argparse.ArgumentParser(description='Network Traffic GeoLocation Analyzer')
    parser.add_argument('pcap_file', nargs='?', default='traffic2.pcap', 
                       help='PCAP file to analyze (default: traffic2.pcap)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'], 
                       help='Filter by protocol (tcp/udp/icmp)')
    
    args = parser.parse_args()
    
    print("="*60)
    print("🚀 NETWORK TRAFFIC GEOLOCATION ANALYZER")
    print("="*60)
    print(f"📁 PCAP File: {args.pcap_file}")
    print(f"📍 Your IP: {MY_PUBLIC_IP}")
    if args.protocol:
        print(f"🔍 Protocol Filter: {args.protocol.upper()}")
    print("="*60)
    print()
    
    # Initialize analyzer
    analyzer = NetworkAnalyzer(args.pcap_file, args.protocol)
    
    # Analyze PCAP
    print("📊 Analyzing PCAP file...")
    connections = analyzer.analyze_pcap()
    print(f"✅ Found {len(connections)} geo-located connections")
    
    # Generate outputs
    print("\n📈 Generating statistics report...")
    analyzer.generate_statistics_report()
    
    print("\n🗺️  Generating KML map...")
    analyzer.generate_kml()
    
    print("\n🌐 Generating HTML report...")
    analyzer.generate_html_report()
    
    print("\n" + "="*60)
    print("✅ ANALYSIS COMPLETE!")
    print("="*60)
    print("📁 Generated files:")
    print("   ✓ traffic2_statistics.txt - Statistics Report")
    print("   ✓ traffic2_map.kml - Geographic Visualization")
    print("   ✓ traffic2_report.html - Interactive Report")
    print("="*60)
    print("\n💡 Tip: Open traffic2_map.kml in Google Earth")
    print("💡 Tip: Open traffic2_report.html in your browser")

if __name__ == '__main__':
    main()