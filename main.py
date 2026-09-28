"""Analyze a Wireshark capture (.pcap / .pcapng) from the command line.

Produces, next to the capture (or in --out-dir):
  <name>_statistics.txt   text summary + security alerts
  <name>_map.kml          open in Google My Maps / Google Earth
  <name>_hosts.csv        one row per remote host
  <name>_report.html      self-contained interactive dashboard (map, charts, tables)
  <name>_data.json        raw analysis data
"""
import argparse
import os
import sys
import time

import analyzer as core


def main():
    parser = argparse.ArgumentParser(description='Network traffic geolocation analyzer')
    parser.add_argument('pcap_file', nargs='?', default='traffic2.pcap',
                        help='capture to analyze (default: traffic2.pcap)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'icmp'], help='only analyze this protocol')
    parser.add_argument('--my-ip', help='your public IP when the capture was taken (default: auto-detect)')
    parser.add_argument('--home', help='override your map location as "lat,lon"')
    parser.add_argument('--out-dir', help='where to write reports (default: next to the capture)')
    parser.add_argument('--geoip-db', help='GeoLiteCity.dat or a GeoLite2/DB-IP City .mmdb '
                                           '(default: a *city*.mmdb in this folder, else GeoLiteCity.dat)')
    parser.add_argument('--no-rdns', action='store_true', help='skip reverse-DNS lookups (faster, fully offline)')
    parser.add_argument('--no-ip-lookup', action='store_true', help="don't query the internet for your public IP")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap_file):
        sys.exit(f'Capture file not found: {args.pcap_file}')

    geo = core.GeoLocator(args.geoip_db)
    if geo.error:
        print(f'WARNING: {geo.error}\n         Hosts will not be placed on the map.')
    home = core.resolve_home(geo, args.my_ip, args.home, lookup_ip=not args.no_ip_lookup)

    print(f'Capture:   {args.pcap_file}')
    print(f'GeoIP DB:  {os.path.basename(geo.db_path)}{"" if geo.supports_ipv6 else " (IPv4 only)"}')
    print(f'Your IP:   {home["ip"] or "unknown"} ({home["label"]})')
    if args.protocol:
        print(f'Filter:    {args.protocol.upper()} only')

    started = time.time()

    def progress(frac):
        print(f'\rAnalyzing... {frac * 100:5.1f}%', end='', flush=True)

    try:
        result = core.analyze_file(args.pcap_file, geo, home, resolve_rdns=not args.no_rdns,
                                   protocol_filter=args.protocol, progress=progress)
    except (ValueError, OSError) as e:
        sys.exit(f'\nCould not read capture: {e}')
    print(f'\rAnalyzed {result.total_packets:,} packets in {time.time() - started:.1f}s')
    if not args.no_rdns:
        print('Resolving hostnames...')
        result.wait_for_rdns(timeout=15)
    result.close()
    snap = result.snapshot(max_endpoints=100000)

    out_dir = args.out_dir or os.path.dirname(os.path.abspath(args.pcap_file))
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.splitext(os.path.basename(args.pcap_file))[0]
    outputs = {
        f'{stem}_statistics.txt': core.to_text_report(snap),
        f'{stem}_map.kml': core.to_kml(snap),
        f'{stem}_hosts.csv': core.to_csv(snap),
        f'{stem}_report.html': core.to_html_report(snap),
        f'{stem}_data.json': core.to_json(snap),
    }
    for name, content in outputs.items():
        with open(os.path.join(out_dir, name), 'w', encoding='utf-8') as f:
            f.write(content)

    print()
    print(outputs[f'{stem}_statistics.txt'])
    print('Generated:')
    for name in outputs:
        print(f'  {os.path.join(out_dir, name)}')
    print('\nOpen the _report.html in a browser, or import the .kml into https://www.google.com/mymaps')


if __name__ == '__main__':
    main()
