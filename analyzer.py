"""Core traffic analysis engine shared by the live dashboard (app.py) and the CLI (main.py).

Packets come in as dpkt IP/IP6 objects (from a PCAP file or a live scapy capture) and are
aggregated per remote host: geolocation, hostname (from DNS answers, TLS SNI, HTTP Host or
reverse DNS), services, bytes in/out and security alerts.
"""
import csv
import io
import ipaddress
import json
import math
import os
import re
import socket
import struct
import threading
import time
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from functools import lru_cache
from xml.sax.saxutils import escape as xml_escape

import dpkt
import pygeoip

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_GEOIP_DB = os.path.join(BASE_DIR, 'GeoLiteCity.dat')

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------

# (transport, port) -> service. Transport None matches both TCP and UDP.
SERVICES = {
    ('UDP', 443): 'QUIC', ('TCP', 443): 'HTTPS', (None, 80): 'HTTP', (None, 8080): 'HTTP-alt',
    (None, 8443): 'HTTPS-alt', (None, 53): 'DNS', (None, 853): 'DNS-over-TLS', (None, 5353): 'mDNS',
    (None, 5355): 'LLMNR', (None, 22): 'SSH', (None, 21): 'FTP', (None, 20): 'FTP-data',
    (None, 23): 'Telnet', (None, 25): 'SMTP', (None, 465): 'SMTPS', (None, 587): 'SMTP-submission',
    (None, 110): 'POP3', (None, 995): 'POP3S', (None, 143): 'IMAP', (None, 993): 'IMAPS',
    (None, 123): 'NTP', (None, 67): 'DHCP', (None, 68): 'DHCP', (None, 1900): 'SSDP',
    (None, 3389): 'RDP', (None, 445): 'SMB', (None, 139): 'NetBIOS', (None, 137): 'NetBIOS',
    (None, 135): 'MS-RPC', (None, 3306): 'MySQL', (None, 5432): 'PostgreSQL', (None, 6379): 'Redis',
    (None, 27017): 'MongoDB', (None, 5222): 'XMPP', (None, 5223): 'Apple Push',
    (None, 5228): 'Google Push', (None, 3478): 'STUN/TURN', (None, 19302): 'STUN (Google)',
    (None, 1194): 'OpenVPN', (None, 51820): 'WireGuard', (None, 500): 'IPsec IKE',
    (None, 4500): 'IPsec NAT-T', (None, 5900): 'VNC', (None, 1883): 'MQTT', (None, 8883): 'MQTT-TLS',
    (None, 9001): 'Tor', (None, 9050): 'Tor SOCKS', (None, 6667): 'IRC', (None, 4444): 'Metasploit',
    (None, 161): 'SNMP', (None, 514): 'Syslog', (None, 389): 'LDAP', (None, 636): 'LDAPS',
    (None, 88): 'Kerberos', (None, 1433): 'MSSQL', (None, 3000): 'Dev server', (None, 5000): 'Dev server',
}

ENCRYPTED_SERVICES = {'HTTPS', 'QUIC', 'HTTPS-alt', 'SSH', 'DNS-over-TLS', 'SMTPS', 'POP3S', 'IMAPS',
                      'OpenVPN', 'WireGuard', 'IPsec IKE', 'IPsec NAT-T', 'LDAPS', 'MQTT-TLS',
                      'Apple Push', 'Google Push'}
PLAINTEXT_SERVICES = {'HTTP', 'HTTP-alt', 'FTP', 'FTP-data', 'Telnet', 'POP3', 'IMAP', 'SMTP', 'LDAP'}

# Ports that are suspicious when seen talking to/from the public internet.
RISKY_PORTS = {
    4444: ('high', 'Port 4444 is the default Metasploit/Meterpreter handler'),
    31337: ('high', 'Port 31337 is a classic backdoor ("elite") port'),
    1337: ('medium', 'Port 1337 is frequently used by backdoors and malware'),
    6667: ('medium', 'IRC is commonly used for botnet command-and-control'),
    23: ('high', 'Telnet sends credentials in cleartext'),
    445: ('high', 'SMB over the internet is a common worm/ransomware vector'),
    139: ('medium', 'NetBIOS over the internet leaks host information'),
    135: ('medium', 'MS-RPC exposed to the internet'),
    3389: ('medium', 'RDP to/from the internet is a brute-force target'),
    5900: ('medium', 'VNC to/from the internet is often unauthenticated'),
    9001: ('low', 'Port 9001 is a common Tor relay port'),
    9050: ('low', 'Port 9050 is the Tor SOCKS proxy'),
}

# Hostname fragment -> organisation, checked in order.
ORG_HINTS = [
    ('youtube', 'YouTube'), ('googlevideo', 'YouTube'), ('ytimg', 'YouTube'),
    ('1e100.net', 'Google'), ('google', 'Google'), ('gstatic', 'Google'), ('gvt1', 'Google'),
    ('doubleclick', 'Google Ads'), ('cloudfront', 'Amazon CloudFront'), ('amazonaws', 'Amazon AWS'),
    ('aws', 'Amazon AWS'), ('amazon', 'Amazon'), ('akamai', 'Akamai'), ('edgekey', 'Akamai'),
    ('edgesuite', 'Akamai'), ('fbcdn', 'Meta'), ('facebook', 'Meta'), ('instagram', 'Meta'),
    ('whatsapp', 'WhatsApp'), ('icloud', 'Apple'), ('apple', 'Apple'), ('mzstatic', 'Apple'),
    ('aaplimg', 'Apple'), ('microsoft', 'Microsoft'), ('msedge', 'Microsoft'), ('azure', 'Microsoft Azure'),
    ('office', 'Microsoft'), ('live.com', 'Microsoft'), ('windows', 'Microsoft'), ('bing', 'Microsoft'),
    ('msn.com', 'Microsoft'), ('skype', 'Microsoft'), ('cloudflare', 'Cloudflare'), ('fastly', 'Fastly'),
    ('netflix', 'Netflix'), ('nflx', 'Netflix'), ('twimg', 'X / Twitter'), ('twitter', 'X / Twitter'),
    ('github', 'GitHub'), ('spotify', 'Spotify'), ('zoom', 'Zoom'), ('slack', 'Slack'),
    ('discord', 'Discord'), ('telegram', 'Telegram'), ('reddit', 'Reddit'), ('linkedin', 'LinkedIn'),
    ('tiktok', 'TikTok'), ('bytedance', 'ByteDance'), ('yahoo', 'Yahoo'), ('stackoverflow', 'Stack Overflow'),
    ('anthropic', 'Anthropic'), ('openai', 'OpenAI'), ('vercel', 'Vercel'), ('flipkart', 'Flipkart'),
    ('flixcart', 'Flipkart'), ('live-video.net', 'Amazon IVS / Twitch'), ('twitch', 'Twitch'),
    ('media-amazon', 'Amazon'), ('ssl-images-amazon', 'Amazon'), ('jio', 'Jio'), ('airtel', 'Airtel'),
]

SEVERITY_RANK = {'high': 3, 'medium': 2, 'low': 1}
_CGNAT = ipaddress.ip_network('100.64.0.0/10')
_HTTP_METHODS = (b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'OPTIONS ', b'PATCH ', b'CONNECT ')
_HTTP_HOST_RE = re.compile(rb'\r\nhost:[ \t]*([^\r\n:]+)', re.IGNORECASE)


def service_name(transport, port):
    return SERVICES.get((transport, port)) or SERVICES.get((None, port))


def guess_org(hostname):
    if not hostname:
        return None
    h = hostname.lower()
    for fragment, org in ORG_HINTS:
        if fragment in h:
            return org
    return None


@lru_cache(maxsize=65536)
def is_local(ip):
    """True for addresses that are not routable on the public internet (can't be geolocated)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 4 and addr in _CGNAT:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified or addr.is_reserved or ip == '255.255.255.255')


def address_unit(ip):
    """IPv4 address, or the /64 prefix of an IPv6 address (hosts rotate addresses inside their /64)."""
    if ':' not in ip:
        return ip
    try:
        return str(ipaddress.ip_network(ip + '/64', strict=False).network_address)
    except ValueError:
        return ip


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def extract_sni(data):
    """Return the server name from a TLS ClientHello, or None."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32                       # record hdr, handshake hdr, version, random
        pos += 1 + data[pos]                       # session id
        pos += 2 + struct.unpack('!H', data[pos:pos + 2])[0]   # cipher suites
        pos += 1 + data[pos]                       # compression methods
        end = min(len(data), pos + 2 + struct.unpack('!H', data[pos:pos + 2])[0])
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack('!HH', data[pos:pos + 4])
            pos += 4
            if ext_type == 0:                      # server_name
                name_len = struct.unpack('!H', data[pos + 3:pos + 5])[0]
                name = data[pos + 5:pos + 5 + name_len].decode('ascii', 'ignore').strip().lower()
                return name or None
            pos += ext_len
    except (IndexError, struct.error):
        pass
    return None


def extract_http_host(data):
    if not data.startswith(_HTTP_METHODS):
        return None
    m = _HTTP_HOST_RE.search(data[:4096])
    return m.group(1).decode('ascii', 'ignore').strip().lower() if m else None


# ---------------------------------------------------------------------------
# Geolocation & "home" detection
# ---------------------------------------------------------------------------

def default_geoip_db():
    """Prefer a modern MaxMind/DB-IP .mmdb (IPv4 + IPv6) if one is in the project folder."""
    for name in sorted(os.listdir(BASE_DIR)):
        if name.endswith('.mmdb') and 'city' in name.lower():
            return os.path.join(BASE_DIR, name)
    return DEFAULT_GEOIP_DB


class GeoLocator:
    """Looks up IPs in a legacy GeoLiteCity.dat (IPv4 only) or a GeoLite2/DB-IP .mmdb (IPv4 + IPv6)."""

    def __init__(self, db_path=None):
        self.db_path = db_path or default_geoip_db()
        self.error = None
        self._lock = threading.Lock()
        self._cache = {}
        self._gi = self._mmdb = None
        try:
            if self.db_path.endswith('.mmdb'):
                import maxminddb
                self._mmdb = maxminddb.open_database(self.db_path)
            else:
                self._gi = pygeoip.GeoIP(self.db_path, pygeoip.MEMORY_CACHE)
        except Exception as e:  # missing/corrupt database: everything still works, just no map
            self.error = f'Could not load GeoIP database {self.db_path}: {e}'

    @property
    def available(self):
        return self._gi is not None or self._mmdb is not None

    @property
    def supports_ipv6(self):
        return self._mmdb is not None

    def lookup(self, ip):
        if ip in self._cache:
            return self._cache[ip]
        result = None
        if not is_local(ip):
            try:
                if self._mmdb is not None:
                    result = self._lookup_mmdb(ip)
                elif self._gi is not None and ':' not in ip:
                    with self._lock:
                        rec = self._gi.record_by_addr(ip)
                    if rec and rec.get('latitude') is not None:
                        result = {
                            'city': rec.get('city') or None,
                            'region': rec.get('region_code') or None,
                            'country': rec.get('country_name') or 'Unknown',
                            'cc': rec.get('country_code') or '',
                            'lat': round(rec['latitude'], 4),
                            'lon': round(rec['longitude'], 4),
                        }
            except Exception:
                result = None
        self._cache[ip] = result
        return result

    def _lookup_mmdb(self, ip):
        rec = self._mmdb.get(ip)
        loc = (rec or {}).get('location') or {}
        if loc.get('latitude') is None:
            return None
        name = lambda d: ((d or {}).get('names') or {}).get('en')
        subdivisions = rec.get('subdivisions') or [{}]
        return {
            'city': name(rec.get('city')),
            'region': name(subdivisions[0]),
            'country': name(rec.get('country')) or 'Unknown',
            'cc': (rec.get('country') or {}).get('iso_code') or '',
            'lat': round(loc['latitude'], 4),
            'lon': round(loc['longitude'], 4),
        }


def detect_public_ip(timeout=3):
    for url in ('https://api.ipify.org', 'https://icanhazip.com', 'https://ifconfig.me/ip'):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'curl/8'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode().strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return None


def resolve_home(geo, my_ip=None, home=None, lookup_ip=True):
    """Work out where 'you' are on the map.

    `home` is an optional "lat,lon" string that overrides geolocation.
    """
    ip = my_ip or (detect_public_ip() if lookup_ip else None)
    info = {'ip': ip, 'lat': None, 'lon': None, 'label': 'You', 'source': None}
    if ip:
        g = geo.lookup(ip)
        if g:
            info.update(lat=g['lat'], lon=g['lon'], source='geoip',
                        label=', '.join(x for x in (g['city'], g['country']) if x))
    if home:
        lat, lon = (float(x) for x in home.split(','))
        info.update(lat=lat, lon=lon, source='manual', label='Home')
    return info


# ---------------------------------------------------------------------------
# Link-layer decoding for PCAP / PCAPNG files
# ---------------------------------------------------------------------------

def _raw_ip(buf):
    if not buf:
        return None
    version = buf[0] >> 4
    if version == 4:
        return dpkt.ip.IP(buf)
    if version == 6:
        return dpkt.ip6.IP6(buf)
    return None


def decode_link(linktype, buf):
    """Return a dpkt IP/IP6 object for a frame, or None if it isn't IP."""
    if linktype == 1:                               # Ethernet
        data = dpkt.ethernet.Ethernet(buf).data
    elif linktype in (101, 12, 14, 228, 229):       # Raw IP
        data = _raw_ip(buf)
    elif linktype in (0, 108):                      # BSD loopback / null
        data = _raw_ip(buf[4:])
    elif linktype == 113:                           # Linux cooked capture
        data = dpkt.sll.SLL(buf).data
    elif linktype == 276:                           # Linux cooked capture v2
        data = _raw_ip(buf[20:])
    else:
        return None
    return data if isinstance(data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def iter_capture_file(path, progress=None):
    """Yield (timestamp, ip, frame_length) for every frame in a pcap/pcapng file.

    Non-IP frames yield ip=None so callers can still count them.
    """
    size = os.path.getsize(path) or 1
    with open(path, 'rb') as f:
        magic = f.read(4)
        f.seek(0)
        reader = dpkt.pcapng.Reader(f) if magic == b'\x0a\x0d\x0d\x0a' else dpkt.pcap.Reader(f)
        linktype = reader.datalink()
        if linktype in (105, 127):
            raise ValueError('802.11 / radiotap captures are not supported - capture in non-monitor mode')
        last_report = 0
        for i, (ts, buf) in enumerate(reader):
            try:
                ip = decode_link(linktype, buf)
            except (dpkt.UnpackError, IndexError, ValueError):
                ip = None
            yield ts, ip, len(buf)
            if progress and i - last_report >= 2000:
                last_report = i
                progress(min(f.tell() / size, 1.0))


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class TrafficAnalyzer:
    MAX_ALERTS = 500
    SCAN_THRESHOLD = 20        # distinct ports probed by one host before it's flagged as a scan
    EXFIL_BYTES = 100 * 1024 * 1024

    def __init__(self, geo, home=None, live=False, resolve_rdns=True, protocol_filter=None, source=None):
        self.geo = geo
        self.home = home or {}
        self.live = live
        self.protocol_filter = protocol_filter.upper() if protocol_filter else None
        self.source = source
        self.lock = threading.RLock()
        self.version = 0
        self._rdns_pool = ThreadPoolExecutor(max_workers=8) if resolve_rdns else None
        self._rdns_pending = set()

        self.total_packets = 0
        self.total_bytes = 0
        self.non_ip_packets = 0
        self.lan_packets = 0
        self.filtered_packets = 0
        self.first_ts = None
        self.last_ts = None
        self.protocols = Counter()
        self.services = {}          # name -> [packets, bytes]
        self.local_hosts = {}       # ip -> [packets, bytes]
        self.endpoints = {}         # remote ip -> dict
        self.hostnames = {}         # ip -> (name, priority)
        self.domains = Counter()
        self.flows = {}
        self.timeline = {}          # int second -> [bytes, packets]
        self.alerts = []
        self._alert_keys = set()
        self._syn_ports = {}        # (scanner, target) -> set(ports)
        self.feed = deque(maxlen=200)
        # Public addresses that belong to the capturing machine (IPv6 has no NAT, so they look "remote")
        self.self_units = set()
        if self.home.get('ip'):
            self.self_units.add(address_unit(self.home['ip']))

    def add_self_addresses(self, ips):
        with self.lock:
            self.self_units.update(address_unit(ip) for ip in ips if ip and not is_local(ip))

    def _is_self(self, ip):
        return address_unit(ip) in self.self_units if self.self_units else False

    # -- ingestion ---------------------------------------------------------

    def count_non_ip(self, length):
        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            self.non_ip_packets += 1

    def ingest(self, ts, ip, length):
        if ip is None:
            self.count_non_ip(length)
            return
        try:
            if isinstance(ip, dpkt.ip6.IP6):
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
        except (ValueError, OSError):
            self.count_non_ip(length)
            return

        l4 = ip.data
        sport = dport = 0
        tcp_flags = None
        if isinstance(l4, dpkt.tcp.TCP):
            proto, sport, dport, tcp_flags = 'TCP', l4.sport, l4.dport, l4.flags
        elif isinstance(l4, dpkt.udp.UDP):
            proto, sport, dport = 'UDP', l4.sport, l4.dport
        elif isinstance(l4, dpkt.icmp.ICMP):
            proto = 'ICMP'
        elif isinstance(l4, dpkt.icmp6.ICMP6):
            proto = 'ICMPv6'
        else:
            proto = 'Other'

        with self.lock:
            self.total_packets += 1
            self.total_bytes += length
            if self.protocol_filter and proto != self.protocol_filter:
                self.filtered_packets += 1
                return
            self.version += 1
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
            self.protocols[proto] += 1
            bucket = self.timeline.setdefault(int(ts), [0, 0])
            bucket[0] += length
            bucket[1] += 1

            self._inspect_payload(ts, src, dst, sport, dport, l4, proto)

            # Work out which side is "us" and which side is the remote host
            src_local = is_local(src) or self._is_self(src)
            dst_local = is_local(dst) or self._is_self(dst)
            if src_local and dst_local:
                self.lan_packets += 1
                for h in (src, dst):
                    if not ip_is_special(h):
                        self._bump(self.local_hosts, h, length)
                return
            if src_local:
                local, remote, lport, rport, outbound = src, dst, sport, dport, True
            else:
                local, remote, lport, rport, outbound = dst, src, dport, sport, False
            self._bump(self.local_hosts, local, length)

            if proto in ('TCP', 'UDP'):
                if service_name(proto, rport):
                    svc_port = rport
                elif service_name(proto, lport):
                    svc_port = lport
                else:
                    svc_port = rport if outbound else min(rport, lport)
                svc = service_name(proto, svc_port) or f'{proto}/{svc_port}'
            else:
                svc_port, svc = 0, proto
            self._bump(self.services, svc, length)

            ep = self.endpoints.get(remote)
            if ep is None:
                ep = self._new_endpoint(remote, ts)
            ep['packets'] += 1
            ep['bytes_out' if outbound else 'bytes_in'] += length
            ep['last_seen'] = ts
            ep['services'][svc] += 1
            ep['protocols'].add(proto)
            if svc_port and len(ep['ports']) < 50:
                ep['ports'].add(svc_port)
            if len(ep['locals']) < 50:
                ep['locals'].add(local)

            flow_key = (local, remote, proto, svc_port)
            flow = self.flows.get(flow_key)
            if flow is None:
                # [first_seen, packets, bytes, rules_checked, started_by_remote]
                flow = self.flows[flow_key] = [ts, 0, 0, False, not outbound]
                self.feed.append({'ts': ts, 'local': local, 'remote': remote, 'port': svc_port,
                                  'proto': proto, 'service': svc, 'outbound': outbound})
            flow[1] += 1
            flow[2] += length
            if not flow[3] and self._flow_is_real(flow, outbound, tcp_flags):
                flow[3] = True
                self._check_flow_rules(ts, remote, lport, rport, svc)

            if tcp_flags is not None and tcp_flags & dpkt.tcp.TH_SYN and not tcp_flags & dpkt.tcp.TH_ACK:
                self._track_syn(ts, src, dst, dport)
            if outbound and ep['bytes_out'] >= self.EXFIL_BYTES:
                self._alert(ts, 'medium', 'large-upload', remote,
                            f'More than {self.EXFIL_BYTES // (1024 * 1024)} MB uploaded to {self._label(remote)}')

    def _bump(self, table, key, length):
        row = table.get(key)
        if row is None:
            table[key] = [1, length]
        else:
            row[0] += 1
            row[1] += length

    def _new_endpoint(self, ip, ts):
        geo = self.geo.lookup(ip)
        ep = {'ip': ip, 'geo': geo, 'packets': 0, 'bytes_in': 0, 'bytes_out': 0,
              'first_seen': ts, 'last_seen': ts, 'services': Counter(), 'protocols': set(),
              'ports': set(), 'locals': set(), 'alerts': 0, 'max_sev': 0}
        self.endpoints[ip] = ep
        if ip not in self.hostnames and self._rdns_pool and ip not in self._rdns_pending:
            self._rdns_pending.add(ip)
            self._rdns_pool.submit(self._reverse_dns, ip)
        return ep

    def _reverse_dns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0].lower()
        except (OSError, UnicodeError):
            name = None
        with self.lock:
            self._rdns_pending.discard(ip)
            if name:
                self._set_hostname(ip, name, 1)

    def _set_hostname(self, ip, name, priority):
        current = self.hostnames.get(ip)
        if current is None or priority >= current[1]:
            if current is None or current[0] != name:
                self.version += 1
            self.hostnames[ip] = (name, priority)

    def _inspect_payload(self, ts, src, dst, sport, dport, l4, proto):
        """Pull hostnames out of DNS answers, TLS ClientHellos and HTTP requests."""
        payload = getattr(l4, 'data', b'')
        if not isinstance(payload, bytes) or not payload:
            return
        if proto == 'UDP' and 53 in (sport, dport) or proto == 'UDP' and 5353 in (sport, dport):
            try:
                dns = dpkt.dns.DNS(payload)
            except (dpkt.UnpackError, IndexError, ValueError):
                return
            if not dns.qd:
                return
            qname = dns.qd[0].name.lower().rstrip('.')
            if dns.qr == dpkt.dns.DNS_Q:
                if dport == 53 and qname:
                    self.domains[qname] += 1
                    self._check_domain(ts, src, qname)
            else:
                for rr in dns.an:
                    if rr.type == dpkt.dns.DNS_A and len(rr.rdata) == 4:
                        self._set_hostname(socket.inet_ntoa(rr.rdata), qname, 2)
                    elif rr.type == dpkt.dns.DNS_AAAA and len(rr.rdata) == 16:
                        self._set_hostname(socket.inet_ntop(socket.AF_INET6, rr.rdata), qname, 2)
        elif proto == 'TCP':
            name = extract_sni(payload) if payload[0] == 0x16 else extract_http_host(payload)
            if name:
                self._set_hostname(dst, name, 3)

    # -- detection rules ---------------------------------------------------

    def _alert(self, ts, severity, rule, ip, message):
        key = (rule, ip, message)
        if key in self._alert_keys:
            return
        self._alert_keys.add(key)
        self.alerts.append({'ts': ts, 'severity': severity, 'rule': rule, 'ip': ip, 'message': message})
        if len(self.alerts) > self.MAX_ALERTS:
            self.alerts.pop(0)
        ep = self.endpoints.get(ip)
        if ep:
            ep['alerts'] += 1
            ep['max_sev'] = max(ep['max_sev'], SEVERITY_RANK[severity])
        self.version += 1

    def _label(self, ip):
        name = self.hostnames.get(ip)
        return f'{name[0]} ({ip})' if name else ip

    @staticmethod
    def _flow_is_real(flow, outbound, tcp_flags):
        """Only judge a connection once it is more than an unanswered probe (scans have their own rule)."""
        if tcp_flags is None:
            return True
        if tcp_flags & dpkt.tcp.TH_RST:
            return False
        if flow[4]:        # remote host opened it: wait until it completes the handshake
            return not outbound and bool(tcp_flags & dpkt.tcp.TH_ACK)
        return True

    def _check_flow_rules(self, ts, remote, lport, rport, svc):
        risky = False
        for port in (rport, lport):
            if port in RISKY_PORTS:
                risky = True
                sev, why = RISKY_PORTS[port]
                self._alert(ts, sev, f'risky-port-{port}', remote, f'{why} - traffic with {self._label(remote)}')
        if svc in PLAINTEXT_SERVICES and not risky:
            self._alert(ts, 'low', 'plaintext', remote,
                        f'Unencrypted {svc} with {self._label(remote)} - contents are readable on the wire')

    def _track_syn(self, ts, scanner, target, port):
        key = (scanner, target)
        ports = self._syn_ports.setdefault(key, set())
        if len(ports) <= self.SCAN_THRESHOLD:
            ports.add(port)
            if len(ports) == self.SCAN_THRESHOLD:
                inbound = not is_local(scanner)
                remote = scanner if inbound else target
                if inbound:
                    msg = f'Port scan: {self._label(scanner)} probed {self.SCAN_THRESHOLD}+ ports on {target}'
                else:
                    msg = f'Outbound scan: {scanner} probed {self.SCAN_THRESHOLD}+ ports on {self._label(target)}'
                self._alert(ts, 'high' if inbound else 'medium', 'port-scan', remote, msg)

    def _check_domain(self, ts, src, qname):
        labels = qname.split('.')
        longest = max(labels, key=len)
        if len(qname) > 100 or len(longest) > 50:
            self._alert(ts, 'medium', 'dns-tunnel', src,
                        f'Unusually long DNS query from {src} (possible DNS tunnelling): {qname[:80]}...')
        elif len(longest) >= 20 and shannon_entropy(longest) > 4.0 and not any(c == '-' for c in longest):
            self._alert(ts, 'low', 'dga', src,
                        f'Random-looking domain queried by {src} (possible DGA malware): {qname}')

    # -- output ------------------------------------------------------------

    def wait_for_rdns(self, timeout=10):
        deadline = time.time() + timeout
        while self._rdns_pending and time.time() < deadline:
            time.sleep(0.1)

    def close(self):
        if self._rdns_pool:
            self._rdns_pool.shutdown(wait=False, cancel_futures=True)

    def _endpoint_row(self, ep):
        host = self.hostnames.get(ep['ip'])
        hostname = host[0] if host else None
        services = [s for s, _ in ep['services'].most_common()]
        app_services = [s for s in services if s not in ('ICMP', 'ICMPv6')]   # control traffic, not content
        if ep['max_sev'] >= 2:
            status = 'alert'
        elif any(s in PLAINTEXT_SERVICES for s in services) or ep['max_sev'] == 1:
            status = 'plaintext'
        elif app_services and all(s in ENCRYPTED_SERVICES for s in app_services):
            status = 'encrypted'
        else:
            status = 'other'
        geo = ep['geo'] or {}
        return {
            'ip': ep['ip'], 'hostname': hostname, 'org': guess_org(hostname),
            'city': geo.get('city'), 'country': geo.get('country'), 'cc': geo.get('cc'),
            'lat': geo.get('lat'), 'lon': geo.get('lon'),
            'packets': ep['packets'], 'bytes_in': ep['bytes_in'], 'bytes_out': ep['bytes_out'],
            'bytes': ep['bytes_in'] + ep['bytes_out'], 'services': services[:4],
            'ports': sorted(ep['ports'])[:12], 'protocols': sorted(ep['protocols']),
            'first_seen': ep['first_seen'], 'last_seen': ep['last_seen'],
            'alerts': ep['alerts'], 'status': status, 'locals': sorted(ep['locals'])[:5],
        }

    def _timeline(self):
        if not self.timeline:
            return {'start': None, 'bucket': 1, 'bytes': [], 'packets': []}
        if self.live:
            end = int(max(self.last_ts or 0, time.time()))
            start, bucket = end - 119, 1
            for sec in [s for s in self.timeline if s < end - 600]:
                del self.timeline[sec]
        else:
            start, end = int(self.first_ts), int(self.last_ts)
            bucket = max(1, math.ceil((end - start + 1) / 120))
        n = (end - start) // bucket + 1
        byte_series, pkt_series = [0] * n, [0] * n
        for sec, (b, p) in self.timeline.items():
            if start <= sec <= end:
                idx = (sec - start) // bucket
                byte_series[idx] += b
                pkt_series[idx] += p
        return {'start': start, 'bucket': bucket, 'bytes': byte_series, 'packets': pkt_series}

    def snapshot(self, max_endpoints=600):
        with self.lock:
            rows = [self._endpoint_row(ep) for ep in self.endpoints.values()]
            rows.sort(key=lambda r: r['bytes'], reverse=True)

            countries = {}
            for r in rows:
                if not r['country']:
                    continue
                c = countries.setdefault(r['country'], {'country': r['country'], 'cc': r['cc'], 'hosts': 0,
                                                        'bytes': 0, 'packets': 0, 'alerts': 0})
                c['hosts'] += 1
                c['bytes'] += r['bytes']
                c['packets'] += r['packets']
                c['alerts'] += r['alerts']

            duration = (self.last_ts - self.first_ts) if self.first_ts is not None else 0
            sev_counts = Counter(a['severity'] for a in self.alerts)
            analyzed_bytes = sum(r['bytes'] for r in rows)
            return {
                'version': self.version,
                'source': self.source,
                'live': self.live,
                'home': self.home,
                'generated_at': time.time(),
                'summary': {
                    'packets': self.total_packets,
                    'bytes': self.total_bytes,
                    'internet_bytes': analyzed_bytes,
                    'non_ip_packets': self.non_ip_packets,
                    'lan_packets': self.lan_packets,
                    'filtered_packets': self.filtered_packets,
                    'protocol_filter': self.protocol_filter,
                    'remote_hosts': len(rows),
                    'mapped_hosts': sum(1 for r in rows if r['lat'] is not None),
                    'local_hosts': len(self.local_hosts),
                    'countries': len(countries),
                    'flows': len(self.flows),
                    'domains': len(self.domains),
                    'alerts': len(self.alerts),
                    'alerts_by_severity': dict(sev_counts),
                    'start': self.first_ts,
                    'end': self.last_ts,
                    'duration': duration,
                },
                'endpoints': rows[:max_endpoints],
                'countries': sorted(countries.values(), key=lambda c: c['bytes'], reverse=True),
                'protocols': dict(self.protocols.most_common()),
                'services': [{'name': k, 'packets': v[0], 'bytes': v[1]}
                             for k, v in sorted(self.services.items(), key=lambda kv: kv[1][1], reverse=True)][:15],
                'local_hosts': [{'ip': k, 'packets': v[0], 'bytes': v[1]}
                                for k, v in sorted(self.local_hosts.items(), key=lambda kv: kv[1][1], reverse=True)][:20],
                'domains': [{'name': d, 'count': c} for d, c in self.domains.most_common(100)],
                'timeline': self._timeline(),
                'alerts': sorted(self.alerts, key=lambda a: (SEVERITY_RANK[a['severity']], a['ts']), reverse=True),
                'feed': [dict(f, hostname=(self.hostnames.get(f['remote']) or (None,))[0]) for f in reversed(self.feed)][:100],
            }


def ip_is_special(ip):
    return ip in ('0.0.0.0', '255.255.255.255') or ip.startswith(('224.', '239.', 'ff0', '::'))


def infer_self_addresses(path, progress=None):
    """Guess which public addresses belong to the machine that took the capture.

    The capturing host talks to many peers; each remote server usually talks only to it.
    """
    peers = {}
    for _, ip, _ in iter_capture_file(path, progress):
        if ip is None:
            continue
        try:
            if isinstance(ip, dpkt.ip6.IP6):
                src = socket.inet_ntop(socket.AF_INET6, ip.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
            else:
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
        except (ValueError, OSError):
            continue
        if is_local(src) or is_local(dst):
            continue
        a, b = address_unit(src), address_unit(dst)
        for x, y in ((a, b), (b, a)):
            s = peers.setdefault(x, set())
            if len(s) < 2000:
                s.add(y)
    result = set()
    for family in (lambda u: ':' in u, lambda u: ':' not in u):
        degrees = {u: len(p) for u, p in peers.items() if family(u)}
        if degrees:
            top = max(degrees.values())
            result |= {u for u, d in degrees.items() if d >= max(3, top * 0.5)}
    return result


def analyze_file(path, geo, home=None, resolve_rdns=True, protocol_filter=None, progress=None, analyzer=None):
    analyzer = analyzer or TrafficAnalyzer(geo, home, live=False, resolve_rdns=resolve_rdns,
                                           protocol_filter=protocol_filter, source=os.path.basename(path))
    analyzer.self_units |= infer_self_addresses(path, (lambda f: progress(f * 0.3)) if progress else None)
    for ts, ip, length in iter_capture_file(path, (lambda f: progress(0.3 + f * 0.7)) if progress else None):
        analyzer.ingest(ts, ip, length)
    if progress:
        progress(1.0)
    return analyzer


# ---------------------------------------------------------------------------
# Exporters (all take a snapshot dict)
# ---------------------------------------------------------------------------

def fmt_bytes(n):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if n < 1024 or unit == 'GB':
            return f'{n:.0f} {unit}' if unit == 'B' else f'{n:.1f} {unit}'
        n /= 1024


def fmt_ts(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S') if ts else ''


def to_csv(snap):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(['ip', 'hostname', 'organisation', 'city', 'country', 'latitude', 'longitude', 'packets',
                'bytes_sent', 'bytes_received', 'services', 'ports', 'status', 'alerts', 'first_seen', 'last_seen'])
    for r in snap['endpoints']:
        w.writerow([r['ip'], r['hostname'] or '', r['org'] or '', r['city'] or '', r['country'] or '',
                    r['lat'] if r['lat'] is not None else '', r['lon'] if r['lon'] is not None else '',
                    r['packets'], r['bytes_out'], r['bytes_in'], ' '.join(r['services']),
                    ' '.join(map(str, r['ports'])), r['status'], r['alerts'],
                    fmt_ts(r['first_seen']), fmt_ts(r['last_seen'])])
    return out.getvalue()


def to_json(snap):
    return json.dumps(snap, indent=2, default=str)


# KML colours are aabbggrr
_KML_STYLES = {'alert': 'ff3c14e3', 'plaintext': 'ff1a9df5', 'encrypted': 'ff99cd05', 'other': 'ffff7a43'}


def to_kml(snap):
    home = snap.get('home') or {}
    has_home = home.get('lat') is not None
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2"><Document>',
             f'<name>{xml_escape("Network traffic - " + (snap.get("source") or "capture"))}</name>']
    for status, color in _KML_STYLES.items():
        parts.append(f'<Style id="{status}"><LineStyle><color>{color}</color><width>2</width></LineStyle>'
                     f'<IconStyle><color>{color}</color><scale>0.9</scale><Icon>'
                     f'<href>http://maps.google.com/mapfiles/kml/shapes/placemark_circle.png</href></Icon></IconStyle></Style>')
    if has_home:
        parts.append(f'<Placemark><name>{xml_escape(home.get("label") or "You")}</name>'
                     f'<description>{xml_escape(home.get("ip") or "")}</description>'
                     f'<Point><coordinates>{home["lon"]},{home["lat"]},0</coordinates></Point></Placemark>')

    by_country = {}
    for r in snap['endpoints']:
        if r['lat'] is not None:
            by_country.setdefault(r['country'] or 'Unknown', []).append(r)
    for country in sorted(by_country):
        parts.append(f'<Folder><name>{xml_escape(country)} ({len(by_country[country])})</name>')
        for r in by_country[country]:
            title = r['hostname'] or r['ip']
            desc = (f'IP: {r["ip"]}\nHost: {r["hostname"] or "-"}\nOrganisation: {r["org"] or "-"}\n'
                    f'Location: {", ".join(x for x in (r["city"], r["country"]) if x)}\n'
                    f'Services: {", ".join(r["services"])}\nPorts: {", ".join(map(str, r["ports"]))}\n'
                    f'Sent: {fmt_bytes(r["bytes_out"])}  Received: {fmt_bytes(r["bytes_in"])}  '
                    f'Packets: {r["packets"]}\nStatus: {r["status"]}  Alerts: {r["alerts"]}\n'
                    f'First seen: {fmt_ts(r["first_seen"])}\nLast seen: {fmt_ts(r["last_seen"])}')
            coords = f'{r["lon"]},{r["lat"]},0'
            geom = (f'<MultiGeometry><Point><coordinates>{coords}</coordinates></Point>'
                    f'<LineString><tessellate>1</tessellate><coordinates>{home["lon"]},{home["lat"]},0 {coords}'
                    f'</coordinates></LineString></MultiGeometry>') if has_home else \
                f'<Point><coordinates>{coords}</coordinates></Point>'
            parts.append(f'<Placemark><name>{xml_escape(title)}</name><description><![CDATA[{desc}]]></description>'
                         f'<styleUrl>#{r["status"]}</styleUrl>{geom}</Placemark>')
        parts.append('</Folder>')
    parts.append('</Document></kml>')
    return '\n'.join(parts)


def to_text_report(snap):
    s = snap['summary']
    home = snap.get('home') or {}
    line = '=' * 64
    out = [line, 'NETWORK TRAFFIC ANALYSIS REPORT', line, '',
           f'Source:            {snap.get("source") or "-"}',
           f'Your public IP:    {home.get("ip") or "unknown"}  ({home.get("label") or "-"})',
           f'Capture window:    {fmt_ts(s["start"])} -> {fmt_ts(s["end"])}  ({s["duration"]:.0f}s)', '',
           'OVERVIEW',
           f'  Total packets:         {s["packets"]:,}',
           f'  Total data:            {fmt_bytes(s["bytes"])}',
           f'  Internet data:         {fmt_bytes(s["internet_bytes"])}',
           f'  LAN-only packets:      {s["lan_packets"]:,}',
           f'  Non-IP packets:        {s["non_ip_packets"]:,}',
           f'  Local devices:         {s["local_hosts"]}',
           f'  Remote hosts:          {s["remote_hosts"]} ({s["mapped_hosts"]} geolocated)',
           f'  Countries:             {s["countries"]}',
           f'  Connections (flows):   {s["flows"]}',
           f'  DNS names queried:     {s["domains"]}',
           f'  Security alerts:       {s["alerts"]}', '', 'PROTOCOLS']
    out += [f'  {p:<8} {c:>10,} packets' for p, c in snap['protocols'].items()]
    out += ['', 'TOP SERVICES']
    out += [f'  {sv["name"]:<18} {fmt_bytes(sv["bytes"]):>10}  {sv["packets"]:>8,} packets' for sv in snap['services']]
    out += ['', 'TOP REMOTE HOSTS (by data)']
    for r in snap['endpoints'][:15]:
        loc = ', '.join(x for x in (r['city'], r['country']) if x) or 'unknown'
        out.append(f'  {r["ip"]:<16} {fmt_bytes(r["bytes"]):>10}  {(r["hostname"] or "-")[:38]:<38}  {loc}')
    out += ['', 'COUNTRIES']
    out += [f'  {c["country"]:<24} {c["hosts"]:>4} hosts  {fmt_bytes(c["bytes"]):>10}' for c in snap['countries']]
    out += ['', 'TOP DNS QUERIES']
    out += [f'  {d["count"]:>5}  {d["name"]}' for d in snap['domains'][:15]]
    out += ['', 'SECURITY ALERTS']
    out += [f'  [{a["severity"].upper():<6}] {a["message"]}' for a in snap['alerts'][:50]] or ['  none']
    out += ['', line]
    return '\n'.join(out) + '\n'


def to_html_report(snap):
    """A self-contained HTML copy of the dashboard with the data baked in."""
    import jinja2
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(BASE_DIR, 'templates')),
                             autoescape=True)
    with open(os.path.join(BASE_DIR, 'static', 'css', 'style.css')) as f:
        css = f.read()
    with open(os.path.join(BASE_DIR, 'static', 'js', 'dashboard.js')) as f:
        js = f.read()
    data = json.dumps(snap, default=str).replace('</', '<\\/')
    return env.get_template('index.html').render(static_mode=True, inline_css=css, inline_js=js, snapshot_json=data)
