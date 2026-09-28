"""NetMap dashboard server.

Easiest start: double-click NetMap.command (macOS) / start.bat (Windows), or run ./run_dashboard.sh.
Those set everything up and open http://127.0.0.1:5050 in your browser.

Live capture needs root. If the app isn't running as root, clicking "Start live" shows the normal
system password prompt and runs capture_helper.py with admin rights - no terminal sudo needed.

Run `python app.py --help` for all options.
"""
import argparse
import json
import logging
import os
import secrets
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser

import dpkt
from flask import Flask, Response, abort, jsonify, render_template, request
from flask_socketio import SocketIO
from werkzeug.utils import secure_filename

import analyzer as core

CAPTURE_EXTENSIONS = ('.pcap', '.pcapng', '.cap')
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), 'netmap_uploads')
HELPER_PATH = os.path.join(core.BASE_DIR, 'capture_helper.py')
HELPER_HEADER = struct.Struct('!cdII')     # must match capture_helper.py
DEFAULT_PORT = 5050

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.urandom(16).hex()
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024
socketio = SocketIO(app, async_mode='threading')


class Session:
    """Everything the dashboard is currently showing: one analyzer fed by live capture or a file."""

    def __init__(self, geo, home, resolve_rdns):
        self.geo = geo
        self.home = home
        self.resolve_rdns = resolve_rdns
        self.lock = threading.Lock()
        self.analyzer = core.TrafficAnalyzer(geo, home, live=True, resolve_rdns=resolve_rdns)
        self.mode = 'idle'          # idle | live | pcap
        self.source = None
        self.capturing = False
        self.starting = False       # waiting for the user to approve the password prompt
        self.loading = False
        self.progress = None
        self.error = None
        self._stop = threading.Event()
        self._pending = threading.Event()

    def status(self):
        return {
            'mode': self.mode, 'source': self.source, 'capturing': self.capturing, 'starting': self.starting,
            'loading': self.loading, 'progress': self.progress, 'error': self.error,
            'capture_access': capture_access(),
            'geoip': {'db': os.path.basename(self.geo.db_path), 'ok': self.geo.available,
                      'ipv6': self.geo.supports_ipv6, 'error': self.geo.error},
            'home': self.home,
        }

    def _replace_analyzer(self, live, source):
        self.analyzer.close()
        self.analyzer = core.TrafficAnalyzer(self.geo, self.home, live=live, resolve_rdns=self.resolve_rdns,
                                             source=source)
        self.source = source

    # -- live capture --------------------------------------------------------

    def start_capture(self, iface=None, bpf=None):
        iface = iface or None
        if self.capturing or self.loading or self.starting:
            return
        problem = capture_problem(iface)
        if problem is None:
            stop, analyzer = self._begin_live(iface)
            threading.Thread(target=self._capture_in_process, args=(iface, bpf, stop, analyzer), daemon=True).start()
        elif problem == PERMISSION_HELP and elevation_method():
            self.starting, self.error = True, None
            self._pending = threading.Event()
            threading.Thread(target=self._capture_with_helper, args=(iface, bpf, self._pending), daemon=True).start()
        else:
            self.error = problem            # keep whatever is on screen, just explain
        push_status()

    def _begin_live(self, iface):
        with self.lock:
            if self.mode != 'live':
                self._replace_analyzer(True, f'Live · {iface or default_iface()}')
            self.analyzer.add_self_addresses(local_addresses())
            self.mode, self.capturing, self.starting, self.error = 'live', True, False, None
            # A fresh Event per capture so a stopping thread can never be revived by a quick restart
            self._stop = threading.Event()
            return self._stop, self.analyzer

    def stop_capture(self):
        with self.lock:
            self._stop.set()
            self._pending.set()
            self.capturing = self.starting = False
        push_status()

    def _finish_live(self, stop, error=None):
        if error and not stop.is_set():
            self.error = error
        if self._stop is stop:              # a newer capture may already be running
            self.capturing = False
        push_status()

    def _capture_in_process(self, iface, bpf, stop, analyzer):
        from scapy.all import IP, IPv6, sniff

        def handle(pkt):
            if IP in pkt:
                ip = raw_to_ip(bytes(pkt[IP]))
            elif IPv6 in pkt:
                ip = raw_to_ip(bytes(pkt[IPv6]))
            else:
                ip = None
            analyzer.ingest(float(pkt.time), ip, len(pkt))

        error = None
        try:
            while not stop.is_set():
                sniff(iface=iface, filter=bpf or None, prn=handle, store=False, timeout=1,
                      stop_filter=lambda _: stop.is_set())
        except Exception as e:
            error = friendly_capture_error(e, bpf)
        self._finish_live(stop, error)

    def _capture_with_helper(self, iface, bpf, pending):
        """Run capture_helper.py as root via the OS password prompt and ingest what it streams back."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        srv.settimeout(0.5)
        token = secrets.token_hex(16)
        cmd = helper_command() + ['--port', str(srv.getsockname()[1]), '--token', token,
                                  '--iface', iface or default_iface()]
        if bpf:
            cmd += ['--filter', bpf]
        conn = reader = None
        try:
            proc = launch_elevated(cmd)
            deadline = time.time() + 300
            while conn is None:
                if pending.is_set():
                    return
                try:
                    candidate, _ = srv.accept()
                except socket.timeout:
                    if proc.poll() is not None:
                        err = proc.stderr.read().decode('utf-8', 'replace')
                        cancelled = '-128' in err or 'cancel' in err.lower() or proc.returncode in (126, 127)
                        last_line = next((l for l in reversed(err.strip().splitlines()) if l.strip()), '')
                        self.error = ('Live capture was cancelled at the password prompt.' if cancelled
                                      else f'Could not start live capture: {last_line or proc.returncode}')
                        return
                    if time.time() > deadline:
                        self.error = 'Timed out waiting for the password prompt.'
                        return
                    continue
                candidate.settimeout(10)
                candidate_reader = candidate.makefile('rb')     # keep using this one: it may already buffer frames
                if candidate_reader.readline().strip() == token.encode():
                    conn, reader = candidate, candidate_reader
                else:
                    candidate.close()
        except OSError as e:
            self.error = f'Could not start live capture: {e}'
            return
        finally:
            srv.close()
            if conn is None:
                self.starting = False
                push_status()

        conn.settimeout(None)
        stop, analyzer = self._begin_live(iface)
        push_status()
        # Closing the socket is how we tell the helper to stop
        threading.Thread(target=lambda: (stop.wait(), _shutdown(conn)), daemon=True).start()
        error = None
        linktype = 1
        try:
            while True:
                header = reader.read(HELPER_HEADER.size)
                if len(header) < HELPER_HEADER.size:
                    if not stop.is_set():
                        error = 'Live capture stopped unexpectedly.'
                    break
                kind, ts, value, size = HELPER_HEADER.unpack(header)
                payload = reader.read(size) if size else b''
                if kind == b'L':
                    linktype = value
                elif kind == b'E':
                    error = friendly_capture_error(Exception(payload.decode('utf-8', 'replace')), bpf)
                    break
                elif kind == b'P':
                    try:
                        ip = core.decode_link(linktype, payload)
                    except (dpkt.UnpackError, ValueError, IndexError):
                        ip = None
                    analyzer.ingest(ts, ip, value)
        except OSError:
            pass
        finally:
            _shutdown(conn)
            self._finish_live(stop, error)

    # -- PCAP files ------------------------------------------------------------

    def load_file(self, path, display_name):
        with self.lock:
            if self.loading:
                return False
            self._stop.set()
            self._pending.set()
            self.capturing = self.starting = False
            self._replace_analyzer(False, display_name)
            self.mode, self.loading, self.progress, self.error = 'pcap', True, 0.0, None
            analyzer = self.analyzer
        push_status()
        threading.Thread(target=self._load_worker, args=(path, analyzer), daemon=True).start()
        return True

    def _load_worker(self, path, analyzer):
        last = [0.0]

        def progress(frac):
            self.progress = frac
            if time.time() - last[0] > 0.25:
                last[0] = time.time()
                push_status()

        try:
            core.analyze_file(path, self.geo, self.home, progress=progress, analyzer=analyzer)
        except Exception as e:
            self.error = f'Could not read {os.path.basename(path)}: {e}'
        finally:
            self.loading, self.progress = False, None
            if path.startswith(UPLOAD_DIR):
                try:
                    os.remove(path)
                except OSError:
                    pass
            push_status()

    def reset(self):
        with self.lock:
            if self.loading:
                return
            self._stop.set()
            self._pending.set()
            self.capturing = self.starting = False
            self._replace_analyzer(True, None)
            self.mode, self.error = 'idle', None
        push_status()


session = None


# ---------------------------------------------------------------------------
# Capture permissions
# ---------------------------------------------------------------------------

PERMISSION_HELP = ('Live capture needs administrator access, and no password prompt is available on this '
                   'system. Start NetMap with "sudo ./run_dashboard.sh". Opening capture files works without it.')


def _shutdown(conn):
    try:
        conn.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


def raw_to_ip(payload):
    try:
        return core._raw_ip(payload)
    except (dpkt.UnpackError, ValueError, IndexError):
        return None


def is_root():
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def elevation_method():
    if is_root():
        return None
    if sys.platform == 'darwin' and shutil.which('osascript'):
        return 'macos'
    if sys.platform.startswith('linux') and shutil.which('pkexec') and (
            os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
        return 'pkexec'
    return None


def capture_access():
    """'ready' = can capture now, 'password' = will ask for the admin password, 'unavailable'."""
    if is_root() or sys.platform == 'win32':
        return 'ready'
    if os.path.exists('/dev/bpf0') and os.access('/dev/bpf0', os.R_OK):
        return 'ready'
    return 'password' if elevation_method() else 'unavailable'


ELEVATE_CLAUSE = ' with prompt "NetMap needs your password to watch network traffic on this Mac." with administrator privileges'


def helper_command():
    """Python + inline helper code that a root process can run.

    macOS privacy protection blocks root processes started from the password prompt from reading
    ~/Downloads, ~/Documents and ~/Desktop - so neither the project's .venv interpreter nor
    capture_helper.py on disk can be used there. Use the base interpreter and pass the code inline.
    """
    python = os.path.realpath(getattr(sys, '_base_executable', None) or sys.executable)
    protected = [os.path.expanduser(f'~/{d}') for d in ('Downloads', 'Documents', 'Desktop')]
    if any(python.startswith(p + os.sep) for p in protected):
        python = '/usr/bin/python3'
    with open(HELPER_PATH, encoding='utf-8') as f:
        code = f.read()
    return [python, '-I', '-c', code]


def launch_elevated(cmd):
    if elevation_method() == 'macos':
        shell = ' '.join(shlex.quote(c) for c in cmd)
        shell = shell.replace('\\', '\\\\').replace('"', '\\"')
        script = f'do shell script "{shell}"{ELEVATE_CLAUSE}'
        args = ['osascript', '-e', script]
    else:
        args = ['pkexec'] + cmd
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def friendly_capture_error(e, bpf=None):
    msg = str(e)
    if bpf and 'filter' in msg.lower():
        return f'Invalid capture filter "{bpf}": {msg}'
    if isinstance(e, PermissionError) or 'ermission' in msg or 'not permitted' in msg:
        return PERMISSION_HELP
    if sys.platform == 'win32' and ('winpcap' in msg.lower() or 'npcap' in msg.lower() or 'libpcap' in msg.lower()):
        return 'Live capture on Windows needs Npcap - install it from https://npcap.com (Wireshark includes it).'
    return f'Capture failed: {msg}'


def capture_problem(iface):
    """Try opening the capture device so problems are reported before any data is thrown away."""
    try:
        from scapy.all import conf
        sock = conf.L2listen(iface=iface or conf.iface)
        sock.close()
        return None
    except Exception as e:
        return friendly_capture_error(e)


def default_iface():
    try:
        from scapy.all import conf
        return str(conf.iface)
    except Exception:
        return 'default interface'


def local_addresses():
    try:
        from scapy.all import conf
        return [ip for iface in conf.ifaces.values() for ips in iface.ips.values() for ip in ips]
    except Exception:
        return []


def push_status():
    socketio.emit('status', session.status())


def snapshot_pusher():
    """Push a fresh snapshot to browsers whenever the data changed (at most once a second)."""
    last_version, last_obj = None, None
    while True:
        socketio.sleep(1)
        a = session.analyzer
        if a is not last_obj or a.version != last_version or (a.live and session.capturing):
            last_obj, last_version = a, a.version
            socketio.emit('snapshot', a.snapshot())


def sample_files():
    return sorted(f for f in os.listdir(core.BASE_DIR) if f.lower().endswith(CAPTURE_EXTENSIONS))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html', static_mode=False)


@app.route('/api/status')
def api_status():
    return jsonify(dict(session.status(), app='netmap'))


@app.route('/api/snapshot')
def api_snapshot():
    return jsonify(session.analyzer.snapshot())


@app.route('/api/interfaces')
def api_interfaces():
    try:
        from scapy.all import conf
        default = str(conf.iface)
        rows = []
        for iface in conf.ifaces.values():
            ips = [ip for ip in iface.ips.get(4, []) + iface.ips.get(6, []) if not ip.startswith('fe80')]
            rows.append({'name': iface.name, 'ips': ips, 'default': iface.name == default})
        rows.sort(key=lambda r: (not r['default'], not r['ips'], r['name']))
        return jsonify({'interfaces': rows})
    except Exception as e:
        return jsonify({'interfaces': [], 'error': str(e)})


@app.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    data = request.get_json(silent=True) or {}
    session.start_capture(data.get('iface'), (data.get('filter') or '').strip())
    return jsonify(session.status())


@app.route('/api/capture/stop', methods=['POST'])
def api_capture_stop():
    session.stop_capture()
    return jsonify(session.status())


@app.route('/api/reset', methods=['POST'])
def api_reset():
    session.reset()
    return jsonify(session.status())


@app.route('/api/pcap/samples')
def api_samples():
    return jsonify({'files': sample_files()})


@app.route('/api/pcap/open', methods=['POST'])
def api_open_sample():
    name = (request.get_json(silent=True) or {}).get('name')
    if name not in sample_files():          # only files listed above - no path traversal
        abort(404)
    session.load_file(os.path.join(core.BASE_DIR, name), name)
    return jsonify(session.status())


@app.route('/api/pcap/upload', methods=['POST'])
def api_upload():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': 'No file uploaded'}), 400
    name = secure_filename(f.filename) or 'capture.pcap'
    if not name.lower().endswith(CAPTURE_EXTENSIONS):
        return jsonify({'error': 'Please choose a .pcap, .pcapng or .cap file (in Wireshark: File → Save As)'}), 400
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    fd, path = tempfile.mkstemp(suffix='_' + name, dir=UPLOAD_DIR)
    os.close(fd)
    f.save(path)
    session.load_file(path, name)
    return jsonify(session.status())


EXPORTS = {
    'csv': (core.to_csv, 'text/csv', 'hosts.csv'),
    'kml': (core.to_kml, 'application/vnd.google-earth.kml+xml', 'map.kml'),
    'json': (core.to_json, 'application/json', 'data.json'),
    'txt': (core.to_text_report, 'text/plain', 'statistics.txt'),
    'html': (core.to_html_report, 'text/html', 'report.html'),
}


@app.route('/api/export/<fmt>')
def api_export(fmt):
    if fmt not in EXPORTS:
        abort(404)
    fn, mime, suffix = EXPORTS[fmt]
    snap = session.analyzer.snapshot(max_endpoints=100000)
    base = os.path.splitext(snap.get('source') or 'capture')[0]
    base = secure_filename(base.replace('Live · ', 'live_')) or 'capture'
    return Response(fn(snap), mimetype=mime,
                    headers={'Content-Disposition': f'attachment; filename="{base}_{suffix}"'})


@app.errorhandler(413)
def too_large(_):
    return jsonify({'error': 'File is larger than 2 GB'}), 413


@socketio.on('connect')
def on_connect():
    socketio.emit('status', session.status(), to=request.sid)
    socketio.emit('snapshot', session.analyzer.snapshot(), to=request.sid)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

def running_instance(port):
    """True if NetMap is already serving on this port."""
    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/status', timeout=1) as r:
            return json.load(r).get('app') == 'netmap'
    except Exception:
        return False


def port_free(host, port):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # same as the web server does
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def main():
    global session
    parser = argparse.ArgumentParser(description='NetMap - see where your network traffic goes')
    parser.add_argument('--host', default='127.0.0.1', help='bind address (use 0.0.0.0 to allow other devices)')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--open', action='store_true', help='open the dashboard in your browser')
    parser.add_argument('--capture', action='store_true', help='start live capture immediately')
    parser.add_argument('--iface', help='interface for --capture (default: system default)')
    parser.add_argument('--filter', help='BPF capture filter for --capture, e.g. "not port 22"')
    parser.add_argument('--pcap', help='open this capture file on startup')
    parser.add_argument('--my-ip', help='your public IP (default: auto-detect)')
    parser.add_argument('--home', help='override your map location as "lat,lon"')
    parser.add_argument('--geoip-db', help='GeoLiteCity.dat or a GeoLite2/DB-IP City .mmdb')
    parser.add_argument('--no-rdns', action='store_true', help='disable reverse-DNS lookups')
    parser.add_argument('--no-ip-lookup', action='store_true', help="don't query the internet for your public IP")
    args = parser.parse_args()

    port = args.port
    if running_instance(port):
        url = f'http://127.0.0.1:{port}'
        print(f'NetMap is already running at {url}')
        if args.open:
            webbrowser.open(url)
        return
    while not port_free(args.host, port) and port < args.port + 20:
        port += 1

    # Warm up scapy in the background so the first "Start live" click is instant
    threading.Thread(target=lambda: __import__('scapy.all'), daemon=True).start()

    geo = core.GeoLocator(args.geoip_db)
    print(f'GeoIP database: {geo.db_path}' + (f'\n  WARNING: {geo.error}' if geo.error else ''))
    home = core.resolve_home(geo, args.my_ip, args.home, lookup_ip=not args.no_ip_lookup)
    print(f'Your location:  {home["label"]} ({home["ip"] or "public IP unknown"})')
    session = Session(geo, home, resolve_rdns=not args.no_rdns)

    if args.pcap:
        session.load_file(os.path.abspath(args.pcap), os.path.basename(args.pcap))
    elif args.capture:
        session.start_capture(args.iface, args.filter)

    socketio.start_background_task(snapshot_pusher)
    url = f'http://{"127.0.0.1" if args.host == "0.0.0.0" else args.host}:{port}'
    print(f'\n  NetMap is running at {url}\n  Keep this window open while you use it; close it (or press Ctrl+C) to quit.\n')
    if args.open:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    logging.getLogger('werkzeug').setLevel(logging.ERROR)     # hide per-request logs & dev-server banner
    socketio.run(app, host=args.host, port=port, allow_unsafe_werkzeug=True, log_output=False)


if __name__ == '__main__':
    main()
