"""Privileged packet-capture helper.

The dashboard runs as a normal user. When live capture needs root, it launches this script through
the OS password prompt (macOS: osascript, Linux: pkexec). The helper sniffs packets and streams the
raw IP bytes to the dashboard over a localhost socket; it exits as soon as that socket closes.

Frame format: type (1 byte: b'P' packet, b'E' error) + timestamp (double) + wire length (uint32)
              + payload length (uint32) + payload.
"""
import argparse
import socket
import struct
import sys
import threading

HEADER = struct.Struct('!cdII')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--iface')
    parser.add_argument('--filter')
    args = parser.parse_args()

    conn = socket.create_connection(('127.0.0.1', args.port), timeout=10)
    conn.settimeout(None)
    conn.sendall(args.token.encode() + b'\n')
    stop = threading.Event()
    send_lock = threading.Lock()

    def send(kind, ts, wire_len, payload):
        try:
            with send_lock:
                conn.sendall(HEADER.pack(kind, ts, wire_len, len(payload)) + payload)
        except OSError:
            stop.set()

    def watch_parent():
        # The dashboard closing the socket (Stop button, app quit) ends the capture.
        try:
            while conn.recv(64):
                pass
        except OSError:
            pass
        stop.set()

    threading.Thread(target=watch_parent, daemon=True).start()

    try:
        from scapy.all import IP, IPv6, sniff

        def handle(pkt):
            if IP in pkt:
                payload = bytes(pkt[IP])
            elif IPv6 in pkt:
                payload = bytes(pkt[IPv6])
            else:
                payload = b''
            send(b'P', float(pkt.time), len(pkt), payload)

        while not stop.is_set():
            sniff(iface=args.iface or None, filter=args.filter or None, prn=handle, store=False,
                  timeout=1, stop_filter=lambda _: stop.is_set())
    except Exception as e:
        send(b'E', 0.0, 0, str(e).encode('utf-8', 'replace'))
    finally:
        try:
            conn.close()
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
