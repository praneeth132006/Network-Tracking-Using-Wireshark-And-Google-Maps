"""Privileged packet-capture helper.

The dashboard runs as a normal user. When live capture needs root, it launches this code through the
OS password prompt (macOS: osascript, Linux: pkexec). The helper captures with the system libpcap and
streams raw frames to the dashboard over a localhost socket; it exits as soon as that socket closes.

It deliberately uses only the Python standard library and is passed to the interpreter with `-c`:
macOS privacy protection stops root processes from reading files in ~/Downloads, ~/Documents or
~/Desktop, so the helper must not depend on anything inside the project folder or its virtualenv.

Frame format: type (1 byte) + timestamp (double) + uint32 + payload length (uint32) + payload.
  b'L'  link type of the capture (in the uint32 field)
  b'P'  a packet (uint32 = original frame length, payload = captured bytes)
  b'E'  an error message (payload = utf-8 text)
"""
import argparse
import ctypes
import ctypes.util
import socket
import struct
import sys
import threading

HEADER = struct.Struct('!cdII')


class Timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long),
                ('tv_usec', ctypes.c_int32 if sys.platform == 'darwin' else ctypes.c_long)]


class PcapPkthdr(ctypes.Structure):
    _fields_ = [('ts', Timeval), ('caplen', ctypes.c_uint32), ('len', ctypes.c_uint32)]


class BpfProgram(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_uint), ('bf_insns', ctypes.c_void_p)]


def load_libpcap():
    name = ctypes.util.find_library('pcap')
    candidates = [name] if name else []
    candidates += ['/usr/lib/libpcap.A.dylib', 'libpcap.so.1', 'libpcap.so.0.8', 'libpcap.so', 'wpcap.dll']
    for candidate in candidates:
        try:
            lib = ctypes.CDLL(candidate)
            break
        except OSError:
            continue
    else:
        raise OSError('libpcap is not installed')
    lib.pcap_open_live.restype = ctypes.c_void_p
    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
    lib.pcap_open_offline.restype = ctypes.c_void_p
    lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram)]
    lib.pcap_next_ex.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    return lib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--iface')
    parser.add_argument('--filter')
    parser.add_argument('--read-file', help=argparse.SUPPRESS)   # replay a capture file (for testing)
    args = parser.parse_args()

    conn = socket.create_connection(('127.0.0.1', args.port), timeout=10)
    conn.settimeout(None)
    conn.sendall(args.token.encode() + b'\n')
    stop = threading.Event()

    def send(kind, ts, value, payload=b''):
        try:
            conn.sendall(HEADER.pack(kind, ts, value, len(payload)) + payload)
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

    handle = None
    lib = None
    try:
        lib = load_libpcap()
        errbuf = ctypes.create_string_buffer(512)
        if args.read_file:
            handle = lib.pcap_open_offline(args.read_file.encode(), errbuf)
        else:
            # snaplen 65535, not promiscuous, 500 ms read timeout so Stop is noticed quickly
            handle = lib.pcap_open_live((args.iface or 'en0').encode(), 65535, 0, 500, errbuf)
        if not handle:
            raise OSError(errbuf.value.decode('utf-8', 'replace') or 'could not open capture device')
        if args.filter:
            prog = BpfProgram()
            if lib.pcap_compile(handle, ctypes.byref(prog), args.filter.encode(), 1, 0xFFFFFFFF) != 0 \
                    or lib.pcap_setfilter(handle, ctypes.byref(prog)) != 0:
                raise ValueError(f'invalid filter: {lib.pcap_geterr(handle).decode("utf-8", "replace")}')
        send(b'L', 0.0, lib.pcap_datalink(handle))

        header = ctypes.POINTER(PcapPkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        while not stop.is_set():
            rc = lib.pcap_next_ex(handle, ctypes.byref(header), ctypes.byref(data))
            if rc == 1:
                h = header.contents
                frame = ctypes.string_at(data, h.caplen)
                send(b'P', h.ts.tv_sec + h.ts.tv_usec / 1e6, h.len, frame)
            elif rc == 0:
                continue                    # read timeout, no packets
            elif rc == -2:
                break                       # end of a replayed file
            else:
                raise OSError(lib.pcap_geterr(handle).decode('utf-8', 'replace'))
        if args.read_file:
            stop.wait()                     # keep the connection open like a live capture would
    except Exception as e:
        send(b'E', 0.0, 0, str(e).encode('utf-8', 'replace'))
    finally:
        if handle and lib:
            lib.pcap_close(handle)
        try:
            conn.close()
        except OSError:
            pass


if __name__ == '__main__':
    sys.exit(main())
