#!/bin/bash
# Start NetMap: sets itself up on first run, then opens the dashboard in your browser.
#   ./run_dashboard.sh                 normal start (live capture asks for your password when needed)
#   ./run_dashboard.sh --sudo          run everything as root instead
#   Other flags go to app.py, e.g.  ./run_dashboard.sh --pcap mycapture.pcapng
cd "$(dirname "$0")" || exit 1

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
        PY="$candidate"; break
    fi
done
if [ -z "$PY" ]; then
    echo "NetMap needs Python 3.9 or newer."
    if [ "$(uname)" = "Darwin" ]; then
        echo "Install it with:  xcode-select --install   (or from https://www.python.org/downloads/)"
    else
        echo "Install it from your package manager or https://www.python.org/downloads/"
    fi
    exit 1
fi

if [ ! -x .venv/bin/python ]; then
    echo "First run: setting up NetMap (about a minute)..."
    "$PY" -m venv .venv || { echo "Could not create a virtual environment."; exit 1; }
fi
if ! .venv/bin/python -c "import flask_socketio, scapy, dpkt, pygeoip, maxminddb" 2>/dev/null; then
    echo "Installing dependencies..."
    .venv/bin/python -m pip install -q --upgrade pip >/dev/null 2>&1
    .venv/bin/python -m pip install -q -r requirements.txt || { echo "Dependency install failed - check your internet connection."; exit 1; }
fi

ARGS=(--open)
USE_SUDO=0
for arg in "$@"; do
    if [ "$arg" = "--sudo" ]; then USE_SUDO=1; else ARGS+=("$arg"); fi
done

if [ "$USE_SUDO" = 1 ] && [ "$(id -u)" != 0 ]; then
    exec sudo .venv/bin/python app.py "${ARGS[@]}"
fi
exec .venv/bin/python app.py "${ARGS[@]}"
