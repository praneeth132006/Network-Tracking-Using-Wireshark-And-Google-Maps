@echo off
REM Windows: double-click this file to start NetMap.
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py -3) || (set PY=python)
%PY% -c "import sys; sys.exit(sys.version_info < (3, 9))" >nul 2>nul
if errorlevel 1 (
    echo NetMap needs Python 3.9 or newer: https://www.python.org/downloads/  ^(tick "Add python.exe to PATH"^)
    pause
    exit /b 1
)
if not exist .venv\Scripts\python.exe (
    echo First run: setting up NetMap ^(about a minute^)...
    %PY% -m venv .venv
)
.venv\Scripts\python.exe -c "import flask_socketio, scapy, dpkt, pygeoip, maxminddb" >nul 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    .venv\Scripts\python.exe -m pip install -q -r requirements.txt
)
.venv\Scripts\python.exe app.py --open %*
pause
