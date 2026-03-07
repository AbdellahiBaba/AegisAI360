===============================================
  AegisAI360 Endpoint Agent - Build Guide
===============================================

This directory contains everything needed to build and package the
AegisAI360 Endpoint Agent for Windows.

Contents:
  main.go               - Go agent source code
  AegisAI360Agent.xml   - WinSW service wrapper configuration
  installer.nsi         - NSIS installer script
  README.txt            - This file


PREREQUISITES
-------------
1. Go 1.21+ (https://go.dev/dl/)
2. WinSW binary (https://github.com/winsw/winsw/releases)
   Download WinSW-x64.exe from the latest release
3. NSIS 3.x (https://nsis.sourceforge.io/Download)
   Required only for building the installer


STEP 1: BUILD THE AGENT
------------------------
From this directory, run:

  Windows (native):
    go build -o agent.exe main.go

  Cross-compile from Linux/macOS:
    GOOS=windows GOARCH=amd64 go build -o agent.exe main.go

This produces agent.exe, the endpoint agent binary.


STEP 2: DOWNLOAD WinSW
-----------------------
1. Go to: https://github.com/winsw/winsw/releases
2. Download "WinSW-x64.exe" from the latest release
3. Rename the downloaded file to: AegisAI360Agent.exe
4. Place it in this directory alongside agent.exe


STEP 3: CONFIGURE THE AGENT
----------------------------
Edit AegisAI360Agent.xml and set:

  <env name="AEGIS_SERVER_URL" value="https://YOUR-SERVER-URL"/>
  <env name="AEGIS_DEVICE_TOKEN" value="YOUR_DEVICE_TOKEN"/>

Get your device token from the AegisAI360 dashboard:
  Dashboard > Deploy Agent > Generate Device Token


STEP 4: BUILD THE INSTALLER
----------------------------
Ensure agent.exe, AegisAI360Agent.exe, and AegisAI360Agent.xml
are all in this directory, then run:

  makensis installer.nsi

This produces: AegisAI360-Agent-Setup.exe


STEP 5: INSTALL
---------------
1. Run AegisAI360-Agent-Setup.exe as Administrator
2. Follow the installation wizard
3. The agent service will start automatically
4. Verify in the AegisAI360 dashboard that the endpoint appears


TESTING WITHOUT INSTALLER
-------------------------
You can run the agent directly without the installer:

  Set environment variables:
    set AEGIS_SERVER_URL=https://YOUR-SERVER-URL
    set AEGIS_DEVICE_TOKEN=YOUR_TOKEN
    agent.exe

  Or pass as arguments:
    agent.exe https://YOUR-SERVER-URL YOUR_TOKEN

The agent will:
  - Register with the server
  - Send heartbeats every 30 seconds
  - Poll for commands every 5 seconds
  - Execute whitelisted terminal commands


UNINSTALL
---------
Option A: Use Windows Add/Remove Programs
  Settings > Apps > AegisAI360 Endpoint Agent > Uninstall

Option B: Run the uninstaller directly
  "C:\Program Files\AegisAI360\Agent\uninstall.exe"

Option C: Manual removal
  1. Stop the service:   AegisAI360Agent.exe stop
  2. Remove the service: AegisAI360Agent.exe uninstall
  3. Delete the install directory


SUPPORTED COMMANDS
------------------
The agent responds to commands sent from the SOC dashboard:

  ping              - Returns a pong response with timestamp
  run_system_scan   - Returns basic system information
  terminal_exec     - Executes whitelisted shell commands

Terminal whitelist (Windows):
  whoami, ipconfig, netstat -ano, tasklist, dir,
  systeminfo, hostname, ver

Terminal whitelist (Linux):
  whoami, ifconfig, ip a, netstat -tunap, ss -tunap,
  ps aux, ls, uname -a, df -h, free -m, uptime, hostname


TROUBLESHOOTING
---------------
- Service won't start: Check AegisAI360Agent.xml has correct
  SERVER_URL and DEVICE_TOKEN values
- Registration fails: Ensure the device token hasn't been used
  already (tokens are single-use)
- Connection errors: Verify the server URL is reachable from
  the endpoint
- Logs location: C:\Program Files\AegisAI360\Agent\logs\
