===============================================
  AegisAI360 Endpoint Agent - Build Guide
  Version 1.0.0
  AegisAI Cyber Defense
===============================================

This directory contains everything needed to build and package the
AegisAI360 Endpoint Agent for Windows. The agent runs as both a
Windows service (background) and a system tray application (GUI).


FILE STRUCTURE
--------------
  main.go               - Entry point, mode detection (tray vs service), logger
  config.go             - Config file loading (config.json + env vars)
  backend.go            - API communication with retry logic
  telemetry.go          - System monitoring (CPU, RAM, processes, network)
  commands.go           - Remote command handler
  updater.go            - Auto-update system
  service.go            - Agent run loop with heartbeat and status tracking
  status.go             - Thread-safe agent status (shared between service and tray)
  tray.go               - System tray GUI (icon, menu, dashboard launcher)
  icons.go              - Embedded tray icons (connected/disconnected)
  config.json           - Configuration template
  AegisAI360Agent.xml   - WinSW service wrapper configuration
  installer.nsi         - NSIS installer script
  AegisAI360-Header.bmp - Installer header image (150x57, 24-bit BMP)
  AegisAI360-Banner.bmp - Installer banner image (164x314, 24-bit BMP)
  go.mod                - Go module file with dependencies
  README.txt            - This file


PREREQUISITES
-------------
1. Go 1.21+ (https://go.dev/dl/)
2. WinSW binary (https://github.com/winsw/winsw/releases)
   Download WinSW-x64.exe from the latest release
3. NSIS 3.x (https://nsis.sourceforge.io/Download)
   Required only for building the installer
4. GCC (MinGW-w64) for CGo — required by systray
   Download: https://www.mingw-w64.org/ or via MSYS2


STEP 1: GENERATE A DEVICE TOKEN
---------------------------------
Before building or installing the agent, you need a device token:

  1. Log into your AegisAI360 dashboard at https://aegisai360.com
  2. Navigate to the Endpoints page
  3. Click "Generate Device Token"
  4. Copy the token (format: agt_xxxxxxxxxxxxxxxx)

The token is single-use. Each endpoint needs its own token.


STEP 2: BUILD THE AGENT
------------------------
From this directory, run:

  Windows (native, requires MinGW for CGo):
    set CGO_ENABLED=1
    go build -ldflags "-H windowsgui" -o agent.exe .

  The -H windowsgui flag prevents a console window from appearing
  when running in tray mode.

  For service-only build (no GUI, no CGo needed):
    set CGO_ENABLED=0
    go build -tags headless -o agent.exe .


STEP 3: DOWNLOAD WinSW
-----------------------
1. Go to: https://github.com/winsw/winsw/releases
2. Download "WinSW-x64.exe" from the latest release
3. Rename the downloaded file to: AegisAI360Agent.exe
4. Place it in this directory alongside agent.exe


STEP 4: BUILD THE INSTALLER
----------------------------
Ensure agent.exe, AegisAI360Agent.exe, AegisAI360Agent.xml,
config.json, and both BMP files are in this directory, then run:

  makensis installer.nsi

This produces: AegisAI360-Agent-Setup.exe

The installer will:
  - Show a branded welcome page with the AegisAI360 banner
  - Prompt the user for their device token
  - Install all files to C:\Program Files\AegisAI360\Agent\
  - Write the token into config.json
  - Register and start the Windows service
  - Create Start Menu and Desktop shortcuts
  - Set the tray app to auto-start on login
  - Launch the system tray agent immediately


RUNNING MODES
-------------
The agent has two running modes:

  1. TRAY MODE (interactive, with GUI):
     agent.exe --tray
     - Shows an icon in the Windows notification area (system tray)
     - Right-click the icon for options:
       * Status — shows connection state, agent ID, CPU/RAM
       * Open Dashboard — opens https://aegisai360.com in your browser
       * Test Connection — verifies connectivity to the server
       * View Logs — opens the log folder in Explorer
       * Restart Agent — restarts the background service
       * Exit — closes the tray app (service keeps running)
     - Icon color: Green = connected, Red = disconnected
     - The agent core (heartbeat, commands) runs inside the tray app

  2. SERVICE MODE (headless, background):
     agent.exe --service
     - Runs as a background process with no GUI
     - Used by the WinSW service wrapper
     - Logs to files only (no tray icon)

  If no flag is provided, the agent auto-detects:
     - If running interactively (with a terminal) → tray mode
     - If running as a service (no terminal) → service mode


ACCESSING THE DASHBOARD
-----------------------
The agent does NOT embed the full dashboard. Instead:

  1. Right-click the tray icon → "Open Dashboard"
  2. Your default browser opens to https://aegisai360.com
  3. Log in with your AegisAI360 credentials
  4. You have full access to the cloud-based SOC platform:
     - View all your endpoints and their status
     - Send remote commands to agents
     - Access the remote terminal
     - View threat intelligence
     - Manage firewall rules, alerts, and more

The dashboard shows real-time data from this agent including
hostname, OS, IP, CPU/RAM usage, and command history.


TESTING WITHOUT INSTALLER
-------------------------
You can run the agent directly without the installer:

  Option A: Use config.json
    Edit config.json with your token, then:
      agent.exe --tray

  Option B: Set environment variables
    set AEGIS_SERVER_URL=https://aegisai360.com
    set AEGIS_DEVICE_TOKEN=agt_your_token_here
    agent.exe --tray

  Option C: Pass as arguments
    agent.exe https://aegisai360.com agt_your_token_here


AGENT FEATURES
--------------
  - System tray GUI with connection status indicator
  - One-click access to cloud dashboard via browser
  - Connection test from the tray menu
  - Registers with the AegisAI360 backend on startup
  - Sends heartbeats every 30 seconds with CPU/RAM metrics
  - Polls for remote commands every 5 seconds
  - Collects system telemetry (CPU, RAM, processes, network)
  - Supports remote terminal commands (whitelisted only)
  - Auto-updates when a new version is available
  - Rotating log files in the logs/ directory
  - Retry logic with exponential backoff for all API calls
  - Graceful shutdown on exit
  - Secure HTTPS with TLS 1.2+
  - Auto-starts on Windows login (tray mode)


SUPPORTED COMMANDS
------------------
  ping              - Returns a pong response with timestamp
  get_info          - Returns detailed system information
  run_system_scan   - Returns system scan report
  terminal_exec     - Executes whitelisted shell commands
  restart           - Restarts the agent service
  update            - Checks for and applies agent updates

Terminal whitelist (Windows):
  whoami, ipconfig, netstat, tasklist, dir,
  systeminfo, hostname, ver

Terminal whitelist (Linux):
  whoami, ifconfig, ip a, netstat, ss,
  ps aux, ls, uname -a, df -h, free -m, uptime, hostname


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


TROUBLESHOOTING
---------------
- Tray icon not appearing:
    Make sure you're running agent.exe --tray (not --service)
    Check if the icon is hidden in the overflow area

- Service won't start:
    Check config.json has a valid apiKey (device token)
    Ensure the token hasn't been used by another endpoint

- Tray shows "Disconnected":
    Right-click → Test Connection to diagnose
    Check your internet connection
    Verify https://aegisai360.com is reachable

- Registration fails:
    Verify internet connectivity
    Check if the organization has reached its agent limit

- Agent not appearing in dashboard:
    Wait 30 seconds for the first heartbeat
    Check logs in C:\Program Files\AegisAI360\Agent\logs\

- Logs location:
    C:\Program Files\AegisAI360\Agent\logs\agent_YYYYMMDD.log
