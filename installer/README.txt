===============================================
  AegisAI360 Endpoint Agent - Build Guide
  Version 1.0.0
  AegisAI Cyber Defense
===============================================

This directory contains everything needed to build and package the
AegisAI360 Endpoint Agent for Windows.


FILE STRUCTURE
--------------
  main.go               - Entry point, logger, branding constants
  config.go             - Config file loading (config.json + env vars)
  backend.go            - API communication with retry logic
  telemetry.go          - System monitoring (CPU, RAM, processes, network)
  commands.go           - Remote command handler (ping, get_info, terminal, etc.)
  updater.go            - Auto-update system
  service.go            - Agent run loop with graceful shutdown
  config.json           - Configuration template (server URL + device token)
  AegisAI360Agent.xml   - WinSW service wrapper configuration
  installer.nsi         - NSIS installer script
  AegisAI360-Header.bmp - Installer header image (150x57, 24-bit BMP)
  AegisAI360-Banner.bmp - Installer banner image (164x314, 24-bit BMP)
  README.txt            - This file


PREREQUISITES
-------------
1. Go 1.21+ (https://go.dev/dl/)
2. WinSW binary (https://github.com/winsw/winsw/releases)
   Download WinSW-x64.exe from the latest release
3. NSIS 3.x (https://nsis.sourceforge.io/Download)
   Required only for building the installer


STEP 1: GENERATE A DEVICE TOKEN
---------------------------------
Before building or installing the agent, you need a device token:

  1. Log into your AegisAI360 dashboard at https://aegisai360.com
  2. Navigate to the Endpoints page
  3. Click "Generate Device Token"
  4. Copy the token (format: agt_xxxxxxxxxxxxxxxx)

The token is single-use. Each endpoint needs its own token.
Tokens are tied to your organization and count against your plan's
agent limit.


STEP 2: BUILD THE AGENT
------------------------
From this directory, run:

  Windows (native):
    go build -o agent.exe .

  Cross-compile from Linux/macOS:
    GOOS=windows GOARCH=amd64 go build -o agent.exe .

This compiles all Go files (main.go, config.go, backend.go,
telemetry.go, commands.go, updater.go, service.go) into agent.exe.


STEP 3: DOWNLOAD WinSW
-----------------------
1. Go to: https://github.com/winsw/winsw/releases
2. Download "WinSW-x64.exe" from the latest release
3. Rename the downloaded file to: AegisAI360Agent.exe
4. Place it in this directory alongside agent.exe


STEP 4: CONFIGURE THE AGENT
----------------------------
Option A: Edit config.json
  Set the "apiKey" field to your device token:
    {
      "serverUrl": "https://aegisai360.com",
      "apiKey": "agt_your_device_token_here",
      ...
    }

Option B: The NSIS installer will prompt for the token
  during installation and write it to config.json automatically.


STEP 5: BUILD THE INSTALLER
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


STEP 6: INSTALL
---------------
1. Run AegisAI360-Agent-Setup.exe as Administrator
2. Enter your device token when prompted
3. Choose install directory (default: C:\Program Files\AegisAI360\Agent)
4. The agent service will start automatically
5. Verify in the AegisAI360 dashboard that the endpoint appears


TESTING WITHOUT INSTALLER
-------------------------
You can run the agent directly without the installer:

  Option A: Use config.json
    Edit config.json with your token, then:
      agent.exe

  Option B: Set environment variables
    set AEGIS_SERVER_URL=https://aegisai360.com
    set AEGIS_DEVICE_TOKEN=agt_your_token_here
    agent.exe

  Option C: Pass as arguments
    agent.exe https://aegisai360.com agt_your_token_here

Priority order: CLI args > env vars > config.json


AGENT FEATURES
--------------
  - Registers with the AegisAI360 backend on startup
  - Sends heartbeats every 30 seconds with CPU/RAM metrics
  - Polls for remote commands every 5 seconds
  - Collects system telemetry (CPU, RAM, processes, network)
  - Supports remote terminal commands (whitelisted only)
  - Auto-updates when a new version is available
  - Rotating log files in the logs/ directory
  - Retry logic with exponential backoff for all API calls
  - Graceful shutdown on SIGINT/SIGTERM
  - Secure HTTPS with TLS 1.2+


SUPPORTED COMMANDS
------------------
The agent responds to commands sent from the SOC dashboard:

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


SECURITY
--------
  - Device tokens are never logged in plain text
  - SSL/TLS certificate validation is enforced
  - Terminal commands are whitelisted (no arbitrary execution)
  - Dangerous patterns are blocked (rm, del, shutdown, etc.)
  - Command chaining is blocked (;, &&, ||, |, backticks)
  - Config file permissions are set to owner-only (0600)


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
- Service won't start:
    Check config.json has a valid apiKey (device token)
    Ensure the token hasn't been used by another endpoint

- Registration fails:
    Verify internet connectivity
    Check if the organization has reached its agent limit

- Connection errors:
    Verify https://aegisai360.com is reachable
    Check firewall/proxy settings

- Agent not appearing in dashboard:
    Wait 30 seconds for the first heartbeat
    Check logs in C:\Program Files\AegisAI360\Agent\logs\

- Logs location:
    C:\Program Files\AegisAI360\Agent\logs\agent_YYYYMMDD.log
