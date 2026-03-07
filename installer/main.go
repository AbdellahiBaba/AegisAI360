package main

import (
        "bufio"
        "context"
        "fmt"
        "io"
        "log"
        "os"
        "os/exec"
        "os/signal"
        "path/filepath"
        "runtime"
        "strings"
        "sync"
        "syscall"
        "time"
)

const (
        serviceName        = "AegisAI360Agent"
        serviceDisplayName = "AegisAI360 Endpoint Agent"
        serviceDescription = "Security agent for AegisAI360 SOC platform"
        companyName        = "AegisAI Cyber Defense"
        agentVersion       = "1.1.0"
        logFolder          = "logs"
        registryKey        = `Software\Microsoft\Windows\CurrentVersion\Uninstall\AegisAI360Agent`
)

var (
        logger      *log.Logger
        logMu       sync.Mutex
        logFile     *os.File
        logPath     string
        logMaxBytes int64
        logMaxKeep  int
)

var silentMode bool

func isSilentMode() bool {
        if silentMode {
                return true
        }
        for _, arg := range os.Args[1:] {
                lower := strings.ToLower(arg)
                if lower == "--silent" || lower == "-silent" || lower == "--quiet" || lower == "-quiet" {
                        return true
                }
        }
        if os.Getenv("AEGIS_SILENT") == "1" || os.Getenv("AEGIS_SILENT") == "true" {
                return true
        }
        return false
}

func isInfoOnlyCommand() bool {
        if len(os.Args) < 2 {
                return false
        }
        cmd := strings.ToLower(os.Args[1])
        switch cmd {
        case "--help", "-help", "help", "-h", "/?", "--version", "-version", "version", "-v", "--status", "-status", "status":
                return true
        }
        return false
}

func enforceAdminPrivilege() bool {
        if isInfoOnlyCommand() {
                return true
        }

        if isRunningAsAdmin() {
                logMessage("INFO", "Running with Administrator privileges")
                if !silentMode {
                        fmt.Println("  Privilege: Administrator")
                }
                return true
        }

        logMessage("WARN", "Agent requires Administrator privileges")

        if silentMode {
                logMessage("FATAL", "Not running as Administrator in silent mode, exiting")
                os.Exit(1)
                return false
        }

        fmt.Println()
        fmt.Println("  WARNING: AegisAI360 Agent requires Administrator privileges.")
        fmt.Println("  Many features (WiFi control, firewall, services, process management)")
        fmt.Println("  will not work without elevated permissions.")
        fmt.Println()

        if isInteractiveTerminal() {
                fmt.Println("  Attempting to restart with Administrator privileges...")
                fmt.Println()

                if requestAdminElevation() {
                        logMessage("INFO", "Elevated process launched, exiting current process")
                        return false
                }

                fmt.Println()
                fmt.Println("  Could not obtain Administrator privileges.")
                fmt.Println("  Please right-click the agent and select 'Run as administrator'.")
                fmt.Println()
                waitForExit()
                return false
        }

        fmt.Fprintln(os.Stderr, "  Error: Agent must be run as Administrator.")
        fmt.Fprintln(os.Stderr, "  Right-click the .exe and select 'Run as administrator'")
        fmt.Fprintln(os.Stderr, "  Or run from an elevated command prompt.")
        os.Exit(1)
        return false
}

func main() {
        silentMode = isSilentMode()

        if silentMode {
                initLoggerSilent()
        } else {
                initLogger()
        }
        defer closeLogger()

        if !silentMode {
                printBanner()
        }

        if !enforceAdminPrivilege() {
                return
        }

        if handleServiceCommands() {
                return
        }

        mode := detectMode()
        logMessage("INFO", "Running in %s mode (silent=%v, privilege=%s)", mode, silentMode, getPrivilegeLevel())

        cfg, err := loadConfig()
        if err != nil {
                logMessage("WARN", "Configuration incomplete: %v", err)

                if !silentMode {
                        fmt.Println()
                        fmt.Println("  No valid configuration found.")
                        fmt.Println()
                }

                if isInteractiveTerminal() && !silentMode {
                        fmt.Println("  Starting interactive setup...")
                        fmt.Println()
                        cfg, err = runInteractiveSetup()
                        if err != nil {
                                logMessage("FATAL", "Setup failed: %v", err)
                                fmt.Fprintf(os.Stderr, "\n  Setup failed: %v\n", err)
                                waitForExit()
                                os.Exit(1)
                        }
                        logMessage("INFO", "Configuration saved successfully")
                        fmt.Println()
                        fmt.Println("  Configuration saved! Starting agent...")
                        fmt.Println()
                } else if silentMode {
                        logMessage("FATAL", "No configuration found, cannot run in silent mode")
                        os.Exit(1)
                } else {
                        fmt.Fprintln(os.Stderr, "  Setup options:")
                        fmt.Fprintln(os.Stderr, "    1. Run the agent directly (double-click) for interactive setup")
                        fmt.Fprintln(os.Stderr, "    2. Edit config.json in the agent directory")
                        fmt.Fprintln(os.Stderr, "    3. Set AEGIS_SERVER_URL and AEGIS_DEVICE_TOKEN env vars")
                        fmt.Fprintln(os.Stderr, "    4. Pass as arguments: agent.exe <SERVER_URL> <DEVICE_TOKEN>")
                        os.Exit(1)
                }
        }

        applyConfigToLogger(cfg)

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

        go func() {
                sig := <-sigCh
                logMessage("INFO", "Received signal: %v, shutting down...", sig)
                cancel()
        }()

        if mode == "tray" {
                go func() {
                        if err := runAgent(ctx, cfg); err != nil {
                                logMessage("FATAL", "Agent error: %v", err)
                                globalStatus.SetDisconnected(err.Error())
                        }
                }()
                runTray(cfg)
                logMessage("INFO", "Tray exited, stopping agent...")
                cancel()
                time.Sleep(2 * time.Second)
        } else {
                if err := runAgent(ctx, cfg); err != nil {
                        logMessage("FATAL", "Agent error: %v", err)
                        if isInteractiveTerminal() && !silentMode {
                                fmt.Fprintf(os.Stderr, "\n  Agent stopped with error: %v\n", err)
                                waitForExit()
                        }
                        os.Exit(1)
                }
        }

        logMessage("INFO", "Agent stopped")
}

func printBanner() {
        fmt.Println()
        fmt.Println("  ╔══════════════════════════════════════════════════╗")
        fmt.Println("  ║                                                  ║")
        fmt.Printf("  ║   %s v%s          ║\n", serviceDisplayName, agentVersion)
        fmt.Printf("  ║   %s                   ║\n", companyName)
        fmt.Println("  ║                                                  ║")
        fmt.Println("  ╚══════════════════════════════════════════════════╝")
        fmt.Println()

        logMessage("INFO", "========================================")
        logMessage("INFO", " %s v%s", serviceDisplayName, agentVersion)
        logMessage("INFO", " %s", companyName)
        logMessage("INFO", "========================================")
}

func handleServiceCommands() bool {
        if len(os.Args) < 2 {
                return false
        }

        cmd := strings.ToLower(os.Args[1])

        switch cmd {
        case "--install", "-install", "install":
                installService()
                return true
        case "--uninstall", "-uninstall", "uninstall":
                uninstallService()
                return true
        case "--status", "-status", "status":
                checkServiceStatus()
                return true
        case "--setup", "-setup", "setup":
                fmt.Println("  Starting interactive setup...")
                fmt.Println()
                cfg, err := runInteractiveSetup()
                if err != nil {
                        fmt.Fprintf(os.Stderr, "  Setup failed: %v\n", err)
                        waitForExit()
                        os.Exit(1)
                }
                _ = cfg
                fmt.Println()
                fmt.Println("  Configuration saved successfully!")
                fmt.Println("  Run the agent again to connect to the server.")
                waitForExit()
                return true
        case "--help", "-help", "help", "-h", "/?":
                printHelp()
                return true
        case "--version", "-version", "version", "-v":
                fmt.Printf("  %s v%s\n", serviceDisplayName, agentVersion)
                return true
        }

        return false
}

func printHelp() {
        fmt.Println("  Usage:")
        fmt.Println()
        fmt.Println("    AegisAI360-Agent.exe                              Run agent (interactive setup if not configured)")
        fmt.Println("    AegisAI360-Agent.exe <SERVER_URL> <TOKEN>         Run with server URL and device token")
        fmt.Println("    AegisAI360-Agent.exe --setup                      Run interactive setup wizard")
        fmt.Println("    AegisAI360-Agent.exe --install                    Install as Windows service (auto-start on boot)")
        fmt.Println("    AegisAI360-Agent.exe --uninstall                  Remove Windows service and startup entry")
        fmt.Println("    AegisAI360-Agent.exe --status                     Check service status")
        fmt.Println("    AegisAI360-Agent.exe --silent                     Run silently in background (no console output)")
        fmt.Println("    AegisAI360-Agent.exe --version                    Show version")
        fmt.Println("    AegisAI360-Agent.exe --help                       Show this help")
        fmt.Println()
        fmt.Println("  Environment variables:")
        fmt.Println()
        fmt.Println("    AEGIS_SERVER_URL       Server URL (e.g., https://aegisai360.com)")
        fmt.Println("    AEGIS_DEVICE_TOKEN     Device token from the AegisAI360 dashboard")
        fmt.Println("    AEGIS_RUN_MODE         Run mode: 'service' or 'tray'")
        fmt.Println("    AEGIS_SILENT           Set to '1' or 'true' for silent background mode")
        fmt.Println()
}

func installService() {
        if runtime.GOOS != "windows" {
                fmt.Println("  Service installation is only supported on Windows.")
                fmt.Println("  On Linux, create a systemd unit file instead.")
                return
        }

        exePath, err := os.Executable()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  Error: Cannot determine executable path: %v\n", err)
                waitForExit()
                return
        }

        absPath, _ := filepath.Abs(exePath)

        configPath := filepath.Join(filepath.Dir(absPath), "config.json")
        if _, err := os.Stat(configPath); os.IsNotExist(err) {
                fmt.Println("  Warning: No config.json found. Run --setup first to configure the agent.")
                fmt.Println()
        }

        fmt.Printf("  Installing service '%s'...\n", serviceName)
        fmt.Printf("  Executable: %s\n", absPath)

        cmd := exec.Command("sc", "create", serviceName,
                "binPath=", fmt.Sprintf("\"%s\" --service", absPath),
                "DisplayName=", serviceDisplayName,
                "start=", "auto",
                "obj=", "LocalSystem",
        )
        output, err := cmd.CombinedOutput()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  Failed to install service: %v\n", err)
                fmt.Fprintf(os.Stderr, "  Output: %s\n", string(output))
                fmt.Println()
                fmt.Println("  Make sure you are running as Administrator.")
                waitForExit()
                return
        }

        descCmd := exec.Command("sc", "description", serviceName, serviceDescription)
        descCmd.Run()

        failCmd := exec.Command("sc", "failure", serviceName,
                "reset=", "86400",
                "actions=", "restart/5000/restart/10000/restart/30000",
        )
        failCmd.Run()

        addStartupRegistryEntry(absPath)

        fmt.Println("  Service installed successfully!")
        fmt.Println("  Auto-start on boot: enabled (service + registry fallback)")
        fmt.Println()
        fmt.Printf("  To start the service:  sc start %s\n", serviceName)
        fmt.Printf("  To stop the service:   sc stop %s\n", serviceName)
        fmt.Printf("  To check status:       sc query %s\n", serviceName)
        fmt.Println()
        waitForExit()
}

func addStartupRegistryEntry(exePath string) {
        if runtime.GOOS != "windows" {
                return
        }
        regCmd := exec.Command("reg", "add",
                `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
                "/v", serviceName,
                "/t", "REG_SZ",
                "/d", fmt.Sprintf(`"%s" --silent`, exePath),
                "/f",
        )
        if out, err := regCmd.CombinedOutput(); err != nil {
                logMessage("WARN", "Failed to add startup registry entry: %v (%s)", err, string(out))
        } else {
                logMessage("INFO", "Added startup registry entry for auto-start on boot")
        }
}

func removeStartupRegistryEntry() {
        if runtime.GOOS != "windows" {
                return
        }
        regCmd := exec.Command("reg", "delete",
                `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
                "/v", serviceName,
                "/f",
        )
        regCmd.Run()
        logMessage("INFO", "Removed startup registry entry")
}

func uninstallService() {
        if runtime.GOOS != "windows" {
                fmt.Println("  Service management is only supported on Windows.")
                return
        }

        fmt.Printf("  Stopping service '%s'...\n", serviceName)
        stopCmd := exec.Command("sc", "stop", serviceName)
        stopCmd.Run()
        time.Sleep(2 * time.Second)

        fmt.Printf("  Removing service '%s'...\n", serviceName)
        cmd := exec.Command("sc", "delete", serviceName)
        output, err := cmd.CombinedOutput()
        if err != nil {
                fmt.Fprintf(os.Stderr, "  Failed to remove service: %v\n", err)
                fmt.Fprintf(os.Stderr, "  Output: %s\n", string(output))
                fmt.Println()
                fmt.Println("  Make sure you are running as Administrator.")
                waitForExit()
                return
        }

        removeStartupRegistryEntry()
        fmt.Println("  Service and startup entry removed successfully!")
        waitForExit()
}

func checkServiceStatus() {
        if runtime.GOOS != "windows" {
                fmt.Println("  Service management is only supported on Windows.")
                return
        }

        cmd := exec.Command("sc", "query", serviceName)
        output, err := cmd.CombinedOutput()
        if err != nil {
                fmt.Printf("  Service '%s' is not installed.\n", serviceName)
                waitForExit()
                return
        }

        outStr := string(output)
        fmt.Printf("  Service: %s\n", serviceName)

        if strings.Contains(outStr, "RUNNING") {
                fmt.Println("  Status:  RUNNING")
        } else if strings.Contains(outStr, "STOPPED") {
                fmt.Println("  Status:  STOPPED")
        } else if strings.Contains(outStr, "PAUSED") {
                fmt.Println("  Status:  PAUSED")
        } else {
                fmt.Println("  Status:  UNKNOWN")
        }

        exePath, _ := os.Executable()
        configPath := filepath.Join(filepath.Dir(exePath), "config.json")
        if _, err := os.Stat(configPath); err == nil {
                fmt.Println("  Config:  config.json found")
        } else {
                fmt.Println("  Config:  config.json NOT FOUND (run --setup)")
        }

        logDir := filepath.Join(filepath.Dir(exePath), logFolder)
        if entries, err := os.ReadDir(logDir); err == nil {
                fmt.Printf("  Logs:    %d log files in %s\n", len(entries), logDir)
        }

        fmt.Println()
        waitForExit()
}

func runInteractiveSetup() (*AgentConfig, error) {
        reader := bufio.NewReader(os.Stdin)

        cfg := &AgentConfig{
                ServerURL:           "https://aegisai360.com",
                AgentVersion:        agentVersion,
                HeartbeatInterval:   30,
                CommandPollInterval: 15,
                UpdateCheckInterval: 300,
                TelemetryInterval:   30,
                LogMaxSizeMB:        10,
                LogMaxBackups:       5,
        }

        existingPath := findConfigFile()
        if existingPath != "" {
                data, err := os.ReadFile(existingPath)
                if err == nil {
                        parseConfigJSON(data, cfg)
                }
        }

        fmt.Printf("  Server URL [%s]: ", cfg.ServerURL)
        line, _ := reader.ReadString('\n')
        line = strings.TrimSpace(line)
        if line != "" {
                cfg.ServerURL = strings.TrimRight(line, "/")
        }

        tokenPrompt := "  Device Token"
        if cfg.APIKey != "" && cfg.APIKey != "REPLACE_WITH_YOUR_DEVICE_TOKEN" {
                tokenPrompt += fmt.Sprintf(" [%s]", maskToken(cfg.APIKey))
        }
        tokenPrompt += ": "
        fmt.Print(tokenPrompt)
        line, _ = reader.ReadString('\n')
        line = strings.TrimSpace(line)
        if line != "" {
                cfg.APIKey = line
        }

        if cfg.ServerURL == "" {
                return nil, fmt.Errorf("server URL is required")
        }
        if cfg.APIKey == "" || cfg.APIKey == "REPLACE_WITH_YOUR_DEVICE_TOKEN" {
                return nil, fmt.Errorf("device token is required — generate one from the AegisAI360 dashboard")
        }

        if err := saveConfig(cfg); err != nil {
                return nil, fmt.Errorf("failed to save config: %w", err)
        }

        return cfg, nil
}

func isInteractiveTerminal() bool {
        for _, arg := range os.Args[1:] {
                lower := strings.ToLower(arg)
                if lower == "--service" || lower == "-service" || lower == "--headless" || lower == "--silent" || lower == "-silent" || lower == "--quiet" {
                        return false
                }
        }

        if os.Getenv("AEGIS_RUN_MODE") == "service" {
                return false
        }

        fi, err := os.Stdin.Stat()
        if err != nil {
                return false
        }
        return (fi.Mode() & os.ModeCharDevice) != 0
}

func waitForExit() {
        if !isInteractiveTerminal() {
                return
        }
        fmt.Println()
        fmt.Print("  Press Enter to exit...")
        bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func detectMode() string {
        for _, arg := range os.Args[1:] {
                switch strings.ToLower(arg) {
                case "--tray", "-tray":
                        return "tray"
                case "--service", "-service", "--headless", "--silent", "-silent", "--quiet":
                        return "service"
                }
        }

        if os.Getenv("AEGIS_RUN_MODE") == "service" {
                return "service"
        }
        if os.Getenv("AEGIS_RUN_MODE") == "tray" {
                return "tray"
        }

        return "service"
}

func initLoggerSilent() {
        logMaxBytes = 10 * 1024 * 1024
        logMaxKeep = 5

        exePath, err := os.Executable()
        logDir := logFolder
        if err == nil {
                logDir = filepath.Join(filepath.Dir(exePath), logFolder)
        }

        os.MkdirAll(logDir, 0755)
        rotateLogFiles(logDir, logMaxKeep)

        logFileName := fmt.Sprintf("agent_%s.log", time.Now().Format("20060102"))
        logPath = filepath.Join(logDir, logFileName)

        f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
                logger = log.New(io.Discard, "", 0)
                return
        }

        logFile = f
        logger = log.New(f, "", 0)
}

func initLogger() {
        logMaxBytes = 10 * 1024 * 1024
        logMaxKeep = 5

        exePath, err := os.Executable()
        logDir := logFolder
        if err == nil {
                logDir = filepath.Join(filepath.Dir(exePath), logFolder)
        }

        os.MkdirAll(logDir, 0755)

        rotateLogFiles(logDir, logMaxKeep)

        logFileName := fmt.Sprintf("agent_%s.log", time.Now().Format("20060102"))
        logPath = filepath.Join(logDir, logFileName)

        f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
                logger = log.New(os.Stdout, "", 0)
                return
        }

        logFile = f
        multiWriter := io.MultiWriter(os.Stdout, f)
        logger = log.New(multiWriter, "", 0)
}

func applyConfigToLogger(cfg *AgentConfig) {
        logMaxBytes = int64(cfg.LogMaxSizeMB) * 1024 * 1024
        logMaxKeep = cfg.LogMaxBackups
        if logMaxKeep < 1 {
                logMaxKeep = 5
        }
}

func closeLogger() {
        if logFile != nil {
                logFile.Close()
        }
}

func logMessage(level, format string, args ...interface{}) {
        logMu.Lock()
        defer logMu.Unlock()

        timestamp := time.Now().Format("2006-01-02 15:04:05")
        msg := fmt.Sprintf(format, args...)
        line := fmt.Sprintf("[%s] [%s] %s", timestamp, level, msg)

        if logger != nil {
                logger.Println(line)
        } else {
                fmt.Println(line)
        }

        checkLogRotation()
}

func checkLogRotation() {
        if logFile == nil || logPath == "" || logMaxBytes <= 0 {
                return
        }
        info, err := logFile.Stat()
        if err != nil || info.Size() < logMaxBytes {
                return
        }

        logFile.Close()

        logDir := filepath.Dir(logPath)
        rotatedName := fmt.Sprintf("agent_%s_%d.log", time.Now().Format("20060102"), time.Now().UnixMilli())
        os.Rename(logPath, filepath.Join(logDir, rotatedName))

        rotateLogFiles(logDir, logMaxKeep)

        f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
        if err != nil {
                logFile = nil
                logger = log.New(os.Stdout, "", 0)
                return
        }
        logFile = f
        logger = log.New(io.MultiWriter(os.Stdout, f), "", 0)
}

func rotateLogFiles(logDir string, maxBackups int) {
        entries, err := os.ReadDir(logDir)
        if err != nil {
                return
        }

        var logFiles []string
        for _, e := range entries {
                if !e.IsDir() && strings.HasPrefix(e.Name(), "agent_") && strings.HasSuffix(e.Name(), ".log") {
                        logFiles = append(logFiles, filepath.Join(logDir, e.Name()))
                }
        }

        if len(logFiles) > maxBackups {
                for _, f := range logFiles[:len(logFiles)-maxBackups] {
                        os.Remove(f)
                }
        }
}
