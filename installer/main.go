package main

import (
        "context"
        "fmt"
        "io"
        "log"
        "os"
        "os/signal"
        "path/filepath"
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
        agentVersion       = "1.0.0"
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

func main() {
        initLogger()
        defer closeLogger()

        logMessage("INFO", "========================================")
        logMessage("INFO", " %s v%s", serviceDisplayName, agentVersion)
        logMessage("INFO", " %s", companyName)
        logMessage("INFO", "========================================")

        mode := detectMode()
        logMessage("INFO", "Running in %s mode", mode)

        cfg, err := loadConfig()
        if err != nil {
                logMessage("FATAL", "Configuration error: %v", err)
                fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
                fmt.Fprintln(os.Stderr, "")
                fmt.Fprintln(os.Stderr, "Setup options:")
                fmt.Fprintln(os.Stderr, "  1. Edit config.json in the agent directory")
                fmt.Fprintln(os.Stderr, "  2. Set AEGIS_SERVER_URL and AEGIS_DEVICE_TOKEN env vars")
                fmt.Fprintln(os.Stderr, "  3. Pass as arguments: agent.exe <SERVER_URL> <DEVICE_TOKEN>")
                os.Exit(1)
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
                        os.Exit(1)
                }
        }

        logMessage("INFO", "Agent stopped")
}

func detectMode() string {
        for _, arg := range os.Args[1:] {
                switch strings.ToLower(arg) {
                case "--tray", "-tray":
                        return "tray"
                case "--service", "-service", "--headless":
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
                fmt.Printf("WARN: Could not open log file %s: %v, logging to stdout only\n", logPath, err)
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
