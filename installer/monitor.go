package main

import (
        "context"
        "crypto/sha256"
        "encoding/hex"
        "fmt"
        "io"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "strings"
        "sync"
        "time"
)

const (
        defaultMonitorInterval    = 600
        defaultProcessCheckInterval = 120
        defaultFileCheckInterval  = 300
        defaultNetCheckInterval   = 180
)

var knownMaliciousProcesses = []string{
        "mimikatz", "meterpreter", "cobaltstrike", "beacon",
        "lazagne", "rubeus", "sharphound", "bloodhound",
        "psexec", "procdump", "ncat", "netcat",
        "powersploit", "empire", "covenant",
        "cryptolocker", "wannacry", "petya",
        "xmrig", "minerd", "cgminer", "bfgminer",
        "rat", "njrat", "darkcomet", "poison",
}

var suspiciousPorts = []int{
        4444, 5555, 6666, 7777, 8888, 9999,
        1234, 31337, 12345, 65535,
        4443, 8443, 8000, 9090,
}

var criticalDirsWindows = []string{
        `C:\Windows\System32`,
        `C:\Windows\Temp`,
        `C:\Users\Public\Downloads`,
}

var criticalDirsLinux = []string{
        "/tmp",
        "/var/tmp",
        "/usr/local/bin",
        "/opt",
}

type SecurityEventReport struct {
        EventType   string `json:"eventType"`
        Severity    string `json:"severity"`
        Description string `json:"description"`
        Source      string `json:"source"`
        SourceIp    string `json:"sourceIp,omitempty"`
        RawData     string `json:"rawData,omitempty"`
}

type SecurityEventsRequest struct {
        AgentID float64               `json:"agentId"`
        Token   string                `json:"token"`
        Events  []SecurityEventReport `json:"events"`
}

type FileScanFileEntry struct {
        Path         string `json:"path"`
        Size         int64  `json:"size"`
        SHA256       string `json:"sha256,omitempty"`
        ModifiedAt   string `json:"modifiedAt,omitempty"`
        IsRecent     bool   `json:"isRecent,omitempty"`
        IsSuspicious bool   `json:"isSuspicious,omitempty"`
        Reason       string `json:"reason,omitempty"`
}

type FileScanReport struct {
        ScannedDirs     []string           `json:"scannedDirs,omitempty"`
        TotalFiles      int                `json:"totalFiles,omitempty"`
        Executables     int                `json:"executables,omitempty"`
        RecentFiles     int                `json:"recentFiles,omitempty"`
        SuspiciousFiles int                `json:"suspiciousFiles,omitempty"`
        Files           []FileScanFileEntry `json:"files,omitempty"`
        ScanTime        string             `json:"scanTime,omitempty"`
        Duration        string             `json:"duration,omitempty"`
}

type FileScanRequest struct {
        AgentID float64        `json:"agentId"`
        Token   string         `json:"token"`
        Report  FileScanReport `json:"report"`
}

var (
        monitorRunning   bool
        monitorMu        sync.Mutex
        monitorCancel    context.CancelFunc
        monitorCfg       *AgentConfig
        monitorAgentID   float64
        fileHashes       map[string]string
        fileHashesMu     sync.Mutex
)

func init() {
        fileHashes = make(map[string]string)
}

func startBackgroundMonitoring(ctx context.Context, cfg *AgentConfig, agentID float64) {
        monitorMu.Lock()
        if monitorRunning {
                monitorMu.Unlock()
                logMessage("INFO", "Background monitoring already running")
                return
        }
        monitorRunning = true
        monitorCfg = cfg
        monitorAgentID = agentID

        monitorCtx, cancel := context.WithCancel(ctx)
        monitorCancel = cancel
        monitorMu.Unlock()

        logMessage("INFO", "Starting background monitoring goroutines")

        go periodicSecurityScan(monitorCtx, cfg, agentID)
        go processWatchlistMonitor(monitorCtx, cfg, agentID)
        go fileIntegrityMonitor(monitorCtx, cfg, agentID)
        go networkConnectionMonitor(monitorCtx, cfg, agentID)

        sendAgentLog(cfg, agentID, "monitoring_started", "info",
                "Background monitoring started: security scan, process watchlist, file integrity, network connections")
}

func enableBackgroundMonitoring() string {
        monitorMu.Lock()
        cfg := monitorCfg
        agentID := monitorAgentID
        running := monitorRunning
        monitorMu.Unlock()

        if running {
                return "Background monitoring is already running"
        }

        if cfg == nil {
                return "Agent not fully initialized yet, monitoring will start automatically"
        }

        ctx := context.Background()
        startBackgroundMonitoring(ctx, cfg, agentID)
        return "Background monitoring enabled successfully"
}

func disableBackgroundMonitoring() string {
        monitorMu.Lock()
        defer monitorMu.Unlock()

        if !monitorRunning {
                return "Background monitoring is not currently running"
        }

        if monitorCancel != nil {
                monitorCancel()
                monitorCancel = nil
        }
        monitorRunning = false

        logMessage("INFO", "Background monitoring disabled")
        if monitorCfg != nil {
                sendAgentLog(monitorCfg, monitorAgentID, "monitoring_stopped", "info",
                        "Background monitoring disabled via command")
        }

        return "Background monitoring disabled successfully"
}

func periodicSecurityScan(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := time.Duration(defaultMonitorInterval) * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Periodic security scan started (every %ds)", defaultMonitorInterval)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Periodic security scan stopped")
                        return
                case <-ticker.C:
                        logMessage("INFO", "Running periodic security scan...")
                        result := securityScan()

                        var events []SecurityEventReport
                        lines := strings.Split(result, "\n")
                        for _, line := range lines {
                                line = strings.TrimSpace(line)
                                if strings.Contains(strings.ToLower(line), "warning") || strings.Contains(strings.ToLower(line), "critical") {
                                        severity := "medium"
                                        if strings.Contains(strings.ToLower(line), "critical") {
                                                severity = "critical"
                                        }
                                        events = append(events, SecurityEventReport{
                                                EventType:   "security_scan_finding",
                                                Severity:    severity,
                                                Description: line,
                                                Source:      "agent-periodic-scan",
                                        })
                                }
                        }

                        if len(events) > 0 {
                                sendSecurityEvents(cfg, agentID, events)
                                logMessage("INFO", "Periodic scan found %d security findings", len(events))
                        } else {
                                logMessage("DEBUG", "Periodic security scan completed with no findings")
                        }
                }
        }
}

func processWatchlistMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := time.Duration(defaultProcessCheckInterval) * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Process watchlist monitor started (every %ds)", defaultProcessCheckInterval)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Process watchlist monitor stopped")
                        return
                case <-ticker.C:
                        checkRunningProcesses(cfg, agentID)
                }
        }
}

func checkRunningProcesses(cfg *AgentConfig, agentID float64) {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
        } else {
                cmd = exec.Command("ps", "aux")
        }

        out, err := cmd.Output()
        if err != nil {
                logMessage("WARN", "Process watchlist check failed: %v", err)
                return
        }

        processes := strings.ToLower(string(out))
        var events []SecurityEventReport

        for _, malicious := range knownMaliciousProcesses {
                if strings.Contains(processes, malicious) {
                        logMessage("WARN", "Malicious process detected: %s", malicious)
                        events = append(events, SecurityEventReport{
                                EventType:   "malicious_process_detected",
                                Severity:    "critical",
                                Description: fmt.Sprintf("Known malicious process detected: %s on host %s", malicious, getHostname()),
                                Source:      "agent-process-monitor",
                                RawData:     fmt.Sprintf("process_name=%s", malicious),
                        })
                }
        }

        if len(events) > 0 {
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Process monitor detected %d malicious processes", len(events))
        }
}

func fileIntegrityMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := time.Duration(defaultFileCheckInterval) * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "File integrity monitor started (every %ds)", defaultFileCheckInterval)

        scanCriticalDirs(cfg, agentID, true)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "File integrity monitor stopped")
                        return
                case <-ticker.C:
                        scanCriticalDirs(cfg, agentID, false)
                }
        }
}

func scanCriticalDirs(cfg *AgentConfig, agentID float64, initialScan bool) {
        var dirs []string
        if runtime.GOOS == "windows" {
                dirs = criticalDirsWindows
                userProfile := os.Getenv("USERPROFILE")
                if userProfile != "" {
                        dirs = append(dirs, filepath.Join(userProfile, "Downloads"))
                        dirs = append(dirs, filepath.Join(userProfile, "AppData", "Local", "Temp"))
                        dirs = append(dirs, filepath.Join(userProfile, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
                }
        } else {
                dirs = criticalDirsLinux
                homeDir := os.Getenv("HOME")
                if homeDir != "" {
                        dirs = append(dirs, filepath.Join(homeDir, "Downloads"))
                }
        }

        var events []SecurityEventReport
        var scanResults []FileScanFileEntry
        totalFiles := 0
        execCount := 0
        recentCount := 0
        execExtensions := map[string]bool{
                ".exe": true, ".dll": true, ".bat": true, ".cmd": true,
                ".ps1": true, ".vbs": true, ".js": true, ".msi": true,
                ".sh": true, ".bin": true, ".elf": true, ".so": true,
        }

        for _, dir := range dirs {
                if _, err := os.Stat(dir); os.IsNotExist(err) {
                        continue
                }

                entries, err := os.ReadDir(dir)
                if err != nil {
                        continue
                }

                for _, entry := range entries {
                        if entry.IsDir() {
                                continue
                        }

                        ext := strings.ToLower(filepath.Ext(entry.Name()))
                        if !execExtensions[ext] {
                                continue
                        }

                        fullPath := filepath.Join(dir, entry.Name())
                        info, err := entry.Info()
                        if err != nil {
                                continue
                        }

                        totalFiles++
                        hash := hashFile(fullPath)
                        if hash == "" {
                                continue
                        }
                        execCount++

                        recentlyModified := time.Since(info.ModTime()) < 24*time.Hour
                        if recentlyModified {
                                recentCount++
                        }

                        result := FileScanFileEntry{
                                Path:       fullPath,
                                Size:       info.Size(),
                                SHA256:     hash,
                                ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
                                IsRecent:   recentlyModified,
                        }

                        fileHashesMu.Lock()
                        oldHash, exists := fileHashes[fullPath]
                        if initialScan {
                                fileHashes[fullPath] = hash
                                fileHashesMu.Unlock()
                                if recentlyModified {
                                        result.IsSuspicious = true
                                        result.Reason = "Recently modified executable in critical directory"
                                        scanResults = append(scanResults, result)
                                }
                                continue
                        }

                        if exists && oldHash != hash {
                                fileHashes[fullPath] = hash
                                fileHashesMu.Unlock()

                                result.IsSuspicious = true
                                result.Reason = "File hash changed since last scan"
                                scanResults = append(scanResults, result)

                                events = append(events, SecurityEventReport{
                                        EventType:   "file_integrity_changed",
                                        Severity:    "high",
                                        Description: fmt.Sprintf("File hash changed: %s (old: %s, new: %s)", fullPath, oldHash[:16]+"...", hash[:16]+"..."),
                                        Source:      "agent-file-integrity",
                                        RawData:     fmt.Sprintf("path=%s;old_hash=%s;new_hash=%s", fullPath, oldHash, hash),
                                })
                        } else if !exists {
                                fileHashes[fullPath] = hash
                                fileHashesMu.Unlock()

                                if recentlyModified {
                                        result.IsSuspicious = true
                                        result.Reason = "New executable detected in critical directory"
                                        scanResults = append(scanResults, result)

                                        events = append(events, SecurityEventReport{
                                                EventType:   "new_executable_detected",
                                                Severity:    "medium",
                                                Description: fmt.Sprintf("New executable found in critical directory: %s (hash: %s)", fullPath, hash[:16]+"..."),
                                                Source:      "agent-file-integrity",
                                                RawData:     fmt.Sprintf("path=%s;hash=%s;size=%d", fullPath, hash, info.Size()),
                                        })
                                }
                        } else {
                                fileHashesMu.Unlock()
                        }
                }
        }

        if len(events) > 0 {
                sendSecurityEvents(cfg, agentID, events)
                logMessage("INFO", "File integrity monitor detected %d changes", len(events))
        }

        if len(scanResults) > 0 {
                suspiciousCount := 0
                for _, r := range scanResults {
                        if r.IsSuspicious {
                                suspiciousCount++
                        }
                }
                sendFileScanResults(cfg, agentID, dirs, totalFiles, execCount, recentCount, suspiciousCount, scanResults)
        }
}

func hashFile(path string) string {
        f, err := os.Open(path)
        if err != nil {
                return ""
        }
        defer f.Close()

        h := sha256.New()
        if _, err := io.Copy(h, io.LimitReader(f, 50*1024*1024)); err != nil {
                return ""
        }
        return hex.EncodeToString(h.Sum(nil))
}

func networkConnectionMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := time.Duration(defaultNetCheckInterval) * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Network connection monitor started (every %ds)", defaultNetCheckInterval)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Network connection monitor stopped")
                        return
                case <-ticker.C:
                        checkSuspiciousConnections(cfg, agentID)
                }
        }
}

func checkSuspiciousConnections(cfg *AgentConfig, agentID float64) {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("netstat", "-an")
        } else {
                cmd = exec.Command("ss", "-tun")
        }

        out, err := cmd.Output()
        if err != nil {
                logMessage("WARN", "Network connection check failed: %v", err)
                return
        }

        lines := strings.Split(string(out), "\n")
        var events []SecurityEventReport

        suspiciousPortMap := make(map[int]bool)
        for _, p := range suspiciousPorts {
                suspiciousPortMap[p] = true
        }

        for _, line := range lines {
                line = strings.TrimSpace(line)
                if !strings.Contains(line, "ESTABLISHED") && !strings.Contains(line, "ESTAB") {
                        continue
                }

                fields := strings.Fields(line)
                if len(fields) < 5 {
                        continue
                }

                var remoteAddr string
                if runtime.GOOS == "windows" {
                        if len(fields) >= 3 {
                                remoteAddr = fields[2]
                        }
                } else {
                        if len(fields) >= 5 {
                                remoteAddr = fields[4]
                        }
                }

                if remoteAddr == "" {
                        continue
                }

                parts := strings.Split(remoteAddr, ":")
                if len(parts) < 2 {
                        continue
                }
                portStr := parts[len(parts)-1]
                var port int
                fmt.Sscanf(portStr, "%d", &port)

                if suspiciousPortMap[port] {
                        ip := strings.Join(parts[:len(parts)-1], ":")
                        events = append(events, SecurityEventReport{
                                EventType:   "suspicious_connection",
                                Severity:    "high",
                                Description: fmt.Sprintf("Suspicious outbound connection detected to %s on port %d from host %s", ip, port, getHostname()),
                                Source:      "agent-network-monitor",
                                SourceIp:    ip,
                                RawData:     fmt.Sprintf("remote=%s;port=%d;line=%s", remoteAddr, port, line),
                        })
                }
        }

        if len(events) > 0 {
                if len(events) > 10 {
                        events = events[:10]
                }
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Network monitor detected %d suspicious connections", len(events))
        }
}

func sendSecurityEvents(cfg *AgentConfig, agentID float64, events []SecurityEventReport) {
        if len(events) == 0 {
                return
        }

        body := SecurityEventsRequest{
                AgentID: agentID,
                Token:   cfg.APIKey,
                Events:  events,
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/security-events", body)
        if err != nil {
                logMessage("WARN", "Failed to send security events: %v", err)
                return
        }
        resp.Body.Close()

        if resp.StatusCode != 201 {
                logMessage("WARN", "Security events endpoint returned status %d", resp.StatusCode)
        } else {
                logMessage("INFO", "Sent %d security events to server", len(events))
        }
}

func sendFileScanResults(cfg *AgentConfig, agentID float64, scannedDirs []string, totalFiles, executables, recentFiles, suspiciousFiles int, files []FileScanFileEntry) {
        if len(files) == 0 {
                return
        }

        body := FileScanRequest{
                AgentID: agentID,
                Token:   cfg.APIKey,
                Report: FileScanReport{
                        ScannedDirs:     scannedDirs,
                        TotalFiles:      totalFiles,
                        Executables:     executables,
                        RecentFiles:     recentFiles,
                        SuspiciousFiles: suspiciousFiles,
                        Files:           files,
                        ScanTime:        time.Now().UTC().Format(time.RFC3339),
                },
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/file-scan", body)
        if err != nil {
                logMessage("WARN", "Failed to send file scan results: %v", err)
                return
        }
        resp.Body.Close()

        if resp.StatusCode != 201 {
                logMessage("WARN", "File scan endpoint returned status %d", resp.StatusCode)
        } else {
                logMessage("INFO", "Sent %d file scan results to server", len(files))
        }
}
