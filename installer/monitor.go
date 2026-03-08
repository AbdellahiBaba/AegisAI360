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
        "certutil", "bitsadmin", "regsvr32", "mshta", "wmic",
        "cscript", "wscript", "rundll32", "msbuild",
        "installutil", "regasm", "regsvcs", "cmstp",
        "fodhelper", "eventvwr", "sdclt", "slui",
        "forfiles", "pcalua", "infdefaultinstall",
        "msconfig", "dnscmd", "ftp", "desktopimgdownldr",
        "esentutl", "extrac32", "findstr", "hh",
        "makecab", "nltest", "replace", "rpcping",
        "schtasks", "scriptrunner", "syncappvpublishingserver",
        "tttracer", "vbc", "xwizard", "advpack",
        "ieexec", "bash", "pcwrun",
}

var monitorSuspiciousPorts = []int{
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

type FileScanRequest struct {
        AgentID float64        `json:"agentId"`
        Token   string         `json:"token"`
        Report  FileScanReport `json:"report"`
}

var registryPersistenceKeys = []string{
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
        `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
        `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
        `HKLM\SYSTEM\CurrentControlSet\Services`,
        `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`,
}

var suspiciousScriptPatterns = []struct {
        pattern string
        reason  string
}{
        {"-enc ", "Encoded PowerShell command detected"},
        {"-encodedcommand", "Encoded PowerShell command detected"},
        {"invoke-expression", "PowerShell Invoke-Expression (download cradle)"},
        {"iex ", "PowerShell IEX shorthand (potential download cradle)"},
        {"downloadstring", "PowerShell DownloadString (download cradle)"},
        {"downloadfile", "PowerShell DownloadFile (download cradle)"},
        {"invoke-webrequest", "PowerShell web request (potential download cradle)"},
        {"start-bitstransfer", "PowerShell BITS transfer (potential download cradle)"},
        {"new-object net.webclient", "PowerShell WebClient instantiation"},
        {"bypass", "PowerShell execution policy bypass"},
        {"-nop ", "PowerShell -NoProfile flag (evasion)"},
        {"-w hidden", "PowerShell hidden window (evasion)"},
        {"-windowstyle hidden", "PowerShell hidden window (evasion)"},
}

var suspiciousScriptHosts = []string{
        "cscript.exe", "wscript.exe", "mshta.exe",
        "cscript", "wscript", "mshta",
}

var uacBypassProcesses = []string{
        "fodhelper.exe", "eventvwr.exe", "sdclt.exe", "slui.exe",
        "computerdefaults.exe", "dccw.exe",
        "fodhelper", "eventvwr", "sdclt", "slui",
        "computerdefaults", "dccw",
}

var (
        monitorRunning       bool
        monitorMu            sync.Mutex
        monitorCancel        context.CancelFunc
        monitorCfg           *AgentConfig
        monitorAgentID       float64
        fileHashes           map[string]string
        fileHashesMu         sync.Mutex
        registrySnapshots    map[string]string
        registrySnapshotsMu  sync.Mutex
        scheduledTaskSnapshot string
        taskSnapshotMu       sync.Mutex
        adminUsersSnapshot   string
        adminSnapshotMu      sync.Mutex
        selfBinaryHash       string
        selfBinaryPath       string
)

func init() {
        fileHashes = make(map[string]string)
        registrySnapshots = make(map[string]string)
        exePath, err := os.Executable()
        if err == nil {
                selfBinaryPath = exePath
                selfBinaryHash = hashSelfBinary(exePath)
        }
}

func hashSelfBinary(path string) string {
        f, err := os.Open(path)
        if err != nil {
                return ""
        }
        defer f.Close()
        h := sha256.New()
        if _, err := io.Copy(h, f); err != nil {
                return ""
        }
        return hex.EncodeToString(h.Sum(nil))
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
        go registryPersistenceMonitor(monitorCtx, cfg, agentID)
        go scheduledTaskMonitor(monitorCtx, cfg, agentID)
        go privilegeEscalationMonitor(monitorCtx, cfg, agentID)
        go powershellScriptMonitor(monitorCtx, cfg, agentID)
        go dllSideloadMonitor(monitorCtx, cfg, agentID)
        go selfProtectionMonitor(monitorCtx, cfg, agentID)

        sendAgentLog(cfg, agentID, "monitoring_started", "info",
                "Background monitoring started: security scan, process watchlist, file integrity, network connections, registry persistence, scheduled tasks, privilege escalation, script monitoring, DLL sideloading, self-protection")
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
        var scanResults []FileScanEntry
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

                        result := FileScanEntry{
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
        for _, p := range monitorSuspiciousPorts {
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

func sendFileScanResults(cfg *AgentConfig, agentID float64, scannedDirs []string, totalFiles, executables, recentFiles, suspiciousFiles int, files []FileScanEntry) {
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

func registryPersistenceMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        if runtime.GOOS != "windows" {
                logMessage("INFO", "Registry persistence monitor skipped (non-Windows OS)")
                return
        }

        interval := 120 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Registry persistence monitor started (every 120s)")

        checkRegistryPersistence(cfg, agentID, true)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Registry persistence monitor stopped")
                        return
                case <-ticker.C:
                        checkRegistryPersistence(cfg, agentID, false)
                }
        }
}

func checkRegistryPersistence(cfg *AgentConfig, agentID float64, initialScan bool) {
        var events []SecurityEventReport

        for _, key := range registryPersistenceKeys {
                out, err := exec.Command("reg", "query", key).Output()
                if err != nil {
                        continue
                }

                currentSnapshot := strings.TrimSpace(string(out))

                registrySnapshotsMu.Lock()
                previousSnapshot, exists := registrySnapshots[key]
                registrySnapshots[key] = currentSnapshot
                registrySnapshotsMu.Unlock()

                if initialScan || !exists {
                        continue
                }

                if currentSnapshot != previousSnapshot {
                        newEntries := diffLines(previousSnapshot, currentSnapshot)
                        for _, entry := range newEntries {
                                entry = strings.TrimSpace(entry)
                                if entry == "" || strings.HasPrefix(entry, "HKEY") {
                                        continue
                                }
                                events = append(events, SecurityEventReport{
                                        EventType:   "registry_persistence_change",
                                        Severity:    "high",
                                        Description: fmt.Sprintf("Registry persistence key modified: %s — new/changed entry: %s", key, truncate(entry, 200)),
                                        Source:      "agent-registry-monitor",
                                        RawData:     fmt.Sprintf("key=%s;entry=%s", key, entry),
                                })
                        }
                }
        }

        if len(events) > 0 {
                if len(events) > 20 {
                        events = events[:20]
                }
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Registry persistence monitor detected %d changes", len(events))
        }
}

func scheduledTaskMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        if runtime.GOOS != "windows" {
                logMessage("INFO", "Scheduled task monitor skipped (non-Windows OS)")
                return
        }

        interval := 180 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Scheduled task monitor started (every 180s)")

        snapshot := captureScheduledTasks()
        taskSnapshotMu.Lock()
        scheduledTaskSnapshot = snapshot
        taskSnapshotMu.Unlock()

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Scheduled task monitor stopped")
                        return
                case <-ticker.C:
                        checkScheduledTaskChanges(cfg, agentID)
                }
        }
}

func captureScheduledTasks() string {
        out, err := exec.Command("schtasks", "/query", "/fo", "csv", "/nh", "/v").Output()
        if err != nil {
                out2, err2 := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output()
                if err2 != nil {
                        return ""
                }
                return string(out2)
        }
        return string(out)
}

func checkScheduledTaskChanges(cfg *AgentConfig, agentID float64) {
        currentSnapshot := captureScheduledTasks()
        if currentSnapshot == "" {
                return
        }

        taskSnapshotMu.Lock()
        previousSnapshot := scheduledTaskSnapshot
        scheduledTaskSnapshot = currentSnapshot
        taskSnapshotMu.Unlock()

        if previousSnapshot == "" {
                return
        }

        newTasks := diffLines(previousSnapshot, currentSnapshot)
        var events []SecurityEventReport

        suspiciousCreators := []string{"powershell", "cmd.exe", "wscript", "cscript", "mshta", "svchost"}

        for _, task := range newTasks {
                task = strings.TrimSpace(task)
                if task == "" {
                        continue
                }

                severity := "medium"
                taskLower := strings.ToLower(task)
                for _, creator := range suspiciousCreators {
                        if strings.Contains(taskLower, creator) {
                                severity = "high"
                                break
                        }
                }

                if strings.Contains(taskLower, "hidden") || strings.Contains(taskLower, "system32") {
                        severity = "high"
                }

                events = append(events, SecurityEventReport{
                        EventType:   "scheduled_task_change",
                        Severity:    severity,
                        Description: fmt.Sprintf("New or modified scheduled task detected: %s", truncate(task, 200)),
                        Source:      "agent-task-monitor",
                        RawData:     truncate(task, 500),
                })
        }

        if len(events) > 0 {
                if len(events) > 15 {
                        events = events[:15]
                }
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Scheduled task monitor detected %d task changes", len(events))
        }
}

func privilegeEscalationMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := 120 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Privilege escalation monitor started (every 120s)")

        snapshot := captureAdminUsers()
        adminSnapshotMu.Lock()
        adminUsersSnapshot = snapshot
        adminSnapshotMu.Unlock()

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Privilege escalation monitor stopped")
                        return
                case <-ticker.C:
                        checkPrivilegeEscalation(cfg, agentID)
                }
        }
}

func captureAdminUsers() string {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("net", "localgroup", "Administrators").Output()
                if err != nil {
                        return ""
                }
                return string(out)
        }
        out, err := exec.Command("getent", "group", "sudo").Output()
        if err != nil {
                out2, _ := exec.Command("grep", "^sudo:", "/etc/group").Output()
                return string(out2)
        }
        return string(out)
}

func checkPrivilegeEscalation(cfg *AgentConfig, agentID float64) {
        var events []SecurityEventReport

        currentAdmins := captureAdminUsers()
        adminSnapshotMu.Lock()
        previousAdmins := adminUsersSnapshot
        adminUsersSnapshot = currentAdmins
        adminSnapshotMu.Unlock()

        if previousAdmins != "" && currentAdmins != previousAdmins {
                newAdmins := diffLines(previousAdmins, currentAdmins)
                for _, admin := range newAdmins {
                        admin = strings.TrimSpace(admin)
                        if admin == "" || strings.HasPrefix(admin, "---") || strings.HasPrefix(admin, "The command") || strings.HasPrefix(admin, "Comment") || strings.HasPrefix(admin, "Members") || strings.HasPrefix(admin, "Alias") {
                                continue
                        }
                        events = append(events, SecurityEventReport{
                                EventType:   "new_admin_user",
                                Severity:    "critical",
                                Description: fmt.Sprintf("New administrator user detected: %s on host %s", admin, getHostname()),
                                Source:      "agent-privesc-monitor",
                                RawData:     fmt.Sprintf("user=%s", admin),
                        })
                }
        }

        checkUACBypass(cfg, agentID, &events)

        if len(events) > 0 {
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Privilege escalation monitor detected %d events", len(events))
        }
}

func checkUACBypass(cfg *AgentConfig, agentID float64, events *[]SecurityEventReport) {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
        } else {
                cmd = exec.Command("ps", "aux")
        }

        out, err := cmd.Output()
        if err != nil {
                return
        }

        processes := strings.ToLower(string(out))
        for _, uacProc := range uacBypassProcesses {
                if strings.Contains(processes, uacProc) {
                        *events = append(*events, SecurityEventReport{
                                EventType:   "uac_bypass_attempt",
                                Severity:    "critical",
                                Description: fmt.Sprintf("Potential UAC bypass process detected: %s — known auto-elevate binary used for privilege escalation", uacProc),
                                Source:      "agent-privesc-monitor",
                                RawData:     fmt.Sprintf("process=%s", uacProc),
                        })
                }
        }
}

func powershellScriptMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := 90 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "PowerShell/Script monitor started (every 90s)")

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "PowerShell/Script monitor stopped")
                        return
                case <-ticker.C:
                        checkSuspiciousScripts(cfg, agentID)
                }
        }
}

func checkSuspiciousScripts(cfg *AgentConfig, agentID float64) {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("wmic", "process", "get", "CommandLine,ProcessId", "/format:csv")
        } else {
                cmd = exec.Command("ps", "-eo", "pid,args")
        }

        out, err := cmd.Output()
        if err != nil {
                return
        }

        lines := strings.Split(string(out), "\n")
        var events []SecurityEventReport

        for _, line := range lines {
                lineLower := strings.ToLower(strings.TrimSpace(line))
                if lineLower == "" {
                        continue
                }

                for _, pattern := range suspiciousScriptPatterns {
                        if strings.Contains(lineLower, pattern.pattern) {
                                events = append(events, SecurityEventReport{
                                        EventType:   "suspicious_script_execution",
                                        Severity:    "high",
                                        Description: fmt.Sprintf("%s: %s", pattern.reason, truncate(line, 200)),
                                        Source:      "agent-script-monitor",
                                        RawData:     truncate(line, 500),
                                })
                                break
                        }
                }

                for _, host := range suspiciousScriptHosts {
                        if strings.Contains(lineLower, host) {
                                events = append(events, SecurityEventReport{
                                        EventType:   "suspicious_script_host",
                                        Severity:    "medium",
                                        Description: fmt.Sprintf("Suspicious script host process detected: %s — %s", host, truncate(line, 150)),
                                        Source:      "agent-script-monitor",
                                        RawData:     truncate(line, 500),
                                })
                                break
                        }
                }
        }

        if len(events) > 0 {
                if len(events) > 15 {
                        events = events[:15]
                }
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Script monitor detected %d suspicious script executions", len(events))
        }
}

func dllSideloadMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        if runtime.GOOS != "windows" {
                logMessage("INFO", "DLL sideloading monitor skipped (non-Windows OS)")
                return
        }

        interval := 300 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "DLL sideloading monitor started (every 300s)")

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "DLL sideloading monitor stopped")
                        return
                case <-ticker.C:
                        checkDLLSideloading(cfg, agentID)
                }
        }
}

func checkDLLSideloading(cfg *AgentConfig, agentID float64) {
        suspiciousDirs := []string{
                os.Getenv("TEMP"),
                os.Getenv("TMP"),
                filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
                filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
                `C:\Users\Public`,
                `C:\Users\Public\Downloads`,
        }

        systemDirs := []string{
                `C:\Windows\System32`,
                `C:\Windows\SysWOW64`,
        }

        var events []SecurityEventReport

        for _, dir := range suspiciousDirs {
                if dir == "" {
                        continue
                }
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
                        name := strings.ToLower(entry.Name())
                        if !strings.HasSuffix(name, ".dll") {
                                continue
                        }
                        info, err := entry.Info()
                        if err != nil {
                                continue
                        }
                        if time.Since(info.ModTime()) < 48*time.Hour {
                                fullPath := filepath.Join(dir, entry.Name())
                                events = append(events, SecurityEventReport{
                                        EventType:   "dll_suspicious_location",
                                        Severity:    "high",
                                        Description: fmt.Sprintf("DLL found in suspicious directory: %s (size: %d bytes, modified: %s)", fullPath, info.Size(), info.ModTime().Format(time.RFC3339)),
                                        Source:      "agent-dll-monitor",
                                        RawData:     fmt.Sprintf("path=%s;size=%d;modified=%s", fullPath, info.Size(), info.ModTime().Format(time.RFC3339)),
                                })
                        }
                }
        }

        for _, dir := range systemDirs {
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
                        name := strings.ToLower(entry.Name())
                        if !strings.HasSuffix(name, ".dll") {
                                continue
                        }
                        info, err := entry.Info()
                        if err != nil {
                                continue
                        }
                        if time.Since(info.ModTime()) < 24*time.Hour {
                                fullPath := filepath.Join(dir, entry.Name())
                                out, err := exec.Command("powershell", "-Command",
                                        fmt.Sprintf("(Get-AuthenticodeSignature '%s').Status", fullPath)).Output()
                                if err != nil {
                                        continue
                                }
                                sigStatus := strings.TrimSpace(string(out))
                                if sigStatus != "Valid" {
                                        events = append(events, SecurityEventReport{
                                                EventType:   "unsigned_dll_system_dir",
                                                Severity:    "critical",
                                                Description: fmt.Sprintf("Unsigned/invalid DLL in system directory: %s (signature: %s)", fullPath, sigStatus),
                                                Source:      "agent-dll-monitor",
                                                RawData:     fmt.Sprintf("path=%s;signature=%s;size=%d", fullPath, sigStatus, info.Size()),
                                        })
                                }
                        }
                }
        }

        if len(events) > 0 {
                if len(events) > 20 {
                        events = events[:20]
                }
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "DLL sideloading monitor detected %d suspicious DLLs", len(events))
        }
}

func selfProtectionMonitor(ctx context.Context, cfg *AgentConfig, agentID float64) {
        interval := 60 * time.Second
        ticker := time.NewTicker(interval)
        defer ticker.Stop()

        logMessage("INFO", "Self-protection monitor started (every 60s)")

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Self-protection monitor stopped")
                        return
                case <-ticker.C:
                        checkSelfProtection(cfg, agentID)
                }
        }
}

func checkSelfProtection(cfg *AgentConfig, agentID float64) {
        var events []SecurityEventReport

        if selfBinaryPath != "" && selfBinaryHash != "" {
                currentHash := hashSelfBinary(selfBinaryPath)
                if currentHash != "" && currentHash != selfBinaryHash {
                        events = append(events, SecurityEventReport{
                                EventType:   "agent_binary_modified",
                                Severity:    "critical",
                                Description: fmt.Sprintf("Agent binary has been modified! Path: %s, original hash: %s, current hash: %s", selfBinaryPath, selfBinaryHash[:16]+"...", currentHash[:16]+"..."),
                                Source:      "agent-self-protection",
                                RawData:     fmt.Sprintf("path=%s;original_hash=%s;current_hash=%s", selfBinaryPath, selfBinaryHash, currentHash),
                        })
                }
        }

        if runtime.GOOS == "windows" {
                out, err := exec.Command("sc", "query", serviceName).Output()
                if err == nil {
                        outStr := string(out)
                        if strings.Contains(outStr, "STOPPED") || strings.Contains(outStr, "STOP_PENDING") {
                                logMessage("WARN", "Self-protection: agent service was stopped externally, attempting restart")
                                events = append(events, SecurityEventReport{
                                        EventType:   "agent_service_stopped",
                                        Severity:    "critical",
                                        Description: fmt.Sprintf("Agent service '%s' was stopped externally — auto-restart initiated", serviceName),
                                        Source:      "agent-self-protection",
                                })
                                go func() {
                                        time.Sleep(2 * time.Second)
                                        restartService()
                                }()
                        }
                }
        } else {
                out, err := exec.Command("systemctl", "is-active", "aegisai360-agent").Output()
                if err == nil {
                        status := strings.TrimSpace(string(out))
                        if status != "active" && status != "activating" {
                                logMessage("WARN", "Self-protection: agent service is not active (%s), attempting restart", status)
                                events = append(events, SecurityEventReport{
                                        EventType:   "agent_service_stopped",
                                        Severity:    "critical",
                                        Description: fmt.Sprintf("Agent service status is '%s' — auto-restart initiated", status),
                                        Source:      "agent-self-protection",
                                })
                                go func() {
                                        time.Sleep(2 * time.Second)
                                        restartService()
                                }()
                        }
                }
        }

        if len(events) > 0 {
                sendSecurityEvents(cfg, agentID, events)
                logMessage("WARN", "Self-protection detected %d issues", len(events))
        }
}

func RunDeepScan() string {
        var sb strings.Builder
        sb.WriteString("=== AegisAI360 Deep Security Scan ===\n")
        sb.WriteString(fmt.Sprintf("Scan started: %s\n", time.Now().UTC().Format(time.RFC3339)))
        sb.WriteString(fmt.Sprintf("Host: %s (%s)\n\n", getHostname(), runtime.GOOS))

        sb.WriteString("--- [1/7] Standard Security Scan ---\n")
        sb.WriteString(securityScan())
        sb.WriteString("\n\n")

        sb.WriteString("--- [2/7] Process Watchlist Check ---\n")
        sb.WriteString(deepScanProcesses())
        sb.WriteString("\n\n")

        sb.WriteString("--- [3/7] Registry Persistence Check ---\n")
        sb.WriteString(deepScanRegistryPersistence())
        sb.WriteString("\n\n")

        sb.WriteString("--- [4/7] Scheduled Task Analysis ---\n")
        sb.WriteString(deepScanScheduledTasks())
        sb.WriteString("\n\n")

        sb.WriteString("--- [5/7] Privilege Escalation Check ---\n")
        sb.WriteString(deepScanPrivilegeEscalation())
        sb.WriteString("\n\n")

        sb.WriteString("--- [6/7] PowerShell/Script Monitoring ---\n")
        sb.WriteString(deepScanScripts())
        sb.WriteString("\n\n")

        sb.WriteString("--- [7/7] DLL Sideloading Check ---\n")
        sb.WriteString(deepScanDLLSideloading())
        sb.WriteString("\n\n")

        sb.WriteString("--- Self-Protection Status ---\n")
        sb.WriteString(deepScanSelfProtection())
        sb.WriteString("\n\n")

        sb.WriteString(fmt.Sprintf("Scan completed: %s\n", time.Now().UTC().Format(time.RFC3339)))
        return sb.String()
}

func deepScanProcesses() string {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
        } else {
                cmd = exec.Command("ps", "aux")
        }

        out, err := cmd.Output()
        if err != nil {
                return fmt.Sprintf("Process check failed: %v", err)
        }

        processes := strings.ToLower(string(out))
        var sb strings.Builder
        found := 0

        for _, malicious := range knownMaliciousProcesses {
                if strings.Contains(processes, malicious) {
                        found++
                        sb.WriteString(fmt.Sprintf("  [CRITICAL] Malicious/suspicious process detected: %s\n", malicious))
                }
        }

        if found == 0 {
                sb.WriteString("  No known malicious processes detected\n")
        } else {
                sb.WriteString(fmt.Sprintf("  Total suspicious processes: %d\n", found))
        }
        sb.WriteString(fmt.Sprintf("  Watchlist size: %d signatures\n", len(knownMaliciousProcesses)))
        return sb.String()
}

func deepScanRegistryPersistence() string {
        if runtime.GOOS != "windows" {
                return "  Registry scanning only available on Windows\n"
        }

        var sb strings.Builder
        totalEntries := 0

        for _, key := range registryPersistenceKeys {
                out, err := exec.Command("reg", "query", key).Output()
                if err != nil {
                        sb.WriteString(fmt.Sprintf("  [INFO] Key not accessible: %s\n", key))
                        continue
                }
                lines := strings.Split(strings.TrimSpace(string(out)), "\n")
                entryCount := 0
                for _, line := range lines {
                        line = strings.TrimSpace(line)
                        if line != "" && !strings.HasPrefix(line, "HKEY") {
                                entryCount++
                        }
                }
                totalEntries += entryCount
                if entryCount > 0 {
                        sb.WriteString(fmt.Sprintf("  [CHECK] %s — %d entries\n", key, entryCount))
                }
        }

        sb.WriteString(fmt.Sprintf("  Total persistence entries: %d across %d keys\n", totalEntries, len(registryPersistenceKeys)))
        return sb.String()
}

func deepScanScheduledTasks() string {
        if runtime.GOOS != "windows" {
                return "  Scheduled task scanning only available on Windows\n"
        }

        out, err := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output()
        if err != nil {
                return fmt.Sprintf("  Failed to query scheduled tasks: %v\n", err)
        }

        lines := strings.Split(string(out), "\n")
        var sb strings.Builder
        taskCount := 0
        suspiciousCount := 0

        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                taskCount++
                lineLower := strings.ToLower(line)
                isSuspicious := false
                for _, pattern := range []string{"powershell", "cmd.exe", "wscript", "cscript", "mshta", "temp", "appdata"} {
                        if strings.Contains(lineLower, pattern) {
                                isSuspicious = true
                                break
                        }
                }
                if isSuspicious {
                        suspiciousCount++
                        sb.WriteString(fmt.Sprintf("  [WARNING] Suspicious task: %s\n", truncate(line, 200)))
                }
        }

        sb.WriteString(fmt.Sprintf("  Total tasks: %d, Suspicious: %d\n", taskCount, suspiciousCount))
        return sb.String()
}

func deepScanPrivilegeEscalation() string {
        var sb strings.Builder

        admins := captureAdminUsers()
        if admins != "" {
                sb.WriteString("  Admin/sudo group members:\n")
                for _, line := range strings.Split(admins, "\n") {
                        line = strings.TrimSpace(line)
                        if line != "" && !strings.HasPrefix(line, "---") && !strings.HasPrefix(line, "The command") && !strings.HasPrefix(line, "Comment") && !strings.HasPrefix(line, "Members") && !strings.HasPrefix(line, "Alias") {
                                sb.WriteString(fmt.Sprintf("    - %s\n", line))
                        }
                }
        }

        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
        } else {
                cmd = exec.Command("ps", "aux")
        }

        out, err := cmd.Output()
        if err == nil {
                processes := strings.ToLower(string(out))
                for _, uacProc := range uacBypassProcesses {
                        if strings.Contains(processes, uacProc) {
                                sb.WriteString(fmt.Sprintf("  [CRITICAL] UAC bypass process detected: %s\n", uacProc))
                        }
                }
        }

        return sb.String()
}

func deepScanScripts() string {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("wmic", "process", "get", "CommandLine,ProcessId", "/format:csv")
        } else {
                cmd = exec.Command("ps", "-eo", "pid,args")
        }

        out, err := cmd.Output()
        if err != nil {
                return fmt.Sprintf("  Script check failed: %v\n", err)
        }

        lines := strings.Split(string(out), "\n")
        var sb strings.Builder
        found := 0

        for _, line := range lines {
                lineLower := strings.ToLower(strings.TrimSpace(line))
                if lineLower == "" {
                        continue
                }

                for _, pattern := range suspiciousScriptPatterns {
                        if strings.Contains(lineLower, pattern.pattern) {
                                found++
                                sb.WriteString(fmt.Sprintf("  [WARNING] %s: %s\n", pattern.reason, truncate(line, 150)))
                                break
                        }
                }

                for _, host := range suspiciousScriptHosts {
                        if strings.Contains(lineLower, host) {
                                found++
                                sb.WriteString(fmt.Sprintf("  [WARNING] Script host running: %s\n", truncate(line, 150)))
                                break
                        }
                }
        }

        if found == 0 {
                sb.WriteString("  No suspicious script executions detected\n")
        } else {
                sb.WriteString(fmt.Sprintf("  Total suspicious script activities: %d\n", found))
        }
        return sb.String()
}

func deepScanDLLSideloading() string {
        if runtime.GOOS != "windows" {
                return "  DLL sideloading check only available on Windows\n"
        }

        var sb strings.Builder
        suspiciousDirs := []string{
                os.Getenv("TEMP"),
                os.Getenv("TMP"),
                filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
                filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
        }

        found := 0
        for _, dir := range suspiciousDirs {
                if dir == "" {
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
                        if strings.HasSuffix(strings.ToLower(entry.Name()), ".dll") {
                                info, err := entry.Info()
                                if err != nil {
                                        continue
                                }
                                if time.Since(info.ModTime()) < 48*time.Hour {
                                        found++
                                        sb.WriteString(fmt.Sprintf("  [WARNING] DLL in suspicious location: %s (size: %d, modified: %s)\n",
                                                filepath.Join(dir, entry.Name()), info.Size(), info.ModTime().Format(time.RFC3339)))
                                }
                        }
                }
        }

        if found == 0 {
                sb.WriteString("  No suspicious DLLs found in temp/download directories\n")
        } else {
                sb.WriteString(fmt.Sprintf("  Total suspicious DLLs: %d\n", found))
        }
        return sb.String()
}

func deepScanSelfProtection() string {
        var sb strings.Builder

        if selfBinaryPath != "" && selfBinaryHash != "" {
                currentHash := hashSelfBinary(selfBinaryPath)
                if currentHash == selfBinaryHash {
                        sb.WriteString("  Agent binary integrity: OK (hash unchanged)\n")
                } else if currentHash == "" {
                        sb.WriteString("  Agent binary integrity: UNABLE TO VERIFY\n")
                } else {
                        sb.WriteString("  [CRITICAL] Agent binary integrity: MODIFIED!\n")
                        sb.WriteString(fmt.Sprintf("    Original hash: %s\n", selfBinaryHash))
                        sb.WriteString(fmt.Sprintf("    Current hash:  %s\n", currentHash))
                }
        } else {
                sb.WriteString("  Agent binary path not available for integrity check\n")
        }

        if runtime.GOOS == "windows" {
                out, err := exec.Command("sc", "query", serviceName).Output()
                if err == nil {
                        if strings.Contains(string(out), "RUNNING") {
                                sb.WriteString("  Agent service status: RUNNING\n")
                        } else {
                                sb.WriteString("  [WARNING] Agent service status: NOT RUNNING\n")
                        }
                }
        }

        return sb.String()
}

func diffLines(oldText, newText string) []string {
        oldLines := make(map[string]bool)
        for _, line := range strings.Split(oldText, "\n") {
                oldLines[strings.TrimSpace(line)] = true
        }

        var newLines []string
        for _, line := range strings.Split(newText, "\n") {
                trimmed := strings.TrimSpace(line)
                if trimmed != "" && !oldLines[trimmed] {
                        newLines = append(newLines, trimmed)
                }
        }
        return newLines
}

func truncate(s string, maxLen int) string {
        s = strings.TrimSpace(s)
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen] + "..."
}
