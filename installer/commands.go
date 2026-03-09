package main

import (
        "bytes"
        "crypto/sha256"
        "encoding/base64"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "strconv"
        "strings"
        "sync"
        "time"
)

var terminalWhitelistLinux = []string{
        "whoami", "ifconfig", "ip a", "ip addr", "netstat", "ss",
        "ps aux", "ps -ef", "ls", "cat /etc/os-release", "uname -a",
        "df -h", "free -m", "uptime", "hostname", "w", "last", "top -bn1",
}

var terminalWhitelistWindows = []string{
        "whoami", "ipconfig", "netstat", "tasklist", "dir",
        "systeminfo", "hostname", "ver",
}

type CommandParams struct {
        Cmd        string `json:"cmd"`
        SSID       string `json:"ssid"`
        Name       string `json:"name"`
        Direction  string `json:"direction"`
        Action     string `json:"action"`
        Port       string `json:"port"`
        Protocol   string `json:"protocol"`
        PID        int    `json:"pid"`
        Path       string `json:"path"`
        Pattern    string `json:"pattern"`
        MaxResults int    `json:"maxResults"`
        Filter     string `json:"filter"`
        Log        string `json:"log"`
        Count      int    `json:"count"`
        Key        string `json:"key"`
        Duration   int    `json:"duration"`
        Target     string `json:"target"`
        PortRange  string `json:"portRange"`
        Ports      string `json:"ports"`
}

func parseParams(paramsJSON string) CommandParams {
        var p CommandParams
        if paramsJSON != "" {
                json.Unmarshal([]byte(paramsJSON), &p)
        }
        return p
}

func executeCommand(cmd Command) (string, string) {
        logMessage("INFO", "Executing command: %s (id=%.0f)", cmd.Command, cmd.ID)
        p := parseParams(cmd.Params)

        switch cmd.Command {

        case "ping":
                result := fmt.Sprintf("pong from %s at %s (v%s)", getHostname(), time.Now().Format(time.RFC3339), agentVersion)
                return result, "done"

        case "get_info":
                info := collectSystemInfo()
                return formatSystemInfo(info), "done"

        case "run_system_scan":
                return runSystemScan(), "done"

        case "security_scan":
                return securityScan(), "done"

        case "terminal_exec":
                return executeTerminal(cmd.Params)

        case "restart":
                logMessage("INFO", "Agent restart requested")
                go func() {
                        time.Sleep(2 * time.Second)
                        restartService()
                }()
                return "Agent restart initiated", "done"

        case "update":
                logMessage("INFO", "Agent update requested via command")
                go func() {
                        time.Sleep(1 * time.Second)
                        triggerUpdateCheck()
                }()
                return "Update check initiated", "done"

        case "disk_usage":
                return collectDiskUsage(), "done"

        case "network_scan":
                return collectNetworkScanInfo(), "done"

        case "wifi_list":
                return listWifiNetworks(), "done"

        case "wifi_profiles":
                return listWifiProfiles(), "done"

        case "wifi_connect":
                return connectWifi(p.SSID), "done"

        case "wifi_disconnect":
                return disconnectWifi(), "done"

        case "network_interfaces":
                return listNetworkInterfaces(), "done"

        case "network_connections":
                return collectNetworkScanInfo(), "done"

        case "network_dns":
                return getDNSInfo(), "done"

        case "network_arp":
                return getARPTable(), "done"

        case "network_route":
                return getRoutingTable(), "done"

        case "network_firewall_rules":
                return listFirewallRules(p.Filter), "done"

        case "network_firewall_add":
                return addFirewallRule(p.Name, p.Direction, p.Action, p.Port, p.Protocol), "done"

        case "network_firewall_remove":
                return removeFirewallRule(p.Name), "done"

        case "process_list":
                return processListDetailed(), "done"

        case "process_kill":
                return processKill(p.PID, p.Name), "done"

        case "service_list":
                return listServices(), "done"

        case "service_control":
                return controlService(p.Name, p.Action), "done"

        case "user_list":
                return listUserAccounts(), "done"

        case "user_sessions":
                return listUserSessions(), "done"

        case "installed_software":
                return listInstalledSoftware(), "done"

        case "startup_programs":
                return listStartupPrograms(), "done"

        case "file_search":
                return fileSearch(p.Path, p.Pattern, p.MaxResults), "done"

        case "file_hash":
                return fileHash(p.Path), "done"

        case "event_log":
                return queryEventLog(p.Log, p.Count), "done"

        case "scheduled_tasks":
                return listScheduledTasks(), "done"

        case "env_vars":
                return listEnvVars(), "done"

        case "registry_query":
                return queryRegistry(p.Key), "done"

        case "packet_capture":
                duration := p.Duration
                if duration <= 0 {
                        duration = 10
                }
                return captureTraffic(duration), "done"

        case "rogue_scan":
                return scanLocalNetwork(), "done"

        case "vuln_scan":
                return scanTarget(p.Target, p.PortRange), "done"

        case "arp_monitor":
                return runARPMonitor(), "done"

        case "bandwidth_stats":
                return getBandwidthStats(), "done"

        case "honeypot_monitor":
                ports := p.Ports
                if ports == "" {
                        ports = "23,445,1433,3389,5900,8080"
                }
                duration := p.Duration
                if duration <= 0 {
                        duration = 300
                }
                if duration > 3600 {
                        duration = 3600
                }
                return runHoneypotMonitor(ports, duration), "done"

        case "file_scan":
                return runFileScan(), "done"

        case "deep_scan":
                return RunDeepScan(), "done"

        case "enable_monitoring":
                return enableBackgroundMonitoring(), "done"

        case "disable_monitoring":
                return disableBackgroundMonitoring(), "done"

        case "host_isolate":
                return hostIsolate(p.Target), "done"

        case "host_unisolate":
                return hostUnisolate(), "done"

        case "file_retrieve":
                return fileRetrieve(p.Path), "done"

        default:
                logMessage("WARN", "Unknown command: %s", cmd.Command)
                return fmt.Sprintf("Unknown command: %s", cmd.Command), "failed"
        }
}

func runSystemScan() string {
        info := collectSystemInfo()
        var sb strings.Builder
        sb.WriteString("=== System Scan Report ===\n")
        sb.WriteString(fmt.Sprintf("Hostname:      %s\n", info.Hostname))
        sb.WriteString(fmt.Sprintf("OS:            %s\n", info.OS))
        sb.WriteString(fmt.Sprintf("CPUs:          %d\n", info.CPUs))
        sb.WriteString(fmt.Sprintf("Agent:         %s\n", info.AgentVersion))
        sb.WriteString(fmt.Sprintf("CPU Usage:     %.1f%%\n", info.CPUUsage))
        sb.WriteString(fmt.Sprintf("RAM Usage:     %.1f%% (%d MB free / %d MB total)\n", info.RAMUsage, info.RAMFreeMB, info.RAMTotalMB))
        sb.WriteString(fmt.Sprintf("Net Conns:     %d\n", info.NetConnections))
        sb.WriteString(fmt.Sprintf("Local IP:      %s\n", info.LocalIP))
        sb.WriteString(fmt.Sprintf("Uptime:        %s\n", info.Uptime))
        sb.WriteString(fmt.Sprintf("Scan Time:     %s\n", info.Time))

        if len(info.TopProcesses) > 0 {
                sb.WriteString("\n--- Top Processes ---\n")
                for i, p := range info.TopProcesses {
                        sb.WriteString(fmt.Sprintf("  %2d. %s\n", i+1, p))
                }
        }
        return sb.String()
}

func executeTerminal(paramsJSON string) (string, string) {
        var params struct {
                Cmd string `json:"cmd"`
        }
        if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
                return "Failed to parse command parameters", "failed"
        }

        cmdStr := strings.TrimSpace(params.Cmd)
        if cmdStr == "" {
                return "Empty command", "failed"
        }

        if !isCommandAllowed(cmdStr) {
                logMessage("WARN", "Blocked disallowed terminal command: %s", cmdStr)
                return fmt.Sprintf("Command not allowed: %s", cmdStr), "failed"
        }

        var execCmd *exec.Cmd
        if runtime.GOOS == "windows" {
                execCmd = exec.Command("cmd", "/C", cmdStr)
        } else {
                execCmd = exec.Command("sh", "-c", cmdStr)
        }

        var stdout, stderr bytes.Buffer
        execCmd.Stdout = &stdout
        execCmd.Stderr = &stderr

        done := make(chan error, 1)
        go func() {
                done <- execCmd.Run()
        }()

        select {
        case err := <-done:
                output := stdout.String()
                if stderr.Len() > 0 {
                        output += "\n" + stderr.String()
                }
                if err != nil {
                        return output + "\nError: " + err.Error(), "failed"
                }
                return output, "done"
        case <-time.After(30 * time.Second):
                if execCmd.Process != nil {
                        execCmd.Process.Kill()
                }
                return "Command timed out after 30 seconds", "failed"
        }
}

func isCommandAllowed(cmd string) bool {
        cmdLower := strings.ToLower(strings.TrimSpace(cmd))

        separators := []string{";", "&&", "||", "|", "`", "$(", "${", "\n", "\r"}
        for _, sep := range separators {
                if strings.Contains(cmdLower, sep) {
                        return false
                }
        }

        blocked := []string{
                "rm ", "rm -", "del ", "format", "shutdown", "reboot", "halt",
                "mkfs", "dd ", "fdisk", "wget ", "curl ", "chmod ", "chown ",
                "sudo ", "su ", "passwd", "> /dev", "| bash", "| sh",
                "eval ", "exec ", "kill ", "killall", "pkill",
        }
        for _, b := range blocked {
                if strings.Contains(cmdLower, b) {
                        return false
                }
        }

        fields := strings.Fields(cmdLower)
        if len(fields) == 0 {
                return false
        }
        baseCmd := fields[0]

        allWhitelists := append(terminalWhitelistLinux, terminalWhitelistWindows...)
        for _, allowed := range allWhitelists {
                allowedBase := strings.Fields(allowed)[0]
                if baseCmd == allowedBase {
                        return true
                }
        }

        return false
}

type HoneypotConnection struct {
        SourceIP   string `json:"sourceIp"`
        SourcePort int    `json:"sourcePort"`
        TargetPort int    `json:"targetPort"`
        Protocol   string `json:"protocol"`
        Payload    string `json:"payload"`
        Timestamp  string `json:"timestamp"`
}

func runHoneypotMonitor(portsStr string, durationSecs int) string {
        portStrs := strings.Split(portsStr, ",")
        var ports []int
        for _, ps := range portStrs {
                ps = strings.TrimSpace(ps)
                p, err := strconv.Atoi(ps)
                if err != nil || p < 1 || p > 65535 {
                        continue
                }
                ports = append(ports, p)
        }

        if len(ports) == 0 {
                return "No valid ports specified"
        }

        logMessage("INFO", "Honeypot monitor starting on ports: %v for %ds", ports, durationSecs)

        var mu sync.Mutex
        var connections []HoneypotConnection
        var listeners []net.Listener
        var wg sync.WaitGroup
        var listenedPorts []int
        var failedPorts []string

        for _, port := range ports {
                addr := fmt.Sprintf("0.0.0.0:%d", port)
                ln, err := net.Listen("tcp", addr)
                if err != nil {
                        failedPorts = append(failedPorts, fmt.Sprintf("%d(%s)", port, err.Error()))
                        continue
                }
                listeners = append(listeners, ln)
                listenedPorts = append(listenedPorts, port)

                wg.Add(1)
                go func(listener net.Listener, targetPort int) {
                        defer wg.Done()
                        for {
                                conn, err := listener.Accept()
                                if err != nil {
                                        return
                                }
                                go handleHoneypotConn(conn, targetPort, &mu, &connections)
                        }
                }(ln, port)
        }

        if len(listeners) == 0 {
                return fmt.Sprintf("Failed to listen on any ports: %s", strings.Join(failedPorts, ", "))
        }

        time.Sleep(time.Duration(durationSecs) * time.Second)

        for _, ln := range listeners {
                ln.Close()
        }
        wg.Wait()

        mu.Lock()
        captured := make([]HoneypotConnection, len(connections))
        copy(captured, connections)
        mu.Unlock()

        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("=== Honeypot Monitor Report ===\n"))
        sb.WriteString(fmt.Sprintf("Duration: %d seconds\n", durationSecs))
        sb.WriteString(fmt.Sprintf("Monitored ports: %v\n", listenedPorts))
        if len(failedPorts) > 0 {
                sb.WriteString(fmt.Sprintf("Failed ports: %s\n", strings.Join(failedPorts, ", ")))
        }
        sb.WriteString(fmt.Sprintf("Connections captured: %d\n\n", len(captured)))

        for i, c := range captured {
                sb.WriteString(fmt.Sprintf("[%d] %s | %s:%d -> port %d | payload_len=%d\n",
                        i+1, c.Timestamp, c.SourceIP, c.SourcePort, c.TargetPort, len(c.Payload)))
        }

        if len(captured) > 0 {
                eventsJSON, _ := json.Marshal(captured)
                sb.WriteString(fmt.Sprintf("\n__HONEYPOT_EVENTS_JSON__:%s", string(eventsJSON)))
        }

        return sb.String()
}

func handleHoneypotConn(conn net.Conn, targetPort int, mu *sync.Mutex, connections *[]HoneypotConnection) {
        defer conn.Close()

        remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
        logMessage("INFO", "Honeypot: connection from %s:%d to port %d", remoteAddr.IP.String(), remoteAddr.Port, targetPort)

        buf := make([]byte, 1024)
        conn.SetReadDeadline(time.Now().Add(5 * time.Second))
        n, _ := conn.Read(buf)

        payload := ""
        if n > 0 {
                payload = fmt.Sprintf("%x", buf[:n])
                if len(payload) > 200 {
                        payload = payload[:200]
                }
        }

        event := HoneypotConnection{
                SourceIP:   remoteAddr.IP.String(),
                SourcePort: remoteAddr.Port,
                TargetPort: targetPort,
                Protocol:   "tcp",
                Payload:    payload,
                Timestamp:  time.Now().UTC().Format(time.RFC3339),
        }

        mu.Lock()
        *connections = append(*connections, event)
        mu.Unlock()
}

type FileScanEntry struct {
        Path         string `json:"path"`
        Size         int64  `json:"size"`
        SHA256       string `json:"sha256"`
        ModifiedAt   string `json:"modifiedAt"`
        IsRecent     bool   `json:"isRecent"`
        IsSuspicious bool   `json:"isSuspicious"`
        Reason       string `json:"reason,omitempty"`
}

type FileScanReport struct {
        ScannedDirs   []string        `json:"scannedDirs"`
        TotalFiles    int             `json:"totalFiles"`
        Executables   int             `json:"executables"`
        RecentFiles   int             `json:"recentFiles"`
        SuspiciousFiles int           `json:"suspiciousFiles"`
        Files         []FileScanEntry `json:"files"`
        ScanTime      string          `json:"scanTime"`
        Duration      string          `json:"duration"`
}

func getFileScanDirs() []string {
        if runtime.GOOS == "windows" {
                home := os.Getenv("USERPROFILE")
                appData := os.Getenv("APPDATA")
                localAppData := os.Getenv("LOCALAPPDATA")
                temp := os.Getenv("TEMP")
                dirs := []string{}
                if home != "" {
                        dirs = append(dirs, filepath.Join(home, "Downloads"))
                }
                if temp != "" {
                        dirs = append(dirs, temp)
                }
                if appData != "" {
                        dirs = append(dirs, appData)
                }
                if localAppData != "" {
                        dirs = append(dirs, localAppData)
                }
                dirs = append(dirs,
                        `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`,
                        filepath.Join(home, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`),
                )
                return dirs
        }

        home := os.Getenv("HOME")
        dirs := []string{"/tmp", "/var/tmp"}
        if home != "" {
                dirs = append(dirs, filepath.Join(home, "Downloads"))
                dirs = append(dirs, filepath.Join(home, ".local/bin"))
                dirs = append(dirs, filepath.Join(home, ".config/autostart"))
        }
        dirs = append(dirs, "/etc/init.d")
        return dirs
}

func isExecutableFile(name string) bool {
        exts := []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".scr", ".com", ".pif", ".sh", ".bin", ".elf", ".py", ".pl"}
        lower := strings.ToLower(name)
        for _, ext := range exts {
                if strings.HasSuffix(lower, ext) {
                        return true
                }
        }
        return false
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

func isSuspiciousFileName(name string) (bool, string) {
        lower := strings.ToLower(name)
        suspicious := []struct {
                pattern string
                reason  string
        }{
                {"svchost", "Mimics system process name"},
                {"csrss", "Mimics system process name"},
                {"lsass", "Mimics system process name"},
                {"winlogon", "Mimics system process name"},
                {"explorer", "Mimics system process name"},
                {"payload", "Common malware naming"},
                {"backdoor", "Common malware naming"},
                {"keylog", "Potential keylogger"},
                {"trojan", "Potential trojan"},
                {"rat.", "Potential RAT"},
                {"meterpreter", "Known pen-test tool"},
                {"mimikatz", "Known credential tool"},
                {"reverse_shell", "Potential reverse shell"},
                {"nc.exe", "Netcat utility"},
                {"ncat", "Netcat variant"},
        }
        for _, s := range suspicious {
                if strings.Contains(lower, s.pattern) {
                        return true, s.reason
                }
        }
        return false, ""
}

func runFileScan() string {
        startTime := time.Now()
        logMessage("INFO", "Starting file scan")

        dirs := getFileScanDirs()
        cutoff := time.Now().Add(-24 * time.Hour)
        var files []FileScanEntry
        totalFiles := 0
        executables := 0
        recentFiles := 0
        suspiciousFiles := 0
        scannedDirs := []string{}

        for _, dir := range dirs {
                info, err := os.Stat(dir)
                if err != nil || !info.IsDir() {
                        continue
                }
                scannedDirs = append(scannedDirs, dir)

                filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
                        if err != nil {
                                return nil
                        }
                        if fi.IsDir() {
                                if totalFiles > 5000 {
                                        return filepath.SkipDir
                                }
                                return nil
                        }
                        totalFiles++

                        if !isExecutableFile(fi.Name()) {
                                return nil
                        }
                        executables++

                        isRecent := fi.ModTime().After(cutoff)
                        if isRecent {
                                recentFiles++
                        }

                        isSusp, reason := isSuspiciousFileName(fi.Name())
                        if isSusp {
                                suspiciousFiles++
                        }

                        if len(files) < 500 {
                                hash := ""
                                if fi.Size() < 50*1024*1024 {
                                        hash = hashFile(path)
                                }
                                files = append(files, FileScanEntry{
                                        Path:         path,
                                        Size:         fi.Size(),
                                        SHA256:       hash,
                                        ModifiedAt:   fi.ModTime().UTC().Format(time.RFC3339),
                                        IsRecent:     isRecent,
                                        IsSuspicious: isSusp,
                                        Reason:       reason,
                                })
                        }

                        return nil
                })
        }

        duration := time.Since(startTime)
        report := FileScanReport{
                ScannedDirs:     scannedDirs,
                TotalFiles:      totalFiles,
                Executables:     executables,
                RecentFiles:     recentFiles,
                SuspiciousFiles: suspiciousFiles,
                Files:           files,
                ScanTime:        startTime.UTC().Format(time.RFC3339),
                Duration:        duration.String(),
        }

        var sb strings.Builder
        sb.WriteString("=== File Scan Report ===\n")
        sb.WriteString(fmt.Sprintf("Scanned Dirs:     %d\n", len(scannedDirs)))
        sb.WriteString(fmt.Sprintf("Total Files:      %d\n", totalFiles))
        sb.WriteString(fmt.Sprintf("Executables:      %d\n", executables))
        sb.WriteString(fmt.Sprintf("Recent (24h):     %d\n", recentFiles))
        sb.WriteString(fmt.Sprintf("Suspicious:       %d\n", suspiciousFiles))
        sb.WriteString(fmt.Sprintf("Scan Duration:    %s\n\n", duration.String()))

        if suspiciousFiles > 0 {
                sb.WriteString("--- Suspicious Files ---\n")
                for _, f := range files {
                        if f.IsSuspicious {
                                sb.WriteString(fmt.Sprintf("  [!] %s (%s) - %s\n", f.Path, formatFileSize(f.Size), f.Reason))
                        }
                }
                sb.WriteString("\n")
        }

        if recentFiles > 0 {
                sb.WriteString("--- Recently Modified Executables (24h) ---\n")
                count := 0
                for _, f := range files {
                        if f.IsRecent && count < 20 {
                                sb.WriteString(fmt.Sprintf("  %s (%s) modified=%s\n", f.Path, formatFileSize(f.Size), f.ModifiedAt))
                                count++
                        }
                }
                sb.WriteString("\n")
        }

        reportJSON, _ := json.Marshal(report)
        sb.WriteString(fmt.Sprintf("__FILE_SCAN_JSON__:%s", string(reportJSON)))

        logMessage("INFO", "File scan complete: %d files, %d executables, %d suspicious", totalFiles, executables, suspiciousFiles)
        return sb.String()
}

func formatFileSize(size int64) string {
        if size > 1073741824 {
                return fmt.Sprintf("%.1f GB", float64(size)/1073741824)
        }
        if size > 1048576 {
                return fmt.Sprintf("%.1f MB", float64(size)/1048576)
        }
        if size > 1024 {
                return fmt.Sprintf("%.1f KB", float64(size)/1024)
        }
        return fmt.Sprintf("%d B", size)
}

func fileRetrieve(filePath string) string {
        if filePath == "" {
                return `{"error":"file path is required"}`
        }

        info, err := os.Stat(filePath)
        if err != nil {
                return fmt.Sprintf(`{"error":"file not found: %s"}`, err.Error())
        }
        if info.IsDir() {
                return `{"error":"path is a directory, not a file"}`
        }

        const maxSize = 10 * 1024 * 1024
        if info.Size() > int64(maxSize) {
                return fmt.Sprintf(`{"error":"file too large (%s, max 10MB)"}`, formatFileSize(info.Size()))
        }

        data, err := os.ReadFile(filePath)
        if err != nil {
                return fmt.Sprintf(`{"error":"cannot read file: %s"}`, err.Error())
        }

        hash := sha256.Sum256(data)
        hashStr := hex.EncodeToString(hash[:])
        b64 := base64.StdEncoding.EncodeToString(data)

        result := fmt.Sprintf(`__FILE_RETRIEVE_JSON__:{"name":"%s","path":"%s","size":%d,"sizeFormatted":"%s","sha256":"%s","modifiedAt":"%s","data":"%s"}`,
                filepath.Base(filePath),
                filePath,
                info.Size(),
                formatFileSize(info.Size()),
                hashStr,
                info.ModTime().Format(time.RFC3339),
                b64,
        )
        return result
}

func restartService() {
        logMessage("INFO", "Restarting agent service...")
        if runtime.GOOS == "windows" {
                exec.Command("cmd", "/C", "net stop AegisAI360Agent && net start AegisAI360Agent").Run()
        } else {
                exec.Command("systemctl", "restart", "aegisai360-agent").Run()
        }
}
