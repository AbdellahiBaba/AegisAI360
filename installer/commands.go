package main

import (
        "bytes"
        "encoding/json"
        "fmt"
        "os/exec"
        "runtime"
        "strings"
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

func restartService() {
        logMessage("INFO", "Restarting agent service...")
        if runtime.GOOS == "windows" {
                exec.Command("cmd", "/C", "net stop AegisAI360Agent && net start AegisAI360Agent").Run()
        } else {
                exec.Command("systemctl", "restart", "aegisai360-agent").Run()
        }
}
