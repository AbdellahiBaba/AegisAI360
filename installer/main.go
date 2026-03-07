package main

import (
        "bytes"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "net/http"
        "os"
        "os/exec"
        "runtime"
        "strings"
        "time"
)

var (
        serverURL   string
        deviceToken string
        agentID     float64
        agentToken  string
        httpClient  = &http.Client{Timeout: 10 * time.Second}
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

type RegisterRequest struct {
        Token    string `json:"token"`
        Hostname string `json:"hostname"`
        OS       string `json:"os"`
        IP       string `json:"ip"`
}

type RegisterResponse struct {
        AgentID float64 `json:"agentId"`
        Status  string  `json:"status"`
}

type HeartbeatRequest struct {
        AgentID  float64 `json:"agentId"`
        Token    string  `json:"token"`
        CPUUsage float64 `json:"cpuUsage"`
        RAMUsage float64 `json:"ramUsage"`
        IP       string  `json:"ip"`
}

type LogEntry struct {
        EventType   string `json:"eventType"`
        Severity    string `json:"severity"`
        Description string `json:"description"`
        Source      string `json:"source"`
}

type LogRequest struct {
        AgentID float64    `json:"agentId"`
        Token   string     `json:"token"`
        Logs    []LogEntry `json:"logs"`
}

type Command struct {
        ID      float64 `json:"id"`
        Command string  `json:"command"`
        Params  string  `json:"params"`
        Status  string  `json:"status"`
}

type CommandResultRequest struct {
        CommandID float64 `json:"commandId"`
        AgentID   float64 `json:"agentId"`
        Token     string  `json:"token"`
        Status    string  `json:"status"`
        Result    string  `json:"result"`
}

func main() {
        serverURL = os.Getenv("AEGIS_SERVER_URL")
        deviceToken = os.Getenv("AEGIS_DEVICE_TOKEN")

        if serverURL == "" || deviceToken == "" {
                if len(os.Args) >= 3 {
                        serverURL = os.Args[1]
                        deviceToken = os.Args[2]
                } else {
                        fmt.Println("Usage: agent.exe <SERVER_URL> <DEVICE_TOKEN>")
                        fmt.Println("  or set AEGIS_SERVER_URL and AEGIS_DEVICE_TOKEN environment variables")
                        os.Exit(1)
                }
        }

        serverURL = strings.TrimRight(serverURL, "/")
        fmt.Printf("[AegisAI360] Connecting to %s\n", serverURL)

        if err := register(); err != nil {
                fmt.Printf("[AegisAI360] Registration failed: %v\n", err)
                os.Exit(1)
        }

        fmt.Printf("[AegisAI360] Registered as agent %v\n", agentID)

        sendLog("agent_started", "info", "AegisAI360 Agent started on "+runtime.GOOS)

        go heartbeatLoop()

        commandLoop()
}

func register() error {
        hostname, _ := os.Hostname()
        ip := getLocalIP()

        body := RegisterRequest{
                Token:    deviceToken,
                Hostname: hostname,
                OS:       runtime.GOOS,
                IP:       ip,
        }

        resp, err := postJSON("/api/agent/register", body)
        if err != nil {
                return fmt.Errorf("request failed: %w", err)
        }
        defer resp.Body.Close()

        data, _ := io.ReadAll(resp.Body)
        if resp.StatusCode != 201 {
                return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(data))
        }

        var result RegisterResponse
        if err := json.Unmarshal(data, &result); err != nil {
                return fmt.Errorf("parse response: %w", err)
        }

        agentID = result.AgentID
        agentToken = deviceToken
        return nil
}

func heartbeatLoop() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()

        for {
                sendHeartbeat()
                <-ticker.C
        }
}

func sendHeartbeat() {
        body := HeartbeatRequest{
                AgentID:  agentID,
                Token:    agentToken,
                CPUUsage: 0,
                RAMUsage: 0,
                IP:       getLocalIP(),
        }

        resp, err := postJSON("/api/agent/heartbeat", body)
        if err != nil {
                fmt.Printf("[AegisAI360] Heartbeat error: %v\n", err)
                return
        }
        resp.Body.Close()
}

func commandLoop() {
        ticker := time.NewTicker(5 * time.Second)
        defer ticker.Stop()

        for {
                pollCommands()
                <-ticker.C
        }
}

func pollCommands() {
        url := fmt.Sprintf("%s/api/agent/commands?agentId=%v&token=%s", serverURL, agentID, agentToken)
        resp, err := httpClient.Get(url)
        if err != nil {
                return
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                return
        }

        data, _ := io.ReadAll(resp.Body)
        var commands []Command
        if err := json.Unmarshal(data, &commands); err != nil {
                return
        }

        for _, cmd := range commands {
                fmt.Printf("[AegisAI360] Executing command: %s (id=%v)\n", cmd.Command, cmd.ID)
                result, status := executeCommand(cmd)
                sendCommandResult(cmd.ID, status, result)
        }
}

func executeCommand(cmd Command) (string, string) {
        switch cmd.Command {
        case "ping":
                return fmt.Sprintf("pong from %s at %s", getHostname(), time.Now().Format(time.RFC3339)), "done"

        case "run_system_scan":
                return runSystemScan(), "done"

        case "terminal_exec":
                return executeTerminal(cmd.Params)

        default:
                return fmt.Sprintf("Unknown command: %s", cmd.Command), "failed"
        }
}

func runSystemScan() string {
        info := fmt.Sprintf("System Scan Report\n")
        info += fmt.Sprintf("==================\n")
        info += fmt.Sprintf("Hostname: %s\n", getHostname())
        info += fmt.Sprintf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH)
        info += fmt.Sprintf("CPUs: %d\n", runtime.NumCPU())
        info += fmt.Sprintf("Go Version: %s\n", runtime.Version())
        info += fmt.Sprintf("Time: %s\n", time.Now().Format(time.RFC3339))
        return info
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

        blocked := []string{"rm ", "rm -", "del ", "format", "shutdown", "reboot", "halt",
                "mkfs", "dd ", "fdisk", "wget ", "curl ", "chmod ", "chown ",
                "sudo ", "su ", "passwd", "> /dev", "| bash", "| sh",
                "eval ", "exec ", "kill ", "killall", "pkill"}
        for _, b := range blocked {
                if strings.Contains(cmdLower, b) {
                        return false
                }
        }

        baseCmd := strings.Fields(cmdLower)[0]
        allWhitelists := append(terminalWhitelistLinux, terminalWhitelistWindows...)
        for _, allowed := range allWhitelists {
                allowedBase := strings.Fields(allowed)[0]
                if baseCmd == allowedBase {
                        return true
                }
        }

        return false
}

func sendCommandResult(commandID float64, status, result string) {
        body := CommandResultRequest{
                CommandID: commandID,
                AgentID:   agentID,
                Token:     agentToken,
                Status:    status,
                Result:    result,
        }

        resp, err := postJSON("/api/agent/command-result", body)
        if err != nil {
                fmt.Printf("[AegisAI360] Failed to send result for command %v: %v\n", commandID, err)
                return
        }
        resp.Body.Close()
}

func sendLog(eventType, severity, description string) {
        body := LogRequest{
                AgentID: agentID,
                Token:   agentToken,
                Logs: []LogEntry{
                        {
                                EventType:   eventType,
                                Severity:    severity,
                                Description: description,
                                Source:      "agent",
                        },
                },
        }

        resp, err := postJSON("/api/agent/logs", body)
        if err != nil {
                fmt.Printf("[AegisAI360] Failed to send log: %v\n", err)
                return
        }
        resp.Body.Close()
}

func postJSON(path string, body interface{}) (*http.Response, error) {
        jsonData, err := json.Marshal(body)
        if err != nil {
                return nil, err
        }

        url := serverURL + path
        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
        if err != nil {
                return nil, err
        }
        req.Header.Set("Content-Type", "application/json")

        return httpClient.Do(req)
}

func getHostname() string {
        name, err := os.Hostname()
        if err != nil {
                return "unknown"
        }
        return name
}

func getLocalIP() string {
        addrs, err := net.InterfaceAddrs()
        if err != nil {
                return "127.0.0.1"
        }
        for _, addr := range addrs {
                if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
                        return ipnet.IP.String()
                }
        }
        return "127.0.0.1"
}
