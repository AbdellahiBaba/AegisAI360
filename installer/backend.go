package main

import (
        "bytes"
        "crypto/tls"
        "encoding/json"
        "fmt"
        "io"
        "net"
        "net/http"
        "os"
        "runtime"
        "time"
)

var httpClient *http.Client

func initHTTPClient() {
        httpClient = &http.Client{
                Timeout: 15 * time.Second,
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{
                                MinVersion: tls.VersionTLS12,
                        },
                        DialContext: (&net.Dialer{
                                Timeout:   10 * time.Second,
                                KeepAlive: 30 * time.Second,
                        }).DialContext,
                        MaxIdleConns:        10,
                        IdleConnTimeout:     60 * time.Second,
                        TLSHandshakeTimeout: 10 * time.Second,
                },
        }
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

type VersionResponse struct {
        Version     string `json:"version"`
        DownloadURL string `json:"downloadUrl"`
        Checksum    string `json:"checksum"`
}

type TelemetryRequest struct {
        AgentID        float64  `json:"agentId"`
        Token          string   `json:"token"`
        Hostname       string   `json:"hostname"`
        OS             string   `json:"os"`
        Arch           string   `json:"arch"`
        CPUUsage       float64  `json:"cpuUsage"`
        RAMUsage       float64  `json:"ramUsage"`
        RAMTotalMB     uint64   `json:"ramTotalMB"`
        RAMFreeMB      uint64   `json:"ramFreeMB"`
        CPUs           int      `json:"cpus"`
        Uptime         string   `json:"uptime"`
        AgentVersion   string   `json:"agentVersion"`
        TopProcesses   []string `json:"topProcesses"`
        NetConnections int      `json:"netConnections"`
        DiskUsage      string   `json:"diskUsage"`
        LocalIP        string   `json:"localIP"`
        Timestamp      string   `json:"timestamp"`
}

const maxRetries = 3

func registerAgent(cfg *AgentConfig) (float64, error) {
        hostname, _ := os.Hostname()
        ip := getLocalIP()

        body := RegisterRequest{
                Token:    cfg.APIKey,
                Hostname: hostname,
                OS:       runtime.GOOS,
                IP:       ip,
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/register", body)
        if err != nil {
                return 0, fmt.Errorf("registration request failed: %w", err)
        }
        defer resp.Body.Close()

        data, _ := io.ReadAll(resp.Body)
        if resp.StatusCode != 201 {
                return 0, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(data))
        }

        var result RegisterResponse
        if err := json.Unmarshal(data, &result); err != nil {
                return 0, fmt.Errorf("failed to parse registration response: %w", err)
        }

        return result.AgentID, nil
}

func sendHeartbeat(cfg *AgentConfig, agentID float64) error {
        cpu, ram := collectCPUAndRAM()

        body := HeartbeatRequest{
                AgentID:  agentID,
                Token:    cfg.APIKey,
                CPUUsage: cpu,
                RAMUsage: ram,
                IP:       getLocalIP(),
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/heartbeat", body)
        if err != nil {
                return fmt.Errorf("heartbeat failed: %w", err)
        }
        resp.Body.Close()

        if resp.StatusCode != 200 {
                return fmt.Errorf("heartbeat returned status %d", resp.StatusCode)
        }
        return nil
}

func pollCommands(cfg *AgentConfig, agentID float64) ([]Command, error) {
        url := fmt.Sprintf("%s/api/agent/commands?agentId=%v&token=%s", cfg.ServerURL, agentID, cfg.APIKey)

        var lastErr error
        for attempt := 1; attempt <= maxRetries; attempt++ {
                resp, err := httpClient.Get(url)
                if err != nil {
                        lastErr = err
                        backoff(attempt)
                        continue
                }

                data, _ := io.ReadAll(resp.Body)
                resp.Body.Close()

                if resp.StatusCode != 200 {
                        return nil, nil
                }

                var commands []Command
                if err := json.Unmarshal(data, &commands); err != nil {
                        return nil, fmt.Errorf("failed to parse commands: %w", err)
                }
                return commands, nil
        }
        return nil, lastErr
}

func sendCommandResult(cfg *AgentConfig, agentID float64, commandID float64, status, result string) error {
        body := CommandResultRequest{
                CommandID: commandID,
                AgentID:   agentID,
                Token:     cfg.APIKey,
                Status:    status,
                Result:    result,
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/command-result", body)
        if err != nil {
                return fmt.Errorf("failed to send command result: %w", err)
        }
        resp.Body.Close()
        return nil
}

func sendAgentLog(cfg *AgentConfig, agentID float64, eventType, severity, description string) {
        body := LogRequest{
                AgentID: agentID,
                Token:   cfg.APIKey,
                Logs: []LogEntry{
                        {
                                EventType:   eventType,
                                Severity:    severity,
                                Description: description,
                                Source:      "agent",
                        },
                },
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/logs", body)
        if err != nil {
                logMessage("WARN", "Failed to send log to server: %v", err)
                return
        }
        resp.Body.Close()
}

func checkForUpdate(cfg *AgentConfig) (*VersionResponse, error) {
        url := fmt.Sprintf("%s/api/agent/version?version=%s", cfg.ServerURL, cfg.AgentVersion)

        resp, err := httpClient.Get(url)
        if err != nil {
                return nil, err
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                return nil, fmt.Errorf("version check returned %d", resp.StatusCode)
        }

        data, _ := io.ReadAll(resp.Body)
        var ver VersionResponse
        if err := json.Unmarshal(data, &ver); err != nil {
                return nil, err
        }
        return &ver, nil
}

func sendTelemetry(cfg *AgentConfig, agentID float64) error {
        info := collectSystemInfo()

        body := TelemetryRequest{
                AgentID:        agentID,
                Token:          cfg.APIKey,
                Hostname:       info.Hostname,
                OS:             info.OS,
                Arch:           info.Arch,
                CPUUsage:       info.CPUUsage,
                RAMUsage:       info.RAMUsage,
                RAMTotalMB:     info.RAMTotalMB,
                RAMFreeMB:      info.RAMFreeMB,
                CPUs:           info.CPUs,
                Uptime:         info.Uptime,
                AgentVersion:   info.AgentVersion,
                TopProcesses:   info.TopProcesses,
                NetConnections: info.NetConnections,
                DiskUsage:      collectDiskUsage(),
                LocalIP:        info.LocalIP,
                Timestamp:      info.Time,
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/telemetry", body)
        if err != nil {
                return fmt.Errorf("telemetry send failed: %w", err)
        }
        resp.Body.Close()

        if resp.StatusCode != 200 {
                return fmt.Errorf("telemetry returned status %d", resp.StatusCode)
        }
        return nil
}

type HoneypotEventRequest struct {
        AgentID float64              `json:"agentId"`
        Token   string               `json:"token"`
        Events  []HoneypotConnection `json:"events"`
}

func sendHoneypotEvents(cfg *AgentConfig, agentID float64, events []HoneypotConnection) error {
        if len(events) == 0 {
                return nil
        }

        body := HoneypotEventRequest{
                AgentID: agentID,
                Token:   cfg.APIKey,
                Events:  events,
        }

        resp, err := postJSONWithRetry(cfg.ServerURL+"/api/agent/honeypot-events", body)
        if err != nil {
                return fmt.Errorf("failed to send honeypot events: %w", err)
        }
        resp.Body.Close()

        if resp.StatusCode != 201 {
                return fmt.Errorf("honeypot events returned status %d", resp.StatusCode)
        }
        logMessage("INFO", "Sent %d honeypot events to server", len(events))
        return nil
}

func postJSONWithRetry(url string, body interface{}) (*http.Response, error) {
        var lastErr error

        for attempt := 1; attempt <= maxRetries; attempt++ {
                resp, err := postJSON(url, body)
                if err != nil {
                        lastErr = err
                        logMessage("WARN", "Request to %s failed (attempt %d/%d): %v", url, attempt, maxRetries, err)
                        backoff(attempt)
                        continue
                }
                return resp, nil
        }

        return nil, fmt.Errorf("all %d attempts failed: %w", maxRetries, lastErr)
}

func postJSON(url string, body interface{}) (*http.Response, error) {
        jsonData, err := json.Marshal(body)
        if err != nil {
                return nil, err
        }

        req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
        if err != nil {
                return nil, err
        }
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("User-Agent", fmt.Sprintf("AegisAI360-Agent/%s", agentVersion))

        return httpClient.Do(req)
}

func backoff(attempt int) {
        delay := time.Duration(attempt*attempt) * time.Second
        if delay > 30*time.Second {
                delay = 30 * time.Second
        }
        time.Sleep(delay)
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

func getHostname() string {
        name, err := os.Hostname()
        if err != nil {
                return "unknown"
        }
        return name
}
