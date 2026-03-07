package main

import (
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"
)

type AgentConfig struct {
        ServerURL            string `json:"serverUrl"`
        APIKey               string `json:"apiKey"`
        AgentVersion         string `json:"agentVersion"`
        HeartbeatInterval    int    `json:"heartbeatInterval"`
        CommandPollInterval  int    `json:"commandPollInterval"`
        UpdateCheckInterval  int    `json:"updateCheckInterval"`
        TelemetryInterval    int    `json:"telemetryInterval"`
        LogMaxSizeMB         int    `json:"logMaxSizeMB"`
        LogMaxBackups        int    `json:"logMaxBackups"`
}

func loadConfig() (*AgentConfig, error) {
        cfg := &AgentConfig{
                ServerURL:            "https://aegisai360.com",
                AgentVersion:         agentVersion,
                HeartbeatInterval:    30,
                CommandPollInterval:  5,
                UpdateCheckInterval:  300,
                TelemetryInterval:    30,
                LogMaxSizeMB:         10,
                LogMaxBackups:        5,
        }

        configPath := findConfigFile()
        if configPath != "" {
                data, err := os.ReadFile(configPath)
                if err == nil {
                        if err := json.Unmarshal(data, cfg); err != nil {
                                logMessage("WARN", "Failed to parse config file: %v, using defaults", err)
                        } else {
                                logMessage("INFO", "Loaded config from %s", configPath)
                        }
                }
        }

        if envURL := os.Getenv("AEGIS_SERVER_URL"); envURL != "" {
                cfg.ServerURL = envURL
        }
        if envKey := os.Getenv("AEGIS_DEVICE_TOKEN"); envKey != "" {
                cfg.APIKey = envKey
        }

        if len(os.Args) >= 3 {
                cfg.ServerURL = os.Args[1]
                cfg.APIKey = os.Args[2]
        }

        cfg.ServerURL = strings.TrimRight(cfg.ServerURL, "/")

        if cfg.ServerURL == "" {
                return nil, fmt.Errorf("server URL not configured")
        }
        if cfg.APIKey == "" || cfg.APIKey == "REPLACE_WITH_YOUR_DEVICE_TOKEN" {
                return nil, fmt.Errorf("device token not configured — set apiKey in config.json or AEGIS_DEVICE_TOKEN env var")
        }

        if cfg.HeartbeatInterval < 5 {
                cfg.HeartbeatInterval = 5
        }
        if cfg.CommandPollInterval < 2 {
                cfg.CommandPollInterval = 2
        }
        if cfg.UpdateCheckInterval < 60 {
                cfg.UpdateCheckInterval = 60
        }
        if cfg.TelemetryInterval < 10 {
                cfg.TelemetryInterval = 10
        }

        return cfg, nil
}

func findConfigFile() string {
        exePath, err := os.Executable()
        if err == nil {
                p := filepath.Join(filepath.Dir(exePath), "config.json")
                if _, err := os.Stat(p); err == nil {
                        return p
                }
        }

        cwd, err := os.Getwd()
        if err == nil {
                p := filepath.Join(cwd, "config.json")
                if _, err := os.Stat(p); err == nil {
                        return p
                }
        }

        return ""
}

func saveConfig(cfg *AgentConfig) error {
        configPath := findConfigFile()
        if configPath == "" {
                exePath, err := os.Executable()
                if err != nil {
                        return fmt.Errorf("cannot determine config path: %w", err)
                }
                configPath = filepath.Join(filepath.Dir(exePath), "config.json")
        }

        data, err := json.MarshalIndent(cfg, "", "  ")
        if err != nil {
                return fmt.Errorf("failed to marshal config: %w", err)
        }

        return os.WriteFile(configPath, data, 0600)
}

func maskToken(token string) string {
        if len(token) <= 8 {
                return "****"
        }
        return token[:4] + "..." + token[len(token)-4:]
}
