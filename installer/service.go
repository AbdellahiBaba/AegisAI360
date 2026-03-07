package main

import (
        "context"
        "fmt"
        "time"
)

var triggerUpdateCheck func()

const (
        maxRegistrationRetries  = 10
        maxHeartbeatFailures    = 5
        maxReregistrationRetries = 3
)

func runAgent(ctx context.Context, cfg *AgentConfig) error {
        logMessage("INFO", "AegisAI360 Endpoint Agent v%s starting...", cfg.AgentVersion)
        logMessage("INFO", "Server: %s", cfg.ServerURL)
        logMessage("INFO", "Token: %s", maskToken(cfg.APIKey))

        initHTTPClient()

        agentID, err := registerWithRetry(ctx, cfg)
        if err != nil {
                return fmt.Errorf("failed to connect to server: %w", err)
        }

        logMessage("INFO", "Registered successfully as agent %.0f", agentID)
        globalStatus.SetRegistered(agentID, getHostname(), getLocalIP(), cfg.ServerURL, cfg.AgentVersion)

        fmt.Println()
        fmt.Printf("  Connected! Agent ID: %.0f\n", agentID)
        fmt.Printf("  Server: %s\n", cfg.ServerURL)
        fmt.Println("  Press Ctrl+C to stop.")
        fmt.Println()

        sendAgentLog(cfg, agentID, "agent_started", "info",
                fmt.Sprintf("AegisAI360 Agent v%s started on %s (%s)", cfg.AgentVersion, getHostname(), getLocalIP()))

        heartbeatTicker := time.NewTicker(time.Duration(cfg.HeartbeatInterval) * time.Second)
        defer heartbeatTicker.Stop()

        commandTicker := time.NewTicker(time.Duration(cfg.CommandPollInterval) * time.Second)
        defer commandTicker.Stop()

        updateTicker := time.NewTicker(time.Duration(cfg.UpdateCheckInterval) * time.Second)
        defer updateTicker.Stop()

        telemetryTicker := time.NewTicker(time.Duration(cfg.TelemetryInterval) * time.Second)
        defer telemetryTicker.Stop()

        manualUpdateCh := make(chan struct{}, 1)
        triggerUpdateCheck = func() {
                select {
                case manualUpdateCh <- struct{}{}:
                default:
                }
        }

        consecutiveHeartbeatFailures := 0

        sendHeartbeatSafe(cfg, agentID, &consecutiveHeartbeatFailures)
        sendTelemetrySafe(cfg, agentID)

        logMessage("INFO", "Agent running -- heartbeat every %ds, commands every %ds, telemetry every %ds, update check every %ds",
                cfg.HeartbeatInterval, cfg.CommandPollInterval, cfg.TelemetryInterval, cfg.UpdateCheckInterval)

        for {
                select {
                case <-ctx.Done():
                        logMessage("INFO", "Agent shutting down...")
                        sendAgentLog(cfg, agentID, "agent_stopped", "info", "Agent shutting down gracefully")
                        globalStatus.SetDisconnected("Agent stopped")
                        return nil

                case <-heartbeatTicker.C:
                        sendHeartbeatSafe(cfg, agentID, &consecutiveHeartbeatFailures)

                        if consecutiveHeartbeatFailures >= maxHeartbeatFailures {
                                logMessage("WARN", "Too many heartbeat failures (%d), attempting re-registration...", consecutiveHeartbeatFailures)
                                consecutiveHeartbeatFailures = 0

                                newID, err := reregisterAgent(ctx, cfg)
                                if err != nil {
                                        logMessage("ERROR", "Re-registration failed: %v", err)
                                        globalStatus.SetDisconnected("Re-registration failed")
                                } else {
                                        agentID = newID
                                        logMessage("INFO", "Re-registered as agent %.0f", agentID)
                                        globalStatus.SetRegistered(agentID, getHostname(), getLocalIP(), cfg.ServerURL, cfg.AgentVersion)
                                        sendHeartbeatSafe(cfg, agentID, &consecutiveHeartbeatFailures)
                                        sendTelemetrySafe(cfg, agentID)
                                }
                        }

                case <-commandTicker.C:
                        processCommands(cfg, agentID)

                case <-updateTicker.C:
                        checkAndUpdate(cfg, agentID)

                case <-telemetryTicker.C:
                        sendTelemetrySafe(cfg, agentID)

                case <-manualUpdateCh:
                        checkAndUpdate(cfg, agentID)
                }
        }
}

func registerWithRetry(ctx context.Context, cfg *AgentConfig) (float64, error) {
        var lastErr error

        for attempt := 1; attempt <= maxRegistrationRetries; attempt++ {
                select {
                case <-ctx.Done():
                        return 0, fmt.Errorf("registration cancelled")
                default:
                }

                logMessage("INFO", "Registering with server (attempt %d/%d)...", attempt, maxRegistrationRetries)
                agentID, err := registerAgent(cfg)
                if err == nil {
                        return agentID, nil
                }

                lastErr = err
                logMessage("WARN", "Registration attempt %d failed: %v", attempt, err)

                if attempt < maxRegistrationRetries {
                        delay := registrationBackoff(attempt)
                        logMessage("INFO", "Retrying in %v...", delay)

                        select {
                        case <-ctx.Done():
                                return 0, fmt.Errorf("registration cancelled during backoff")
                        case <-time.After(delay):
                        }
                }
        }

        return 0, fmt.Errorf("registration failed after %d attempts: %w", maxRegistrationRetries, lastErr)
}

func registrationBackoff(attempt int) time.Duration {
        delays := []time.Duration{
                5 * time.Second,
                10 * time.Second,
                20 * time.Second,
                30 * time.Second,
                45 * time.Second,
                60 * time.Second,
        }
        if attempt-1 < len(delays) {
                return delays[attempt-1]
        }
        return 60 * time.Second
}

func reregisterAgent(ctx context.Context, cfg *AgentConfig) (float64, error) {
        for attempt := 1; attempt <= maxReregistrationRetries; attempt++ {
                select {
                case <-ctx.Done():
                        return 0, fmt.Errorf("re-registration cancelled")
                default:
                }

                agentID, err := registerAgent(cfg)
                if err == nil {
                        return agentID, nil
                }

                logMessage("WARN", "Re-registration attempt %d/%d failed: %v", attempt, maxReregistrationRetries, err)

                if attempt < maxReregistrationRetries {
                        delay := time.Duration(attempt*10) * time.Second
                        select {
                        case <-ctx.Done():
                                return 0, fmt.Errorf("re-registration cancelled")
                        case <-time.After(delay):
                        }
                }
        }

        return 0, fmt.Errorf("re-registration failed after %d attempts", maxReregistrationRetries)
}

func sendHeartbeatSafe(cfg *AgentConfig, agentID float64, failCount *int) {
        if err := sendHeartbeat(cfg, agentID); err != nil {
                *failCount++
                logMessage("WARN", "Heartbeat failed (%d/%d): %v", *failCount, maxHeartbeatFailures, err)
                globalStatus.SetDisconnected(err.Error())
        } else {
                *failCount = 0
                cpu, ram := collectCPUAndRAM()
                globalStatus.SetConnected(agentID, getHostname(), getLocalIP(), cpu, ram)
        }
}

func sendTelemetrySafe(cfg *AgentConfig, agentID float64) {
        if err := sendTelemetry(cfg, agentID); err != nil {
                logMessage("WARN", "Telemetry send failed: %v", err)
        } else {
                logMessage("DEBUG", "Telemetry sent successfully")
        }
}

func processCommands(cfg *AgentConfig, agentID float64) {
        commands, err := pollCommands(cfg, agentID)
        if err != nil {
                logMessage("WARN", "Command poll failed: %v", err)
                return
        }

        for _, cmd := range commands {
                result, status := executeCommand(cmd)
                if err := sendCommandResult(cfg, agentID, cmd.ID, status, result); err != nil {
                        logMessage("WARN", "Failed to send result for command %.0f: %v", cmd.ID, err)
                }
        }
}
