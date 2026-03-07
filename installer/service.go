package main

import (
	"context"
	"fmt"
	"time"
)

var triggerUpdateCheck func()

func runAgent(ctx context.Context, cfg *AgentConfig) error {
	logMessage("INFO", "AegisAI360 Endpoint Agent v%s starting...", cfg.AgentVersion)
	logMessage("INFO", "Server: %s", cfg.ServerURL)
	logMessage("INFO", "Token: %s", maskToken(cfg.APIKey))

	initHTTPClient()

	logMessage("INFO", "Registering with server...")
	agentID, err := registerAgent(cfg)
	if err != nil {
		globalStatus.SetDisconnected(fmt.Sprintf("Registration failed: %v", err))
		return fmt.Errorf("registration failed: %w", err)
	}
	logMessage("INFO", "Registered successfully as agent %.0f", agentID)

	globalStatus.SetRegistered(agentID, getHostname(), getLocalIP(), cfg.ServerURL, cfg.AgentVersion)

	sendAgentLog(cfg, agentID, "agent_started", "info",
		fmt.Sprintf("AegisAI360 Agent v%s started on %s (%s)", cfg.AgentVersion, getHostname(), getLocalIP()))

	heartbeatTicker := time.NewTicker(time.Duration(cfg.HeartbeatInterval) * time.Second)
	defer heartbeatTicker.Stop()

	commandTicker := time.NewTicker(time.Duration(cfg.CommandPollInterval) * time.Second)
	defer commandTicker.Stop()

	updateTicker := time.NewTicker(1 * time.Hour)
	defer updateTicker.Stop()

	manualUpdateCh := make(chan struct{}, 1)
	triggerUpdateCheck = func() {
		select {
		case manualUpdateCh <- struct{}{}:
		default:
		}
	}

	sendHeartbeatSafe(cfg, agentID)

	logMessage("INFO", "Agent running — heartbeat every %ds, polling every %ds", cfg.HeartbeatInterval, cfg.CommandPollInterval)

	for {
		select {
		case <-ctx.Done():
			logMessage("INFO", "Agent shutting down...")
			sendAgentLog(cfg, agentID, "agent_stopped", "info", "Agent shutting down gracefully")
			globalStatus.SetDisconnected("Agent stopped")
			return nil

		case <-heartbeatTicker.C:
			sendHeartbeatSafe(cfg, agentID)

		case <-commandTicker.C:
			processCommands(cfg, agentID)

		case <-updateTicker.C:
			checkAndUpdate(cfg, agentID)

		case <-manualUpdateCh:
			checkAndUpdate(cfg, agentID)
		}
	}
}

func sendHeartbeatSafe(cfg *AgentConfig, agentID float64) {
	if err := sendHeartbeat(cfg, agentID); err != nil {
		logMessage("WARN", "Heartbeat failed: %v", err)
		globalStatus.SetDisconnected(err.Error())
	} else {
		cpu, ram := collectCPUAndRAM()
		globalStatus.SetConnected(agentID, getHostname(), getLocalIP(), cpu, ram)
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
