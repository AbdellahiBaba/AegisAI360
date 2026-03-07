//go:build headless

package main

import "context"

func runTray(cfg *AgentConfig) {
        logMessage("WARN", "Tray mode not available in headless build, falling back to service mode")
        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()
        if err := runAgent(ctx, cfg); err != nil {
                logMessage("FATAL", "Agent error: %v", err)
        }
}
