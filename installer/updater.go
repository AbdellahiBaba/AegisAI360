package main

import (
        "fmt"
        "io"
        "net/http"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "time"
)

func checkAndUpdate(cfg *AgentConfig, agentID float64) {
        logMessage("INFO", "Checking for agent updates...")

        ver, err := checkForUpdate(cfg)
        if err != nil {
                logMessage("WARN", "Update check failed: %v", err)
                return
        }

        if ver.Version == "" || ver.Version == cfg.AgentVersion {
                logMessage("INFO", "Agent is up to date (v%s)", cfg.AgentVersion)
                return
        }

        if ver.DownloadURL == "" {
                logMessage("WARN", "New version %s available but no download URL provided", ver.Version)
                return
        }

        logMessage("INFO", "New version available: %s (current: %s)", ver.Version, cfg.AgentVersion)
        sendAgentLog(cfg, agentID, "agent_update", "info",
                fmt.Sprintf("Updating from v%s to v%s", cfg.AgentVersion, ver.Version))

        if err := performUpdate(cfg, ver); err != nil {
                logMessage("ERROR", "Update failed: %v", err)
                sendAgentLog(cfg, agentID, "agent_update_failed", "error",
                        fmt.Sprintf("Update to v%s failed: %v", ver.Version, err))
                return
        }

        cfg.AgentVersion = ver.Version
        if err := saveConfig(cfg); err != nil {
                logMessage("WARN", "Failed to save updated config: %v", err)
        }

        sendAgentLog(cfg, agentID, "agent_updated", "info",
                fmt.Sprintf("Updated to v%s, restarting...", ver.Version))

        restartService()
}

func performUpdate(cfg *AgentConfig, ver *VersionResponse) error {
        exePath, err := os.Executable()
        if err != nil {
                return fmt.Errorf("cannot determine executable path: %w", err)
        }

        dir := filepath.Dir(exePath)
        tmpPath := filepath.Join(dir, "agent_update.tmp")

        logMessage("INFO", "Downloading update from %s", ver.DownloadURL)

        resp, err := http.Get(ver.DownloadURL)
        if err != nil {
                return fmt.Errorf("download failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode != 200 {
                return fmt.Errorf("download returned status %d", resp.StatusCode)
        }

        tmpFile, err := os.Create(tmpPath)
        if err != nil {
                return fmt.Errorf("cannot create temp file: %w", err)
        }

        written, err := io.Copy(tmpFile, resp.Body)
        tmpFile.Close()
        if err != nil {
                os.Remove(tmpPath)
                return fmt.Errorf("download write failed: %w", err)
        }

        logMessage("INFO", "Downloaded %d bytes", written)

        agentBinary := filepath.Join(dir, "agent.exe")
        if runtime.GOOS != "windows" {
                agentBinary = filepath.Join(dir, "agent")
        }

        if runtime.GOOS == "windows" {
                logMessage("INFO", "Stopping service before binary replacement...")
                stopCmd := exec.Command("cmd", "/C", "net stop AegisAI360Agent")
                stopCmd.Run()
                time.Sleep(2 * time.Second)
        }

        backupPath := agentBinary + ".bak"
        os.Remove(backupPath)
        if err := os.Rename(agentBinary, backupPath); err != nil {
                os.Remove(tmpPath)
                return fmt.Errorf("failed to backup current binary: %w", err)
        }

        if err := os.Rename(tmpPath, agentBinary); err != nil {
                os.Rename(backupPath, agentBinary)
                return fmt.Errorf("failed to replace binary: %w", err)
        }

        if runtime.GOOS != "windows" {
                os.Chmod(agentBinary, 0755)
        }

        logMessage("INFO", "Binary replaced successfully, backup at %s", backupPath)

        go func() {
                time.Sleep(10 * time.Second)
                os.Remove(backupPath)
        }()

        return nil
}
