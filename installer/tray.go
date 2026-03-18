//go:build !headless

package main

import (
        "fmt"
        "net/http"
        "os"
        "os/exec"
        "path/filepath"
        "runtime"
        "time"

        "github.com/getlantern/systray"
)

var (
        trayReady    chan struct{}
        trayQuitFunc func()
)

func runTray(cfg *AgentConfig) {
        trayReady = make(chan struct{})
        systray.Run(func() { onTrayReady(cfg) }, onTrayExit)
}

func onTrayReady(cfg *AgentConfig) {
        systray.SetIcon(iconDisconnected)
        systray.SetTitle("")
        systray.SetTooltip("AegisAI360 Agent - Starting...")

        mStatus := systray.AddMenuItem("Status: Starting...", "Agent connection status")
        mStatus.Disable()

        mAgentInfo := systray.AddMenuItem("Agent: Not registered", "Agent details")
        mAgentInfo.Disable()

        mHostInfo := systray.AddMenuItem("Host: "+getHostname(), "Hostname")
        mHostInfo.Disable()

        systray.AddSeparator()

        mDashboard := systray.AddMenuItem("Open Dashboard", "Open AegisAI360 in your browser")
        mTestConn := systray.AddMenuItem("Test Connection", "Test connectivity to server")

        systray.AddSeparator()

        mViewLogs := systray.AddMenuItem("View Logs", "Open agent log folder")
        mRestart := systray.AddMenuItem("Restart Agent", "Restart the agent service")

        systray.AddSeparator()

        mAbout := systray.AddMenuItem(
                fmt.Sprintf("AegisAI360 Endpoint Agent v%s", agentVersion),
                companyName,
        )
        mAbout.Disable()

        mQuit := systray.AddMenuItem("Exit", "Close the tray application")

        if trayReady != nil {
                close(trayReady)
        }

        go func() {
                ticker := time.NewTicker(3 * time.Second)
                defer ticker.Stop()
                for range ticker.C {
                        updateTrayStatus(mStatus, mAgentInfo)
                }
        }()

        for {
                select {
                case <-mDashboard.ClickedCh:
                        openDashboard(cfg.ServerURL)

                case <-mTestConn.ClickedCh:
                        go testConnection(cfg, mTestConn)

                case <-mViewLogs.ClickedCh:
                        openLogFolder()

                case <-mRestart.ClickedCh:
                        go restartService()

                case <-mQuit.ClickedCh:
                        systray.Quit()
                        return
                }
        }
}

func onTrayExit() {
        logMessage("INFO", "System tray exiting")
}

func updateTrayStatus(mStatus, mAgentInfo *systray.MenuItem) {
        connected, agentID, hostname, ip, _, lastErr, _, cpu, ram, lastHB := globalStatus.GetInfo()

        if connected {
                systray.SetIcon(iconConnected)
                systray.SetTooltip(fmt.Sprintf("AegisAI360 Agent - Connected\n%s (%s)\nCPU: %.0f%% RAM: %.0f%%", hostname, ip, cpu, ram))
                mStatus.SetTitle(fmt.Sprintf("Status: Connected (last: %s)", timeSinceShort(lastHB)))
                mAgentInfo.SetTitle(fmt.Sprintf("Agent #%.0f | CPU: %.0f%% | RAM: %.0f%%", agentID, cpu, ram))
        } else {
                systray.SetIcon(iconDisconnected)
                errMsg := "Connecting..."
                if lastErr != "" {
                        errMsg = lastErr
                        if len(errMsg) > 40 {
                                errMsg = errMsg[:40] + "..."
                        }
                }
                systray.SetTooltip("AegisAI360 Agent - Disconnected")
                mStatus.SetTitle(fmt.Sprintf("Status: Disconnected - %s", errMsg))
                if agentID > 0 {
                        mAgentInfo.SetTitle(fmt.Sprintf("Agent #%.0f | Reconnecting...", agentID))
                } else {
                        mAgentInfo.SetTitle("Agent: Not registered")
                }
        }
}

func timeSinceShort(t time.Time) string {
        if t.IsZero() {
                return "never"
        }
        d := time.Since(t)
        if d < time.Minute {
                return fmt.Sprintf("%ds ago", int(d.Seconds()))
        }
        if d < time.Hour {
                return fmt.Sprintf("%dm ago", int(d.Minutes()))
        }
        return fmt.Sprintf("%dh ago", int(d.Hours()))
}

func openDashboard(serverURL string) {
        url := serverURL
        if url == "" {
                url = "https://aegisai360.com"
        }
        logMessage("INFO", "Opening dashboard: %s", url)

        var cmd *exec.Cmd
        switch runtime.GOOS {
        case "windows":
                cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
        case "darwin":
                cmd = exec.Command("open", url)
        default:
                cmd = exec.Command("xdg-open", url)
        }
        if err := cmd.Start(); err != nil {
                logMessage("WARN", "Failed to open browser: %v", err)
        }
}

func testConnection(cfg *AgentConfig, menuItem *systray.MenuItem) {
        menuItem.SetTitle("Testing connection...")
        menuItem.Disable()
        defer func() {
                menuItem.SetTitle("Test Connection")
                menuItem.Enable()
        }()

        url := cfg.ServerURL + "/api/agent/ping"
        client := &http.Client{Timeout: 10 * time.Second}

        start := time.Now()
        resp, err := client.Get(url)
        elapsed := time.Since(start)

        if err != nil {
                logMessage("WARN", "Connection test failed: %v", err)
                menuItem.SetTitle(fmt.Sprintf("Test Failed: %v", err))
                time.Sleep(3 * time.Second)
                return
        }
        resp.Body.Close()

        if resp.StatusCode == 200 {
                logMessage("INFO", "Connection test OK (%dms)", elapsed.Milliseconds())
                menuItem.SetTitle(fmt.Sprintf("Connected OK (%dms)", elapsed.Milliseconds()))
        } else {
                logMessage("WARN", "Connection test returned status %d", resp.StatusCode)
                menuItem.SetTitle(fmt.Sprintf("Test: Server returned %d", resp.StatusCode))
        }
        time.Sleep(3 * time.Second)
}

func openLogFolder() {
        exePath, err := os.Executable()
        if err != nil {
                logMessage("WARN", "Cannot determine log folder: %v", err)
                return
        }
        logDir := filepath.Join(filepath.Dir(exePath), logFolder)
        os.MkdirAll(logDir, 0755)

        var cmd *exec.Cmd
        switch runtime.GOOS {
        case "windows":
                cmd = exec.Command("explorer", logDir)
        case "darwin":
                cmd = exec.Command("open", logDir)
        default:
                cmd = exec.Command("xdg-open", logDir)
        }
        if err := cmd.Start(); err != nil {
                logMessage("WARN", "Failed to open log folder: %v", err)
        }
}
