package main

import (
        "fmt"
        "os/exec"
        "runtime"
        "strings"
        "time"
)

func listWifiNetworks() string {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("netsh", "wlan", "show", "networks", "mode=bssid").Output()
                if err != nil {
                        return fmt.Sprintf("Failed to list WiFi networks: %v", err)
                }
                return parseWifiNetworks(string(out))
        }
        out, err := exec.Command("nmcli", "-t", "-f", "SSID,SIGNAL,SECURITY,BSSID", "dev", "wifi", "list").Output()
        if err != nil {
                out2, err2 := exec.Command("iwlist", "wlan0", "scan").Output()
                if err2 != nil {
                        return "WiFi scanning not available on this system"
                }
                return string(out2)
        }
        return string(out)
}

func parseWifiNetworks(raw string) string {
        var sb strings.Builder
        sb.WriteString("=== Available WiFi Networks ===\n\n")
        lines := strings.Split(raw, "\n")
        networkCount := 0
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                if strings.HasPrefix(line, "SSID") && strings.Contains(line, ":") {
                        networkCount++
                        parts := strings.SplitN(line, ":", 2)
                        if len(parts) == 2 {
                                ssid := strings.TrimSpace(parts[1])
                                if ssid == "" {
                                        ssid = "(Hidden Network)"
                                }
                                sb.WriteString(fmt.Sprintf("\n  [%d] SSID: %s\n", networkCount, ssid))
                        }
                } else if strings.Contains(line, ":") {
                        parts := strings.SplitN(line, ":", 2)
                        if len(parts) == 2 {
                                key := strings.TrimSpace(parts[0])
                                val := strings.TrimSpace(parts[1])
                                sb.WriteString(fmt.Sprintf("      %s: %s\n", key, val))
                        }
                }
        }
        sb.WriteString(fmt.Sprintf("\nTotal networks found: %d\n", networkCount))
        return sb.String()
}

func listWifiProfiles() string {
        if runtime.GOOS != "windows" {
                out, err := exec.Command("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show").Output()
                if err != nil {
                        return "WiFi profile listing not available on this system"
                }
                return string(out)
        }

        out, err := exec.Command("netsh", "wlan", "show", "profiles").Output()
        if err != nil {
                return fmt.Sprintf("Failed to list WiFi profiles: %v", err)
        }

        var sb strings.Builder
        sb.WriteString("=== Saved WiFi Profiles ===\n\n")
        lines := strings.Split(string(out), "\n")
        profileCount := 0
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if strings.Contains(line, "All User Profile") || strings.Contains(line, "Current User Profile") {
                        parts := strings.SplitN(line, ":", 2)
                        if len(parts) == 2 {
                                profileName := strings.TrimSpace(parts[1])
                                profileCount++
                                sb.WriteString(fmt.Sprintf("  [%d] %s", profileCount, profileName))

                                keyOut, err := exec.Command("netsh", "wlan", "show", "profile", "name="+profileName, "key=clear").Output()
                                if err == nil {
                                        for _, kLine := range strings.Split(string(keyOut), "\n") {
                                                kLine = strings.TrimSpace(kLine)
                                                if strings.Contains(kLine, "Key Content") || strings.Contains(kLine, "Security key") {
                                                        parts := strings.SplitN(kLine, ":", 2)
                                                        if len(parts) == 2 {
                                                                sb.WriteString(fmt.Sprintf(" | Password: %s", strings.TrimSpace(parts[1])))
                                                        }
                                                }
                                                if strings.Contains(kLine, "Authentication") {
                                                        parts := strings.SplitN(kLine, ":", 2)
                                                        if len(parts) == 2 {
                                                                sb.WriteString(fmt.Sprintf(" | Auth: %s", strings.TrimSpace(parts[1])))
                                                        }
                                                }
                                        }
                                }
                                sb.WriteString("\n")
                        }
                }
        }
        sb.WriteString(fmt.Sprintf("\nTotal profiles: %d\n", profileCount))
        return sb.String()
}

func connectWifi(ssid string) string {
        if ssid == "" {
                return "Error: SSID is required"
        }
        if runtime.GOOS == "windows" {
                out, err := exec.Command("netsh", "wlan", "connect", "name="+ssid).CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to connect to '%s': %v\nOutput: %s", ssid, err, string(out))
                }
                return fmt.Sprintf("Connection request sent for '%s'\n%s", ssid, string(out))
        }
        out, err := exec.Command("nmcli", "dev", "wifi", "connect", ssid).CombinedOutput()
        if err != nil {
                return fmt.Sprintf("Failed to connect to '%s': %v\nOutput: %s", ssid, err, string(out))
        }
        return string(out)
}

func disconnectWifi() string {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("netsh", "wlan", "disconnect").CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to disconnect: %v", err)
                }
                return string(out)
        }
        out, err := exec.Command("nmcli", "dev", "disconnect", "wlan0").CombinedOutput()
        if err != nil {
                return fmt.Sprintf("Failed to disconnect: %v", err)
        }
        return string(out)
}

func listNetworkInterfaces() string {
        var sb strings.Builder
        sb.WriteString("=== Network Interfaces ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("ipconfig", "/all").Output()
                if err != nil {
                        return "Failed to list network interfaces"
                }
                return sb.String() + string(out)
        }

        out, err := exec.Command("ip", "-br", "addr").Output()
        if err != nil {
                out2, _ := exec.Command("ifconfig", "-a").Output()
                return sb.String() + string(out2)
        }
        return sb.String() + string(out)
}

func getDNSInfo() string {
        var sb strings.Builder
        sb.WriteString("=== DNS Configuration ===\n\n")

        if runtime.GOOS == "windows" {
                sb.WriteString("--- DNS Servers ---\n")
                out, err := exec.Command("netsh", "interface", "ip", "show", "dnsservers").Output()
                if err == nil {
                        sb.WriteString(string(out))
                }
                sb.WriteString("\n--- DNS Cache (last 30 entries) ---\n")
                out2, err := exec.Command("ipconfig", "/displaydns").Output()
                if err == nil {
                        lines := strings.Split(string(out2), "\n")
                        count := 0
                        for _, line := range lines {
                                line = strings.TrimSpace(line)
                                if line == "" {
                                        continue
                                }
                                sb.WriteString("  " + line + "\n")
                                count++
                                if count >= 100 {
                                        sb.WriteString("  ... (truncated)\n")
                                        break
                                }
                        }
                }
                return sb.String()
        }

        out, _ := exec.Command("cat", "/etc/resolv.conf").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func getARPTable() string {
        var sb strings.Builder
        sb.WriteString("=== ARP Table (Devices on Local Network) ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("arp", "-a").Output()
                if err != nil {
                        return "Failed to retrieve ARP table"
                }
                sb.WriteString(string(out))
                return sb.String()
        }

        out, err := exec.Command("arp", "-a").Output()
        if err != nil {
                out2, _ := exec.Command("ip", "neigh").Output()
                sb.WriteString(string(out2))
                return sb.String()
        }
        sb.WriteString(string(out))
        return sb.String()
}

func getRoutingTable() string {
        var sb strings.Builder
        sb.WriteString("=== Routing Table ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("route", "print").Output()
                if err != nil {
                        return "Failed to retrieve routing table"
                }
                sb.WriteString(string(out))
                return sb.String()
        }

        out, err := exec.Command("ip", "route").Output()
        if err != nil {
                out2, _ := exec.Command("route", "-n").Output()
                sb.WriteString(string(out2))
                return sb.String()
        }
        sb.WriteString(string(out))
        return sb.String()
}

func listFirewallRules(filter string) string {
        var sb strings.Builder
        sb.WriteString("=== Firewall Rules ===\n\n")

        if runtime.GOOS == "windows" {
                args := []string{"advfirewall", "firewall", "show", "rule", "name=all"}
                if filter != "" {
                        args = []string{"advfirewall", "firewall", "show", "rule", "name=" + filter}
                }
                out, err := exec.Command("netsh", args...).Output()
                if err != nil {
                        return fmt.Sprintf("Failed to list firewall rules: %v", err)
                }
                lines := strings.Split(string(out), "\n")
                count := 0
                for _, line := range lines {
                        sb.WriteString(line + "\n")
                        count++
                        if count >= 200 {
                                sb.WriteString("... (truncated at 200 lines)\n")
                                break
                        }
                }
                return sb.String()
        }

        out, err := exec.Command("iptables", "-L", "-n", "--line-numbers").Output()
        if err != nil {
                return "Firewall listing not available (iptables not found or no permission)"
        }
        sb.WriteString(string(out))
        return sb.String()
}

func addFirewallRule(name, direction, action, port, protocol string) string {
        if name == "" || direction == "" || action == "" {
                return "Error: name, direction, and action are required"
        }

        if runtime.GOOS == "windows" {
                dir := "in"
                if strings.ToLower(direction) == "out" || strings.ToLower(direction) == "outbound" {
                        dir = "out"
                }
                act := "block"
                if strings.ToLower(action) == "allow" {
                        act = "allow"
                }
                if protocol == "" {
                        protocol = "tcp"
                }

                args := []string{"advfirewall", "firewall", "add", "rule",
                        "name=" + name,
                        "dir=" + dir,
                        "action=" + act,
                        "protocol=" + strings.ToLower(protocol),
                }
                if port != "" {
                        args = append(args, "localport="+port)
                }
                args = append(args, "enable=yes")

                out, err := exec.Command("netsh", args...).CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to add firewall rule: %v\nOutput: %s", err, string(out))
                }
                return fmt.Sprintf("Firewall rule '%s' added successfully (dir=%s, action=%s, port=%s, proto=%s)\n%s",
                        name, dir, act, port, protocol, string(out))
        }

        return "Firewall rule management requires iptables on Linux (not implemented in this build)"
}

func removeFirewallRule(name string) string {
        if name == "" {
                return "Error: rule name is required"
        }

        if runtime.GOOS == "windows" {
                out, err := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name).CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to remove firewall rule '%s': %v\nOutput: %s", name, err, string(out))
                }
                return fmt.Sprintf("Firewall rule '%s' removed\n%s", name, string(out))
        }

        return "Firewall rule management requires iptables on Linux (not implemented in this build)"
}

func listInstalledSoftware() string {
        var sb strings.Builder
        sb.WriteString("=== Installed Software ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("wmic", "product", "get", "Name,Version,Vendor", "/Format:csv").Output()
                if err != nil {
                        out2, err2 := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, "/s", "/v", "DisplayName").Output()
                        if err2 != nil {
                                return "Failed to list installed software"
                        }
                        lines := strings.Split(string(out2), "\n")
                        count := 0
                        for _, line := range lines {
                                line = strings.TrimSpace(line)
                                if strings.Contains(line, "DisplayName") {
                                        parts := strings.Fields(line)
                                        if len(parts) >= 3 {
                                                name := strings.Join(parts[2:], " ")
                                                count++
                                                sb.WriteString(fmt.Sprintf("  %d. %s\n", count, name))
                                        }
                                }
                        }
                        sb.WriteString(fmt.Sprintf("\nTotal: %d programs\n", count))
                        return sb.String()
                }
                lines := strings.Split(string(out), "\n")
                count := 0
                for _, line := range lines[1:] {
                        line = strings.TrimSpace(line)
                        if line != "" && !strings.HasPrefix(line, "Node") {
                                count++
                                sb.WriteString(fmt.Sprintf("  %d. %s\n", count, line))
                                if count >= 100 {
                                        sb.WriteString("  ... (truncated)\n")
                                        break
                                }
                        }
                }
                sb.WriteString(fmt.Sprintf("\nTotal: %d programs\n", count))
                return sb.String()
        }

        out, err := exec.Command("dpkg", "--list").Output()
        if err != nil {
                out2, _ := exec.Command("rpm", "-qa").Output()
                sb.WriteString(string(out2))
                return sb.String()
        }
        lines := strings.Split(string(out), "\n")
        for i, line := range lines {
                sb.WriteString(line + "\n")
                if i >= 100 {
                        sb.WriteString("... (truncated)\n")
                        break
                }
        }
        return sb.String()
}

func listStartupPrograms() string {
        var sb strings.Builder
        sb.WriteString("=== Startup Programs ===\n\n")

        if runtime.GOOS == "windows" {
                sb.WriteString("--- Registry (HKLM Run) ---\n")
                out, _ := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).Output()
                for _, line := range strings.Split(string(out), "\n") {
                        line = strings.TrimSpace(line)
                        if line != "" && !strings.HasPrefix(line, "HKEY") {
                                sb.WriteString("  " + line + "\n")
                        }
                }

                sb.WriteString("\n--- Registry (HKCU Run) ---\n")
                out2, _ := exec.Command("reg", "query", `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`).Output()
                for _, line := range strings.Split(string(out2), "\n") {
                        line = strings.TrimSpace(line)
                        if line != "" && !strings.HasPrefix(line, "HKEY") {
                                sb.WriteString("  " + line + "\n")
                        }
                }

                sb.WriteString("\n--- Scheduled Tasks (at logon) ---\n")
                out3, _ := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output()
                for _, line := range strings.Split(string(out3), "\n") {
                        if strings.Contains(strings.ToLower(line), "logon") || strings.Contains(strings.ToLower(line), "startup") {
                                sb.WriteString("  " + strings.TrimSpace(line) + "\n")
                        }
                }
                return sb.String()
        }

        out, _ := exec.Command("systemctl", "list-unit-files", "--type=service", "--state=enabled").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func listUserAccounts() string {
        var sb strings.Builder
        sb.WriteString("=== Local User Accounts ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("net", "user").Output()
                if err != nil {
                        return "Failed to list users"
                }
                sb.WriteString(string(out))

                sb.WriteString("\n--- Admin Group Members ---\n")
                out2, _ := exec.Command("net", "localgroup", "Administrators").Output()
                sb.WriteString(string(out2))
                return sb.String()
        }

        out, _ := exec.Command("cat", "/etc/passwd").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func listUserSessions() string {
        var sb strings.Builder
        sb.WriteString("=== Active User Sessions ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("query", "user").Output()
                if err != nil {
                        out2, _ := exec.Command("quser").Output()
                        sb.WriteString(string(out2))
                        return sb.String()
                }
                sb.WriteString(string(out))
                return sb.String()
        }

        out, _ := exec.Command("who").Output()
        sb.WriteString(string(out))
        out2, _ := exec.Command("last", "-n", "20").Output()
        sb.WriteString("\n--- Recent Logins ---\n")
        sb.WriteString(string(out2))
        return sb.String()
}

func listServices() string {
        var sb strings.Builder
        sb.WriteString("=== System Services ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("sc", "query", "state=", "all").Output()
                if err != nil {
                        return "Failed to list services"
                }
                lines := strings.Split(string(out), "\n")
                count := 0
                var currentService string
                for _, line := range lines {
                        line = strings.TrimSpace(line)
                        if strings.HasPrefix(line, "SERVICE_NAME:") {
                                currentService = strings.TrimPrefix(line, "SERVICE_NAME:")
                                currentService = strings.TrimSpace(currentService)
                        }
                        if strings.Contains(line, "STATE") && strings.Contains(line, ":") {
                                state := "UNKNOWN"
                                if strings.Contains(line, "RUNNING") {
                                        state = "RUNNING"
                                } else if strings.Contains(line, "STOPPED") {
                                        state = "STOPPED"
                                } else if strings.Contains(line, "PAUSED") {
                                        state = "PAUSED"
                                }
                                count++
                                sb.WriteString(fmt.Sprintf("  %-40s %s\n", currentService, state))
                                if count >= 100 {
                                        sb.WriteString("  ... (truncated)\n")
                                        break
                                }
                        }
                }
                sb.WriteString(fmt.Sprintf("\nTotal: %d services\n", count))
                return sb.String()
        }

        out, _ := exec.Command("systemctl", "list-units", "--type=service", "--no-pager").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func controlService(name, action string) string {
        if name == "" || action == "" {
                return "Error: service name and action are required"
        }

        action = strings.ToLower(action)
        validActions := map[string]bool{"start": true, "stop": true, "restart": true}
        if !validActions[action] {
                return fmt.Sprintf("Error: invalid action '%s' (use start, stop, or restart)", action)
        }

        if runtime.GOOS == "windows" {
                if action == "restart" {
                        exec.Command("sc", "stop", name).Run()
                        exec.Command("timeout", "/t", "3", "/nobreak").Run()
                        out, err := exec.Command("sc", "start", name).CombinedOutput()
                        if err != nil {
                                return fmt.Sprintf("Failed to restart service '%s': %v\n%s", name, err, string(out))
                        }
                        return fmt.Sprintf("Service '%s' restarted\n%s", name, string(out))
                }
                out, err := exec.Command("sc", action, name).CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to %s service '%s': %v\n%s", action, name, err, string(out))
                }
                return fmt.Sprintf("Service '%s' %sed\n%s", name, action, string(out))
        }

        out, err := exec.Command("systemctl", action, name).CombinedOutput()
        if err != nil {
                return fmt.Sprintf("Failed to %s service '%s': %v\n%s", action, name, err, string(out))
        }
        return fmt.Sprintf("Service '%s' %sed\n%s", name, action, string(out))
}

func listScheduledTasks() string {
        var sb strings.Builder
        sb.WriteString("=== Scheduled Tasks ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("schtasks", "/query", "/fo", "csv").Output()
                if err != nil {
                        return "Failed to list scheduled tasks"
                }
                lines := strings.Split(string(out), "\n")
                for i, line := range lines {
                        sb.WriteString(strings.TrimSpace(line) + "\n")
                        if i >= 100 {
                                sb.WriteString("... (truncated)\n")
                                break
                        }
                }
                return sb.String()
        }

        out, _ := exec.Command("crontab", "-l").Output()
        sb.WriteString("--- Crontab ---\n")
        sb.WriteString(string(out))
        out2, _ := exec.Command("systemctl", "list-timers", "--no-pager").Output()
        sb.WriteString("\n--- Systemd Timers ---\n")
        sb.WriteString(string(out2))
        return sb.String()
}

func queryEventLog(logName string, count int) string {
        if logName == "" {
                logName = "System"
        }
        if count <= 0 || count > 200 {
                count = 50
        }

        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("=== Event Log: %s (last %d) ===\n\n", logName, count))

        if runtime.GOOS == "windows" {
                out, err := exec.Command("wevtutil", "qe", logName, "/c:"+fmt.Sprintf("%d", count), "/f:text", "/rd:true").Output()
                if err != nil {
                        return fmt.Sprintf("Failed to query event log '%s': %v", logName, err)
                }
                sb.WriteString(string(out))
                return sb.String()
        }

        out, _ := exec.Command("journalctl", "-n", fmt.Sprintf("%d", count), "--no-pager").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func listEnvVars() string {
        var sb strings.Builder
        sb.WriteString("=== Environment Variables ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("cmd", "/C", "set").Output()
                if err != nil {
                        return "Failed to list environment variables"
                }
                sb.WriteString(string(out))
                return sb.String()
        }

        out, _ := exec.Command("printenv").Output()
        sb.WriteString(string(out))
        return sb.String()
}

func queryRegistry(key string) string {
        if runtime.GOOS != "windows" {
                return "Registry is only available on Windows"
        }
        if key == "" {
                return "Error: registry key path is required"
        }

        out, err := exec.Command("reg", "query", key).Output()
        if err != nil {
                return fmt.Sprintf("Failed to query registry key '%s': %v", key, err)
        }
        return string(out)
}

func fileSearch(searchPath, pattern string, maxResults int) string {
        if searchPath == "" {
                searchPath = "C:\\"
                if runtime.GOOS != "windows" {
                        searchPath = "/"
                }
        }
        if pattern == "" {
                return "Error: search pattern is required"
        }
        if maxResults <= 0 || maxResults > 200 {
                maxResults = 50
        }

        var sb strings.Builder
        sb.WriteString(fmt.Sprintf("=== File Search: %s in %s ===\n\n", pattern, searchPath))

        if runtime.GOOS == "windows" {
                out, err := exec.Command("cmd", "/C", fmt.Sprintf("dir /s /b \"%s\\%s\" 2>nul", searchPath, pattern)).Output()
                if err != nil {
                        return fmt.Sprintf("Search completed. No files matching '%s' found in '%s'", pattern, searchPath)
                }
                lines := strings.Split(strings.TrimSpace(string(out)), "\n")
                count := 0
                for _, line := range lines {
                        line = strings.TrimSpace(line)
                        if line != "" {
                                count++
                                sb.WriteString(fmt.Sprintf("  %d. %s\n", count, line))
                                if count >= maxResults {
                                        sb.WriteString(fmt.Sprintf("  ... (limited to %d results)\n", maxResults))
                                        break
                                }
                        }
                }
                sb.WriteString(fmt.Sprintf("\nFound: %d files\n", count))
                return sb.String()
        }

        out, err := exec.Command("find", searchPath, "-name", pattern, "-maxdepth", "5", "-type", "f").Output()
        if err != nil {
                return fmt.Sprintf("Search completed. No files matching '%s' found in '%s'", pattern, searchPath)
        }
        lines := strings.Split(strings.TrimSpace(string(out)), "\n")
        count := 0
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line != "" {
                        count++
                        sb.WriteString(fmt.Sprintf("  %d. %s\n", count, line))
                        if count >= maxResults {
                                break
                        }
                }
        }
        sb.WriteString(fmt.Sprintf("\nFound: %d files\n", count))
        return sb.String()
}

func fileHash(filePath string) string {
        if filePath == "" {
                return "Error: file path is required"
        }

        if runtime.GOOS == "windows" {
                out, err := exec.Command("certutil", "-hashfile", filePath, "SHA256").Output()
                if err != nil {
                        return fmt.Sprintf("Failed to hash file '%s': %v", filePath, err)
                }
                return fmt.Sprintf("=== File Hash ===\nFile: %s\n%s", filePath, string(out))
        }

        out, err := exec.Command("sha256sum", filePath).Output()
        if err != nil {
                return fmt.Sprintf("Failed to hash file '%s': %v", filePath, err)
        }
        return fmt.Sprintf("=== File Hash ===\nFile: %s\nSHA256: %s", filePath, string(out))
}

func securityScan() string {
        var sb strings.Builder
        sb.WriteString("=== Security Audit Report ===\n")
        sb.WriteString(fmt.Sprintf("Hostname:  %s\n", getHostname()))
        sb.WriteString(fmt.Sprintf("Scan Time: %s\n", time.Now().Format(time.RFC3339)))
        sb.WriteString(fmt.Sprintf("OS: %s/%s\n\n", runtime.GOOS, runtime.GOARCH))

        sb.WriteString("--- Open Ports ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("netstat", "-an").Output()
                for _, line := range strings.Split(string(out), "\n") {
                        if strings.Contains(line, "LISTENING") || strings.Contains(line, "LISTEN") {
                                sb.WriteString("  " + strings.TrimSpace(line) + "\n")
                        }
                }
        } else {
                out, _ := exec.Command("ss", "-tlnp").Output()
                sb.WriteString(string(out))
        }

        sb.WriteString("\n--- Admin/Root Users ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("net", "localgroup", "Administrators").Output()
                sb.WriteString(string(out))
        } else {
                out, _ := exec.Command("grep", ":0:", "/etc/passwd").Output()
                sb.WriteString(string(out))
        }

        sb.WriteString("\n--- Active Network Connections ---\n")
        sb.WriteString(fmt.Sprintf("  Established connections: %d\n", countNetConnections()))

        sb.WriteString("\n--- Disk Usage ---\n")
        sb.WriteString("  " + collectDiskUsage() + "\n")

        sb.WriteString("\n--- Firewall Status ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
                sb.WriteString(string(out))
        } else {
                out, _ := exec.Command("ufw", "status").Output()
                sb.WriteString(string(out))
        }

        sb.WriteString("\n--- Antivirus Status ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("powershell", "-Command", "Get-MpComputerStatus | Select-Object AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled | Format-List").Output()
                if len(out) > 0 {
                        sb.WriteString(string(out))
                } else {
                        sb.WriteString("  Windows Defender status unavailable\n")
                }
        }

        sb.WriteString("\n--- Suspicious Scheduled Tasks ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output()
                count := 0
                for _, line := range strings.Split(string(out), "\n") {
                        lower := strings.ToLower(line)
                        if strings.Contains(lower, "temp") || strings.Contains(lower, "appdata") || strings.Contains(lower, "powershell") {
                                sb.WriteString("  [!] " + strings.TrimSpace(line) + "\n")
                                count++
                        }
                }
                if count == 0 {
                        sb.WriteString("  No suspicious tasks found\n")
                }
        }

        sb.WriteString("\n--- Windows Update Status ---\n")
        if runtime.GOOS == "windows" {
                out, _ := exec.Command("powershell", "-Command", "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5) | Format-Table -AutoSize").Output()
                if len(out) > 0 {
                        sb.WriteString(string(out))
                } else {
                        sb.WriteString("  Update status unavailable\n")
                }
        }

        return sb.String()
}

func processKill(pid int, name string) string {
        if pid <= 0 && name == "" {
                return "Error: PID or process name is required"
        }

        if runtime.GOOS == "windows" {
                if pid > 0 {
                        out, err := exec.Command("taskkill", "/PID", fmt.Sprintf("%d", pid), "/F").CombinedOutput()
                        if err != nil {
                                return fmt.Sprintf("Failed to kill PID %d: %v\n%s", pid, err, string(out))
                        }
                        return fmt.Sprintf("Process PID %d terminated\n%s", pid, string(out))
                }
                out, err := exec.Command("taskkill", "/IM", name, "/F").CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to kill process '%s': %v\n%s", name, err, string(out))
                }
                return fmt.Sprintf("Process '%s' terminated\n%s", name, string(out))
        }

        if pid > 0 {
                out, err := exec.Command("kill", "-9", fmt.Sprintf("%d", pid)).CombinedOutput()
                if err != nil {
                        return fmt.Sprintf("Failed to kill PID %d: %v\n%s", pid, err, string(out))
                }
                return fmt.Sprintf("Process PID %d terminated", pid)
        }
        out, err := exec.Command("pkill", "-9", name).CombinedOutput()
        if err != nil {
                return fmt.Sprintf("Failed to kill process '%s': %v\n%s", name, err, string(out))
        }
        return fmt.Sprintf("Process '%s' terminated", name)
}

func processListDetailed() string {
        var sb strings.Builder
        sb.WriteString("=== Running Processes ===\n\n")

        if runtime.GOOS == "windows" {
                out, err := exec.Command("tasklist", "/V", "/FO", "CSV").Output()
                if err != nil {
                        return "Failed to list processes"
                }
                lines := strings.Split(string(out), "\n")
                for i, line := range lines {
                        sb.WriteString(strings.TrimSpace(line) + "\n")
                        if i >= 100 {
                                sb.WriteString("... (truncated)\n")
                                break
                        }
                }
                return sb.String()
        }

        out, _ := exec.Command("ps", "aux", "--sort=-pcpu").Output()
        lines := strings.Split(string(out), "\n")
        for i, line := range lines {
                sb.WriteString(line + "\n")
                if i >= 100 {
                        sb.WriteString("... (truncated)\n")
                        break
                }
        }
        return sb.String()
}
