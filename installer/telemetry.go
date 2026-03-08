package main

import (
        "fmt"
        "os"
        "os/exec"
        "runtime"
        "strconv"
        "strings"
        "time"
)

type SystemInfo struct {
        Hostname       string   `json:"hostname"`
        OS             string   `json:"os"`
        Arch           string   `json:"arch"`
        CPUs           int      `json:"cpus"`
        GoVersion      string   `json:"goVersion"`
        AgentVersion   string   `json:"agentVersion"`
        RunMode        string   `json:"runMode"`
        Uptime         string   `json:"uptime"`
        CPUUsage       float64  `json:"cpuUsage"`
        RAMUsage       float64  `json:"ramUsage"`
        RAMTotalMB     uint64   `json:"ramTotalMB"`
        RAMFreeMB      uint64   `json:"ramFreeMB"`
        TopProcesses   []string `json:"topProcesses"`
        NetConnections int      `json:"netConnections"`
        LocalIP        string   `json:"localIP"`
        Time           string   `json:"time"`
}

func collectSystemInfo() *SystemInfo {
        cpu, ram := collectCPUAndRAM()
        totalMB, freeMB := collectRAMDetails()
        procs := collectTopProcesses(20)
        netConns := countNetConnections()

        return &SystemInfo{
                Hostname:       getHostname(),
                OS:             runtime.GOOS + "/" + runtime.GOARCH,
                Arch:           runtime.GOARCH,
                CPUs:           runtime.NumCPU(),
                GoVersion:      runtime.Version(),
                AgentVersion:   agentVersion,
                RunMode:        detectMode(),
                Uptime:         getSystemUptime(),
                CPUUsage:       cpu,
                RAMUsage:       ram,
                RAMTotalMB:     totalMB,
                RAMFreeMB:      freeMB,
                TopProcesses:   procs,
                NetConnections: netConns,
                LocalIP:        getLocalIP(),
                Time:           time.Now().Format(time.RFC3339),
        }
}

func formatSystemInfo(info *SystemInfo) string {
        var sb strings.Builder
        sb.WriteString("=== AegisAI360 System Report ===\n")
        sb.WriteString(fmt.Sprintf("Hostname:        %s\n", info.Hostname))
        sb.WriteString(fmt.Sprintf("OS:              %s\n", info.OS))
        sb.WriteString(fmt.Sprintf("CPUs:            %d\n", info.CPUs))
        sb.WriteString(fmt.Sprintf("Agent Version:   %s\n", info.AgentVersion))
        sb.WriteString(fmt.Sprintf("Go Version:      %s\n", info.GoVersion))
        sb.WriteString(fmt.Sprintf("Uptime:          %s\n", info.Uptime))
        sb.WriteString(fmt.Sprintf("CPU Usage:       %.1f%%\n", info.CPUUsage))
        sb.WriteString(fmt.Sprintf("RAM Usage:       %.1f%% (%d MB free / %d MB total)\n", info.RAMUsage, info.RAMFreeMB, info.RAMTotalMB))
        sb.WriteString(fmt.Sprintf("Network Conns:   %d\n", info.NetConnections))
        sb.WriteString(fmt.Sprintf("Local IP:        %s\n", info.LocalIP))
        sb.WriteString(fmt.Sprintf("Report Time:     %s\n", info.Time))
        if len(info.TopProcesses) > 0 {
                sb.WriteString("\n--- Top Processes ---\n")
                for i, p := range info.TopProcesses {
                        sb.WriteString(fmt.Sprintf("  %2d. %s\n", i+1, p))
                }
        }
        return sb.String()
}

func collectCPUAndRAM() (float64, float64) {
        if runtime.GOOS == "windows" {
                return collectCPUWindows(), collectRAMUsageWindows()
        }
        return collectCPULinux(), collectRAMUsageLinux()
}

func collectCPUWindows() float64 {
        out, err := exec.Command("wmic", "cpu", "get", "loadpercentage").Output()
        if err != nil {
                return 0
        }
        lines := strings.Split(strings.TrimSpace(string(out)), "\n")
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if val, err := strconv.ParseFloat(line, 64); err == nil {
                        return val
                }
        }
        return 0
}

func collectCPULinux() float64 {
        data1, err := os.ReadFile("/proc/stat")
        if err != nil {
                return 0
        }
        idle1, total1 := parseProcStat(string(data1))

        time.Sleep(500 * time.Millisecond)

        data2, err := os.ReadFile("/proc/stat")
        if err != nil {
                return 0
        }
        idle2, total2 := parseProcStat(string(data2))

        idleDelta := idle2 - idle1
        totalDelta := total2 - total1
        if totalDelta == 0 {
                return 0
        }
        return (1.0 - float64(idleDelta)/float64(totalDelta)) * 100.0
}

func parseProcStat(content string) (idle, total uint64) {
        lines := strings.Split(content, "\n")
        for _, line := range lines {
                if strings.HasPrefix(line, "cpu ") {
                        fields := strings.Fields(line)
                        if len(fields) < 5 {
                                return
                        }
                        for i := 1; i < len(fields); i++ {
                                val, _ := strconv.ParseUint(fields[i], 10, 64)
                                total += val
                                if i == 4 {
                                        idle = val
                                }
                        }
                        return
                }
        }
        return
}

func collectRAMUsageWindows() float64 {
        out, err := exec.Command("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/Value").Output()
        if err != nil {
                return 0
        }
        var freeKB, totalKB uint64
        for _, line := range strings.Split(string(out), "\n") {
                line = strings.TrimSpace(line)
                if strings.HasPrefix(line, "FreePhysicalMemory=") {
                        val := strings.TrimPrefix(line, "FreePhysicalMemory=")
                        freeKB, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
                }
                if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
                        val := strings.TrimPrefix(line, "TotalVisibleMemorySize=")
                        totalKB, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
                }
        }
        if totalKB == 0 {
                return 0
        }
        return float64(totalKB-freeKB) / float64(totalKB) * 100.0
}

func collectRAMUsageLinux() float64 {
        data, err := os.ReadFile("/proc/meminfo")
        if err != nil {
                return 0
        }
        total, free := parseMeminfo(string(data))
        if total == 0 {
                return 0
        }
        return float64(total-free) / float64(total) * 100.0
}

func collectRAMDetails() (totalMB, freeMB uint64) {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/Value").Output()
                if err != nil {
                        return
                }
                var freeKB, totalKB uint64
                for _, line := range strings.Split(string(out), "\n") {
                        line = strings.TrimSpace(line)
                        if strings.HasPrefix(line, "FreePhysicalMemory=") {
                                freeKB, _ = strconv.ParseUint(strings.TrimPrefix(line, "FreePhysicalMemory="), 10, 64)
                        }
                        if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
                                totalKB, _ = strconv.ParseUint(strings.TrimPrefix(line, "TotalVisibleMemorySize="), 10, 64)
                        }
                }
                return totalKB / 1024, freeKB / 1024
        }

        data, err := os.ReadFile("/proc/meminfo")
        if err != nil {
                return
        }
        total, free := parseMeminfo(string(data))
        return total / 1024, free / 1024
}

func parseMeminfo(content string) (totalKB, freeKB uint64) {
        var available uint64
        for _, line := range strings.Split(content, "\n") {
                fields := strings.Fields(line)
                if len(fields) < 2 {
                        continue
                }
                val, _ := strconv.ParseUint(fields[1], 10, 64)
                switch fields[0] {
                case "MemTotal:":
                        totalKB = val
                case "MemAvailable:":
                        available = val
                case "MemFree:":
                        if freeKB == 0 {
                                freeKB = val
                        }
                }
        }
        if available > 0 {
                freeKB = available
        }
        return
}

func collectTopProcesses(limit int) []string {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("tasklist", "/FO", "CSV", "/NH")
        } else {
                cmd = exec.Command("ps", "aux", "--sort=-pcpu")
        }

        out, err := cmd.Output()
        if err != nil {
                return nil
        }

        lines := strings.Split(strings.TrimSpace(string(out)), "\n")
        var result []string
        count := 0
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                if runtime.GOOS != "windows" && count == 0 {
                        count++
                        continue
                }
                if runtime.GOOS == "windows" {
                        parts := strings.Split(line, "\",\"")
                        if len(parts) > 0 {
                                name := strings.Trim(parts[0], "\"")
                                mem := ""
                                if len(parts) >= 5 {
                                        mem = strings.Trim(parts[4], "\" \r")
                                }
                                result = append(result, fmt.Sprintf("%s (Mem: %s)", name, mem))
                        }
                } else {
                        fields := strings.Fields(line)
                        if len(fields) >= 11 {
                                result = append(result, fmt.Sprintf("%s CPU:%s%% MEM:%s%%", fields[10], fields[2], fields[3]))
                        }
                }
                count++
                if len(result) >= limit {
                        break
                }
        }
        return result
}

func countNetConnections() int {
        var cmd *exec.Cmd
        if runtime.GOOS == "windows" {
                cmd = exec.Command("netstat", "-an")
        } else {
                cmd = exec.Command("ss", "-tun")
        }

        out, err := cmd.Output()
        if err != nil {
                return 0
        }

        lines := strings.Split(strings.TrimSpace(string(out)), "\n")
        count := 0
        for _, line := range lines {
                line = strings.TrimSpace(line)
                if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "ESTAB") {
                        count++
                }
        }
        return count
}

func collectDiskUsage() string {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("wmic", "logicaldisk", "get", "size,freespace,caption", "/Value").Output()
                if err != nil {
                        return "unknown"
                }
                var sb strings.Builder
                var caption, freeSpace, size string
                for _, line := range strings.Split(string(out), "\n") {
                        line = strings.TrimSpace(line)
                        if strings.HasPrefix(line, "Caption=") {
                                caption = strings.TrimPrefix(line, "Caption=")
                        }
                        if strings.HasPrefix(line, "FreeSpace=") {
                                freeSpace = strings.TrimPrefix(line, "FreeSpace=")
                        }
                        if strings.HasPrefix(line, "Size=") {
                                size = strings.TrimPrefix(line, "Size=")
                                if caption != "" && size != "" {
                                        totalBytes, _ := strconv.ParseUint(strings.TrimSpace(size), 10, 64)
                                        freeBytes, _ := strconv.ParseUint(strings.TrimSpace(freeSpace), 10, 64)
                                        if totalBytes > 0 {
                                                usedPct := float64(totalBytes-freeBytes) / float64(totalBytes) * 100
                                                sb.WriteString(fmt.Sprintf("%s %.1f%% used (%d GB / %d GB); ",
                                                        strings.TrimSpace(caption), usedPct, (totalBytes-freeBytes)/(1024*1024*1024), totalBytes/(1024*1024*1024)))
                                        }
                                }
                                caption, freeSpace, size = "", "", ""
                        }
                }
                result := sb.String()
                if result == "" {
                        return "unknown"
                }
                return result
        }

        out, err := exec.Command("df", "-h", "--output=target,pcent,size,avail", "/").Output()
        if err != nil {
                return "unknown"
        }
        lines := strings.Split(strings.TrimSpace(string(out)), "\n")
        if len(lines) >= 2 {
                return strings.TrimSpace(lines[1])
        }
        return "unknown"
}

func collectNetworkScanInfo() string {
        var sb strings.Builder
        sb.WriteString("=== Network Scan Report ===\n")

        sb.WriteString("\n--- Listening Ports ---\n")
        var listenCmd *exec.Cmd
        if runtime.GOOS == "windows" {
                listenCmd = exec.Command("netstat", "-an")
        } else {
                listenCmd = exec.Command("ss", "-tlnp")
        }
        if out, err := listenCmd.Output(); err == nil {
                lines := strings.Split(strings.TrimSpace(string(out)), "\n")
                count := 0
                for _, line := range lines {
                        if strings.Contains(line, "LISTEN") || strings.Contains(line, "LISTENING") {
                                sb.WriteString("  " + strings.TrimSpace(line) + "\n")
                                count++
                                if count >= 30 {
                                        sb.WriteString("  ... (truncated)\n")
                                        break
                                }
                        }
                }
        }

        sb.WriteString(fmt.Sprintf("\n--- Active Connections: %d ---\n", countNetConnections()))
        sb.WriteString(fmt.Sprintf("Local IP: %s\n", getLocalIP()))

        return sb.String()
}

func getSystemUptime() string {
        if runtime.GOOS == "windows" {
                out, err := exec.Command("wmic", "os", "get", "LastBootUpTime", "/Value").Output()
                if err != nil {
                        return "unknown"
                }
                for _, line := range strings.Split(string(out), "\n") {
                        line = strings.TrimSpace(line)
                        if strings.HasPrefix(line, "LastBootUpTime=") {
                                bootStr := strings.TrimPrefix(line, "LastBootUpTime=")
                                bootStr = strings.TrimSpace(bootStr)
                                if len(bootStr) >= 14 {
                                        bootTime, err := time.Parse("20060102150405", bootStr[:14])
                                        if err == nil {
                                                dur := time.Since(bootTime)
                                                days := int(dur.Hours() / 24)
                                                hours := int(dur.Hours()) % 24
                                                return fmt.Sprintf("%dd %dh", days, hours)
                                        }
                                }
                        }
                }
                return "unknown"
        }

        data, err := os.ReadFile("/proc/uptime")
        if err != nil {
                return "unknown"
        }
        fields := strings.Fields(string(data))
        if len(fields) == 0 {
                return "unknown"
        }
        secs, err := strconv.ParseFloat(fields[0], 64)
        if err != nil {
                return "unknown"
        }
        dur := time.Duration(secs) * time.Second
        days := int(dur.Hours() / 24)
        hours := int(dur.Hours()) % 24
        mins := int(dur.Minutes()) % 60
        return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
}
