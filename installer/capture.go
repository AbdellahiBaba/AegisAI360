package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var suspiciousPorts = map[int]string{
	4444:  "Metasploit default",
	5555:  "Android debug / backdoor",
	1337:  "Common backdoor",
	31337: "Back Orifice",
	6666:  "IRC backdoor",
	6667:  "IRC C2",
	8443:  "Alt HTTPS / C2",
	9001:  "Tor default",
	9050:  "Tor SOCKS",
	9051:  "Tor control",
	1234:  "Common test backdoor",
	12345: "NetBus trojan",
	27374: "SubSeven trojan",
	3127:  "MyDoom backdoor",
	5900:  "VNC (if unexpected)",
}

type CaptureResult struct {
	Duration              int                `json:"duration"`
	PacketCount           int                `json:"packetCount"`
	ProtocolStats         map[string]int     `json:"protocolStats"`
	TopSourceIPs          map[string]int     `json:"topSourceIPs"`
	TopDestIPs            map[string]int     `json:"topDestIPs"`
	DNSQueries            []string           `json:"dnsQueries"`
	SuspiciousConnections []SuspiciousConn   `json:"suspiciousConnections"`
	CaptureTime           string             `json:"captureTime"`
}

type SuspiciousConn struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Reason      string `json:"reason"`
}

func captureTraffic(durationSec int) string {
	if durationSec <= 0 {
		durationSec = 10
	}
	if durationSec > 120 {
		durationSec = 120
	}

	logMessage("INFO", "Starting packet capture for %d seconds", durationSec)

	result := &CaptureResult{
		Duration:      durationSec,
		ProtocolStats: make(map[string]int),
		TopSourceIPs:  make(map[string]int),
		TopDestIPs:    make(map[string]int),
		DNSQueries:    []string{},
		SuspiciousConnections: []SuspiciousConn{},
		CaptureTime:   time.Now().Format(time.RFC3339),
	}

	if runtime.GOOS == "windows" {
		captureWindows(result, durationSec)
	} else {
		captureLinux(result, durationSec)
	}

	enrichWithNetstat(result)

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to serialize capture results: %v"}`, err)
	}
	return string(jsonData)
}

func captureWindows(result *CaptureResult, durationSec int) {
	cmd := exec.Command("netstat", "-an")
	out, err := cmd.Output()
	if err != nil {
		logMessage("WARN", "netstat failed: %v", err)
		return
	}

	parseNetstatForCapture(string(out), result)

	time.Sleep(time.Duration(durationSec) * time.Second)

	cmd2 := exec.Command("netstat", "-an")
	out2, err := cmd2.Output()
	if err == nil {
		parseNetstatForCapture(string(out2), result)
	}

	cmd3 := exec.Command("netstat", "-s")
	out3, err := cmd3.Output()
	if err == nil {
		parseNetstatStats(string(out3), result)
	}

	cmd4 := exec.Command("ipconfig", "/displaydns")
	out4, err := cmd4.Output()
	if err == nil {
		parseDNSCache(string(out4), result)
	}
}

func captureLinux(result *CaptureResult, durationSec int) {
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err == nil {
		cmd := exec.Command(tcpdumpPath, "-c", "1000", "-nn", "-q",
			"-w", "/dev/null",
			"-G", strconv.Itoa(durationSec),
			"-W", "1",
			"--immediate-mode")

		cmd2 := exec.Command(tcpdumpPath, "-c", "500", "-nn", "-q",
			fmt.Sprintf("-G%d", durationSec), "-W1")
		out, err := cmd2.CombinedOutput()
		if err == nil {
			parseTcpdumpOutput(string(out), result)
		} else {
			_ = cmd
			captureLinuxFallback(result, durationSec)
		}
	} else {
		captureLinuxFallback(result, durationSec)
	}
}

func captureLinuxFallback(result *CaptureResult, durationSec int) {
	cmd := exec.Command("ss", "-tunap")
	out, err := cmd.Output()
	if err != nil {
		cmd2 := exec.Command("netstat", "-tunap")
		out, err = cmd2.Output()
		if err != nil {
			return
		}
	}
	parseSSOutput(string(out), result)

	time.Sleep(time.Duration(durationSec) * time.Second)

	cmd3 := exec.Command("ss", "-tunap")
	out3, err := cmd3.Output()
	if err == nil {
		parseSSOutput(string(out3), result)
	}

	cmd4 := exec.Command("cat", "/proc/net/snmp")
	out4, err := cmd4.Output()
	if err == nil {
		parseProcNetSnmp(string(out4), result)
	}
}

func parseNetstatForCapture(output string, result *CaptureResult) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToUpper(fields[0])
		if proto != "TCP" && proto != "UDP" {
			continue
		}

		result.ProtocolStats[proto]++
		result.PacketCount++

		localAddr := fields[1]
		foreignAddr := fields[2]

		srcIP := extractIP(localAddr)
		dstIP := extractIP(foreignAddr)
		dstPort := extractPort(foreignAddr)

		if srcIP != "" && !isLocalhost(srcIP) {
			result.TopSourceIPs[srcIP]++
		}
		if dstIP != "" && !isLocalhost(dstIP) {
			result.TopDestIPs[dstIP]++
		}

		if reason, ok := suspiciousPorts[dstPort]; ok {
			result.SuspiciousConnections = append(result.SuspiciousConnections, SuspiciousConn{
				Source:      localAddr,
				Destination: foreignAddr,
				Port:        dstPort,
				Reason:      reason,
			})
		}
	}
}

func parseNetstatStats(output string, result *CaptureResult) {
	lines := strings.Split(output, "\n")
	currentProto := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasSuffix(trimmed, "Statistics") {
			parts := strings.Fields(trimmed)
			if len(parts) > 0 {
				currentProto = parts[0]
			}
		}
		if currentProto != "" && (strings.Contains(trimmed, "Received") || strings.Contains(trimmed, "Sent")) {
			parts := strings.Fields(trimmed)
			for _, p := range parts {
				if val, err := strconv.Atoi(strings.Replace(p, ",", "", -1)); err == nil && val > 0 {
					if result.ProtocolStats[currentProto] == 0 {
						result.ProtocolStats[currentProto] = val
					}
					break
				}
			}
		}
	}
}

func parseDNSCache(output string, result *CaptureResult) {
	lines := strings.Split(output, "\n")
	seen := make(map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Record Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				if name != "" && !seen[name] {
					seen[name] = true
					result.DNSQueries = append(result.DNSQueries, name)
					if len(result.DNSQueries) >= 50 {
						break
					}
				}
			}
		}
	}
}

func parseTcpdumpOutput(output string, result *CaptureResult) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		result.PacketCount++

		if strings.Contains(line, "IP") {
			result.ProtocolStats["TCP"]++
		}
		if strings.Contains(line, "UDP") {
			result.ProtocolStats["UDP"]++
		}
		if strings.Contains(line, "ICMP") {
			result.ProtocolStats["ICMP"]++
		}

		fields := strings.Fields(line)
		for _, f := range fields {
			if strings.Count(f, ".") >= 3 {
				ip := extractIPFromTcpdump(f)
				if ip != "" && !isLocalhost(ip) {
					result.TopSourceIPs[ip]++
				}
			}
		}
	}
}

func parseSSOutput(output string, result *CaptureResult) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToUpper(fields[0])
		if proto == "TCP" || proto == "UDP" {
			result.ProtocolStats[proto]++
			result.PacketCount++

			localAddr := fields[4]
			peerAddr := ""
			if len(fields) > 5 {
				peerAddr = fields[5]
			}

			srcIP := extractIP(localAddr)
			dstIP := extractIP(peerAddr)
			dstPort := extractPort(peerAddr)

			if srcIP != "" && !isLocalhost(srcIP) {
				result.TopSourceIPs[srcIP]++
			}
			if dstIP != "" && !isLocalhost(dstIP) {
				result.TopDestIPs[dstIP]++
			}

			if reason, ok := suspiciousPorts[dstPort]; ok {
				result.SuspiciousConnections = append(result.SuspiciousConnections, SuspiciousConn{
					Source:      localAddr,
					Destination: peerAddr,
					Port:        dstPort,
					Reason:      reason,
				})
			}
		}
	}
}

func parseProcNetSnmp(output string, result *CaptureResult) {
	lines := strings.Split(output, "\n")
	for i := 0; i < len(lines)-1; i += 2 {
		if strings.HasPrefix(lines[i], "Tcp:") && strings.HasPrefix(lines[i+1], "Tcp:") {
			vals := strings.Fields(lines[i+1])
			if len(vals) > 10 {
				if inSegs, err := strconv.Atoi(vals[10]); err == nil {
					result.ProtocolStats["TCP"] += inSegs
				}
			}
		}
		if strings.HasPrefix(lines[i], "Udp:") && strings.HasPrefix(lines[i+1], "Udp:") {
			vals := strings.Fields(lines[i+1])
			if len(vals) > 1 {
				if inDgrams, err := strconv.Atoi(vals[1]); err == nil {
					result.ProtocolStats["UDP"] += inDgrams
				}
			}
		}
		if strings.HasPrefix(lines[i], "Icmp:") && strings.HasPrefix(lines[i+1], "Icmp:") {
			vals := strings.Fields(lines[i+1])
			if len(vals) > 1 {
				if inMsgs, err := strconv.Atoi(vals[1]); err == nil {
					result.ProtocolStats["ICMP"] += inMsgs
				}
			}
		}
	}
}

func enrichWithNetstat(result *CaptureResult) {
	if result.PacketCount == 0 {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("netstat", "-an")
		} else {
			cmd = exec.Command("ss", "-tun")
		}
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "ESTABLISHED") || strings.Contains(line, "ESTAB") ||
					strings.Contains(line, "LISTEN") || strings.Contains(line, "TIME_WAIT") {
					result.PacketCount++
				}
			}
		}
	}
}

func extractIP(addr string) string {
	if addr == "" || addr == "*:*" || addr == "0.0.0.0:0" {
		return ""
	}
	if strings.HasPrefix(addr, "[") {
		return ""
	}
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 {
		return addr
	}
	return addr[:lastColon]
}

func extractPort(addr string) int {
	if addr == "" {
		return 0
	}
	lastColon := strings.LastIndex(addr, ":")
	if lastColon < 0 {
		return 0
	}
	port, err := strconv.Atoi(addr[lastColon+1:])
	if err != nil {
		return 0
	}
	return port
}

func extractIPFromTcpdump(field string) string {
	field = strings.TrimRight(field, ":")
	parts := strings.Split(field, ".")
	if len(parts) >= 4 {
		ip := strings.Join(parts[:4], ".")
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

func isLocalhost(ip string) bool {
	return ip == "127.0.0.1" || ip == "0.0.0.0" || ip == "::1" || ip == "*"
}
