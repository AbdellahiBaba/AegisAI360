package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 8888,
	9090, 9200, 27017,
}

var portServiceNames = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
	1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
	5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
	8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
	9090: "Web-Admin", 9200: "Elasticsearch", 27017: "MongoDB",
}

var riskyPorts = map[int]string{
	23:    "Telnet - unencrypted remote access",
	21:    "FTP - unencrypted file transfer",
	445:   "SMB - common ransomware target",
	3389:  "RDP - common brute force target",
	5900:  "VNC - remote desktop exposure",
	6379:  "Redis - often unauthenticated",
	27017: "MongoDB - often unauthenticated",
	9200:  "Elasticsearch - often open",
	135:   "MSRPC - Windows RPC exposure",
	139:   "NetBIOS - legacy protocol exposure",
}

type VulnScanResult struct {
	Target     string       `json:"target"`
	ScanTime   string       `json:"scanTime"`
	OpenPorts  []PortResult `json:"openPorts"`
	RiskCount  int          `json:"riskCount"`
	TotalPorts int          `json:"totalPorts"`
}

type PortResult struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
	Risk    string `json:"risk"`
}

type NetworkScanResult struct {
	ScanTime    string           `json:"scanTime"`
	Hosts       []HostResult     `json:"hosts"`
	TotalHosts  int              `json:"totalHosts"`
	TotalOpen   int              `json:"totalOpen"`
	TotalRisks  int              `json:"totalRisks"`
}

type HostResult struct {
	IP        string       `json:"ip"`
	MAC       string       `json:"mac"`
	Hostname  string       `json:"hostname"`
	OpenPorts []PortResult `json:"openPorts"`
	RiskCount int          `json:"riskCount"`
}

func scanTarget(ip string, portRange string) string {
	if ip == "" {
		ip = getLocalIP()
	}

	if net.ParseIP(ip) == nil {
		return fmt.Sprintf(`{"error": "Invalid IP address: %s"}`, ip)
	}

	ports := commonPorts
	if portRange != "" {
		ports = parsePortRange(portRange)
	}

	result := &VulnScanResult{
		Target:     ip,
		ScanTime:   time.Now().Format(time.RFC3339),
		OpenPorts:  []PortResult{},
		TotalPorts: len(ports),
	}

	for _, port := range ports {
		pr := scanPort(ip, port)
		if pr.State == "open" {
			result.OpenPorts = append(result.OpenPorts, pr)
			if pr.Risk != "" {
				result.RiskCount++
			}
		}
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to serialize scan results: %v"}`, err)
	}
	return string(jsonData)
}

func scanLocalNetwork() string {
	logMessage("INFO", "Starting local network scan")

	hosts := discoverHosts()

	scanResult := &NetworkScanResult{
		ScanTime: time.Now().Format(time.RFC3339),
		Hosts:    []HostResult{},
	}

	topPorts := []int{22, 23, 80, 443, 445, 3389, 5900, 8080}

	for _, host := range hosts {
		hr := HostResult{
			IP:        host.IP,
			MAC:       host.MAC,
			Hostname:  host.Hostname,
			OpenPorts: []PortResult{},
		}

		for _, port := range topPorts {
			pr := scanPort(host.IP, port)
			if pr.State == "open" {
				hr.OpenPorts = append(hr.OpenPorts, pr)
				if pr.Risk != "" {
					hr.RiskCount++
					scanResult.TotalRisks++
				}
				scanResult.TotalOpen++
			}
		}

		scanResult.Hosts = append(scanResult.Hosts, hr)
	}

	scanResult.TotalHosts = len(scanResult.Hosts)

	jsonData, err := json.Marshal(scanResult)
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to serialize network scan: %v"}`, err)
	}
	return string(jsonData)
}

func scanPort(ip string, port int) PortResult {
	pr := PortResult{
		Port:    port,
		State:   "closed",
		Service: portServiceNames[port],
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return pr
	}
	defer conn.Close()

	pr.State = "open"

	if risk, ok := riskyPorts[port]; ok {
		pr.Risk = risk
	}

	pr.Banner = grabBanner(conn, port)

	return pr
}

func grabBanner(conn net.Conn, port int) string {
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	switch port {
	case 80, 8080, 8443, 8888, 9090:
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr().String())
	case 21:
		// FTP sends banner automatically
	case 22:
		// SSH sends banner automatically
	case 25:
		// SMTP sends banner automatically
	default:
		// Try reading whatever the server sends
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	banner := strings.TrimSpace(string(buf[:n]))
	if len(banner) > 200 {
		banner = banner[:200]
	}
	banner = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\r' {
			return '.'
		}
		return r
	}, banner)

	lines := strings.Split(banner, "\n")
	if len(lines) > 3 {
		banner = strings.Join(lines[:3], " | ")
	}

	return banner
}

type discoveredHost struct {
	IP       string
	MAC      string
	Hostname string
}

func discoverHosts() []discoveredHost {
	var hosts []discoveredHost
	seen := make(map[string]bool)

	if runtime.GOOS == "windows" {
		out, err := exec.Command("arp", "-a").Output()
		if err == nil {
			hosts = parseARPOutputForHosts(string(out), seen)
		}
	} else {
		out, err := exec.Command("arp", "-a").Output()
		if err == nil {
			hosts = parseARPOutputForHosts(string(out), seen)
		}
		out2, err := exec.Command("ip", "neigh").Output()
		if err == nil {
			for _, host := range parseIPNeighOutput(string(out2), seen) {
				hosts = append(hosts, host)
			}
		}
	}

	localIP := getLocalIP()
	if localIP != "127.0.0.1" && !seen[localIP] {
		hosts = append(hosts, discoveredHost{IP: localIP, Hostname: getHostname()})
	}

	return hosts
}

func parseARPOutputForHosts(output string, seen map[string]bool) []discoveredHost {
	var hosts []discoveredHost
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)

		for _, f := range fields {
			ip := net.ParseIP(f)
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() && !seen[f] {
				seen[f] = true
				host := discoveredHost{IP: f}
				for _, ff := range fields {
					if isMAC(ff) {
						host.MAC = strings.ToUpper(ff)
						break
					}
				}
				names, err := net.LookupAddr(f)
				if err == nil && len(names) > 0 {
					host.Hostname = strings.TrimSuffix(names[0], ".")
				}
				hosts = append(hosts, host)
				break
			}
		}
	}
	return hosts
}

func parseIPNeighOutput(output string, seen map[string]bool) []discoveredHost {
	var hosts []discoveredHost
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil || seen[ip] {
			continue
		}
		seen[ip] = true
		host := discoveredHost{IP: ip}
		for _, f := range fields {
			if isMAC(f) {
				host.MAC = strings.ToUpper(f)
				break
			}
		}
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			host.Hostname = strings.TrimSuffix(names[0], ".")
		}
		hosts = append(hosts, host)
	}
	return hosts
}

func isMAC(s string) bool {
	s = strings.ToLower(s)
	if len(s) == 17 && (strings.Count(s, ":") == 5 || strings.Count(s, "-") == 5) {
		return true
	}
	return false
}

func parsePortRange(portRange string) []int {
	var ports []int
	parts := strings.Split(portRange, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err1 == nil && err2 == nil && start > 0 && end <= 65535 {
				for p := start; p <= end && p-start < 1000; p++ {
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err == nil && p > 0 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	if len(ports) == 0 {
		return commonPorts
	}
	return ports
}
