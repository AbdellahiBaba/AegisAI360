package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type ARPEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

type ARPAlert struct {
	IP        string `json:"ip"`
	OldMAC    string `json:"oldMac"`
	NewMAC    string `json:"newMac"`
	AlertType string `json:"alertType"`
	Timestamp string `json:"timestamp"`
}

type ARPMonitorResult struct {
	Snapshot    []ARPEntry `json:"snapshot"`
	Alerts      []ARPAlert `json:"alerts"`
	MonitorTime string     `json:"monitorTime"`
	DeviceCount int        `json:"deviceCount"`
}

func getARPSnapshot() map[string]string {
	arpTable := make(map[string]string)

	if runtime.GOOS == "windows" {
		out, err := exec.Command("arp", "-a").Output()
		if err != nil {
			return arpTable
		}
		parseARPTableWindows(string(out), arpTable)
	} else {
		out, err := exec.Command("arp", "-a").Output()
		if err != nil {
			out, err = exec.Command("ip", "neigh").Output()
			if err != nil {
				return arpTable
			}
			parseARPTableLinuxIPNeigh(string(out), arpTable)
			return arpTable
		}
		parseARPTableUnix(string(out), arpTable)
	}

	return arpTable
}

func parseARPTableWindows(output string, arpTable map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ip := fields[0]
		mac := fields[1]
		if net.ParseIP(ip) == nil {
			continue
		}
		mac = strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
		if mac == "FF:FF:FF:FF:FF:FF" || mac == "00:00:00:00:00:00" {
			continue
		}
		if isMAC(strings.ToLower(mac)) || (len(mac) == 17 && strings.Count(mac, ":") == 5) {
			arpTable[ip] = mac
		}
	}
}

func parseARPTableUnix(output string, arpTable map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		for i, f := range fields {
			ip := ""
			if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
				ip = f[1 : len(f)-1]
			} else if net.ParseIP(f) != nil {
				ip = f
			}
			if ip == "" || net.ParseIP(ip) == nil {
				continue
			}
			for j := i + 1; j < len(fields); j++ {
				mac := strings.ToUpper(fields[j])
				if isMAC(strings.ToLower(mac)) {
					if mac != "FF:FF:FF:FF:FF:FF" && mac != "00:00:00:00:00:00" {
						arpTable[ip] = mac
					}
					break
				}
			}
			break
		}
	}
}

func parseARPTableLinuxIPNeigh(output string, arpTable map[string]string) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		for _, f := range fields {
			mac := strings.ToUpper(f)
			if isMAC(strings.ToLower(mac)) {
				if mac != "FF:FF:FF:FF:FF:FF" && mac != "00:00:00:00:00:00" {
					arpTable[ip] = mac
				}
				break
			}
		}
	}
}

func detectARPChanges(previous, current map[string]string) []ARPAlert {
	var alerts []ARPAlert
	now := time.Now().Format(time.RFC3339)

	for ip, newMAC := range current {
		oldMAC, existed := previous[ip]
		if !existed {
			alerts = append(alerts, ARPAlert{
				IP:        ip,
				OldMAC:    "",
				NewMAC:    newMAC,
				AlertType: "new_device",
				Timestamp: now,
			})
		} else if oldMAC != newMAC {
			alerts = append(alerts, ARPAlert{
				IP:        ip,
				OldMAC:    oldMAC,
				NewMAC:    newMAC,
				AlertType: "mac_change",
				Timestamp: now,
			})
		}
	}

	macToIPs := make(map[string][]string)
	for ip, mac := range current {
		macToIPs[mac] = append(macToIPs[mac], ip)
	}

	ipToMACs := make(map[string][]string)
	for ip, mac := range current {
		for otherIP, otherMAC := range current {
			if ip != otherIP && mac != otherMAC {
				continue
			}
			if ip != otherIP && mac == otherMAC {
				continue
			}
		}
		_ = ipToMACs
		_ = ip
		_ = mac
	}

	for _, ips := range macToIPs {
		if len(ips) > 1 {
			for _, ip := range ips {
				alerts = append(alerts, ARPAlert{
					IP:        ip,
					OldMAC:    current[ip],
					NewMAC:    current[ip],
					AlertType: "duplicate_ip",
					Timestamp: now,
				})
			}
		}
	}

	return alerts
}

func runARPMonitor() string {
	logMessage("INFO", "Starting ARP monitoring")

	snapshot1 := getARPSnapshot()

	time.Sleep(5 * time.Second)

	snapshot2 := getARPSnapshot()

	alerts := detectARPChanges(snapshot1, snapshot2)

	var entries []ARPEntry
	for ip, mac := range snapshot2 {
		entries = append(entries, ARPEntry{IP: ip, MAC: mac})
	}

	result := ARPMonitorResult{
		Snapshot:    entries,
		Alerts:      alerts,
		MonitorTime: time.Now().Format(time.RFC3339),
		DeviceCount: len(entries),
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to serialize ARP monitor results: %v"}`, err)
	}
	return string(jsonData)
}
