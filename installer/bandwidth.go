package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type InterfaceStats struct {
	Name     string  `json:"name"`
	BytesIn  uint64  `json:"bytesIn"`
	BytesOut uint64  `json:"bytesOut"`
	RateIn   float64 `json:"rateIn"`
	RateOut  float64 `json:"rateOut"`
}

type BandwidthResult struct {
	Interfaces  []InterfaceStats `json:"interfaces"`
	TotalIn     uint64           `json:"totalIn"`
	TotalOut    uint64           `json:"totalOut"`
	TotalRateIn float64          `json:"totalRateIn"`
	TotalRateOut float64         `json:"totalRateOut"`
	PollTime    string           `json:"pollTime"`
	Duration    float64          `json:"duration"`
}

func getBandwidthStats() string {
	logMessage("INFO", "Collecting bandwidth statistics")

	var snap1 map[string][2]uint64
	if runtime.GOOS == "windows" {
		snap1 = getInterfaceCountersWindows()
	} else {
		snap1 = getInterfaceCountersLinux()
	}

	pollInterval := 3 * time.Second
	time.Sleep(pollInterval)

	var snap2 map[string][2]uint64
	if runtime.GOOS == "windows" {
		snap2 = getInterfaceCountersWindows()
	} else {
		snap2 = getInterfaceCountersLinux()
	}

	seconds := pollInterval.Seconds()
	result := BandwidthResult{
		Interfaces: []InterfaceStats{},
		PollTime:   time.Now().Format(time.RFC3339),
		Duration:   seconds,
	}

	for name, counters2 := range snap2 {
		counters1, ok := snap1[name]
		if !ok {
			counters1 = [2]uint64{0, 0}
		}

		bytesIn := counters2[0]
		bytesOut := counters2[1]

		var deltaIn, deltaOut uint64
		if counters2[0] >= counters1[0] {
			deltaIn = counters2[0] - counters1[0]
		}
		if counters2[1] >= counters1[1] {
			deltaOut = counters2[1] - counters1[1]
		}

		rateIn := float64(deltaIn) / seconds
		rateOut := float64(deltaOut) / seconds

		iface := InterfaceStats{
			Name:     name,
			BytesIn:  bytesIn,
			BytesOut: bytesOut,
			RateIn:   rateIn,
			RateOut:  rateOut,
		}

		result.Interfaces = append(result.Interfaces, iface)
		result.TotalIn += bytesIn
		result.TotalOut += bytesOut
		result.TotalRateIn += rateIn
		result.TotalRateOut += rateOut
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error": "Failed to serialize bandwidth stats: %v"}`, err)
	}
	return string(jsonData)
}

func getInterfaceCountersLinux() map[string][2]uint64 {
	counters := make(map[string][2]uint64)

	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return counters
	}

	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i < 2 {
			continue
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}

		fields := strings.Fields(parts[1])
		if len(fields) < 10 {
			continue
		}

		bytesIn, _ := strconv.ParseUint(fields[0], 10, 64)
		bytesOut, _ := strconv.ParseUint(fields[8], 10, 64)

		if bytesIn > 0 || bytesOut > 0 {
			counters[name] = [2]uint64{bytesIn, bytesOut}
		}
	}

	return counters
}

func getInterfaceCountersWindows() map[string][2]uint64 {
	counters := make(map[string][2]uint64)

	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		out2, err2 := exec.Command("netstat", "-e").Output()
		if err2 == nil {
			parseNetstatE(string(out2), counters)
		}
		return counters
	}

	ifaceNames := parseInterfaceNames(string(out))

	for _, name := range ifaceNames {
		statsOut, err := exec.Command("netsh", "interface", "ipv4", "show", "subinterface", name).Output()
		if err != nil {
			continue
		}
		bytesIn, bytesOut := parseSubinterfaceStats(string(statsOut))
		if bytesIn > 0 || bytesOut > 0 {
			counters[name] = [2]uint64{bytesIn, bytesOut}
		}
	}

	if len(counters) == 0 {
		out2, err := exec.Command("netstat", "-e").Output()
		if err == nil {
			parseNetstatE(string(out2), counters)
		}
	}

	return counters
}

func parseInterfaceNames(output string) []string {
	var names []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) >= 5 {
			if _, err := strconv.Atoi(fields[0]); err == nil {
				name := strings.Join(fields[4:], " ")
				if name != "" && name != "Loopback Pseudo-Interface 1" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

func parseSubinterfaceStats(output string) (uint64, uint64) {
	var bytesIn, bytesOut uint64
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.Contains(lower, "bytes in") || strings.Contains(lower, "received") {
			for _, f := range fields {
				if val, err := strconv.ParseUint(f, 10, 64); err == nil && val > 0 {
					bytesIn = val
					break
				}
			}
		}
		if strings.Contains(lower, "bytes out") || strings.Contains(lower, "sent") {
			for _, f := range fields {
				if val, err := strconv.ParseUint(f, 10, 64); err == nil && val > 0 {
					bytesOut = val
					break
				}
			}
		}
	}
	return bytesIn, bytesOut
}

func parseNetstatE(output string, counters map[string][2]uint64) {
	lines := strings.Split(output, "\n")
	var bytesIn, bytesOut uint64
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.Contains(lower, "bytes") {
			val1, err1 := strconv.ParseUint(fields[1], 10, 64)
			val2, err2 := strconv.ParseUint(fields[2], 10, 64)
			if err1 == nil && err2 == nil {
				bytesIn = val1
				bytesOut = val2
			}
		}
	}
	if bytesIn > 0 || bytesOut > 0 {
		counters["default"] = [2]uint64{bytesIn, bytesOut}
	}
}
