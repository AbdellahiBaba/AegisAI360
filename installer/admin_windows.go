//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func isRunningAsAdmin() bool {
	cmd := exec.Command("net", "session")
	cmd.Stdout = nil
	cmd.Stderr = nil
	err := cmd.Run()
	return err == nil
}

func requestAdminElevation() bool {
	exePath, err := os.Executable()
	if err != nil {
		logMessage("ERROR", "Cannot determine executable path for elevation: %v", err)
		return false
	}

	var escapedArgs []string
	for _, arg := range os.Args[1:] {
		escaped := strings.ReplaceAll(arg, "'", "''")
		escapedArgs = append(escapedArgs, fmt.Sprintf("'%s'", escaped))
	}
	argList := strings.Join(escapedArgs, ",")

	logMessage("INFO", "Requesting admin elevation via UAC...")
	fmt.Println("  Requesting Administrator privileges...")

	psCmd := fmt.Sprintf(`Start-Process -FilePath '%s' -ArgumentList @(%s) -Verb RunAs`,
		strings.ReplaceAll(exePath, "'", "''"), argList)

	cmd := exec.Command("powershell", "-Command", psCmd)
	err = cmd.Run()
	if err != nil {
		logMessage("WARN", "UAC elevation failed or was declined: %v", err)
		return false
	}

	return true
}
