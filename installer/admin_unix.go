//go:build !windows

package main

import (
	"fmt"
	"os"
)

func isRunningAsAdmin() bool {
	return os.Getuid() == 0
}

func requestAdminElevation() bool {
	fmt.Println("  On Linux/macOS, run the agent with sudo:")
	fmt.Println("    sudo ./AegisAI360-Agent")
	return false
}
