//go:build !windows

package main

import "fmt"

func runWindowsService() error {
	return fmt.Errorf("Windows Service mode is only supported on Windows")
}
