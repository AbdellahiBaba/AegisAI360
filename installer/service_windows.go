//go:build windows

package main

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
)

type aegisService struct{}

func (s *aegisService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	logMessage("INFO", "Windows Service starting via SCM...")

	cfg, err := loadConfig()
	if err != nil {
		logMessage("FATAL", "Service cannot start: no valid configuration: %v", err)
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	applyConfigToLogger(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agentDone := make(chan error, 1)
	go func() {
		agentDone <- runAgent(ctx, cfg)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	logMessage("INFO", "Windows Service reported RUNNING to SCM")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logMessage("INFO", "Windows Service received stop/shutdown command from SCM")
				changes <- svc.Status{State: svc.StopPending}
				cancel()

				select {
				case <-agentDone:
				case <-time.After(15 * time.Second):
					logMessage("WARN", "Agent did not stop within 15s, forcing exit")
				}

				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}

		case err := <-agentDone:
			if err != nil {
				logMessage("ERROR", "Agent exited with error: %v", err)
				changes <- svc.Status{State: svc.Stopped}
				return false, 1
			}
			logMessage("INFO", "Agent exited cleanly")
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

func runWindowsService() error {
	logMessage("INFO", "Starting as Windows Service via svc.Run...")
	err := svc.Run(serviceName, &aegisService{})
	if err != nil {
		return fmt.Errorf("Windows Service failed: %w", err)
	}
	return nil
}
