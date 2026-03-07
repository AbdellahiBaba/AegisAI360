package main

import (
        "sync"
        "time"
)

type AgentStatus struct {
        mu            sync.RWMutex
        Connected     bool
        AgentID       float64
        Hostname      string
        IP            string
        ServerURL     string
        LastHeartbeat time.Time
        LastError     string
        CPUUsage      float64
        RAMUsage      float64
        Version       string
        Registered    bool
}

var globalStatus = &AgentStatus{}

func (s *AgentStatus) SetConnected(agentID float64, hostname, ip string, cpu, ram float64) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Connected = true
        s.AgentID = agentID
        s.Hostname = hostname
        s.IP = ip
        s.CPUUsage = cpu
        s.RAMUsage = ram
        s.LastHeartbeat = time.Now()
        s.LastError = ""
        s.Registered = true
}

func (s *AgentStatus) SetDisconnected(err string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.Connected = false
        s.LastError = err
}

func (s *AgentStatus) SetRegistered(agentID float64, hostname, ip, serverURL, version string) {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.AgentID = agentID
        s.Hostname = hostname
        s.IP = ip
        s.ServerURL = serverURL
        s.Version = version
        s.Registered = true
        s.LastError = "Waiting for first heartbeat"
}

func (s *AgentStatus) IsConnected() bool {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return s.Connected
}

func (s *AgentStatus) GetInfo() (connected bool, agentID float64, hostname, ip, serverURL, lastErr, version string, cpu, ram float64, lastHB time.Time) {
        s.mu.RLock()
        defer s.mu.RUnlock()
        return s.Connected, s.AgentID, s.Hostname, s.IP, s.ServerURL, s.LastError, s.Version, s.CPUUsage, s.RAMUsage, s.LastHeartbeat
}
