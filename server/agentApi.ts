import { Router } from "express";
import { z } from "zod";
import { randomBytes, createHash } from "crypto";
import fs from "fs";
import path from "path";
import { storage } from "./storage";
import { requireAuth, requireRole, requirePlanFeature } from "./auth";
import type { User, InsertPacketCapture, InsertArpAlert, InsertBandwidthLog } from "@shared/schema";
import { parseRogueScanToDevices, type RogueScanResult } from "./networkMonitor";

const TERMINAL_WHITELIST_LINUX = ["whoami", "ifconfig", "ip a", "ip addr", "netstat", "ss", "ps aux", "ps -ef", "ls", "cat /etc/os-release", "uname -a", "df -h", "free -m", "uptime", "hostname", "w", "last", "top -bn1"];
const TERMINAL_WHITELIST_WINDOWS = ["whoami", "ipconfig", "netstat", "tasklist", "dir", "systeminfo", "hostname", "ver"];
const BLOCKED_PATTERNS = ["rm ", "rm -", "del ", "format", "shutdown", "reboot", "halt", "mkfs", "dd ", "fdisk", "wget ", "curl ", "chmod ", "chown ", "sudo ", "su ", "passwd", "> /dev", "| bash", "| sh", "eval ", "exec ", "kill ", "killall", "pkill"];
const COMMAND_SEPARATORS = [";", "&&", "||", "|", "`", "$(", "${", "\n", "\r"];

function getOrgId(req: any): number {
  return (req.user as User).organizationId!;
}

function getUserId(req: any): string {
  return (req.user as User).id;
}

function isCommandAllowed(command: string): { allowed: boolean; reason?: string } {
  const cmd = command.trim().toLowerCase();
  for (const sep of COMMAND_SEPARATORS) {
    if (cmd.includes(sep)) return { allowed: false, reason: `Command chaining/piping is not allowed` };
  }
  for (const blocked of BLOCKED_PATTERNS) {
    if (cmd.includes(blocked)) return { allowed: false, reason: `Blocked pattern: ${blocked.trim()}` };
  }
  const baseCmd = cmd.split(/\s+/)[0];
  const allAllowed = [...TERMINAL_WHITELIST_LINUX, ...TERMINAL_WHITELIST_WINDOWS].map(c => c.split(/\s+/)[0]);
  if (!allAllowed.includes(baseCmd)) return { allowed: false, reason: `Command not in whitelist: ${baseCmd}` };
  return { allowed: true };
}

export function createAgentRouter(): Router {
  const router = Router();

  router.get("/ping", (_req, res) => {
    res.json({ status: "ok", timestamp: Date.now(), version: "1.1.0" });
  });

  router.get("/supported-commands", requireAuth, (_req, res) => {
    res.json({
      version: "1.1.0",
      categories: [
        {
          name: "System",
          commands: [
            { command: "ping", description: "Test agent connectivity", params: [] },
            { command: "get_info", description: "Get full system information", params: [] },
            { command: "run_system_scan", description: "Run comprehensive system scan", params: [] },
            { command: "security_scan", description: "Deep security audit (ports, users, firewall, AV, patches)", params: [] },
            { command: "disk_usage", description: "Get disk usage for all drives", params: [] },
            { command: "env_vars", description: "List all environment variables", params: [] },
            { command: "restart", description: "Restart the agent service", params: [] },
            { command: "update", description: "Check for agent updates", params: [] },
          ],
        },
        {
          name: "WiFi & Network",
          commands: [
            { command: "wifi_list", description: "Scan and list all visible WiFi networks", params: [] },
            { command: "wifi_profiles", description: "Show saved WiFi profiles with passwords", params: [] },
            { command: "wifi_connect", description: "Connect to a WiFi network", params: [{ name: "ssid", type: "string", required: true, description: "WiFi network name" }] },
            { command: "wifi_disconnect", description: "Disconnect from current WiFi", params: [] },
            { command: "network_interfaces", description: "List all network adapters with IP/MAC", params: [] },
            { command: "network_connections", description: "Show active network connections", params: [] },
            { command: "network_dns", description: "Show DNS servers and cache", params: [] },
            { command: "network_arp", description: "Show ARP table (devices on local network)", params: [] },
            { command: "network_route", description: "Show routing table", params: [] },
            { command: "network_scan", description: "Full network scan (ports, connections, IP)", params: [] },
          ],
        },
        {
          name: "Firewall",
          commands: [
            { command: "network_firewall_rules", description: "List all firewall rules", params: [{ name: "filter", type: "string", required: false, description: "Filter by rule name" }] },
            { command: "network_firewall_add", description: "Add a firewall rule", params: [
              { name: "name", type: "string", required: true, description: "Rule name" },
              { name: "direction", type: "string", required: true, description: "in or out" },
              { name: "action", type: "string", required: true, description: "block or allow" },
              { name: "port", type: "string", required: false, description: "Port number" },
              { name: "protocol", type: "string", required: false, description: "tcp or udp (default: tcp)" },
            ]},
            { command: "network_firewall_remove", description: "Remove a firewall rule", params: [{ name: "name", type: "string", required: true, description: "Rule name to remove" }] },
          ],
        },
        {
          name: "Processes & Services",
          commands: [
            { command: "process_list", description: "List all running processes with details", params: [] },
            { command: "process_kill", description: "Kill a process by PID or name", params: [
              { name: "pid", type: "number", required: false, description: "Process ID" },
              { name: "name", type: "string", required: false, description: "Process name" },
            ]},
            { command: "service_list", description: "List all system services", params: [] },
            { command: "service_control", description: "Start, stop, or restart a service", params: [
              { name: "name", type: "string", required: true, description: "Service name" },
              { name: "action", type: "string", required: true, description: "start, stop, or restart" },
            ]},
          ],
        },
        {
          name: "Users & Sessions",
          commands: [
            { command: "user_list", description: "List all local user accounts", params: [] },
            { command: "user_sessions", description: "Show active login sessions", params: [] },
          ],
        },
        {
          name: "Software & Tasks",
          commands: [
            { command: "installed_software", description: "List all installed programs", params: [] },
            { command: "startup_programs", description: "List programs that run at startup", params: [] },
            { command: "scheduled_tasks", description: "List all scheduled tasks", params: [] },
          ],
        },
        {
          name: "Files & Registry",
          commands: [
            { command: "file_scan", description: "Scan common malware drop locations for suspicious executables", params: [] },
            { command: "file_search", description: "Search for files by pattern", params: [
              { name: "path", type: "string", required: false, description: "Search path (default: C:\\)" },
              { name: "pattern", type: "string", required: true, description: "File pattern (e.g. *.exe)" },
              { name: "maxResults", type: "number", required: false, description: "Max results (default: 50)" },
            ]},
            { command: "file_hash", description: "Get SHA256 hash of a file", params: [{ name: "path", type: "string", required: true, description: "Full file path" }] },
            { command: "registry_query", description: "Query a Windows registry key", params: [{ name: "key", type: "string", required: true, description: "Registry key path" }] },
          ],
        },
        {
          name: "Logs & Events",
          commands: [
            { command: "event_log", description: "Query Windows Event Log", params: [
              { name: "log", type: "string", required: false, description: "Log name: System, Application, Security (default: System)" },
              { name: "count", type: "number", required: false, description: "Number of entries (default: 50)" },
            ]},
          ],
        },
        {
          name: "Traffic & Monitoring",
          commands: [
            { command: "packet_capture", description: "Capture and analyze network traffic (Wireshark-style)", params: [
              { name: "duration", type: "number", required: false, description: "Capture duration in seconds (default: 10, max: 60)" },
            ]},
            { command: "arp_monitor", description: "Scan ARP table for spoofing and rogue devices", params: [] },
            { command: "bandwidth_stats", description: "Get per-interface bandwidth usage statistics", params: [] },
            { command: "rogue_scan", description: "Discover and identify all devices on local network", params: [] },
            { command: "vuln_scan", description: "Scan a target IP for open ports and vulnerabilities", params: [
              { name: "target", type: "string", required: false, description: "Target IP (default: local subnet scan)" },
              { name: "portRange", type: "string", required: false, description: "Port range e.g. 1-1024 (default: top 100)" },
            ]},
            { command: "honeypot_monitor", description: "Monitor bait ports for connection attempts (honeypot)", params: [
              { name: "ports", type: "string", required: false, description: "Comma-separated ports to monitor (default: 23,445,1433,3389,5900,8080)" },
              { name: "duration", type: "number", required: false, description: "Duration in seconds to monitor (default: 300, max: 3600)" },
            ]},
          ],
        },
        {
          name: "Terminal",
          commands: [
            { command: "enable_monitoring", description: "Enable background monitoring (process, file, network)", params: [] },
            { command: "disable_monitoring", description: "Disable background monitoring", params: [] },
            { command: "terminal_exec", description: "Execute a whitelisted terminal command", params: [{ name: "cmd", type: "string", required: true, description: "Command to execute" }] },
          ],
        },
      ],
    });
  });

  router.post("/device-token/create", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });

      const user = req.user as User;
      if (!user.isSuperAdmin && org.planId) {
        const plan = await storage.getPlanById(org.planId);
        if (plan) {
          const existingAgents = await storage.getAgentsByOrg(orgId);
          if (existingAgents.length >= plan.maxAgents) {
            return res.status(403).json({ error: `Agent limit reached (${plan.maxAgents}). Upgrade your plan.` });
          }
        }
      }

      const token = `agt_${randomBytes(32).toString("hex")}`;
      const dt = await storage.createDeviceToken({ organizationId: orgId, token });
      res.status(201).json({ token: dt.token, id: dt.id });
    } catch (error) {
      res.status(500).json({ error: "Failed to create device token" });
    }
  });

  router.get("/device-tokens", requireAuth, async (req, res) => {
    try {
      const tokens = await storage.getDeviceTokensByOrg(getOrgId(req));
      res.json(tokens);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch device tokens" });
    }
  });

  router.post("/register", async (req, res) => {
    try {
      const { token, hostname, os, ip } = z.object({
        token: z.string().min(1),
        hostname: z.string().min(1),
        os: z.string().optional(),
        ip: z.string().optional(),
      }).parse(req.body);

      const dt = await storage.getDeviceToken(token);
      if (!dt) return res.status(401).json({ error: "Invalid device token" });

      if (dt.used) {
        if (dt.usedByAgentId) {
          const existingAgent = await storage.getAgentById(dt.usedByAgentId);
          if (existingAgent && existingAgent.deviceToken === token) {
            await storage.updateAgentStatus(existingAgent.id, "online");
            await storage.updateAgentHeartbeat(existingAgent.id, {
              lastSeen: new Date(),
              ip: ip || undefined,
            });
            return res.status(201).json({ agentId: existingAgent.id, status: "reconnected" });
          }
        }

        const orgAgents = await storage.getAgentsByOrg(dt.organizationId);
        const matchingAgent = orgAgents.find(a => a.deviceToken === token);
        if (matchingAgent) {
          await storage.updateAgentStatus(matchingAgent.id, "online");
          await storage.updateAgentHeartbeat(matchingAgent.id, {
            lastSeen: new Date(),
            ip: ip || undefined,
          });
          return res.status(201).json({ agentId: matchingAgent.id, status: "reconnected" });
        }
      }

      const agent = await storage.createAgent({
        organizationId: dt.organizationId,
        deviceToken: token,
        hostname,
        os: os || null,
        ip: ip || null,
        status: "online",
        cpuUsage: null,
        ramUsage: null,
      });

      if (!dt.used) {
        await storage.markTokenUsed(dt.id, agent.id);
        await storage.incrementUsage(dt.organizationId, "agentsRegistered");
      }
      res.status(201).json({ agentId: agent.id, status: "registered" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to register agent" });
    }
  });

  router.post("/heartbeat", async (req, res) => {
    try {
      const { agentId, token, cpuUsage, ramUsage, ip } = z.object({
        agentId: z.number(),
        token: z.string(),
        cpuUsage: z.number().optional(),
        ramUsage: z.number().optional(),
        ip: z.string().optional(),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      await storage.updateAgentHeartbeat(agentId, {
        lastSeen: new Date(),
        cpuUsage: cpuUsage ?? undefined,
        ramUsage: ramUsage ?? undefined,
        ip: ip ?? undefined,
      });

      res.json({ status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Heartbeat failed" });
    }
  });

  router.post("/logs", async (req, res) => {
    try {
      const { agentId, token, logs } = z.object({
        agentId: z.number(),
        token: z.string(),
        logs: z.array(z.object({
          eventType: z.string(),
          severity: z.string().default("info"),
          description: z.string(),
          source: z.string().default("agent"),
          sourceIp: z.string().optional(),
          rawData: z.string().optional(),
        })),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const org = await storage.getOrganization(agent.organizationId);
      if (org?.planId) {
        const plan = await storage.getPlanById(org.planId);
        const usage = await storage.getUsageForToday(agent.organizationId);
        if (plan && usage && usage.logsSent + logs.length > plan.maxLogsPerDay) {
          return res.status(429).json({ error: "Daily log limit exceeded" });
        }
      }

      for (const log of logs) {
        await storage.createSecurityEvent({
          organizationId: agent.organizationId,
          eventType: log.eventType,
          severity: log.severity,
          source: log.source,
          description: log.description,
          sourceIp: log.sourceIp || agent.ip || null,
          rawData: log.rawData || null,
          status: "new",
        });
        await storage.incrementUsage(agent.organizationId, "logsSent");
      }

      res.json({ accepted: logs.length });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to ingest logs" });
    }
  });

  router.post("/telemetry", async (req, res) => {
    try {
      const { agentId, token, hostname, os, cpuUsage, ramUsage, ramTotalMB, ramFreeMB, cpus, uptime, agentVersion, topProcesses, netConnections, diskUsage, localIP, arch } = z.object({
        agentId: z.number(),
        token: z.string(),
        hostname: z.string().optional(),
        os: z.string().optional(),
        arch: z.string().optional(),
        cpuUsage: z.number().optional(),
        ramUsage: z.number().optional(),
        ramTotalMB: z.number().optional(),
        ramFreeMB: z.number().optional(),
        cpus: z.number().optional(),
        uptime: z.string().optional(),
        agentVersion: z.string().optional(),
        topProcesses: z.array(z.string()).optional(),
        netConnections: z.number().optional(),
        diskUsage: z.string().optional(),
        localIP: z.string().optional(),
        timestamp: z.string().optional(),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const telemetryData: any = {};
      if (hostname !== undefined) telemetryData.hostname = hostname;
      if (os !== undefined) telemetryData.os = os;
      if (arch !== undefined) telemetryData.arch = arch;
      if (cpuUsage !== undefined) telemetryData.cpuUsage = cpuUsage;
      if (ramUsage !== undefined) telemetryData.ramUsage = ramUsage;
      if (ramTotalMB !== undefined) telemetryData.ramTotalMB = ramTotalMB;
      if (ramFreeMB !== undefined) telemetryData.ramFreeMB = ramFreeMB;
      if (cpus !== undefined) telemetryData.cpus = cpus;
      if (uptime !== undefined) telemetryData.uptime = uptime;
      if (agentVersion !== undefined) telemetryData.agentVersion = agentVersion;
      if (topProcesses !== undefined) telemetryData.topProcesses = topProcesses;
      if (netConnections !== undefined) telemetryData.netConnections = netConnections;
      if (diskUsage !== undefined) telemetryData.diskUsage = diskUsage;
      if (localIP !== undefined) telemetryData.localIP = localIP;
      telemetryData.lastUpdated = new Date().toISOString();

      await storage.updateAgentHeartbeat(agentId, {
        lastSeen: new Date(),
        cpuUsage: cpuUsage ?? undefined,
        ramUsage: ramUsage ?? undefined,
        ip: localIP ?? undefined,
        telemetry: telemetryData,
      });

      res.json({ status: "ok" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Telemetry ingestion failed" });
    }
  });

  router.get("/version", (req, res) => {
    const currentVersion = req.query.version as string || "0.0.0";
    const latestVersion = "1.1.0";
    const needsUpdate = currentVersion !== latestVersion;

    let downloadUrl = "";
    let checksum = "";

    if (needsUpdate) {
      const host = req.get("host") || "aegisai360.com";
      const protocol = req.protocol === "https" || req.get("x-forwarded-proto") === "https" ? "https" : "https";
      downloadUrl = `${protocol}://${host}/downloads/AegisAI360-Agent.exe`;

      try {
        const searchPaths = [
          path.resolve(process.cwd(), "public", "downloads", "AegisAI360-Agent.exe"),
          path.resolve("public", "downloads", "AegisAI360-Agent.exe"),
        ];
        for (const exePath of searchPaths) {
          if (fs.existsSync(exePath)) {
            const fileBuffer = fs.readFileSync(exePath);
            checksum = createHash("sha256").update(fileBuffer).digest("hex");
            break;
          }
        }
      } catch (e) {
        checksum = "";
      }
    }

    res.json({ version: latestVersion, downloadUrl, checksum });
  });

  router.get("/commands", async (req, res) => {
    try {
      const { agentId, token } = z.object({
        agentId: z.coerce.number(),
        token: z.string(),
      }).parse(req.query);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const commands = await storage.getPendingCommands(agentId);
      res.json(commands);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch commands" });
    }
  });

  router.post("/command-result", async (req, res) => {
    try {
      const { commandId, agentId, token, status, result } = z.object({
        commandId: z.number(),
        agentId: z.number(),
        token: z.string(),
        status: z.enum(["done", "failed"]),
        result: z.string().optional(),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const existingCmd = await storage.getCommandById(commandId);
      if (!existingCmd || existingCmd.agentId !== agentId) return res.status(403).json({ error: "Command does not belong to this agent" });

      await storage.updateCommandStatus(commandId, { status, result: result || null, executedAt: new Date() });

      if (existingCmd.command === "rogue_scan" && status === "done" && result) {
        try {
          const scanResult: RogueScanResult = JSON.parse(result);
          if (scanResult.hosts && Array.isArray(scanResult.hosts)) {
            const orgId = agent.organizationId;
            const devices = parseRogueScanToDevices(orgId, scanResult);

            let created = 0;
            let updated = 0;
            for (const device of devices) {
              const existing = await storage.getNetworkDeviceByMac(orgId, device.macAddress);
              if (existing) {
                await storage.updateNetworkDevice(existing.id, {
                  ipAddress: device.ipAddress,
                  hostname: device.hostname || existing.hostname,
                  status: "online",
                  lastSeen: new Date(),
                  os: device.os || existing.os,
                  deviceType: device.deviceType !== "unknown" ? device.deviceType : existing.deviceType,
                });
                updated++;
              } else {
                await storage.createNetworkDevice(device);
                created++;
              }
            }

            let scanId: number | null = null;
            if (existingCmd.params) {
              try {
                const params = JSON.parse(existingCmd.params);
                if (params.scanId) scanId = params.scanId;
              } catch {}
            }

            if (scanId) {
              const existingDevices = await storage.getNetworkDevices(orgId);
              const unauthorizedCount = existingDevices.filter(d => d.authorization === "unauthorized").length;
              await storage.updateNetworkScan(scanId, {
                status: "completed",
                devicesFound: existingDevices.length,
                unauthorizedCount,
                completedAt: new Date(),
                results: { newDevices: created, updatedDevices: updated, totalHosts: scanResult.totalHosts, source: "agent" },
              });
            }

            if (created > 0) {
              await storage.createSecurityEvent({
                organizationId: orgId,
                eventType: "network_scan_complete",
                severity: "info",
                source: "agent-rogue-scan",
                description: `Agent rogue scan discovered ${created} new device(s) and updated ${updated} existing device(s) on the network`,
                sourceIp: agent.ip || "agent",
                status: "new",
              });
            }
          }
        } catch (parseErr) {
          console.error("Failed to parse rogue_scan results:", parseErr);
        }
      }

      res.json({ status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Failed to update command result" });
    }
  });

  router.post("/packet-capture", async (req, res) => {
    try {
      const { agentId, token, captureData, duration, packetCount } = z.object({
        agentId: z.number(),
        token: z.string(),
        captureData: z.any(),
        duration: z.number(),
        packetCount: z.number(),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const capture = await storage.createPacketCapture({
        agentId,
        organizationId: agent.organizationId,
        captureData,
        duration,
        packetCount,
      });
      res.status(201).json({ id: capture.id, status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Failed to store packet capture" });
    }
  });

  router.post("/arp-alerts", async (req, res) => {
    try {
      const { agentId, token, alerts } = z.object({
        agentId: z.number(),
        token: z.string(),
        alerts: z.array(z.object({
          ip: z.string(),
          oldMac: z.string().optional(),
          newMac: z.string(),
          alertType: z.string(),
        })),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const created = [];
      for (const alert of alerts) {
        const a = await storage.createArpAlert({
          agentId,
          organizationId: agent.organizationId,
          ip: alert.ip,
          oldMac: alert.oldMac || null,
          newMac: alert.newMac,
          alertType: alert.alertType,
        });
        created.push(a.id);
      }
      res.status(201).json({ ids: created, status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Failed to store ARP alerts" });
    }
  });

  router.post("/bandwidth", async (req, res) => {
    try {
      const { agentId, token, interfaces } = z.object({
        agentId: z.number(),
        token: z.string(),
        interfaces: z.array(z.object({
          interfaceName: z.string(),
          bytesIn: z.number(),
          bytesOut: z.number(),
        })),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      for (const iface of interfaces) {
        await storage.createBandwidthLog({
          agentId,
          organizationId: agent.organizationId,
          interfaceName: iface.interfaceName,
          bytesIn: iface.bytesIn,
          bytesOut: iface.bytesOut,
        });
      }
      res.json({ status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Failed to store bandwidth data" });
    }
  });

  router.post("/send-command", requireAuth, async (req, res) => {
    try {
      const { agentId, command, params } = z.object({
        agentId: z.number(),
        command: z.string(),
        params: z.string().optional(),
      }).parse(req.body);

      const orgId = getOrgId(req);
      const user = req.user as User;
      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.organizationId !== orgId) return res.status(404).json({ error: "Agent not found" });

      if (!user.isSuperAdmin) {
        const org = await storage.getOrganization(orgId);
        if (org?.planId) {
          const plan = await storage.getPlanById(org.planId);
          if (plan) {
            if (command === "kill_process" && !plan.allowProcessKill) {
              return res.status(403).json({ error: "Process kill not available on your plan" });
            }
            if ((command === "isolate_network" || command === "restore_network") && !plan.allowNetworkIsolation) {
              return res.status(403).json({ error: "Network isolation not available on your plan" });
            }
          }
        }
      }

      const cmd = await storage.createCommand({ agentId, command, params: params || null, status: "pending" });
      await storage.incrementUsage(orgId, "commandsExecuted");
      res.status(201).json(cmd);
    } catch (error) {
      res.status(500).json({ error: "Failed to send command" });
    }
  });

  router.get("/list", requireAuth, async (req, res) => {
    try {
      const agents = await storage.getAgentsByOrg(getOrgId(req));
      res.json(agents);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch agents" });
    }
  });

  router.get("/:id", requireAuth, async (req, res) => {
    try {
      const agent = await storage.getAgentById(parseInt(req.params.id));
      if (!agent || agent.organizationId !== getOrgId(req)) return res.status(404).json({ error: "Agent not found" });
      res.json(agent);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch agent" });
    }
  });

  router.get("/:id/commands", requireAuth, async (req, res) => {
    try {
      const agent = await storage.getAgentById(parseInt(req.params.id));
      if (!agent || agent.organizationId !== getOrgId(req)) return res.status(404).json({ error: "Agent not found" });
      const commands = await storage.getCommandsByAgent(agent.id);
      res.json(commands);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch commands" });
    }
  });

  router.post("/terminal/execute", requireAuth, async (req, res) => {
    try {
      const { agentId, command } = z.object({
        agentId: z.number(),
        command: z.string().min(1).max(500),
      }).parse(req.body);

      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const user = req.user as User;

      if (!user.isSuperAdmin) {
        const org = await storage.getOrganization(orgId);
        if (org?.planId) {
          const plan = await storage.getPlanById(org.planId);
          if (plan && !plan.allowTerminalAccess) {
            return res.status(403).json({ error: "Terminal access not available on your plan" });
          }
        }
      }

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.organizationId !== orgId) return res.status(404).json({ error: "Agent not found" });

      const check = isCommandAllowed(command);
      if (!check.allowed) return res.status(403).json({ error: check.reason });

      const cmd = await storage.createCommand({
        agentId,
        command: "terminal_exec",
        params: JSON.stringify({ cmd: command }),
        status: "pending",
      });

      await storage.createTerminalLog({ userId, organizationId: orgId, agentId, command, output: null });
      await storage.incrementUsage(orgId, "terminalCommandsExecuted");

      res.status(201).json({ commandId: cmd.id, status: "pending" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to execute terminal command" });
    }
  });

  router.get("/:id/terminal-logs", requireAuth, async (req, res) => {
    try {
      const agentId = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const logs = await storage.getTerminalLogsByAgent(agentId, orgId);
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch terminal logs" });
    }
  });

  router.post("/security-events", async (req, res) => {
    try {
      const { agentId, token, events } = z.object({
        agentId: z.number(),
        token: z.string(),
        events: z.array(z.object({
          eventType: z.string(),
          severity: z.string().default("medium"),
          description: z.string(),
          source: z.string().default("agent-monitor"),
          sourceIp: z.string().optional(),
          rawData: z.string().optional(),
        })),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const created = [];
      for (const event of events) {
        const se = await storage.createSecurityEvent({
          organizationId: agent.organizationId,
          eventType: event.eventType,
          severity: event.severity,
          source: event.source,
          description: event.description,
          sourceIp: event.sourceIp || agent.ip || null,
          rawData: event.rawData || null,
          status: "new",
        });
        created.push(se.id);
        await storage.incrementUsage(agent.organizationId, "logsSent");
      }

      res.status(201).json({ ids: created, status: "ok" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to store security events" });
    }
  });

  router.post("/file-scan", async (req, res) => {
    try {
      const { agentId, token, report } = z.object({
        agentId: z.number(),
        token: z.string(),
        report: z.object({
          scannedDirs: z.array(z.string()).optional(),
          totalFiles: z.number().optional(),
          executables: z.number().optional(),
          recentFiles: z.number().optional(),
          suspiciousFiles: z.number().optional(),
          files: z.array(z.object({
            path: z.string(),
            size: z.number(),
            sha256: z.string().optional(),
            modifiedAt: z.string().optional(),
            isRecent: z.boolean().optional(),
            isSuspicious: z.boolean().optional(),
            reason: z.string().optional(),
          })).optional(),
          scanTime: z.string().optional(),
          duration: z.string().optional(),
        }),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const suspiciousFiles = report.files?.filter(f => f.isSuspicious) || [];
      if (suspiciousFiles.length > 0) {
        for (const file of suspiciousFiles) {
          await storage.createSecurityEvent({
            organizationId: agent.organizationId,
            eventType: "suspicious_file_detected",
            severity: "high",
            source: "agent-file-scan",
            description: `Suspicious file detected: ${file.path} - ${file.reason || "Unknown reason"}`,
            sourceIp: agent.ip || null,
            rawData: JSON.stringify(file),
            status: "new",
          });
        }
      }

      await storage.createSecurityEvent({
        organizationId: agent.organizationId,
        eventType: "file_scan_complete",
        severity: suspiciousFiles.length > 0 ? "warning" : "info",
        source: "agent-file-scan",
        description: `File scan completed on ${agent.hostname}: ${report.totalFiles || 0} files scanned, ${report.executables || 0} executables, ${report.suspiciousFiles || 0} suspicious`,
        sourceIp: agent.ip || null,
        rawData: JSON.stringify(report),
        status: "new",
      });

      res.status(201).json({ status: "ok", suspiciousCount: suspiciousFiles.length });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to process file scan results" });
    }
  });

  router.post("/honeypot-events", async (req, res) => {
    try {
      const { agentId, token, events } = z.object({
        agentId: z.number(),
        token: z.string(),
        events: z.array(z.object({
          sourceIp: z.string(),
          sourcePort: z.number(),
          targetPort: z.number(),
          protocol: z.string().default("tcp"),
          payload: z.string().optional(),
          timestamp: z.string().optional(),
        })),
      }).parse(req.body);

      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.deviceToken !== token) return res.status(401).json({ error: "Invalid agent credentials" });

      const portServiceMap: Record<number, string> = {
        23: "telnet",
        445: "smb",
        1433: "mssql",
        3389: "rdp",
        5900: "vnc",
        8080: "http-proxy",
      };

      const created = [];
      for (const event of events) {
        const serviceName = portServiceMap[event.targetPort] || `port-${event.targetPort}`;
        const honeypotEvent = await storage.createHoneypotEvent({
          organizationId: agent.organizationId,
          honeypotName: `agent-${agentId}-${serviceName}`,
          attackerIp: event.sourceIp,
          service: serviceName,
          action: `connection_attempt:${event.protocol}/${event.targetPort}`,
          payload: event.payload || null,
          country: null,
          sessionId: `agent-${agentId}-${Date.now()}`,
        });
        created.push(honeypotEvent.id);
      }

      res.status(201).json({ ids: created, status: "ok" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to store honeypot events" });
    }
  });

  return router;
}
