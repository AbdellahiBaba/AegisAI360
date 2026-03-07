import { Router } from "express";
import { z } from "zod";
import { randomBytes, createHash } from "crypto";
import fs from "fs";
import path from "path";
import { storage } from "./storage";
import { requireAuth, requireRole, requirePlanFeature } from "./auth";
import type { User } from "@shared/schema";

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
    res.json({ status: "ok", timestamp: Date.now(), version: "1.0.0" });
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
      if (dt.used) return res.status(400).json({ error: "Token already used" });

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

      await storage.markTokenUsed(dt.id, agent.id);
      await storage.incrementUsage(dt.organizationId, "agentsRegistered");
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

      await storage.updateAgentHeartbeat(agentId, {
        lastSeen: new Date(),
        cpuUsage: cpuUsage ?? undefined,
        ramUsage: ramUsage ?? undefined,
        ip: localIP ?? undefined,
      });

      res.json({ status: "ok" });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Telemetry ingestion failed" });
    }
  });

  router.get("/version", (req, res) => {
    const currentVersion = req.query.version as string || "0.0.0";
    const latestVersion = "1.0.0";
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
      res.json({ status: "ok" });
    } catch (error) {
      res.status(500).json({ error: "Failed to update command result" });
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

  return router;
}
