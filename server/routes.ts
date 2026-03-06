import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { WebSocket, WebSocketServer } from "ws";
import { storage } from "./storage";
import OpenAI from "openai";
import { chatStorage } from "./replit_integrations/chat/storage";
import { z } from "zod";
import { createHash, randomBytes } from "crypto";
import {
  insertSecurityEventSchema,
  insertIncidentSchema,
  insertThreatIntelSchema,
  insertSecurityPolicySchema,
  insertAssetSchema,
  insertQuarantineItemSchema,
  insertResponsePlaybookSchema,
  type User,
} from "@shared/schema";
import { requireAuth, requireRole } from "./auth";
import { generateNetworkDevices, runNetworkVulnerabilityScan } from "./networkMonitor";
import { getUncachableStripeClient, getStripePublishableKey } from "./stripeClient";
import { createIngestionRouter } from "./ingestion";
import { createSuperAdminRouter } from "./superAdmin";
import { createThreatFeedsRouter } from "./threatFeeds";
import { ResponseEngine } from "./responseEngine";
import { AlertEngine } from "./alertEngine";
import { scanPorts, lookupDNS, checkSSL, scanHeaders, scanVulnerabilities, isPrivateTarget } from "./scanEngine";
import { SCENARIOS } from "./threatSimulator";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

const SECURITY_SYSTEM_PROMPT = `You are AegisAI, an advanced cybersecurity analyst assistant integrated into a Security Operations Center (SOC) dashboard. You provide expert analysis of security threats, malware behavior, network anomalies, and incident response recommendations.

Your capabilities include:
- Analyzing security events and log data
- Identifying indicators of compromise (IOCs)
- Providing MITRE ATT&CK technique mappings
- Recommending defensive actions and containment strategies
- Assessing threat severity and risk levels
- Explaining attack patterns and threat actor tactics

Guidelines:
- Communicate clearly and professionally, suitable for security analysts and IT teams
- When analyzing threats, provide severity assessment and recommended actions
- Reference relevant MITRE ATT&CK techniques when applicable
- Focus exclusively on defensive cybersecurity - never provide offensive guidance
- Provide actionable, specific recommendations`;

function getOrgId(req: Request): number {
  const user = req.user as User;
  return user.organizationId!;
}

function getUserId(req: Request): string {
  return (req.user as User).id;
}

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  function broadcast(data: unknown) {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  }

  const responseEngine = new ResponseEngine(broadcast);
  const alertEngine = new AlertEngine(broadcast);

  app.use("/api/ingest", createIngestionRouter(broadcast, (event) => alertEngine.evaluateEvent(event)));
  app.use("/api/admin", createSuperAdminRouter());
  app.use("/api/threat-feeds", createThreatFeedsRouter());

  app.use("/api/dashboard", requireAuth);
  app.use("/api/security-events", requireAuth);
  app.use("/api/incidents", requireAuth);
  app.use("/api/threat-intel", requireAuth);
  app.use("/api/security-policies", requireAuth);
  app.use("/api/ai-conversations", requireAuth);
  app.use("/api/assets", requireAuth);
  app.use("/api/audit-logs", requireAuth);
  app.use("/api/honeypot", requireAuth);
  app.use("/api/quarantine", requireAuth);
  app.use("/api/playbooks", requireAuth);
  app.use("/api/organization", requireAuth);
  app.use("/api/invites", requireAuth);
  app.use("/api/attack-map", requireAuth);
  app.use("/api/firewall", requireAuth);
  app.use("/api/alert-rules", requireAuth);
  app.use("/api/notifications", requireAuth);
  app.use("/api/api-keys", requireAuth);
  app.use("/api/response", requireAuth);
  app.use("/api/scan", requireAuth);
  app.use("/api/settings", requireAuth);
  app.use("/api/simulate", requireAuth);
  app.use("/api/support", requireAuth);
  app.use("/api/network", requireAuth);

  app.post("/api/support/tickets", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      if (!orgId) return res.status(400).json({ error: "Organization required" });
      const userId = getUserId(req);
      const { subject, description, priority, category } = z.object({
        subject: z.string().min(1),
        description: z.string().min(1),
        priority: z.enum(["low", "medium", "high", "critical"]).optional().default("medium"),
        category: z.enum(["technical", "billing", "account", "security"]).optional().default("technical"),
      }).parse(req.body);
      const ticket = await storage.createSupportTicket({
        organizationId: orgId,
        userId,
        subject,
        description,
        priority,
        category,
        messages: [{ role: "user", userId, content: description, timestamp: new Date().toISOString() }],
      });
      res.status(201).json(ticket);
    } catch (error) {
      res.status(500).json({ error: "Failed to create ticket" });
    }
  });

  app.get("/api/support/tickets", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const tickets = await storage.getSupportTickets(orgId);
      res.json(tickets);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch tickets" });
    }
  });

  app.get("/api/support/tickets/:id", async (req, res) => {
    try {
      const ticket = await storage.getSupportTicket(parseInt(req.params.id));
      if (!ticket) return res.status(404).json({ error: "Ticket not found" });
      const orgId = getOrgId(req);
      const user = req.user as any;
      if (ticket.organizationId !== orgId && !user?.isSuperAdmin) {
        return res.status(403).json({ error: "Access denied" });
      }
      res.json(ticket);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch ticket" });
    }
  });

  app.post("/api/support/tickets/:id/messages", async (req, res) => {
    try {
      const ticket = await storage.getSupportTicket(parseInt(req.params.id));
      if (!ticket) return res.status(404).json({ error: "Ticket not found" });
      const orgId = getOrgId(req);
      const user = req.user as any;
      if (ticket.organizationId !== orgId && !user?.isSuperAdmin) {
        return res.status(403).json({ error: "Access denied" });
      }
      const { content } = z.object({ content: z.string().min(1) }).parse(req.body);
      const messages = Array.isArray(ticket.messages) ? [...(ticket.messages as any[])] : [];
      messages.push({ role: user?.isSuperAdmin ? "admin" : "user", userId: getUserId(req), content, timestamp: new Date().toISOString() });
      const updated = await storage.updateSupportTicket(ticket.id, { messages });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to add message" });
    }
  });

  app.post("/api/support/tickets/:id/request-remote", async (req, res) => {
    try {
      const ticket = await storage.getSupportTicket(parseInt(req.params.id));
      if (!ticket) return res.status(404).json({ error: "Ticket not found" });
      const orgId = getOrgId(req);
      if (ticket.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });
      const updated = await storage.updateSupportTicket(ticket.id, { remoteSessionRequested: true });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to request remote session" });
    }
  });

  app.get("/api/network/devices", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const devices = await storage.getNetworkDevices(orgId);
      res.json(devices);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch network devices" });
    }
  });

  app.get("/api/network/devices/:id", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });
      res.json(device);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch device" });
    }
  });

  app.post("/api/network/scan", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { scanType } = z.object({
        scanType: z.enum(["quick", "full"]).optional().default("quick"),
      }).parse(req.body || {});

      const scan = await storage.createNetworkScan({
        organizationId: orgId,
        networkName: "Network Scan",
        scanType,
        status: "running",
        devicesFound: 0,
        unauthorizedCount: 0,
      });

      res.json({ scanId: scan.id, status: "running" });

      try {
        const deviceCount = scanType === "full" ? 15 : 10;
        const newDevices = generateNetworkDevices(orgId, deviceCount);

        const existingDevices = await storage.getNetworkDevices(orgId);
        const existingMacs = new Set(existingDevices.map(d => d.macAddress));

        let created = 0;
        let unauthorizedCount = 0;
        for (const device of newDevices) {
          if (!existingMacs.has(device.macAddress)) {
            await storage.createNetworkDevice(device);
            created++;
          }
          if (device.authorization === "unauthorized") unauthorizedCount++;
        }

        const totalDevices = existingDevices.length + created;
        await storage.updateNetworkScan(scan.id, {
          status: "completed",
          devicesFound: totalDevices,
          unauthorizedCount,
          completedAt: new Date(),
          results: { newDevices: created, totalDevices, scanType },
        });

        if (unauthorizedCount > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "unauthorized_device",
            severity: "high",
            source: "network-monitor",
            description: `Network scan detected ${unauthorizedCount} unauthorized device(s) on the network`,
            sourceIp: "network-scanner",
            status: "new",
          });
        }

      } catch (err) {
        console.error("Network scan error:", err);
        await storage.updateNetworkScan(scan.id, { status: "failed" });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to start network scan" });
    }
  });

  app.post("/api/network/scan/vulnerability", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const devices = await storage.getNetworkDevices(orgId);

      const scan = await storage.createNetworkScan({
        organizationId: orgId,
        networkName: "Vulnerability Scan",
        scanType: "vulnerability",
        status: "running",
        devicesFound: devices.length,
        unauthorizedCount: devices.filter(d => d.authorization === "unauthorized").length,
      });

      res.json({ scanId: scan.id, status: "running" });

      try {
        const { vulnerabilities, riskScore } = runNetworkVulnerabilityScan(devices);

        await storage.updateNetworkScan(scan.id, {
          status: "completed",
          vulnerabilities,
          completedAt: new Date(),
          results: { riskScore, totalVulnerabilities: vulnerabilities.length },
        });

        const criticalVulns = vulnerabilities.filter((v: any) => v.severity === "critical" || v.severity === "high");
        if (criticalVulns.length > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "network_vulnerability",
            severity: "critical",
            source: "network-monitor",
            description: `Network vulnerability scan found ${criticalVulns.length} critical/high severity issue(s)`,
            sourceIp: "vuln-scanner",
            status: "new",
          });
        }

      } catch (err) {
        console.error("Vulnerability scan error:", err);
        await storage.updateNetworkScan(scan.id, { status: "failed" });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to start vulnerability scan" });
    }
  });

  app.get("/api/network/scans", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scans = await storage.getNetworkScans(orgId);
      res.json(scans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scan history" });
    }
  });

  app.patch("/api/network/devices/:id", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      const data = z.object({
        authorization: z.enum(["authorized", "unauthorized", "unknown"]).optional(),
        notes: z.string().nullable().optional(),
        isCompanyDevice: z.boolean().optional(),
        assignedUser: z.string().nullable().optional(),
        hostname: z.string().optional(),
      }).parse(req.body);

      const updated = await storage.updateNetworkDevice(device.id, data);
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update device" });
    }
  });

  app.post("/api/network/devices/:id/block", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      await storage.updateNetworkDevice(device.id, { status: "blocked", authorization: "unauthorized" });

      await storage.createFirewallRule({
        organizationId: orgId,
        ruleType: "ip_block",
        value: device.ipAddress,
        action: "block",
        reason: `Blocked network device: ${device.hostname || device.macAddress}`,
        status: "active",
      });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "block_network_device",
        targetType: "network_device",
        targetId: String(device.id),
        details: `Blocked device ${device.hostname || device.macAddress} (${device.ipAddress})`,
      });

      res.json({ success: true, message: "Device blocked" });
    } catch (error) {
      res.status(500).json({ error: "Failed to block device" });
    }
  });

  app.post("/api/network/devices/:id/kick", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      await storage.updateNetworkDevice(device.id, { status: "offline" });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "kick_network_device",
        targetType: "network_device",
        targetId: String(device.id),
        details: `Kicked device ${device.hostname || device.macAddress} (${device.ipAddress}) from network`,
      });

      res.json({ success: true, message: "Device kicked from network" });
    } catch (error) {
      res.status(500).json({ error: "Failed to kick device" });
    }
  });

  app.post("/api/network/devices/:id/authorize", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      await storage.updateNetworkDevice(device.id, { authorization: "authorized", status: "online" });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "authorize_network_device",
        targetType: "network_device",
        targetId: String(device.id),
        details: `Authorized device ${device.hostname || device.macAddress} (${device.ipAddress})`,
      });

      res.json({ success: true, message: "Device authorized" });
    } catch (error) {
      res.status(500).json({ error: "Failed to authorize device" });
    }
  });

  app.delete("/api/network/devices/:id", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Device not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      await storage.deleteNetworkDevice(device.id);
      res.json({ success: true, message: "Device removed" });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete device" });
    }
  });

  app.get("/api/network/traffic", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const devices = await storage.getNetworkDevices(orgId);
      const totalIn = devices.reduce((sum, d) => sum + (Number(d.dataIn) || 0), 0);
      const totalOut = devices.reduce((sum, d) => sum + (Number(d.dataOut) || 0), 0);
      const topDevices = devices
        .sort((a, b) => (Number(b.dataIn) + Number(b.dataOut)) - (Number(a.dataIn) + Number(a.dataOut)))
        .slice(0, 10)
        .map(d => ({
          id: d.id,
          hostname: d.hostname,
          ipAddress: d.ipAddress,
          dataIn: Number(d.dataIn),
          dataOut: Number(d.dataOut),
          total: Number(d.dataIn) + Number(d.dataOut),
        }));
      res.json({ totalIn, totalOut, totalDevices: devices.length, topDevices });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch traffic data" });
    }
  });

  app.get("/api/dashboard/stats", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getDashboardStats(orgId);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  app.get("/api/dashboard/trend", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const trend = await storage.getEventTrend(orgId);
      res.json(trend);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch trend" });
    }
  });

  app.get("/api/security-events", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);
      res.json(events);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch events" });
    }
  });

  app.post("/api/security-events", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertSecurityEventSchema.parse({ ...req.body, organizationId: orgId });
      const event = await storage.createSecurityEvent(parsed);
      broadcast({ type: "new_event", event, orgId });
      alertEngine.evaluateEvent(event);
      res.status(201).json(event);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create event" });
    }
  });

  app.patch("/api/security-events/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const { status } = z.object({ status: z.enum(["new", "investigating", "resolved", "dismissed"]) }).parse(req.body);
      const updated = await storage.updateSecurityEventStatus(id, orgId, status);
      if (!updated) return res.status(404).json({ error: "Event not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update event" });
    }
  });

  app.get("/api/incidents", async (req, res) => {
    try {
      const list = await storage.getIncidents(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch incidents" });
    }
  });

  app.post("/api/incidents", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertIncidentSchema.parse({ ...req.body, organizationId: orgId });
      const incident = await storage.createIncident(parsed);
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_incident", targetType: "incident", targetId: String(incident.id), details: incident.title });
      res.status(201).json(incident);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const parsed = insertIncidentSchema.partial().extend({
        status: z.enum(["open", "investigating", "contained", "resolved", "closed"]).optional(),
      }).parse(req.body);
      const updated = await storage.updateIncident(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Incident not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "update_incident", targetType: "incident", targetId: String(id), details: JSON.stringify(parsed) });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update incident" });
    }
  });

  app.get("/api/threat-intel", async (req, res) => {
    try {
      const list = await storage.getThreatIntel(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threat intel" });
    }
  });

  app.post("/api/threat-intel", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertThreatIntelSchema.parse({ ...req.body, organizationId: orgId });
      const intel = await storage.createThreatIntel(parsed);
      res.status(201).json(intel);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create threat intel" });
    }
  });

  app.patch("/api/threat-intel/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const parsed = z.object({ active: z.boolean() }).parse(req.body);
      const updated = await storage.updateThreatIntel(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Indicator not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update indicator" });
    }
  });

  app.get("/api/security-policies", async (req, res) => {
    try {
      const list = await storage.getSecurityPolicies(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch policies" });
    }
  });

  app.post("/api/security-policies", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertSecurityPolicySchema.parse({ ...req.body, organizationId: orgId });
      const policy = await storage.createSecurityPolicy(parsed);
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_policy", targetType: "policy", targetId: String(policy.id), details: policy.name });
      res.status(201).json(policy);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create policy" });
    }
  });

  app.patch("/api/security-policies/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const parsed = z.object({ enabled: z.boolean() }).parse(req.body);
      const updated = await storage.updateSecurityPolicy(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Policy not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "toggle_policy", targetType: "policy", targetId: String(id), details: `enabled=${parsed.enabled}` });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update policy" });
    }
  });

  app.get("/api/assets", async (req, res) => {
    try {
      const list = await storage.getAssets(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch assets" });
    }
  });

  app.post("/api/assets", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertAssetSchema.parse({ ...req.body, organizationId: orgId });
      const asset = await storage.createAsset(parsed);
      res.status(201).json(asset);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create asset" });
    }
  });

  app.patch("/api/assets/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const updated = await storage.updateAsset(id, orgId, req.body);
      if (!updated) return res.status(404).json({ error: "Asset not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update asset" });
    }
  });

  app.get("/api/audit-logs", async (req, res) => {
    try {
      const list = await storage.getAuditLogs(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch audit logs" });
    }
  });

  app.get("/api/honeypot", async (req, res) => {
    try {
      const list = await storage.getHoneypotEvents(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch honeypot events" });
    }
  });

  app.get("/api/quarantine", async (req, res) => {
    try {
      const list = await storage.getQuarantineItems(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch quarantine items" });
    }
  });

  app.post("/api/quarantine", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertQuarantineItemSchema.parse({ ...req.body, organizationId: orgId });
      const item = await storage.createQuarantineItem(parsed);
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "quarantine_file", targetType: "quarantine", targetId: String(item.id), details: item.fileName });
      res.status(201).json(item);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create quarantine item" });
    }
  });

  app.patch("/api/quarantine/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const parsed = z.object({
        status: z.enum(["quarantined", "restored", "deleted"]).optional(),
        action: z.enum(["quarantined", "restored", "deleted"]).optional(),
      }).parse(req.body);
      const updated = await storage.updateQuarantineItem(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Item not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: `quarantine_${parsed.status || parsed.action}`, targetType: "quarantine", targetId: String(id) });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update quarantine item" });
    }
  });

  app.get("/api/playbooks", async (req, res) => {
    try {
      const list = await storage.getResponsePlaybooks(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbooks" });
    }
  });

  app.post("/api/playbooks", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = insertResponsePlaybookSchema.parse({ ...req.body, organizationId: orgId });
      const playbook = await storage.createResponsePlaybook(parsed);
      res.status(201).json(playbook);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create playbook" });
    }
  });

  app.patch("/api/playbooks/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const parsed = z.object({ enabled: z.boolean() }).parse(req.body);
      const updated = await storage.updateResponsePlaybook(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Playbook not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update playbook" });
    }
  });

  app.get("/api/organization", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      res.json(org);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch organization" });
    }
  });

  app.patch("/api/organization", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = z.object({ name: z.string().min(1) }).parse(req.body);
      const updated = await storage.updateOrganization(orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Organization not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update organization" });
    }
  });

  app.get("/api/invites", requireRole("admin"), async (req, res) => {
    try {
      const list = await storage.getInvites(getOrgId(req));
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch invites" });
    }
  });

  app.post("/api/invites", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { role, email } = z.object({
        role: z.enum(["admin", "analyst", "auditor", "readonly"]).default("analyst"),
        email: z.string().optional(),
      }).parse(req.body);

      const code = randomBytes(16).toString("hex");
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
      const invite = await storage.createInvite({ organizationId: orgId, email: email || null, role, code, used: false, expiresAt });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_invite", targetType: "invite", targetId: String(invite.id), details: `role=${role}` });
      res.status(201).json(invite);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create invite" });
    }
  });

  app.get("/api/attack-map/stats", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);
      const techniqueMap: Record<string, { count: number; tactic: string }> = {};
      for (const event of events) {
        if (event.techniqueId) {
          if (!techniqueMap[event.techniqueId]) {
            techniqueMap[event.techniqueId] = { count: 0, tactic: event.tactic || "" };
          }
          techniqueMap[event.techniqueId].count++;
        }
      }
      const techniques = Object.entries(techniqueMap).map(([id, data]) => ({
        techniqueId: id,
        tactic: data.tactic,
        count: data.count,
      }));
      res.json({ techniques, totalEvents: events.length });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch attack map stats" });
    }
  });

  // API Keys management
  app.get("/api/api-keys", async (req, res) => {
    try {
      const keys = await storage.getApiKeys(getOrgId(req));
      res.json(keys.map(k => ({ ...k, keyHash: undefined })));
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch API keys" });
    }
  });

  app.post("/api/api-keys", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { name, permissions } = z.object({ name: z.string().min(1), permissions: z.string().default("ingest") }).parse(req.body);
      const rawKey = `aegis_${randomBytes(32).toString("hex")}`;
      const keyHash = createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 12);

      const key = await storage.createApiKey({ organizationId: orgId, name, keyHash, keyPrefix, permissions });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_api_key", targetType: "api_key", targetId: String(key.id), details: name });
      res.status(201).json({ ...key, rawKey, keyHash: undefined });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create API key" });
    }
  });

  app.delete("/api/api-keys/:id", requireRole("admin"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const deleted = await storage.deleteApiKey(id, orgId);
      if (!deleted) return res.status(404).json({ error: "API key not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "revoke_api_key", targetType: "api_key", targetId: String(id) });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete API key" });
    }
  });

  // Firewall rules management
  app.get("/api/firewall", async (req, res) => {
    try {
      const rules = await storage.getFirewallRules(getOrgId(req));
      res.json(rules);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch firewall rules" });
    }
  });

  app.post("/api/firewall", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = z.object({
        ruleType: z.enum(["ip_block", "domain_block", "port_block", "cidr_block"]),
        value: z.string().min(1),
        action: z.enum(["block", "allow", "sinkhole"]).default("block"),
        reason: z.string().optional(),
        expiresAt: z.string().optional(),
      }).parse(req.body);

      const rule = await storage.createFirewallRule({
        organizationId: orgId,
        ruleType: parsed.ruleType,
        value: parsed.value,
        action: parsed.action,
        reason: parsed.reason || null,
        createdBy: getUserId(req),
        expiresAt: parsed.expiresAt ? new Date(parsed.expiresAt) : null,
        status: "active",
      });

      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_firewall_rule", targetType: "firewall_rule", targetId: String(rule.id), details: `${parsed.ruleType}: ${parsed.value}` });
      res.status(201).json(rule);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create firewall rule" });
    }
  });

  app.patch("/api/firewall/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const { status } = z.object({ status: z.enum(["active", "disabled"]) }).parse(req.body);
      const updated = await storage.updateFirewallRule(id, orgId, { status });
      if (!updated) return res.status(404).json({ error: "Rule not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update firewall rule" });
    }
  });

  app.delete("/api/firewall/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const deleted = await storage.deleteFirewallRule(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Rule not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "delete_firewall_rule", targetType: "firewall_rule", targetId: String(id) });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete firewall rule" });
    }
  });

  // Alert rules management
  app.get("/api/alert-rules", async (req, res) => {
    try {
      const rules = await storage.getAlertRules(getOrgId(req));
      res.json(rules);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch alert rules" });
    }
  });

  app.post("/api/alert-rules", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const parsed = z.object({
        name: z.string().min(1),
        conditions: z.string(),
        severity: z.enum(["critical", "high", "medium", "low"]).default("medium"),
        actions: z.string(),
        enabled: z.boolean().default(true),
      }).parse(req.body);

      const rule = await storage.createAlertRule({ ...parsed, organizationId: orgId });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_alert_rule", targetType: "alert_rule", targetId: String(rule.id), details: parsed.name });
      res.status(201).json(rule);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create alert rule" });
    }
  });

  app.patch("/api/alert-rules/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
      const updated = await storage.updateAlertRule(id, orgId, { enabled });
      if (!updated) return res.status(404).json({ error: "Rule not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update alert rule" });
    }
  });

  app.delete("/api/alert-rules/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const deleted = await storage.deleteAlertRule(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Rule not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete alert rule" });
    }
  });

  // Notifications
  app.get("/api/notifications", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const notifs = await storage.getNotifications(orgId, userId);
      res.json(notifs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch notifications" });
    }
  });

  app.get("/api/notifications/unread-count", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const count = await storage.getUnreadNotificationCount(orgId, userId);
      res.json({ count });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch unread count" });
    }
  });

  app.patch("/api/notifications/:id/read", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      await storage.markNotificationRead(id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to mark notification read" });
    }
  });

  app.post("/api/notifications/mark-all-read", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      await storage.markAllNotificationsRead(orgId, userId);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to mark all read" });
    }
  });

  // Response actions
  app.post("/api/response/block-ip", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { ip, reason } = z.object({ ip: z.string(), reason: z.string().default("Manual block") }).parse(req.body);
      const result = await responseEngine.blockIP(orgId, ip, reason, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to block IP" });
    }
  });

  app.post("/api/response/isolate-asset", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { assetId } = z.object({ assetId: z.number() }).parse(req.body);
      const result = await responseEngine.isolateAsset(orgId, assetId, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to isolate asset" });
    }
  });

  app.post("/api/response/quarantine-file", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { fileName, fileHash, threat, sourceAsset } = z.object({
        fileName: z.string(), fileHash: z.string().default(""), threat: z.string(), sourceAsset: z.string().default(""),
      }).parse(req.body);
      const result = await responseEngine.quarantineFile(orgId, fileName, fileHash, threat, sourceAsset, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to quarantine file" });
    }
  });

  app.post("/api/response/sinkhole-domain", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { domain } = z.object({ domain: z.string() }).parse(req.body);
      const result = await responseEngine.sinkholeDomain(orgId, domain, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to sinkhole domain" });
    }
  });

  app.post("/api/response/create-incident-from-event", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { eventId } = z.object({ eventId: z.number() }).parse(req.body);
      const result = await responseEngine.createIncidentFromEvent(orgId, eventId, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to create incident" });
    }
  });

  app.post("/api/response/execute-playbook", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { playbookId, context } = z.object({ playbookId: z.number(), context: z.record(z.any()).default({}) }).parse(req.body);
      const result = await responseEngine.executePlaybook(orgId, playbookId, context, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to execute playbook" });
    }
  });

  app.post("/api/response/emergency-lockdown", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const result = await responseEngine.emergencyLockdown(orgId, userId);
      res.json(result);
    } catch (error: any) {
      res.status(500).json({ error: error.message || "Failed to initiate lockdown" });
    }
  });

  app.post("/api/response/auto-defend", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { eventId } = z.object({ eventId: z.number() }).parse(req.body);
      const events = await storage.getSecurityEvents(orgId);
      const event = events.find(e => e.id === eventId);
      if (!event) return res.status(404).json({ error: "Event not found" });
      const result = await responseEngine.autoThreatResponse(orgId, event);
      res.json(result);
    } catch (error: any) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: error.message || "Failed to execute auto-defend" });
    }
  });

  app.get("/api/response/actions", async (req, res) => {
    try {
      const actions = await storage.getResponseActions(getOrgId(req));
      res.json(actions);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch response actions" });
    }
  });

  // AI conversations
  app.get("/api/ai-conversations", async (req, res) => {
    try {
      const convs = await chatStorage.getAllConversations(getOrgId(req));
      res.json(convs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch conversations" });
    }
  });

  app.get("/api/ai-conversations/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const conv = await chatStorage.getConversation(id);
      if (!conv) return res.status(404).json({ error: "Not found" });
      const messages = await chatStorage.getMessagesByConversation(id);
      res.json({ ...conv, messages });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch conversation" });
    }
  });

  app.post("/api/ai-conversations", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const conv = await chatStorage.createConversation(req.body.title || "New Analysis", orgId);
      res.status(201).json(conv);
    } catch (error) {
      res.status(500).json({ error: "Failed to create conversation" });
    }
  });

  app.delete("/api/ai-conversations/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      await chatStorage.deleteConversation(id);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ error: "Failed to delete conversation" });
    }
  });

  // Billing
  app.use("/api/billing", requireAuth);

  app.get("/api/billing/config", async (_req, res) => {
    try {
      const publishableKey = await getStripePublishableKey();
      res.json({ publishableKey });
    } catch (error) {
      res.status(500).json({ error: "Stripe not configured" });
    }
  });

  app.get("/api/billing/status", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      res.json({
        plan: org.plan,
        maxUsers: org.maxUsers,
        stripeCustomerId: org.stripeCustomerId,
        stripeSubscriptionId: org.stripeSubscriptionId,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch billing status" });
    }
  });

  app.post("/api/billing/create-checkout", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { priceId } = z.object({ priceId: z.string() }).parse(req.body);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });

      const stripe = await getUncachableStripeClient();

      let customerId = org.stripeCustomerId;
      if (!customerId) {
        const customer = await stripe.customers.create({
          metadata: { organizationId: String(orgId) },
        });
        customerId = customer.id;
        await storage.updateOrganization(orgId, { stripeCustomerId: customerId });
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        payment_method_types: ['card'],
        line_items: [{ price: priceId, quantity: 1 }],
        mode: 'subscription',
        success_url: `https://${req.get('host')}/billing?success=true`,
        cancel_url: `https://${req.get('host')}/billing?canceled=true`,
        metadata: { organizationId: String(orgId) },
      });

      res.json({ url: session.url });
    } catch (error) {
      console.error("Checkout error:", error);
      res.status(500).json({ error: "Failed to create checkout session" });
    }
  });

  app.post("/api/billing/portal", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org?.stripeCustomerId) {
        return res.status(400).json({ error: "No billing account found" });
      }

      const stripe = await getUncachableStripeClient();
      const session = await stripe.billingPortal.sessions.create({
        customer: org.stripeCustomerId,
        return_url: `https://${req.get('host')}/billing`,
      });

      res.json({ url: session.url });
    } catch (error) {
      res.status(500).json({ error: "Failed to create portal session" });
    }
  });

  app.get("/api/billing/products", async (_req, res) => {
    try {
      const { db: drizzleDb } = await import("./db");
      const { sql } = await import("drizzle-orm");
      const result = await drizzleDb.execute(
        sql`SELECT p.id, p.name, p.description, p.metadata,
              pr.id as price_id, pr.unit_amount, pr.currency, pr.recurring
            FROM stripe.products p
            JOIN stripe.prices pr ON pr.product = p.id AND pr.active = true
            WHERE p.active = true
            ORDER BY pr.unit_amount ASC`
      );
      res.json(result.rows);
    } catch (error) {
      res.json([]);
    }
  });

  app.get("/api/organization/users", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const orgUsers = await storage.getOrganizationUsers(orgId);
      res.json(orgUsers);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });

  app.patch("/api/organization/users/:userId/role", requireRole("admin"), async (req, res) => {
    try {
      const { userId } = req.params;
      const orgId = getOrgId(req);
      const { role } = z.object({ role: z.enum(["admin", "analyst", "auditor", "readonly"]) }).parse(req.body);
      const updated = await storage.updateUserRole(userId, orgId, role);
      if (!updated) return res.status(404).json({ error: "User not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "change_role", targetType: "user", targetId: userId, details: `role=${role}` });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update role" });
    }
  });

  app.post("/api/ai-conversations/:id/messages", async (req, res) => {
    try {
      const conversationId = parseInt(req.params.id);
      const { content } = z.object({ content: z.string().min(1) }).parse(req.body);

      const conv = await chatStorage.getConversation(conversationId);
      if (!conv) return res.status(404).json({ error: "Conversation not found" });

      await chatStorage.createMessage(conversationId, "user", content);

      const messages = await chatStorage.getMessagesByConversation(conversationId);
      const chatMessages: { role: "system" | "user" | "assistant"; content: string }[] = [
        { role: "system", content: SECURITY_SYSTEM_PROMPT },
        ...messages.map((m) => ({
          role: m.role as "user" | "assistant",
          content: m.content,
        })),
      ];

      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");

      const stream = await openai.chat.completions.create({
        model: "openai/gpt-4o-mini",
        messages: chatMessages,
        stream: true,
        max_completion_tokens: 8192,
      });

      let fullResponse = "";
      for await (const chunk of stream) {
        const text = chunk.choices[0]?.delta?.content || "";
        if (text) {
          fullResponse += text;
          res.write(`data: ${JSON.stringify({ content: text })}\n\n`);
        }
      }

      await chatStorage.createMessage(conversationId, "assistant", fullResponse);
      res.write(`data: ${JSON.stringify({ done: true })}\n\n`);
      res.end();
    } catch (error) {
      console.error("AI analysis error:", error);
      if (res.headersSent) {
        res.write(`data: ${JSON.stringify({ error: "Failed to process" })}\n\n`);
        res.end();
      } else {
        res.status(500).json({ error: "Failed to process message" });
      }
    }
  });

  app.post("/api/scan/ports", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target, ports } = z.object({
        target: z.string().min(1),
        ports: z.array(z.number()).optional(),
      }).parse(req.body);
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "port_scan",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await scanPorts(target, ports);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.openPorts.length,
          severity: results.riskLevel,
          completedAt: new Date(),
        });
        if (results.openPorts.some(p => p.risk === "high" || p.risk === "critical")) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "reconnaissance",
            severity: results.riskLevel,
            source: "Port Scanner",
            sourceIp: target,
            description: `Port scan on ${target}: ${results.openPorts.length} open ports found (${results.openPorts.filter(p => p.risk === "high" || p.risk === "critical").length} high-risk)`,
          });
        }
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.post("/api/scan/dns", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "dns_lookup",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await lookupDNS(target);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.totalRecords,
          severity: "info",
          completedAt: new Date(),
        });
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.post("/api/scan/ssl", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "ssl_check",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await checkSSL(target);
        let severity = "info";
        if (results.expired) severity = "critical";
        else if (results.selfSigned) severity = "high";
        else if (results.expiringSoon) severity = "medium";
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.expired ? 1 : results.expiringSoon ? 1 : 0,
          severity,
          completedAt: new Date(),
        });
        if (results.expired || results.selfSigned) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "anomaly",
            severity,
            source: "SSL Scanner",
            description: `SSL certificate issue on ${target}: ${results.expired ? "Certificate EXPIRED" : "Self-signed certificate"} (Grade: ${results.grade})`,
          });
        }
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.post("/api/scan/headers", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "header_scan",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await scanHeaders(target);
        let severity = "info";
        if (results.score < 40) severity = "high";
        else if (results.score < 60) severity = "medium";
        else if (results.score < 80) severity = "low";
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.findings,
          severity,
          completedAt: new Date(),
        });
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.post("/api/scan/vulnerabilities", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "vuln_scan",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await scanVulnerabilities(target);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.findings,
          severity: results.riskLevel,
          completedAt: new Date(),
        });
        if (results.findings > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "anomaly",
            severity: results.riskLevel,
            source: "Vulnerability Scanner",
            description: `Vulnerability scan on ${target}: ${results.findings} issues found (Risk: ${results.riskLevel})`,
          });
        }
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Scan failed" });
    }
  });

  app.get("/api/scan/history", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const results = await storage.getScanResults(orgId);
      res.json(results);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scan history" });
    }
  });

  app.get("/api/settings/defense-mode", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      res.json({ defenseMode: (org as any)?.defenseMode || "auto" });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch defense mode" });
    }
  });

  app.patch("/api/settings/defense-mode", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { defenseMode } = z.object({
        defenseMode: z.enum(["auto", "semi-auto", "manual"]),
      }).parse(req.body);
      await storage.updateOrganization(orgId, { defenseMode } as any);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "update_defense_mode",
        targetType: "organization",
        targetId: String(orgId),
        details: `Defense mode changed to: ${defenseMode}`,
      });
      res.json({ defenseMode });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update defense mode" });
    }
  });

  app.get("/api/simulate/scenarios", async (_req, res) => {
    const scenarios = Object.entries(SCENARIOS).map(([id, s]) => ({
      id,
      name: s.name,
      description: s.description,
    }));
    res.json(scenarios);
  });

  app.post("/api/simulate/:scenario", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { scenario } = req.params;
      const scenarioConfig = SCENARIOS[scenario];
      if (!scenarioConfig) {
        return res.status(404).json({ error: "Scenario not found" });
      }
      res.json({ status: "running", scenario: scenarioConfig.name });
      try {
        const result = await scenarioConfig.fn(orgId);
        await storage.createAuditLog({
          organizationId: orgId,
          userId: getUserId(req),
          action: "run_simulation",
          targetType: "simulation",
          targetId: scenario,
          details: result.description,
        });
        broadcast({ type: "simulation_complete", scenario, ...result, orgId });
      } catch (err) {
        console.error("Simulation error:", err);
      }
    } catch (error) {
      res.status(500).json({ error: "Simulation failed" });
    }
  });

  return httpServer;
}
