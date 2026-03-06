import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { WebSocket, WebSocketServer } from "ws";
import { storage } from "./storage";
import OpenAI from "openai";
import { chatStorage } from "./replit_integrations/chat/storage";
import { z } from "zod";
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
import { randomBytes } from "crypto";

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
- Communicate clearly and professionally, suitable for SOC analysts
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

const attackTechniques = [
  { techniqueId: "T1078", tactic: "Initial Access", desc: "Valid Accounts" },
  { techniqueId: "T1059", tactic: "Execution", desc: "Command and Scripting Interpreter" },
  { techniqueId: "T1021", tactic: "Lateral Movement", desc: "Remote Services" },
  { techniqueId: "T1048", tactic: "Exfiltration", desc: "Exfiltration Over Alternative Protocol" },
  { techniqueId: "T1190", tactic: "Initial Access", desc: "Exploit Public-Facing Application" },
  { techniqueId: "T1566", tactic: "Initial Access", desc: "Phishing" },
  { techniqueId: "T1071", tactic: "Command and Control", desc: "Application Layer Protocol" },
  { techniqueId: "T1486", tactic: "Impact", desc: "Data Encrypted for Impact" },
  { techniqueId: "T1053", tactic: "Execution", desc: "Scheduled Task/Job" },
  { techniqueId: "T1055", tactic: "Defense Evasion", desc: "Process Injection" },
  { techniqueId: "T1003", tactic: "Credential Access", desc: "OS Credential Dumping" },
  { techniqueId: "T1027", tactic: "Defense Evasion", desc: "Obfuscated Files or Information" },
];

const eventTemplates = [
  { eventType: "intrusion_attempt", severity: "critical", source: "IDS", description: "SSH brute force attack detected", protocol: "SSH", port: 22, techniqueId: "T1078", tactic: "Initial Access" },
  { eventType: "malware", severity: "critical", source: "Endpoint", description: "Trojan.GenericKD detected in executable download", protocol: "HTTPS", port: 443, techniqueId: "T1059", tactic: "Execution" },
  { eventType: "anomaly", severity: "high", source: "ML Engine", description: "Anomalous outbound data transfer - potential exfiltration", protocol: "HTTPS", port: 443, techniqueId: "T1048", tactic: "Exfiltration" },
  { eventType: "reconnaissance", severity: "medium", source: "Firewall", description: "Port scanning activity from external IP", protocol: "TCP", port: 0, techniqueId: "T1046", tactic: "Discovery" },
  { eventType: "policy_violation", severity: "medium", source: "DLP", description: "Unauthorized file sharing to external cloud", protocol: "HTTPS", port: 443, techniqueId: "T1567", tactic: "Exfiltration" },
  { eventType: "intrusion_attempt", severity: "high", source: "WAF", description: "SQL injection attempt blocked", protocol: "HTTP", port: 80, techniqueId: "T1190", tactic: "Initial Access" },
  { eventType: "anomaly", severity: "low", source: "Network Monitor", description: "Unusual DNS query pattern - NXDOMAIN flood", protocol: "DNS", port: 53, techniqueId: "T1071", tactic: "Command and Control" },
  { eventType: "malware", severity: "high", source: "Email Gateway", description: "Phishing email with malicious attachment quarantined", protocol: "SMTP", port: 25, techniqueId: "T1566", tactic: "Initial Access" },
  { eventType: "intrusion_attempt", severity: "critical", source: "IDS", description: "C2 beacon activity - periodic encrypted connections", protocol: "HTTPS", port: 443, techniqueId: "T1071", tactic: "Command and Control" },
  { eventType: "policy_violation", severity: "low", source: "Endpoint", description: "Unauthorized USB device connected", protocol: "N/A", port: 0, techniqueId: "T1091", tactic: "Initial Access" },
  { eventType: "anomaly", severity: "medium", source: "SIEM", description: "Privilege escalation - unusual sudo usage", protocol: "N/A", port: 0, techniqueId: "T1548", tactic: "Privilege Escalation" },
  { eventType: "data_exfiltration", severity: "critical", source: "DLP", description: "Large volume data transfer to external endpoint", protocol: "HTTPS", port: 443, techniqueId: "T1048", tactic: "Exfiltration" },
  { eventType: "malware", severity: "high", source: "Sandbox", description: "Fileless malware - PowerShell encoded command", protocol: "N/A", port: 0, techniqueId: "T1059", tactic: "Execution" },
];

const honeypotTemplates = [
  { honeypotName: "SSH-Trap-01", service: "SSH", action: "login_attempt", payload: "root:admin123" },
  { honeypotName: "HTTP-Decoy-01", service: "HTTP", action: "directory_traversal", payload: "GET /../../etc/passwd" },
  { honeypotName: "SMB-Honeypot-01", service: "SMB", action: "share_enumeration", payload: "net share /all" },
  { honeypotName: "SSH-Trap-01", service: "SSH", action: "brute_force", payload: "admin:password" },
  { honeypotName: "HTTP-Decoy-01", service: "HTTP", action: "sql_injection", payload: "' OR 1=1 --" },
  { honeypotName: "RDP-Trap-01", service: "RDP", action: "login_attempt", payload: "Administrator:P@ssw0rd" },
  { honeypotName: "FTP-Honeypot-01", service: "FTP", action: "anonymous_login", payload: "anonymous:guest" },
];

const countries = ["CN", "RU", "US", "KR", "BR", "IN", "DE", "NL", "UA", "IR", "VN", "RO"];

function randomIp() {
  const prefixes = ["185.220.101", "45.33.32", "192.168.1", "10.0.0", "172.16.0", "203.0.113", "198.51.100"];
  return `${prefixes[Math.floor(Math.random() * prefixes.length)]}.${Math.floor(Math.random() * 254) + 1}`;
}

function generateRandomEvent(orgId: number) {
  const template = eventTemplates[Math.floor(Math.random() * eventTemplates.length)];
  return {
    ...template,
    organizationId: orgId,
    sourceIp: randomIp(),
    destinationIp: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    status: "new" as const,
  };
}

function generateHoneypotEvent(orgId: number) {
  const template = honeypotTemplates[Math.floor(Math.random() * honeypotTemplates.length)];
  return {
    ...template,
    organizationId: orgId,
    attackerIp: randomIp(),
    country: countries[Math.floor(Math.random() * countries.length)],
    sessionId: randomBytes(8).toString("hex"),
  };
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

  const orgEventIntervals = new Map<number, NodeJS.Timeout>();

  function startEventGeneration(orgId: number) {
    if (orgEventIntervals.has(orgId)) return;
    const interval = setInterval(async () => {
      try {
        const event = generateRandomEvent(orgId);
        const stored = await storage.createSecurityEvent(event);
        broadcast({ type: "new_event", event: stored, orgId });

        if (Math.random() < 0.3) {
          const hp = generateHoneypotEvent(orgId);
          const storedHp = await storage.createHoneypotEvent(hp);
          broadcast({ type: "new_honeypot_event", event: storedHp, orgId });
        }
      } catch {}
    }, 25000);
    orgEventIntervals.set(orgId, interval);
  }

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

  app.get("/api/dashboard/stats", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      startEventGeneration(orgId);
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

  return httpServer;
}
