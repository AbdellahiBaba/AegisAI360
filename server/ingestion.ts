import { Router, Request, Response } from "express";
import { createHash } from "crypto";
import { storage } from "./storage";
import type { InsertSecurityEvent } from "@shared/schema";

const SEVERITY_KEYWORDS: Record<string, string[]> = {
  critical: ["ransomware", "c2 beacon", "data exfiltration", "zero-day", "rootkit", "backdoor", "remote code execution", "rce"],
  high: ["brute force", "sql injection", "xss", "phishing", "lateral movement", "privilege escalation", "trojan", "malware"],
  medium: ["port scan", "policy violation", "unauthorized", "anomal", "suspicious", "unusual"],
  low: ["failed login", "usb device", "login attempt", "scanner"],
};

const TECHNIQUE_MAP: Record<string, { techniqueId: string; tactic: string }> = {
  "brute force": { techniqueId: "T1078", tactic: "Initial Access" },
  "ssh": { techniqueId: "T1078", tactic: "Initial Access" },
  "sql injection": { techniqueId: "T1190", tactic: "Initial Access" },
  "xss": { techniqueId: "T1189", tactic: "Initial Access" },
  "phishing": { techniqueId: "T1566", tactic: "Initial Access" },
  "lateral movement": { techniqueId: "T1021", tactic: "Lateral Movement" },
  "rdp": { techniqueId: "T1021", tactic: "Lateral Movement" },
  "powershell": { techniqueId: "T1059", tactic: "Execution" },
  "command": { techniqueId: "T1059", tactic: "Execution" },
  "exfiltration": { techniqueId: "T1048", tactic: "Exfiltration" },
  "data transfer": { techniqueId: "T1048", tactic: "Exfiltration" },
  "c2": { techniqueId: "T1071", tactic: "Command and Control" },
  "beacon": { techniqueId: "T1071", tactic: "Command and Control" },
  "dns tunnel": { techniqueId: "T1071", tactic: "Command and Control" },
  "ransomware": { techniqueId: "T1486", tactic: "Impact" },
  "encrypt": { techniqueId: "T1486", tactic: "Impact" },
  "privilege escalation": { techniqueId: "T1548", tactic: "Privilege Escalation" },
  "sudo": { techniqueId: "T1548", tactic: "Privilege Escalation" },
  "port scan": { techniqueId: "T1046", tactic: "Discovery" },
  "credential": { techniqueId: "T1003", tactic: "Credential Access" },
  "process injection": { techniqueId: "T1055", tactic: "Defense Evasion" },
};

function classifySeverity(description: string): string {
  const lower = description.toLowerCase();
  for (const [sev, keywords] of Object.entries(SEVERITY_KEYWORDS)) {
    if (keywords.some(kw => lower.includes(kw))) return sev;
  }
  return "info";
}

function mapTechnique(description: string): { techniqueId?: string; tactic?: string } {
  const lower = description.toLowerCase();
  for (const [keyword, mapping] of Object.entries(TECHNIQUE_MAP)) {
    if (lower.includes(keyword)) return mapping;
  }
  return {};
}

function parseSyslog(message: string): Partial<InsertSecurityEvent> {
  const ipMatch = message.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const portMatch = message.match(/port\s+(\d+)/i);
  const protocolMatch = message.match(/\b(TCP|UDP|SSH|HTTP|HTTPS|FTP|DNS|SMB|RDP|SMTP)\b/i);

  let eventType = "anomaly";
  const lower = message.toLowerCase();
  if (lower.includes("failed") || lower.includes("denied") || lower.includes("blocked")) eventType = "intrusion_attempt";
  else if (lower.includes("malware") || lower.includes("virus") || lower.includes("trojan")) eventType = "malware";
  else if (lower.includes("scan") || lower.includes("probe")) eventType = "reconnaissance";
  else if (lower.includes("policy") || lower.includes("violation")) eventType = "policy_violation";
  else if (lower.includes("exfil") || lower.includes("transfer")) eventType = "data_exfiltration";

  return {
    eventType,
    description: message.trim(),
    sourceIp: ipMatch ? ipMatch[1] : undefined,
    port: portMatch ? parseInt(portMatch[1]) : undefined,
    protocol: protocolMatch ? protocolMatch[1].toUpperCase() : undefined,
    source: "Syslog",
  };
}

export function createIngestionRouter(broadcast: (data: unknown) => void, evaluateAlertRules?: (event: any) => void) {
  const router = Router();

  async function authenticateApiKey(req: Request, res: Response): Promise<number | null> {
    const apiKey = req.headers["x-api-key"] as string;
    if (!apiKey) {
      res.status(401).json({ error: "Missing X-API-Key header" });
      return null;
    }

    const keyHash = createHash("sha256").update(apiKey).digest("hex");
    const key = await storage.getApiKeyByHash(keyHash);
    if (!key) {
      res.status(401).json({ error: "Invalid API key" });
      return null;
    }

    if (key.revokedAt) {
      res.status(401).json({ error: "API key has been revoked" });
      return null;
    }

    if (key.expiresAt && new Date(key.expiresAt) < new Date()) {
      res.status(401).json({ error: "API key has expired" });
      return null;
    }

    storage.touchApiKey(key.id).catch((err) => console.error("Failed to touch API key:", err));
    return key.organizationId;
  }

  router.post("/events", async (req: Request, res: Response) => {
    const orgId = await authenticateApiKey(req, res);
    if (orgId === null) return;

    try {
      const events: any[] = Array.isArray(req.body) ? req.body : [req.body];
      const results = [];

      for (const raw of events) {
        const severity = raw.severity || classifySeverity(raw.description || "");
        const technique = mapTechnique(raw.description || "");

        const event: InsertSecurityEvent = {
          organizationId: orgId,
          eventType: raw.eventType || raw.event_type || "anomaly",
          severity,
          source: raw.source || "API",
          sourceIp: raw.sourceIp || raw.source_ip || raw.src_ip || null,
          destinationIp: raw.destinationIp || raw.destination_ip || raw.dst_ip || null,
          port: raw.port ? parseInt(raw.port) : null,
          protocol: raw.protocol || null,
          description: raw.description || raw.message || "Event ingested via API",
          status: "new",
          rawData: raw.rawData || raw.raw || JSON.stringify(raw),
          techniqueId: raw.techniqueId || technique.techniqueId || null,
          tactic: raw.tactic || technique.tactic || null,
        };

        const stored = await storage.createSecurityEvent(event);
        broadcast({ type: "new_event", event: stored, orgId });
        if (evaluateAlertRules) Promise.resolve(evaluateAlertRules(stored)).catch(console.error);
        results.push(stored);
      }

      res.status(201).json({ ingested: results.length, events: results });
    } catch (error: any) {
      console.error("[ingestion] Event ingestion failed:", error);
      res.status(500).json({ error: "Ingestion failed" });
    }
  });

  router.post("/syslog", async (req: Request, res: Response) => {
    const orgId = await authenticateApiKey(req, res);
    if (orgId === null) return;

    try {
      const messages: string[] = Array.isArray(req.body.messages) ? req.body.messages : [req.body.message || req.body];
      const results = [];

      for (const msg of messages) {
        const parsed = parseSyslog(typeof msg === "string" ? msg : JSON.stringify(msg));
        const severity = classifySeverity(parsed.description || "");
        const technique = mapTechnique(parsed.description || "");

        const event: InsertSecurityEvent = {
          organizationId: orgId,
          eventType: parsed.eventType || "anomaly",
          severity,
          source: "Syslog",
          sourceIp: parsed.sourceIp || null,
          destinationIp: null,
          port: parsed.port || null,
          protocol: parsed.protocol || null,
          description: parsed.description || msg,
          status: "new",
          rawData: typeof msg === "string" ? msg : JSON.stringify(msg),
          techniqueId: technique.techniqueId || null,
          tactic: technique.tactic || null,
        };

        const stored = await storage.createSecurityEvent(event);
        broadcast({ type: "new_event", event: stored, orgId });
        if (evaluateAlertRules) Promise.resolve(evaluateAlertRules(stored)).catch(console.error);
        results.push(stored);
      }

      res.status(201).json({ ingested: results.length, events: results });
    } catch (error: any) {
      console.error("[ingestion] Syslog ingestion failed:", error);
      res.status(500).json({ error: "Syslog ingestion failed" });
    }
  });

  router.post("/webhook", async (req: Request, res: Response) => {
    const orgId = await authenticateApiKey(req, res);
    if (orgId === null) return;

    try {
      const payload = req.body;
      const description = payload.alert?.description || payload.message || payload.summary || payload.title || "Webhook event received";
      const severity = payload.alert?.severity || payload.severity || classifySeverity(description);
      const technique = mapTechnique(description);

      const event: InsertSecurityEvent = {
        organizationId: orgId,
        eventType: payload.type || payload.event_type || payload.alert?.type || "anomaly",
        severity,
        source: payload.source || payload.integration || "Webhook",
        sourceIp: payload.source_ip || payload.src || payload.alert?.source_ip || null,
        destinationIp: payload.destination_ip || payload.dst || payload.alert?.destination_ip || null,
        port: payload.port ? parseInt(payload.port) : null,
        protocol: payload.protocol || null,
        description,
        status: "new",
        rawData: JSON.stringify(payload),
        techniqueId: payload.technique_id || technique.techniqueId || null,
        tactic: payload.tactic || technique.tactic || null,
      };

      const stored = await storage.createSecurityEvent(event);
      broadcast({ type: "new_event", event: stored, orgId });
      if (evaluateAlertRules) Promise.resolve(evaluateAlertRules(stored)).catch(console.error);

      res.status(201).json({ ingested: 1, event: stored });
    } catch (error: any) {
      console.error("[ingestion] Webhook ingestion failed:", error);
      res.status(500).json({ error: "Webhook ingestion failed" });
    }
  });

  return router;
}
