import type { Express } from "express";
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
} from "@shared/schema";

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

const eventTemplates = [
  { eventType: "intrusion_attempt", severity: "critical", source: "IDS", description: "SSH brute force attack detected - multiple failed authentication attempts", protocol: "SSH", port: 22 },
  { eventType: "malware", severity: "critical", source: "Endpoint", description: "Trojan.GenericKD detected in executable download", protocol: "HTTPS", port: 443 },
  { eventType: "anomaly", severity: "high", source: "ML Engine", description: "Anomalous outbound data transfer pattern detected - potential data exfiltration", protocol: "HTTPS", port: 443 },
  { eventType: "reconnaissance", severity: "medium", source: "Firewall", description: "Port scanning activity detected from external IP", protocol: "TCP", port: 0 },
  { eventType: "policy_violation", severity: "medium", source: "DLP", description: "Unauthorized file sharing to external cloud service", protocol: "HTTPS", port: 443 },
  { eventType: "intrusion_attempt", severity: "high", source: "WAF", description: "SQL injection attempt blocked on web application", protocol: "HTTP", port: 80 },
  { eventType: "anomaly", severity: "low", source: "Network Monitor", description: "Unusual DNS query pattern - high volume of NXDOMAIN responses", protocol: "DNS", port: 53 },
  { eventType: "malware", severity: "high", source: "Email Gateway", description: "Phishing email with malicious attachment quarantined", protocol: "SMTP", port: 25 },
  { eventType: "intrusion_attempt", severity: "critical", source: "IDS", description: "Possible C2 beacon activity - periodic encrypted connections to known threat IP", protocol: "HTTPS", port: 443 },
  { eventType: "policy_violation", severity: "low", source: "Endpoint", description: "Unauthorized USB device connected to workstation", protocol: "N/A", port: 0 },
  { eventType: "anomaly", severity: "medium", source: "SIEM", description: "Privilege escalation attempt detected - unusual sudo usage pattern", protocol: "N/A", port: 0 },
  { eventType: "reconnaissance", severity: "info", source: "Honeypot", description: "Honeypot interaction detected - automated scanning tools", protocol: "TCP", port: 8080 },
  { eventType: "data_exfiltration", severity: "critical", source: "DLP", description: "Large volume data transfer to unauthorized external endpoint", protocol: "HTTPS", port: 443 },
  { eventType: "malware", severity: "high", source: "Sandbox", description: "Suspicious PowerShell script execution - fileless malware indicators", protocol: "N/A", port: 0 },
  { eventType: "intrusion_attempt", severity: "medium", source: "WAF", description: "Cross-site scripting (XSS) attempt detected and blocked", protocol: "HTTP", port: 443 },
];

function randomIp() {
  const prefixes = ["185.220.101", "45.33.32", "192.168.1", "10.0.0", "172.16.0", "203.0.113", "198.51.100"];
  return `${prefixes[Math.floor(Math.random() * prefixes.length)]}.${Math.floor(Math.random() * 254) + 1}`;
}

function generateRandomEvent() {
  const template = eventTemplates[Math.floor(Math.random() * eventTemplates.length)];
  return {
    ...template,
    sourceIp: randomIp(),
    destinationIp: `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`,
    status: "new" as const,
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

  setInterval(async () => {
    try {
      const event = generateRandomEvent();
      const stored = await storage.createSecurityEvent(event);
      broadcast({ type: "new_event", event: stored });
    } catch {}
  }, 20000);

  app.get("/api/dashboard/stats", async (_req, res) => {
    try {
      const stats = await storage.getDashboardStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch stats" });
    }
  });

  app.get("/api/dashboard/trend", async (_req, res) => {
    try {
      const trend = await storage.getEventTrend();
      res.json(trend);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch trend" });
    }
  });

  app.get("/api/security-events", async (_req, res) => {
    try {
      const events = await storage.getSecurityEvents();
      res.json(events);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch events" });
    }
  });

  app.post("/api/security-events", async (req, res) => {
    try {
      const parsed = insertSecurityEventSchema.parse(req.body);
      const event = await storage.createSecurityEvent(parsed);
      broadcast({ type: "new_event", event });
      res.status(201).json(event);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create event" });
    }
  });

  app.patch("/api/security-events/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const { status } = z.object({ status: z.enum(["new", "investigating", "resolved", "dismissed"]) }).parse(req.body);
      const updated = await storage.updateSecurityEventStatus(id, status);
      if (!updated) return res.status(404).json({ error: "Event not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update event" });
    }
  });

  app.get("/api/incidents", async (_req, res) => {
    try {
      const list = await storage.getIncidents();
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch incidents" });
    }
  });

  app.post("/api/incidents", async (req, res) => {
    try {
      const parsed = insertIncidentSchema.parse(req.body);
      const incident = await storage.createIncident(parsed);
      res.status(201).json(incident);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create incident" });
    }
  });

  app.patch("/api/incidents/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const parsed = insertIncidentSchema.partial().extend({
        status: z.enum(["open", "investigating", "contained", "resolved", "closed"]).optional(),
      }).parse(req.body);
      const updated = await storage.updateIncident(id, parsed);
      if (!updated) return res.status(404).json({ error: "Incident not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update incident" });
    }
  });

  app.get("/api/threat-intel", async (_req, res) => {
    try {
      const list = await storage.getThreatIntel();
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threat intel" });
    }
  });

  app.post("/api/threat-intel", async (req, res) => {
    try {
      const parsed = insertThreatIntelSchema.parse(req.body);
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
      const parsed = z.object({ active: z.boolean() }).parse(req.body);
      const updated = await storage.updateThreatIntel(id, parsed);
      if (!updated) return res.status(404).json({ error: "Indicator not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update indicator" });
    }
  });

  app.get("/api/security-policies", async (_req, res) => {
    try {
      const list = await storage.getSecurityPolicies();
      res.json(list);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch policies" });
    }
  });

  app.post("/api/security-policies", async (req, res) => {
    try {
      const parsed = insertSecurityPolicySchema.parse(req.body);
      const policy = await storage.createSecurityPolicy(parsed);
      res.status(201).json(policy);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create policy" });
    }
  });

  app.patch("/api/security-policies/:id", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const parsed = z.object({ enabled: z.boolean() }).parse(req.body);
      const updated = await storage.updateSecurityPolicy(id, parsed);
      if (!updated) return res.status(404).json({ error: "Policy not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update policy" });
    }
  });

  app.get("/api/ai-conversations", async (_req, res) => {
    try {
      const convs = await chatStorage.getAllConversations();
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
      const conv = await chatStorage.createConversation(req.body.title || "New Analysis");
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
