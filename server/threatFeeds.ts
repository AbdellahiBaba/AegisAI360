import { Router, Request, Response } from "express";
import { storage } from "./storage";
import { requireAuth } from "./auth";
import type { User } from "@shared/schema";

function getOrgId(req: Request): number {
  return (req.user as User).organizationId!;
}

export function createThreatFeedsRouter() {
  const router = Router();
  router.use(requireAuth);

  router.get("/configs", async (req: Request, res: Response) => {
    try {
      const configs = await storage.getThreatFeedConfigs(getOrgId(req));
      const sanitized = configs.map(c => ({ ...c, apiKey: c.apiKey ? "********" : null }));
      res.json(sanitized);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch feed configs" });
    }
  });

  router.post("/configs", async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const { feedName, apiKey, enabled } = req.body;
      const config = await storage.createThreatFeedConfig({
        organizationId: orgId,
        feedName,
        apiKey: apiKey || null,
        enabled: !!enabled,
      });
      res.status(201).json({ ...config, apiKey: config.apiKey ? "********" : null });
    } catch (error) {
      res.status(500).json({ error: "Failed to create feed config" });
    }
  });

  router.patch("/configs/:id", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const data: any = {};
      if (req.body.enabled !== undefined) data.enabled = req.body.enabled;
      if (req.body.apiKey !== undefined) data.apiKey = req.body.apiKey;
      const updated = await storage.updateThreatFeedConfig(id, orgId, data);
      if (!updated) return res.status(404).json({ error: "Config not found" });
      res.json({ ...updated, apiKey: updated.apiKey ? "********" : null });
    } catch (error) {
      res.status(500).json({ error: "Failed to update feed config" });
    }
  });

  router.post("/check-ip", async (req: Request, res: Response) => {
    try {
      const { ip } = req.body;
      if (!ip) return res.status(400).json({ error: "IP required" });

      const orgId = getOrgId(req);
      const configs = await storage.getThreatFeedConfigs(orgId);
      const abuseConfig = configs.find(c => c.feedName === "AbuseIPDB" && c.enabled && c.apiKey);

      if (!abuseConfig) {
        return res.json({ source: "local", result: "No AbuseIPDB API key configured. Add one in Settings > Integrations." });
      }

      try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
          headers: { "Key": abuseConfig.apiKey!, "Accept": "application/json" },
        });
        const data = await response.json();
        res.json({ source: "AbuseIPDB", result: data });
      } catch {
        res.json({ source: "AbuseIPDB", error: "API request failed" });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to check IP" });
    }
  });

  router.post("/check-hash", async (req: Request, res: Response) => {
    try {
      const { hash } = req.body;
      if (!hash) return res.status(400).json({ error: "Hash required" });

      const orgId = getOrgId(req);
      const configs = await storage.getThreatFeedConfigs(orgId);
      const vtConfig = configs.find(c => c.feedName === "VirusTotal" && c.enabled && c.apiKey);

      if (!vtConfig) {
        return res.json({ source: "local", result: "No VirusTotal API key configured. Add one in Settings > Integrations." });
      }

      try {
        const response = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(hash)}`, {
          headers: { "x-apikey": vtConfig.apiKey! },
        });
        const data = await response.json();
        res.json({ source: "VirusTotal", result: data });
      } catch {
        res.json({ source: "VirusTotal", error: "API request failed" });
      }
    } catch (error) {
      res.status(500).json({ error: "Failed to check hash" });
    }
  });

  return router;
}
