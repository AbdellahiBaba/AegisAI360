import { Router, Request, Response } from "express";
import { storage } from "./storage";
import type { User } from "@shared/schema";
import os from "os";
import { getSecurityStats } from "./securityMiddleware";

function requireSuperAdmin(req: Request, res: Response, next: any) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Authentication required" });
  const user = req.user as User;
  if (!user.isSuperAdmin) return res.status(403).json({ error: "Super admin access required" });
  next();
}

export function createSuperAdminRouter() {
  const router = Router();
  router.use(requireSuperAdmin);

  router.get("/organizations", async (_req: Request, res: Response) => {
    try {
      const orgs = await storage.getAllOrganizations();
      const orgsWithStats = await Promise.all(
        orgs.map(async (org) => {
          const userCount = await storage.getOrganizationUserCount(org.id);
          return { ...org, userCount };
        })
      );
      res.json(orgsWithStats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch organizations" });
    }
  });

  router.get("/users", async (_req: Request, res: Response) => {
    try {
      const allUsers = await storage.getAllUsers();
      res.json(allUsers);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch users" });
    }
  });

  router.get("/platform-stats", async (_req: Request, res: Response) => {
    try {
      const stats = await storage.getPlatformStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch platform stats" });
    }
  });

  router.post("/organizations/:id/suspend", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const { suspended } = req.body;
      const updated = await storage.updateOrganization(id, { suspended: !!suspended });
      if (!updated) return res.status(404).json({ error: "Organization not found" });

      await storage.createAuditLog({
        organizationId: id,
        userId: (req.user as User).id,
        action: suspended ? "suspend_org" : "unsuspend_org",
        targetType: "organization",
        targetId: String(id),
        details: `Organization ${suspended ? "suspended" : "activated"} by super admin`,
      });

      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update organization" });
    }
  });

  router.post("/organizations/:id/change-plan", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const { plan } = req.body;
      const planLimits: Record<string, number> = { starter: 5, professional: 25, enterprise: 100 };
      const updated = await storage.updateOrganization(id, { plan, maxUsers: planLimits[plan] || 5 });
      if (!updated) return res.status(404).json({ error: "Organization not found" });

      await storage.createAuditLog({
        organizationId: id,
        userId: (req.user as User).id,
        action: "change_plan",
        targetType: "organization",
        targetId: String(id),
        details: `Plan changed to ${plan} by super admin`,
      });

      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update plan" });
    }
  });

  router.get("/audit-log", async (_req: Request, res: Response) => {
    try {
      const logs = await storage.getAllAuditLogs();
      res.json(logs);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch audit logs" });
    }
  });

  router.get("/security-stats", async (_req: Request, res: Response) => {
    try {
      const stats = getSecurityStats();
      res.json(stats);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch security stats" });
    }
  });

  router.get("/system-health", async (_req: Request, res: Response) => {
    try {
      const uptime = process.uptime();
      const memUsage = process.memoryUsage();
      const loadAvg = os.loadavg();

      res.json({
        uptime: Math.floor(uptime),
        memory: {
          heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
          heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
          rss: Math.round(memUsage.rss / 1024 / 1024),
        },
        loadAvg: loadAvg.map(l => Math.round(l * 100) / 100),
        platform: os.platform(),
        nodeVersion: process.version,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch system health" });
    }
  });

  return router;
}
