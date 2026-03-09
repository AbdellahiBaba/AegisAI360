import { Router, Request, Response } from "express";
import { storage } from "./storage";
import type { User } from "@shared/schema";
import os from "os";
import { getSecurityStats } from "./securityMiddleware";
import { z } from "zod";

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
      const orgsWithStats = await storage.getAllOrganizationsWithUserCount();
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

  router.get("/support/tickets", async (_req: Request, res: Response) => {
    try {
      const tickets = await storage.getAllSupportTickets();
      res.json(tickets);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch support tickets" });
    }
  });

  router.patch("/support/tickets/:id", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const parsed = z.object({
        status: z.enum(["open", "in_progress", "resolved", "closed"]).optional(),
        priority: z.enum(["low", "medium", "high", "critical"]).optional(),
        assignedTo: z.string().nullable().optional(),
      }).parse(req.body);
      const data: any = {};
      if (parsed.status) data.status = parsed.status;
      if (parsed.priority) data.priority = parsed.priority;
      if (parsed.assignedTo !== undefined) data.assignedTo = parsed.assignedTo;
      const updated = await storage.updateSupportTicket(id, data);
      if (!updated) return res.status(404).json({ error: "Ticket not found" });
      await storage.createAuditLog({
        organizationId: updated.organizationId,
        userId: (req.user as User).id,
        action: "update_support_ticket",
        targetType: "support_ticket",
        targetId: String(id),
        details: `Ticket updated: ${JSON.stringify(data)}`,
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update ticket" });
    }
  });

  router.post("/support/tickets/:id/messages", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const ticket = await storage.getSupportTicket(id);
      if (!ticket) return res.status(404).json({ error: "Ticket not found" });
      const { content } = req.body;
      if (!content) return res.status(400).json({ error: "Content required" });
      const messages = Array.isArray(ticket.messages) ? [...(ticket.messages as any[])] : [];
      messages.push({ role: "admin", userId: (req.user as User).id, content, timestamp: new Date().toISOString() });
      const updated = await storage.updateSupportTicket(id, { messages, status: ticket.status === "open" ? "in_progress" : ticket.status });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to add message" });
    }
  });

  router.post("/support/tickets/:id/remote-session", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const { active } = req.body;
      const updated = await storage.updateSupportTicket(id, { remoteSessionActive: !!active });
      if (!updated) return res.status(404).json({ error: "Ticket not found" });
      await storage.createAuditLog({
        organizationId: updated.organizationId,
        userId: (req.user as User).id,
        action: active ? "start_remote_session" : "end_remote_session",
        targetType: "support_ticket",
        targetId: String(id),
        details: `Remote session ${active ? "started" : "ended"} by super admin`,
      });
      res.json(updated);
    } catch (error) {
      res.status(500).json({ error: "Failed to update remote session" });
    }
  });

  router.post("/support/tickets/:id/take-action", async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const ticket = await storage.getSupportTicket(id);
      if (!ticket) return res.status(404).json({ error: "Ticket not found" });
      const { actionType, details } = req.body;
      if (!actionType) return res.status(400).json({ error: "Action type required" });
      const messages = Array.isArray(ticket.messages) ? [...(ticket.messages as any[])] : [];
      messages.push({ role: "system", content: `Admin action: ${actionType} - ${details || ""}`, timestamp: new Date().toISOString() });
      await storage.updateSupportTicket(id, { messages });
      await storage.createAuditLog({
        organizationId: ticket.organizationId,
        userId: (req.user as User).id,
        action: "admin_support_action",
        targetType: "support_ticket",
        targetId: String(id),
        details: `Action: ${actionType} - ${details || "No details"}`,
      });
      res.json({ success: true, actionType, details });
    } catch (error) {
      res.status(500).json({ error: "Failed to execute action" });
    }
  });

  router.get("/system-health", async (_req: Request, res: Response) => {
    try {
      const uptime = process.uptime();
      const memUsage = process.memoryUsage();
      const loadAvg = os.loadavg();

      const totalMem = os.totalmem();
      const freeMem = os.freemem();
      const usedMem = totalMem - freeMem;
      res.json({
        uptime: Math.floor(uptime),
        memory: {
          used: usedMem,
          total: totalMem,
          percentage: (usedMem / totalMem) * 100,
        },
        load: loadAvg.map(l => Math.round(l * 100) / 100),
        platform: os.platform(),
        nodeVersion: process.version,
      });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch system health" });
    }
  });

  return router;
}
