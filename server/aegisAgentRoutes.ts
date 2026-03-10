import type { Express, Request, Response } from "express";
import { z } from "zod";
import { requireAuth, requirePlanFeature } from "./auth";
import { storage } from "./storage";
import {
  streamAgentChat,
  generateSecureCode,
  generateCodePackage,
  AGENT_CAPABILITIES,
  type CodeBlock,
} from "./aegisAgent";
import type { User } from "@shared/schema";

function getOrgId(req: Request): number {
  const user = req.user as User;
  if (!user.organizationId) throw new Error("No organization");
  return user.organizationId;
}

function getUserId(req: Request): string {
  return (req.user as User).id;
}

async function verifyConversationOwnership(conversationId: number, orgId: number, userId: string): Promise<boolean> {
  const conversations = await storage.getAgentConversations(orgId, userId);
  return conversations.some((c) => c.id === conversationId);
}

const agentPlanGate = requirePlanFeature("allowAegisAgent");

export function registerAegisAgentRoutes(app: Express): void {
  app.get("/api/aegis-agent/capabilities", requireAuth, agentPlanGate, (_req: Request, res: Response) => {
    res.json(AGENT_CAPABILITIES);
  });

  app.get("/api/aegis-agent/conversations", requireAuth, agentPlanGate, async (req: Request, res: Response) => {
    try {
      const conversations = await storage.getAgentConversations(getOrgId(req), getUserId(req));
      res.json(conversations);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch conversations" });
    }
  });

  app.delete("/api/aegis-agent/conversations/:id", requireAuth, agentPlanGate, async (req: Request, res: Response) => {
    try {
      const id = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const owns = await verifyConversationOwnership(id, orgId, userId);
      if (!owns) return res.status(404).json({ error: "Conversation not found" });
      await storage.deleteAgentConversation(id, orgId);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete conversation" });
    }
  });

  app.get("/api/aegis-agent/conversations/:id/messages", requireAuth, agentPlanGate, async (req: Request, res: Response) => {
    try {
      const conversationId = parseInt(req.params.id);
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const owns = await verifyConversationOwnership(conversationId, orgId, userId);
      if (!owns) return res.status(404).json({ error: "Conversation not found" });
      const messages = await storage.getAgentMessages(conversationId);
      res.json(messages);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch messages" });
    }
  });

  app.post("/api/aegis-agent/chat", requireAuth, agentPlanGate, async (req: Request, res: Response) => {
    try {
      const orgId = getOrgId(req);
      const userId = getUserId(req);
      const { message, conversationId } = z.object({
        message: z.string().min(1).max(10000),
        conversationId: z.number().optional(),
      }).parse(req.body);

      let convId = conversationId;

      if (convId) {
        const owns = await verifyConversationOwnership(convId, orgId, userId);
        if (!owns) return res.status(404).json({ error: "Conversation not found" });
      } else {
        const title = message.substring(0, 80) + (message.length > 80 ? "..." : "");
        const conv = await storage.createAgentConversation({
          organizationId: orgId,
          userId,
          title,
          mode: "chat",
        });
        convId = conv.id;
      }

      await storage.createAgentMessage({
        conversationId: convId,
        role: "user",
        content: message,
      });

      const history = await storage.getAgentMessages(convId);
      const chatMessages = history.map((m) => ({
        role: m.role as "user" | "assistant",
        content: m.content,
      }));

      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("X-Conversation-Id", String(convId));
      res.flushHeaders();

      streamAgentChat(
        chatMessages,
        (text) => {
          res.write(`data: ${JSON.stringify({ type: "chunk", text })}\n\n`);
        },
        async (fullResponse, codeBlocks) => {
          await storage.createAgentMessage({
            conversationId: convId!,
            role: "assistant",
            content: fullResponse,
            codeBlocks: codeBlocks.length > 0 ? codeBlocks : null,
          });
          res.write(`data: ${JSON.stringify({ type: "done", conversationId: convId, codeBlocks })}\n\n`);
          res.end();
        },
        (error) => {
          res.write(`data: ${JSON.stringify({ type: "error", error: error.message })}\n\n`);
          res.end();
        },
      );
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid request" });
      }
      res.status(500).json({ error: "Failed to process chat" });
    }
  });

  app.post("/api/aegis-agent/generate-code", requireAuth, agentPlanGate, async (req: Request, res: Response) => {
    try {
      const { task, language } = z.object({
        task: z.string().min(1).max(5000),
        language: z.string().min(1).max(50),
      }).parse(req.body);

      const result = await generateSecureCode(task, language);
      res.json(result);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid request" });
      }
      res.status(500).json({ error: "Failed to generate code" });
    }
  });

  app.post("/api/aegis-agent/package-download", requireAuth, agentPlanGate, (req: Request, res: Response) => {
    try {
      const { code, filename } = z.object({
        code: z.string().min(1).max(1000000),
        filename: z.string().min(1).max(255),
      }).parse(req.body);

      const safeName = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
      const buffer = generateCodePackage(code, safeName);

      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${safeName}"`);
      res.setHeader("Content-Length", buffer.length.toString());
      res.send(buffer);
    } catch (error: any) {
      if (error?.name === "ZodError") {
        return res.status(400).json({ error: "Invalid request" });
      }
      res.status(500).json({ error: "Failed to package code" });
    }
  });
}
