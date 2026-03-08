import { db } from "./db";
import { storage } from "./storage";
import {
  securityEvents,
  auditLogs,
  honeypotEvents,
  packetCaptures,
  agentCommands,
  organizations,
} from "@shared/schema";
import { lt, sql, and, eq } from "drizzle-orm";

async function cleanupForOrganization(org: { id: number; logRetentionDays: number; auditRetentionDays: number }) {
  const now = new Date();
  const logCutoff = new Date(now.getTime() - org.logRetentionDays * 24 * 60 * 60 * 1000);
  const auditCutoff = new Date(now.getTime() - org.auditRetentionDays * 24 * 60 * 60 * 1000);
  const honeypotCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const commandCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const captureCutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  let deletedEvents = 0;
  let deletedAuditLogs = 0;
  let deletedHoneypot = 0;
  let deletedCaptures = 0;
  let deletedCommands = 0;

  const eventsResult = await db.delete(securityEvents)
    .where(and(eq(securityEvents.organizationId, org.id), lt(securityEvents.createdAt, logCutoff)))
    .returning({ id: securityEvents.id });
  deletedEvents = eventsResult.length;

  const auditResult = await db.delete(auditLogs)
    .where(and(eq(auditLogs.organizationId, org.id), lt(auditLogs.createdAt, auditCutoff)))
    .returning({ id: auditLogs.id });
  deletedAuditLogs = auditResult.length;

  const honeypotResult = await db.delete(honeypotEvents)
    .where(and(eq(honeypotEvents.organizationId, org.id), lt(honeypotEvents.createdAt, honeypotCutoff)))
    .returning({ id: honeypotEvents.id });
  deletedHoneypot = honeypotResult.length;

  const captureResult = await db.delete(packetCaptures)
    .where(and(eq(packetCaptures.organizationId, org.id), lt(packetCaptures.createdAt, captureCutoff)))
    .returning({ id: packetCaptures.id });
  deletedCaptures = captureResult.length;

  const staleCommandResult = await db.delete(agentCommands)
    .where(and(
      lt(agentCommands.createdAt, commandCutoff),
      sql`${agentCommands.status} IN ('completed', 'failed')`
    ))
    .returning({ id: agentCommands.id });
  deletedCommands = staleCommandResult.length;

  return { deletedEvents, deletedAuditLogs, deletedHoneypot, deletedCaptures, deletedCommands };
}

export async function runDataRetention() {
  try {
    const allOrgs = await storage.getAllOrganizations();

    let totalStats = { deletedEvents: 0, deletedAuditLogs: 0, deletedHoneypot: 0, deletedCaptures: 0, deletedCommands: 0 };

    for (const org of allOrgs) {
      const stats = await cleanupForOrganization(org);
      totalStats.deletedEvents += stats.deletedEvents;
      totalStats.deletedAuditLogs += stats.deletedAuditLogs;
      totalStats.deletedHoneypot += stats.deletedHoneypot;
      totalStats.deletedCaptures += stats.deletedCaptures;
      totalStats.deletedCommands += stats.deletedCommands;

      const totalDeleted = stats.deletedEvents + stats.deletedAuditLogs + stats.deletedHoneypot + stats.deletedCaptures + stats.deletedCommands;
      if (totalDeleted > 0) {
        await storage.createAuditLog({
          organizationId: org.id,
          userId: "system",
          action: "data_retention_cleanup",
          targetType: "organization",
          targetId: String(org.id),
          details: `Automated cleanup: ${stats.deletedEvents} events, ${stats.deletedAuditLogs} audit logs, ${stats.deletedHoneypot} honeypot events, ${stats.deletedCaptures} packet captures, ${stats.deletedCommands} stale commands removed`,
        });
      }
    }

    const grandTotal = totalStats.deletedEvents + totalStats.deletedAuditLogs + totalStats.deletedHoneypot + totalStats.deletedCaptures + totalStats.deletedCommands;
    if (grandTotal > 0) {
      console.log(`[DataRetention] Cleanup complete: ${grandTotal} total records removed across ${allOrgs.length} organizations`);
    }

    return totalStats;
  } catch (error) {
    console.error("[DataRetention] Cleanup failed:", error);
    throw error;
  }
}

export function startDataRetentionScheduler() {
  const ONE_DAY_MS = 24 * 60 * 60 * 1000;

  const now = new Date();
  const midnight = new Date(now);
  midnight.setHours(24, 0, 0, 0);
  const msUntilMidnight = midnight.getTime() - now.getTime();

  setTimeout(() => {
    runDataRetention().catch(console.error);
    setInterval(() => {
      runDataRetention().catch(console.error);
    }, ONE_DAY_MS);
  }, msUntilMidnight);

  console.log(`[DataRetention] Scheduler started. First cleanup in ${Math.round(msUntilMidnight / 60000)} minutes`);
}
