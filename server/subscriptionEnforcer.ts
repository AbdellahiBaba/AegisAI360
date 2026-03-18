import { storage } from "./storage";

const CHECK_INTERVAL_MS = 5 * 60 * 1000;

async function enforceSubscriptions() {
  try {
    const expired = await storage.getOrgsWithExpiredSubscriptions();
    for (const org of expired) {
      await storage.updateOrganization(org.id, { subscriptionStatus: "expired" });
      console.log(`[SubscriptionEnforcer] Org #${org.id} (${org.name}) subscription expired — agents will be disconnected on next heartbeat.`);
      try {
        await storage.createAuditLog({
          organizationId: org.id,
          userId: "system",
          action: "subscription_auto_expired",
          targetType: "organization",
          targetId: String(org.id),
          details: `Subscription auto-expired at ${new Date().toISOString()}. All agents will disconnect within 60 seconds.`,
        });
      } catch (_) {}
    }
  } catch (err) {
    console.error("[SubscriptionEnforcer] Error during enforcement check:", err);
  }
}

export function startSubscriptionEnforcer() {
  console.log("[SubscriptionEnforcer] Started — checking every 5 minutes.");
  enforceSubscriptions();
  setInterval(enforceSubscriptions, CHECK_INTERVAL_MS);
}
