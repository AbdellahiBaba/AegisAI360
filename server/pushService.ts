import webpush from "web-push";
import { storage } from "./storage";

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || "";
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || "";
const VAPID_SUBJECT = "mailto:admin@aegisai360.com";

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

export function getVapidPublicKey(): string {
  return VAPID_PUBLIC_KEY;
}

export async function sendPushToUser(userId: string, payload: { title: string; body: string; url?: string; icon?: string }) {
  const subs = await storage.getPushSubscriptionsByUser(userId);
  const results: { endpoint: string; success: boolean; error?: string }[] = [];

  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        JSON.stringify(payload)
      );
      results.push({ endpoint: sub.endpoint, success: true });
    } catch (err: any) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        await storage.deletePushSubscriptionByEndpoint(sub.endpoint);
      }
      results.push({ endpoint: sub.endpoint, success: false, error: err.message });
    }
  }

  return results;
}

export async function sendPushToAll(payload: { title: string; body: string; url?: string; icon?: string }) {
  const subs = await storage.getAllPushSubscriptions();
  const results: { endpoint: string; success: boolean; error?: string }[] = [];

  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        JSON.stringify(payload)
      );
      results.push({ endpoint: sub.endpoint, success: true });
    } catch (err: any) {
      if (err.statusCode === 410 || err.statusCode === 404) {
        await storage.deletePushSubscriptionByEndpoint(sub.endpoint);
      }
      results.push({ endpoint: sub.endpoint, success: false, error: err.message });
    }
  }

  return results;
}
