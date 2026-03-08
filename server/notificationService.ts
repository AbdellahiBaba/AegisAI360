import { storage } from "./storage";
import type { NotificationChannel } from "@shared/schema";

interface AlertPayload {
  ruleName: string;
  severity: string;
  eventDescription: string;
  eventSource: string;
  sourceIp: string | null;
  timestamp: string;
  organizationId: number;
}

function isPrivateUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    if (!["https:", "http:"].includes(parsed.protocol)) return true;
    const host = parsed.hostname.toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0") return true;
    if (host.startsWith("10.") || host.startsWith("192.168.") || host.endsWith(".local") || host.endsWith(".internal")) return true;
    if (host.startsWith("172.")) {
      const second = parseInt(host.split(".")[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
    if (host === "169.254.169.254" || host.startsWith("metadata.")) return true;
    return false;
  } catch {
    return true;
  }
}

async function sendWebhook(channel: NotificationChannel, payload: AlertPayload): Promise<{ success: boolean; error?: string }> {
  try {
    const config = channel.config as { url: string; secret?: string };
    if (!config.url) return { success: false, error: "No webhook URL configured" };
    if (isPrivateUrl(config.url)) return { success: false, error: "Webhook URL must be a public HTTPS endpoint" };

    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (config.secret) {
      const { createHmac } = await import("crypto");
      const body = JSON.stringify(payload);
      const signature = createHmac("sha256", config.secret).update(body).digest("hex");
      headers["X-Signature-256"] = `sha256=${signature}`;
    }

    const resp = await fetch(config.url, {
      method: "POST",
      headers,
      body: JSON.stringify({
        event: "alert_triggered",
        ...payload,
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      return { success: false, error: `HTTP ${resp.status}: ${resp.statusText}` };
    }
    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message || "Webhook delivery failed" };
  }
}

async function sendEmail(channel: NotificationChannel, payload: AlertPayload): Promise<{ success: boolean; error?: string }> {
  try {
    const config = channel.config as { recipients: string };
    if (!config.recipients) return { success: false, error: "No recipients configured" };

    const smtpHost = process.env.SMTP_HOST;
    const smtpPort = parseInt(process.env.SMTP_PORT || "587");
    const smtpUser = process.env.SMTP_USER;
    const smtpPass = process.env.SMTP_PASS;
    const smtpFrom = process.env.SMTP_FROM || smtpUser;

    if (!smtpHost || !smtpUser || !smtpPass) {
      return { success: false, error: "SMTP not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS environment variables." };
    }

    const nodemailer = require("nodemailer") as typeof import("nodemailer");
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
    });

    const recipients = config.recipients.split(",").map((e: string) => e.trim()).filter(Boolean);

    const severityColors: Record<string, string> = {
      critical: "#dc2626",
      high: "#ea580c",
      medium: "#ca8a04",
      low: "#2563eb",
      info: "#6b7280",
    };
    const color = severityColors[payload.severity] || "#6b7280";

    const html = `
      <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #0f172a; color: white; padding: 16px 24px; border-radius: 8px 8px 0 0;">
          <h2 style="margin: 0;">AegisAI360 Alert</h2>
        </div>
        <div style="border: 1px solid #e2e8f0; border-top: none; padding: 24px; border-radius: 0 0 8px 8px;">
          <div style="display: inline-block; background: ${color}; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 12px;">
            ${payload.severity}
          </div>
          <h3 style="margin: 8px 0;">${payload.ruleName}</h3>
          <p style="color: #475569; margin: 8px 0;">${payload.eventDescription}</p>
          <table style="width: 100%; border-collapse: collapse; margin-top: 16px;">
            <tr><td style="padding: 6px 0; color: #64748b; font-size: 13px;">Source</td><td style="padding: 6px 0; font-size: 13px;">${payload.eventSource}</td></tr>
            <tr><td style="padding: 6px 0; color: #64748b; font-size: 13px;">Source IP</td><td style="padding: 6px 0; font-size: 13px;">${payload.sourceIp || "N/A"}</td></tr>
            <tr><td style="padding: 6px 0; color: #64748b; font-size: 13px;">Time</td><td style="padding: 6px 0; font-size: 13px;">${payload.timestamp}</td></tr>
          </table>
        </div>
      </div>
    `;

    await transporter.sendMail({
      from: smtpFrom,
      to: recipients.join(", "),
      subject: `[${payload.severity.toUpperCase()}] AegisAI360 Alert: ${payload.ruleName}`,
      html,
    });

    return { success: true };
  } catch (err: any) {
    return { success: false, error: err.message || "Email delivery failed" };
  }
}

export async function dispatchToChannels(payload: AlertPayload): Promise<void> {
  try {
    const channels = await storage.getNotificationChannels(payload.organizationId);
    const enabledChannels = channels.filter((c) => c.enabled);

    for (const channel of enabledChannels) {
      let result: { success: boolean; error?: string };

      if (channel.type === "webhook") {
        result = await sendWebhook(channel, payload);
      } else if (channel.type === "email") {
        result = await sendEmail(channel, payload);
      } else {
        continue;
      }

      if (result.success) {
        await storage.updateNotificationChannel(channel.id, payload.organizationId, { lastUsed: new Date() });
      } else {
        console.error(`Notification channel "${channel.name}" (${channel.type}) failed:`, result.error);
      }
    }
  } catch (err) {
    console.error("Error dispatching to notification channels:", err);
  }
}

export async function testChannel(channel: NotificationChannel): Promise<{ success: boolean; error?: string }> {
  const testPayload: AlertPayload = {
    ruleName: "Test Notification",
    severity: "info",
    eventDescription: "This is a test notification from AegisAI360 to verify your notification channel configuration.",
    eventSource: "notification-test",
    sourceIp: "127.0.0.1",
    timestamp: new Date().toISOString(),
    organizationId: channel.organizationId,
  };

  if (channel.type === "webhook") {
    return sendWebhook(channel, testPayload);
  } else if (channel.type === "email") {
    return sendEmail(channel, testPayload);
  }
  return { success: false, error: "Unknown channel type" };
}
