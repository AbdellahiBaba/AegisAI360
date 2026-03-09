import { storage } from "./storage";
import { sendReportEmail } from "./notificationService";
import { log } from "./index";
import { calculateNextRun } from "./scanScheduler";
import type { ScheduledReport } from "@shared/schema";

function buildReportHtml(
  reportType: string,
  stats: {
    totalEvents: number;
    criticalAlerts: number;
    activeIncidents: number;
    threatScore: number;
    eventTrend: number;
    assetCount: number;
    quarantineCount: number;
    honeypotActivity: number;
    blockedIps: number;
    activeRules: number;
  },
): string {
  const now = new Date().toLocaleString("en-US", { dateStyle: "full", timeStyle: "short" });

  const threatColor =
    stats.threatScore >= 75 ? "#dc2626" :
    stats.threatScore >= 50 ? "#ea580c" :
    stats.threatScore >= 25 ? "#ca8a04" : "#16a34a";

  const trendIcon = stats.eventTrend > 0 ? "+" : "";

  let title = "Security Report";
  let bodyContent = "";

  switch (reportType) {
    case "executive_summary":
      title = "Executive Security Summary";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b; border-left: 3px solid #D4AF37; padding-left: 10px;">Security Posture Overview</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%; border-top: 2px solid #D4AF37;">
              <div style="font-size: 28px; font-weight: bold; color: ${threatColor};">${stats.threatScore}</div>
              <div style="font-size: 12px; color: #64748b;">Threat Score</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%; border-top: 2px solid #D4AF37;">
              <div style="font-size: 28px; font-weight: bold; color: #1e293b;">${stats.totalEvents}</div>
              <div style="font-size: 12px; color: #64748b;">Events (24h) ${trendIcon}${stats.eventTrend}%</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%; border-top: 2px solid #D4AF37;">
              <div style="font-size: 28px; font-weight: bold; color: #dc2626;">${stats.criticalAlerts}</div>
              <div style="font-size: 12px; color: #64748b;">Critical Alerts</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%; border-top: 2px solid #D4AF37;">
              <div style="font-size: 28px; font-weight: bold; color: #ea580c;">${stats.activeIncidents}</div>
              <div style="font-size: 12px; color: #64748b;">Active Incidents</div>
            </td>
          </tr>
        </table>
        <h3 style="margin: 24px 0 8px; color: #1e293b; border-left: 3px solid #D4AF37; padding-left: 10px;">Infrastructure Summary</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Monitored Assets</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.assetCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Quarantined Items</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.quarantineCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Honeypot Activity (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.honeypotActivity}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Firewall Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.blockedIps}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Active Alert Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeRules}</td></tr>
        </table>`;
      break;

    case "incident":
      title = "Incident Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b; border-left: 3px solid #D4AF37; padding-left: 10px;">Incident Status</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Active Incidents</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: #ea580c;">${stats.activeIncidents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Critical Alerts (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: #dc2626;">${stats.criticalAlerts}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Total Events (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.totalEvents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Quarantined Items</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.quarantineCount}</td></tr>
        </table>
        <p style="color: #64748b; font-size: 13px; margin-top: 16px;">For detailed incident investigation, please log in to the <span style="color: #D4AF37; font-weight: 600;">AegisAI360</span> dashboard.</p>`;
      break;

    case "compliance":
      title = "Compliance Status Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b; border-left: 3px solid #D4AF37; padding-left: 10px;">Security Compliance Overview</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Threat Score</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: ${threatColor};">${stats.threatScore}/100</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Alert Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeRules}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Monitored Assets</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.assetCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Firewall Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.blockedIps}</td></tr>
        </table>
        <p style="color: #64748b; font-size: 13px; margin-top: 16px;">For full compliance assessments (NIST, SOC2, ISO 27001), please use the Compliance page in the <span style="color: #D4AF37; font-weight: 600;">AegisAI360</span> dashboard.</p>`;
      break;

    default:
      title = "Security Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b; border-left: 3px solid #D4AF37; padding-left: 10px;">Summary</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Threat Score</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.threatScore}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Total Events (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.totalEvents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b; background: #fdfaf0;">Critical Alerts</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.criticalAlerts}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Incidents</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeIncidents}</td></tr>
        </table>`;
  }

  const shieldSvg = `<svg width="36" height="36" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path d="M24 2L6 10v12c0 11.1 7.7 21.4 18 24 10.3-2.6 18-12.9 18-24V10L24 2z" fill="#D4AF37" stroke="#E5C75D" stroke-width="0.5" stroke-opacity="0.6"/>
    <path d="M24 6L10 12.5v9.5c0 9 6 17.5 14 19.8 8-2.3 14-10.8 14-19.8v-9.5L24 6z" fill="#0f172a" stroke="#D4AF37" stroke-width="0.3" stroke-opacity="0.4"/>
    <circle cx="24" cy="20" r="5" fill="none" stroke="#D4AF37" stroke-width="1.2"/>
    <circle cx="24" cy="20" r="2" fill="#D4AF37"/>
    <line x1="24" y1="15" x2="24" y2="10" stroke="#D4AF37" stroke-width="0.8"/>
    <line x1="24" y1="25" x2="24" y2="30" stroke="#D4AF37" stroke-width="0.8"/>
    <line x1="19" y1="20" x2="14" y2="20" stroke="#D4AF37" stroke-width="0.8"/>
    <line x1="29" y1="20" x2="34" y2="20" stroke="#D4AF37" stroke-width="0.8"/>
    <circle cx="14" cy="20" r="1" fill="#D4AF37" fill-opacity="0.7"/>
    <circle cx="34" cy="20" r="1" fill="#D4AF37" fill-opacity="0.7"/>
    <circle cx="24" cy="10" r="1" fill="#D4AF37" fill-opacity="0.7"/>
    <circle cx="24" cy="30" r="1" fill="#D4AF37" fill-opacity="0.7"/>
  </svg>`;

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 640px; margin: 0 auto;">
      <div style="background: #D4AF37; height: 3px; border-radius: 8px 8px 0 0;"></div>
      <div style="background: #0f172a; color: white; padding: 20px 24px;">
        <table style="width: 100%; border: none;"><tr>
          <td style="vertical-align: middle; width: 44px; border: none; padding: 0;">${shieldSvg}</td>
          <td style="vertical-align: middle; padding-left: 12px; border: none;">
            <div style="font-size: 16px; font-weight: bold; color: #D4AF37; letter-spacing: 2px;">AEGIS<span style="color: #E5C75D;">AI</span></div>
            <div style="font-size: 8px; color: #94a3b8; letter-spacing: 3px; text-transform: uppercase;">Cyber Defense Platform</div>
          </td>
          <td style="vertical-align: middle; text-align: right; border: none; padding: 0;">
            <div style="background: #D4AF37; color: #0f172a; font-size: 9px; font-weight: bold; padding: 3px 10px; border-radius: 3px; display: inline-block; letter-spacing: 1px;">CONFIDENTIAL</div>
          </td>
        </tr></table>
      </div>
      <div style="background: #141e37; padding: 14px 24px; border-bottom: 1px solid #1e293b;">
        <h2 style="margin: 0; font-size: 16px; color: #ffffff; font-weight: 600;">${title}</h2>
        <p style="margin: 4px 0 0; font-size: 12px; color: #94a3b8;">${now}</p>
      </div>
      <div style="border: 1px solid #e2e8f0; border-top: none; padding: 24px; background: #ffffff;">
        ${bodyContent}
      </div>
      <div style="border: 1px solid #e2e8f0; border-top: none; padding: 16px 24px; background: #fdfaf0; border-radius: 0 0 8px 8px;">
        <table style="width: 100%; border: none;"><tr>
          <td style="border: none; padding: 0; text-align: center;">
            <div style="height: 1px; background: linear-gradient(to right, transparent, #D4AF37, transparent); margin-bottom: 12px;"></div>
            <div style="font-size: 10px; color: #D4AF37; font-weight: bold; letter-spacing: 1px;">AEGISAI360</div>
            <p style="font-size: 11px; color: #94a3b8; margin: 4px 0 0;">This report was automatically generated by AegisAI360 Cyber Defense Platform</p>
            <p style="font-size: 10px; color: #a3821f; margin: 6px 0 0;"><a href="https://aegisai360.com" style="color: #a3821f; text-decoration: none;">aegisai360.com</a></p>
          </td>
        </tr></table>
      </div>
    </div>`;
}

async function executeReport(report: ScheduledReport) {
  const now = new Date();

  try {
    const stats = await storage.getDashboardStats(report.organizationId);
    const html = buildReportHtml(report.reportType, stats);
    const recipients = report.recipients.split(",").map((e) => e.trim()).filter(Boolean);

    if (recipients.length === 0) {
      log(`Scheduled report ${report.id}: no recipients configured`, "report-scheduler");
      return;
    }

    const typeLabel = report.reportType.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    const subject = `[AegisAI360] ${typeLabel} - ${now.toLocaleDateString("en-US")}`;

    const result = await sendReportEmail(recipients, subject, html);

    if (result.success) {
      log(`Scheduled report ${report.id} (${report.reportType}) sent to ${recipients.length} recipient(s)`, "report-scheduler");
    } else {
      log(`Scheduled report ${report.id} email failed: ${result.error}`, "report-scheduler");
    }
  } catch (err: any) {
    log(`Scheduled report ${report.id} execution error: ${err.message}`, "report-scheduler");
  }

  const nextRun = calculateNextRun(report.frequency, now);
  await storage.updateScheduledReport(report.id, report.organizationId, {
    lastRun: now,
    nextRun,
  });
}

let reportSchedulerInterval: ReturnType<typeof setInterval> | null = null;

export function startReportScheduler() {
  if (reportSchedulerInterval) return;

  log("Report scheduler started (checking every 60s)", "report-scheduler");

  reportSchedulerInterval = setInterval(async () => {
    try {
      const dueReports = await storage.getDueScheduledReports();
      if (dueReports.length > 0) {
        log(`Found ${dueReports.length} due scheduled report(s)`, "report-scheduler");
        for (const report of dueReports) {
          await executeReport(report);
        }
      }
    } catch (err: any) {
      log(`Report scheduler error: ${err.message}`, "report-scheduler");
    }
  }, 60 * 1000);
}

export function stopReportScheduler() {
  if (reportSchedulerInterval) {
    clearInterval(reportSchedulerInterval);
    reportSchedulerInterval = null;
  }
}
