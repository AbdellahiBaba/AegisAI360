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
        <h3 style="margin: 16px 0 8px; color: #1e293b;">Security Posture Overview</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%;">
              <div style="font-size: 28px; font-weight: bold; color: ${threatColor};">${stats.threatScore}</div>
              <div style="font-size: 12px; color: #64748b;">Threat Score</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%;">
              <div style="font-size: 28px; font-weight: bold; color: #1e293b;">${stats.totalEvents}</div>
              <div style="font-size: 12px; color: #64748b;">Events (24h) ${trendIcon}${stats.eventTrend}%</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%;">
              <div style="font-size: 28px; font-weight: bold; color: #dc2626;">${stats.criticalAlerts}</div>
              <div style="font-size: 12px; color: #64748b;">Critical Alerts</div>
            </td>
            <td style="padding: 12px; border: 1px solid #e2e8f0; text-align: center; width: 25%;">
              <div style="font-size: 28px; font-weight: bold; color: #ea580c;">${stats.activeIncidents}</div>
              <div style="font-size: 12px; color: #64748b;">Active Incidents</div>
            </td>
          </tr>
        </table>
        <h3 style="margin: 24px 0 8px; color: #1e293b;">Infrastructure Summary</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Monitored Assets</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.assetCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Quarantined Items</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.quarantineCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Honeypot Activity (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.honeypotActivity}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Firewall Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.blockedIps}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Alert Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeRules}</td></tr>
        </table>`;
      break;

    case "incident":
      title = "Incident Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b;">Incident Status</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Incidents</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: #ea580c;">${stats.activeIncidents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Critical Alerts (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: #dc2626;">${stats.criticalAlerts}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Total Events (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.totalEvents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Quarantined Items</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.quarantineCount}</td></tr>
        </table>
        <p style="color: #64748b; font-size: 13px; margin-top: 16px;">For detailed incident investigation, please log in to the AegisAI360 dashboard.</p>`;
      break;

    case "compliance":
      title = "Compliance Status Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b;">Security Compliance Overview</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Threat Score</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600; color: ${threatColor};">${stats.threatScore}/100</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Alert Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeRules}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Monitored Assets</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.assetCount}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Firewall Rules</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.blockedIps}</td></tr>
        </table>
        <p style="color: #64748b; font-size: 13px; margin-top: 16px;">For full compliance assessments (NIST, SOC2, ISO 27001), please use the Compliance page in the AegisAI360 dashboard.</p>`;
      break;

    default:
      title = "Security Report";
      bodyContent = `
        <h3 style="margin: 16px 0 8px; color: #1e293b;">Summary</h3>
        <table style="width: 100%; border-collapse: collapse;">
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Threat Score</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.threatScore}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Total Events (24h)</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.totalEvents}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Critical Alerts</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.criticalAlerts}</td></tr>
          <tr><td style="padding: 8px 12px; border: 1px solid #e2e8f0; color: #64748b;">Active Incidents</td><td style="padding: 8px 12px; border: 1px solid #e2e8f0; font-weight: 600;">${stats.activeIncidents}</td></tr>
        </table>`;
  }

  return `
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 640px; margin: 0 auto;">
      <div style="background: #0f172a; color: white; padding: 20px 24px; border-radius: 8px 8px 0 0;">
        <h2 style="margin: 0; font-size: 18px;">AegisAI360 - ${title}</h2>
        <p style="margin: 4px 0 0; font-size: 13px; color: #94a3b8;">${now}</p>
      </div>
      <div style="border: 1px solid #e2e8f0; border-top: none; padding: 24px; border-radius: 0 0 8px 8px;">
        ${bodyContent}
        <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e2e8f0; text-align: center;">
          <p style="font-size: 12px; color: #94a3b8; margin: 0;">This report was automatically generated by AegisAI360.</p>
        </div>
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
