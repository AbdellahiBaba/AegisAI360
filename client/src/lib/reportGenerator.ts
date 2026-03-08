import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

const COLORS = {
  primary: [0, 180, 200] as [number, number, number],
  dark: [15, 23, 42] as [number, number, number],
  text: [30, 41, 59] as [number, number, number],
  muted: [100, 116, 139] as [number, number, number],
  white: [255, 255, 255] as [number, number, number],
  critical: [239, 68, 68] as [number, number, number],
  high: [249, 115, 22] as [number, number, number],
  medium: [234, 179, 8] as [number, number, number],
  low: [59, 130, 246] as [number, number, number],
  green: [34, 197, 94] as [number, number, number],
};

function addHeader(doc: jsPDF, title: string, subtitle?: string) {
  doc.setFillColor(...COLORS.dark);
  doc.rect(0, 0, 210, 40, "F");

  doc.setFillColor(...COLORS.primary);
  doc.rect(0, 38, 210, 2, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(...COLORS.white);
  doc.text("AegisAI360", 14, 18);

  doc.setFontSize(10);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(180, 200, 210);
  doc.text(title, 14, 28);

  if (subtitle) {
    doc.setFontSize(8);
    doc.text(subtitle, 14, 34);
  }

  const dateStr = new Date().toLocaleString();
  doc.setFontSize(8);
  doc.setTextColor(150, 160, 170);
  doc.text(`Generated: ${dateStr}`, 196, 28, { align: "right" });
}

function addFooter(doc: jsPDF) {
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(...COLORS.muted);
    doc.text(
      `AegisAI360 Security Report | Page ${i} of ${pageCount} | Confidential`,
      105,
      290,
      { align: "center" }
    );
    doc.setDrawColor(...COLORS.primary);
    doc.setLineWidth(0.5);
    doc.line(14, 286, 196, 286);
  }
}

function addSectionTitle(doc: jsPDF, title: string, y: number): number {
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.setTextColor(...COLORS.dark);
  doc.text(title, 14, y);
  doc.setDrawColor(...COLORS.primary);
  doc.setLineWidth(0.5);
  doc.line(14, y + 2, 80, y + 2);
  return y + 10;
}

function checkPageBreak(doc: jsPDF, y: number, needed: number): number {
  if (y + needed > 275) {
    doc.addPage();
    return 20;
  }
  return y;
}

interface DashboardStats {
  totalEvents: number;
  criticalAlerts: number;
  activeIncidents: number;
  threatScore: number;
  eventTrend: number;
  incidentTrend: number;
  assetCount: number;
  quarantineCount: number;
  honeypotActivity: number;
  blockedIps: number;
  activeRules: number;
}

interface SecurityEvent {
  id: number;
  severity: string;
  eventType: string;
  description: string;
  sourceIp: string | null;
  source: string;
  createdAt: string;
}

export function generateExecutiveSummaryPDF(
  stats: DashboardStats,
  events: SecurityEvent[],
  severityData: { name: string; value: number }[]
) {
  const doc = new jsPDF();
  addHeader(doc, "Executive Security Summary", "Real-time Security Posture Overview");

  let y = 52;

  y = addSectionTitle(doc, "Threat Overview", y);

  const threatLevel =
    stats.criticalAlerts >= 5 || stats.activeIncidents >= 3
      ? "DEFCON 1 - CRITICAL"
      : stats.criticalAlerts >= 3
        ? "DEFCON 2 - SEVERE"
        : stats.criticalAlerts >= 1 || stats.activeIncidents >= 1
          ? "DEFCON 3 - ELEVATED"
          : stats.totalEvents > 0
            ? "DEFCON 4 - GUARDED"
            : "DEFCON 5 - NORMAL";

  doc.setFont("helvetica", "bold");
  doc.setFontSize(14);
  const threatColor = stats.criticalAlerts >= 3 ? COLORS.critical : stats.criticalAlerts >= 1 ? COLORS.high : COLORS.green;
  doc.setTextColor(...threatColor);
  doc.text(threatLevel, 14, y);
  y += 5;
  doc.setFontSize(9);
  doc.setTextColor(...COLORS.muted);
  doc.text(`Threat Score: ${stats.threatScore}/100`, 14, y);
  y += 12;

  y = addSectionTitle(doc, "Key Metrics", y);

  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value", "Status"]],
    body: [
      ["Security Events (24h)", String(stats.totalEvents), stats.totalEvents > 100 ? "High Volume" : "Normal"],
      ["Critical Alerts", String(stats.criticalAlerts), stats.criticalAlerts > 0 ? "Action Required" : "Clear"],
      ["Active Incidents", String(stats.activeIncidents), stats.activeIncidents > 0 ? "Investigating" : "None"],
      ["Blocked IPs", String(stats.blockedIps), stats.blockedIps > 0 ? "Active Blocking" : "None"],
      ["Monitored Assets", String(stats.assetCount), "Online"],
      ["Quarantined Items", String(stats.quarantineCount), stats.quarantineCount > 0 ? "Quarantined" : "Clear"],
      ["Active Alert Rules", String(stats.activeRules), "Configured"],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    alternateRowStyles: { fillColor: [245, 247, 250] },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  y = addSectionTitle(doc, "Severity Distribution", y);

  if (severityData.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Count", "Percentage"]],
      body: severityData.map((d) => {
        const total = severityData.reduce((s, v) => s + v.value, 0);
        const pct = total > 0 ? ((d.value / total) * 100).toFixed(1) : "0";
        return [d.name.toUpperCase(), String(d.value), `${pct}%`];
      }),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const sev = data.cell.raw?.toString().toLowerCase();
          const colorMap: Record<string, [number, number, number]> = {
            critical: COLORS.critical,
            high: COLORS.high,
            medium: COLORS.medium,
            low: COLORS.low,
          };
          if (colorMap[sev]) {
            data.cell.styles.textColor = colorMap[sev];
            data.cell.styles.fontStyle = "bold";
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 60);
  y = addSectionTitle(doc, "Recent Critical Events", y);

  const criticalEvents = events
    .filter((e) => e.severity === "critical" || e.severity === "high")
    .slice(0, 15);

  if (criticalEvents.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Time", "Severity", "Type", "Source IP", "Description"]],
      body: criticalEvents.map((e) => [
        new Date(e.createdAt).toLocaleString(),
        e.severity.toUpperCase(),
        e.eventType,
        e.sourceIp || "N/A",
        e.description.substring(0, 60),
      ]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      columnStyles: { 4: { cellWidth: 60 } },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 1) {
          const sev = data.cell.raw?.toString().toLowerCase();
          if (sev === "critical") data.cell.styles.textColor = COLORS.critical;
          if (sev === "high") data.cell.styles.textColor = COLORS.high;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
  } else {
    doc.setFontSize(9);
    doc.setTextColor(...COLORS.muted);
    doc.text("No critical or high severity events found.", 14, y);
  }

  addFooter(doc);
  doc.save(`AegisAI360-Executive-Summary-${new Date().toISOString().split("T")[0]}.pdf`);
}

interface ComplianceAssessment {
  framework: string;
  frameworkFullName: string;
  version: string;
  grade: string;
  percentage: number;
  overallScore: number;
  maxScore: number;
  lastAssessed: string;
  controls: {
    id: string;
    name: string;
    description: string;
    category: string;
    status: string;
    score: number;
    maxScore: number;
    evidence: string;
    remediation: string;
  }[];
  gaps: {
    control: {
      id: string;
      name: string;
      description: string;
      status: string;
      score: number;
      maxScore: number;
      remediation: string;
    };
    priority: string;
  }[];
  categories: {
    name: string;
    score: number;
    maxScore: number;
    percentage: number;
  }[];
}

export function generateCompliancePDF(assessment: ComplianceAssessment) {
  const doc = new jsPDF();
  addHeader(doc, "Compliance Assessment Report", `${assessment.frameworkFullName} v${assessment.version}`);

  let y = 52;

  y = addSectionTitle(doc, "Assessment Summary", y);

  doc.setFont("helvetica", "bold");
  doc.setFontSize(28);
  const gradeColor = assessment.percentage >= 80 ? COLORS.green : assessment.percentage >= 60 ? COLORS.medium : COLORS.critical;
  doc.setTextColor(...gradeColor);
  doc.text(assessment.grade, 14, y + 5);

  doc.setFontSize(10);
  doc.setTextColor(...COLORS.text);
  doc.text(`Score: ${assessment.overallScore}/${assessment.maxScore} (${assessment.percentage}%)`, 40, y);
  doc.setFontSize(8);
  doc.setTextColor(...COLORS.muted);
  doc.text(`Last Assessed: ${new Date(assessment.lastAssessed).toLocaleString()}`, 40, y + 5);
  y += 18;

  const passCount = assessment.controls?.filter((c) => c.status === "pass").length || 0;
  const partialCount = assessment.controls?.filter((c) => c.status === "partial").length || 0;
  const failCount = assessment.controls?.filter((c) => c.status === "fail").length || 0;

  autoTable(doc, {
    startY: y,
    head: [["Status", "Count", "Percentage"]],
    body: [
      ["PASSING", String(passCount), `${((passCount / (assessment.controls?.length || 1)) * 100).toFixed(1)}%`],
      ["PARTIAL", String(partialCount), `${((partialCount / (assessment.controls?.length || 1)) * 100).toFixed(1)}%`],
      ["FAILING", String(failCount), `${((failCount / (assessment.controls?.length || 1)) * 100).toFixed(1)}%`],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 0) {
        const status = data.cell.raw?.toString();
        if (status === "PASSING") data.cell.styles.textColor = COLORS.green;
        if (status === "PARTIAL") data.cell.styles.textColor = COLORS.medium;
        if (status === "FAILING") data.cell.styles.textColor = COLORS.critical;
        data.cell.styles.fontStyle = "bold";
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  if (assessment.categories?.length > 0) {
    y = addSectionTitle(doc, "Category Scores", y);

    autoTable(doc, {
      startY: y,
      head: [["Category", "Score", "Max Score", "Percentage"]],
      body: assessment.categories.map((cat) => [
        cat.name,
        String(cat.score),
        String(cat.maxScore),
        `${cat.percentage}%`,
      ]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 3) {
          const pct = parseFloat(data.cell.raw?.toString() || "0");
          if (pct >= 80) data.cell.styles.textColor = COLORS.green;
          else if (pct >= 60) data.cell.styles.textColor = COLORS.medium;
          else data.cell.styles.textColor = COLORS.critical;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });

    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (assessment.gaps?.length > 0) {
    y = addSectionTitle(doc, `Gap Analysis (${assessment.gaps.length} Issues)`, y);

    autoTable(doc, {
      startY: y,
      head: [["Priority", "Control ID", "Control Name", "Score", "Remediation"]],
      body: assessment.gaps.map((gap) => [
        gap.priority.toUpperCase(),
        gap.control.id,
        gap.control.name,
        `${gap.control.score}/${gap.control.maxScore}`,
        gap.control.remediation?.substring(0, 80) || "N/A",
      ]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      columnStyles: { 4: { cellWidth: 60 } },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const priority = data.cell.raw?.toString().toLowerCase();
          const colorMap: Record<string, [number, number, number]> = {
            critical: COLORS.critical,
            high: COLORS.high,
            medium: COLORS.medium,
            low: COLORS.low,
          };
          if (colorMap[priority]) {
            data.cell.styles.textColor = colorMap[priority];
            data.cell.styles.fontStyle = "bold";
          }
        }
      },
    });

    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (assessment.controls?.length > 0) {
    y = addSectionTitle(doc, "All Controls", y);

    autoTable(doc, {
      startY: y,
      head: [["Status", "ID", "Control", "Category", "Score"]],
      body: assessment.controls.map((c) => [
        c.status.toUpperCase(),
        c.id,
        c.name.substring(0, 50),
        c.category,
        `${c.score}/${c.maxScore}`,
      ]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const status = data.cell.raw?.toString().toLowerCase();
          if (status === "pass") data.cell.styles.textColor = COLORS.green;
          if (status === "partial") data.cell.styles.textColor = COLORS.medium;
          if (status === "fail") data.cell.styles.textColor = COLORS.critical;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-Compliance-${assessment.framework}-${new Date().toISOString().split("T")[0]}.pdf`);
}

interface Incident {
  id: number;
  title: string;
  description: string;
  severity: string;
  status: string;
  assignee: string | null;
  createdAt: string;
  updatedAt: string | null;
}

export function generateIncidentReportPDF(incidents: Incident[]) {
  const doc = new jsPDF();
  addHeader(doc, "Incident Report", `${incidents.length} Incident${incidents.length !== 1 ? "s" : ""} Documented`);

  let y = 52;

  y = addSectionTitle(doc, "Incident Summary", y);

  const open = incidents.filter((i) => i.status === "open").length;
  const investigating = incidents.filter((i) => i.status === "investigating").length;
  const contained = incidents.filter((i) => i.status === "contained").length;
  const resolved = incidents.filter((i) => i.status === "resolved").length;
  const closed = incidents.filter((i) => i.status === "closed").length;

  autoTable(doc, {
    startY: y,
    head: [["Status", "Count"]],
    body: [
      ["Open", String(open)],
      ["Investigating", String(investigating)],
      ["Contained", String(contained)],
      ["Resolved", String(resolved)],
      ["Closed", String(closed)],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 100 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 0) {
        const status = data.cell.raw?.toString().toLowerCase();
        const colorMap: Record<string, [number, number, number]> = {
          open: COLORS.critical,
          investigating: COLORS.medium,
          contained: COLORS.low,
          resolved: COLORS.green,
        };
        if (colorMap[status]) {
          data.cell.styles.textColor = colorMap[status];
          data.cell.styles.fontStyle = "bold";
        }
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  const sevCritical = incidents.filter((i) => i.severity === "critical").length;
  const sevHigh = incidents.filter((i) => i.severity === "high").length;
  const sevMedium = incidents.filter((i) => i.severity === "medium").length;
  const sevLow = incidents.filter((i) => i.severity === "low").length;

  autoTable(doc, {
    startY: y,
    head: [["Severity", "Count"]],
    body: [
      ["CRITICAL", String(sevCritical)],
      ["HIGH", String(sevHigh)],
      ["MEDIUM", String(sevMedium)],
      ["LOW", String(sevLow)],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 100 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 0) {
        const sev = data.cell.raw?.toString().toLowerCase();
        const colorMap: Record<string, [number, number, number]> = {
          critical: COLORS.critical,
          high: COLORS.high,
          medium: COLORS.medium,
          low: COLORS.low,
        };
        if (colorMap[sev]) {
          data.cell.styles.textColor = colorMap[sev];
          data.cell.styles.fontStyle = "bold";
        }
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  y = addSectionTitle(doc, "Incident Details", y);

  for (const incident of incidents) {
    y = checkPageBreak(doc, y, 35);

    doc.setFillColor(248, 250, 252);
    doc.roundedRect(14, y - 4, 182, 28, 2, 2, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.setTextColor(...COLORS.text);
    doc.text(`#${incident.id}: ${incident.title}`, 18, y + 2);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);

    const sevColor = incident.severity === "critical" ? COLORS.critical : incident.severity === "high" ? COLORS.high : incident.severity === "medium" ? COLORS.medium : COLORS.low;
    doc.setTextColor(...sevColor);
    doc.text(`Severity: ${incident.severity.toUpperCase()}`, 18, y + 8);

    const statusColor = incident.status === "open" ? COLORS.critical : incident.status === "resolved" ? COLORS.green : COLORS.medium;
    doc.setTextColor(...statusColor);
    doc.text(`Status: ${incident.status.toUpperCase()}`, 65, y + 8);

    doc.setTextColor(...COLORS.muted);
    doc.text(`Created: ${new Date(incident.createdAt).toLocaleString()}`, 110, y + 8);

    if (incident.assignee) {
      doc.text(`Assignee: ${incident.assignee}`, 18, y + 14);
    }

    doc.setTextColor(...COLORS.text);
    doc.setFontSize(7);
    const desc = incident.description.substring(0, 150);
    doc.text(desc, 18, y + 20, { maxWidth: 170 });

    y += 34;
  }

  addFooter(doc);
  doc.save(`AegisAI360-Incident-Report-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateScannerReportPDF(scanHistory: any[]) {
  const doc = new jsPDF();
  addHeader(doc, "Security Scanner Report", `${scanHistory.length} Scan(s) Documented`);

  let y = 52;
  y = addSectionTitle(doc, "Scan Summary", y);

  const completed = scanHistory.filter((s) => s.status === "completed").length;
  const failed = scanHistory.filter((s) => s.status === "failed").length;
  const running = scanHistory.filter((s) => s.status === "running").length;

  autoTable(doc, {
    startY: y,
    head: [["Status", "Count"]],
    body: [
      ["Completed", String(completed)],
      ["Failed", String(failed)],
      ["Running", String(running)],
      ["Total", String(scanHistory.length)],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 100 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);
  y = addSectionTitle(doc, "Scan Details", y);

  autoTable(doc, {
    startY: y,
    head: [["Type", "Target", "Status", "Findings", "Severity", "Time"]],
    body: scanHistory.map((s) => [
      s.scanType || "N/A",
      s.target || "N/A",
      (s.status || "N/A").toUpperCase(),
      String(s.findings ?? "-"),
      s.severity ? s.severity.toUpperCase() : "-",
      s.createdAt ? new Date(s.createdAt).toLocaleString() : "N/A",
    ]),
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
    bodyStyles: { fontSize: 7, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 4) {
        const sev = data.cell.raw?.toString().toLowerCase();
        const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
        if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
      }
    },
  });

  addFooter(doc);
  doc.save(`AegisAI360-Scanner-Report-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateSSLInspectorReportPDF(result: any) {
  const doc = new jsPDF();
  addHeader(doc, "SSL/TLS Certificate Inspection Report", `Domain: ${result.domain}`);

  let y = 52;
  y = addSectionTitle(doc, "Overview", y);

  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Domain", result.domain],
      ["IP Address", result.ip || "N/A"],
      ["Security Grade", result.grade],
      ["Days Until Expiration", result.isExpired ? "EXPIRED" : String(result.daysUntilExpiration)],
      ["Self-Signed", result.isSelfSigned ? "Yes" : "No"],
      ["HSTS Enabled", result.hasHSTS ? "Yes" : "No"],
      ["Scanned At", new Date(result.scannedAt).toLocaleString()],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);
  y = addSectionTitle(doc, "Certificate Details", y);

  autoTable(doc, {
    startY: y,
    head: [["Field", "Value"]],
    body: [
      ["Subject", Object.values(result.certificate?.subject || {}).join(", ") || "N/A"],
      ["Issuer", Object.values(result.certificate?.issuer || {}).join(", ") || "N/A"],
      ["Key Size", `${result.certificate?.keySize || "N/A"} bits`],
      ["Signature Algorithm", result.certificate?.signatureAlgorithm || "N/A"],
      ["Valid From", result.certificate?.validFrom ? new Date(result.certificate.validFrom).toLocaleDateString() : "N/A"],
      ["Valid To", result.certificate?.validTo ? new Date(result.certificate.validTo).toLocaleDateString() : "N/A"],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  if (result.protocols) {
    y = addSectionTitle(doc, "Protocol Support", y);
    autoTable(doc, {
      startY: y,
      head: [["Protocol", "Status"]],
      body: Object.entries(result.protocols).map(([proto, supported]) => [proto, supported ? "Supported" : "Not Supported"]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.findings?.length > 0) {
    y = addSectionTitle(doc, `Findings (${result.findings.length})`, y);
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Title", "Description"]],
      body: result.findings.map((f: any) => [f.severity.toUpperCase(), f.title, f.description.substring(0, 80)]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      columnStyles: { 2: { cellWidth: 80 } },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const sev = data.cell.raw?.toString().toLowerCase();
          const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
          if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
        }
      },
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-SSL-Inspector-${result.domain}-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateDarkWebReportPDF(result: any) {
  const doc = new jsPDF();
  addHeader(doc, "Dark Web Exposure Report", `Query: ${result.query} (${result.queryType})`);

  let y = 52;
  y = addSectionTitle(doc, "Risk Overview", y);

  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Query", result.query],
      ["Query Type", result.queryType],
      ["Risk Level", result.riskLevel.toUpperCase()],
      ["Risk Score", `${result.overallRiskScore}/100`],
      ["Total Breaches", String(result.totalBreaches)],
      ["Total Exposed Records", result.totalExposedRecords.toLocaleString()],
      ["Data Types Exposed", String(result.exposedDataTypes?.length || 0)],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  if (result.breaches?.length > 0) {
    y = addSectionTitle(doc, `Breaches (${result.breaches.length})`, y);
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Breach", "Date", "Records", "Risk Score"]],
      body: result.breaches.map((b: any) => [
        b.severity.toUpperCase(),
        b.title || b.name,
        b.breachDate ? new Date(b.breachDate).toLocaleDateString() : "N/A",
        b.pwnCount?.toLocaleString() || "N/A",
        String(b.riskScore),
      ]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const sev = data.cell.raw?.toString().toLowerCase();
          const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
          if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.recommendations?.length > 0) {
    y = addSectionTitle(doc, "Recommendations", y);
    result.recommendations.forEach((rec: string, i: number) => {
      y = checkPageBreak(doc, y, 8);
      doc.setFontSize(8);
      doc.setTextColor(...COLORS.text);
      doc.text(`${i + 1}. ${rec}`, 18, y, { maxWidth: 170 });
      y += 7;
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-DarkWeb-Report-${result.query}-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateCVEReportPDF(results: any[], totalResults: number) {
  const doc = new jsPDF();
  addHeader(doc, "CVE Database Report", `${totalResults} Vulnerabilit${totalResults !== 1 ? "ies" : "y"} Found`);

  let y = 52;
  y = addSectionTitle(doc, "Severity Distribution", y);

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
  for (const r of results) {
    const sev = r.severity in counts ? r.severity as keyof typeof counts : "UNKNOWN";
    counts[sev]++;
  }

  autoTable(doc, {
    startY: y,
    head: [["Severity", "Count", "Percentage"]],
    body: (["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
      const pct = results.length > 0 ? ((counts[sev] / results.length) * 100).toFixed(1) : "0";
      return [sev, String(counts[sev]), `${pct}%`];
    }),
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 100 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 0) {
        const sev = data.cell.raw?.toString().toLowerCase();
        const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
        if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
      }
    },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);
  y = addSectionTitle(doc, "CVE Details", y);

  autoTable(doc, {
    startY: y,
    head: [["CVE ID", "CVSS", "Severity", "Published", "Description"]],
    body: results.slice(0, 50).map((cve) => [
      cve.id,
      cve.cvssScore?.toFixed(1) ?? "N/A",
      cve.severity,
      cve.published ? new Date(cve.published).toLocaleDateString() : "N/A",
      (cve.description || "").substring(0, 80),
    ]),
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
    bodyStyles: { fontSize: 7, textColor: COLORS.text },
    columnStyles: { 4: { cellWidth: 70 } },
    margin: { left: 14, right: 14 },
    didParseCell: (data: any) => {
      if (data.section === "body" && data.column.index === 2) {
        const sev = data.cell.raw?.toString().toLowerCase();
        const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
        if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
      }
    },
  });

  addFooter(doc);
  doc.save(`AegisAI360-CVE-Report-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateNetworkMonitorReportPDF(devices: any[]) {
  const doc = new jsPDF();
  addHeader(doc, "Network Monitor Report", `${devices.length} Asset(s) Monitored`);

  let y = 52;
  y = addSectionTitle(doc, "Asset Summary", y);

  autoTable(doc, {
    startY: y,
    head: [["Hostname / IP", "Device Type", "Status", "OS", "First Seen", "Last Seen"]],
    body: devices.map((d) => [
      d.hostname || d.ipAddress,
      d.deviceType || "unknown",
      d.status || "unknown",
      d.os || "N/A",
      d.firstSeen ? new Date(d.firstSeen).toLocaleDateString() : "N/A",
      d.lastSeen ? new Date(d.lastSeen).toLocaleString() : "N/A",
    ]),
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
    bodyStyles: { fontSize: 7, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  let totalIssues = 0;
  let criticalIssues = 0;
  devices.forEach((d) => {
    try {
      const scan = d.notes ? JSON.parse(d.notes) : null;
      if (scan?.summary) {
        totalIssues += scan.summary.totalIssues || 0;
        criticalIssues += scan.summary.criticalIssues || 0;
      }
    } catch {}
  });

  y = addSectionTitle(doc, "Security Overview", y);
  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Total Assets", String(devices.length)],
      ["Total Issues Found", String(totalIssues)],
      ["Critical Issues", String(criticalIssues)],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 100 },
  });

  addFooter(doc);
  doc.save(`AegisAI360-Network-Monitor-Report-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateEmailAnalysisReportPDF(result: any) {
  const doc = new jsPDF();
  addHeader(doc, "Email Security Analysis Report", `Subject: ${(result.subject || "N/A").substring(0, 60)}`);

  let y = 52;
  y = addSectionTitle(doc, "Verdict & Risk", y);

  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Verdict", (result.verdict || "N/A").replace(/_/g, " ").toUpperCase()],
      ["Confidence Score", `${result.confidenceScore}%`],
      ["Risk Score", `${result.riskScore}/100`],
      ["Total Hops", String(result.totalHops)],
      ["Total Delay", result.totalDelay || "N/A"],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);
  y = addSectionTitle(doc, "Summary", y);

  doc.setFontSize(8);
  doc.setTextColor(...COLORS.text);
  doc.text(result.summary || "No summary available.", 14, y, { maxWidth: 180 });
  y += 15;

  y = checkPageBreak(doc, y, 40);
  y = addSectionTitle(doc, "Sender Information", y);

  autoTable(doc, {
    startY: y,
    head: [["Field", "Value"]],
    body: [
      ["From", result.senderInfo?.from || "N/A"],
      ["Display Name", result.senderInfo?.displayName || "N/A"],
      ["Reply-To", result.senderInfo?.replyTo || "N/A"],
      ["Return-Path", result.senderInfo?.returnPath || "N/A"],
      ["Domain", result.senderInfo?.domain || "N/A"],
      ["Address Mismatch", result.senderInfo?.mismatch ? "YES" : "No"],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;
  y = checkPageBreak(doc, y, 40);

  if (result.authResults?.length > 0) {
    y = addSectionTitle(doc, "Authentication Results", y);
    autoTable(doc, {
      startY: y,
      head: [["Protocol", "Result", "Details"]],
      body: result.authResults.map((a: any) => [a.protocol, a.result.toUpperCase(), (a.details || "").substring(0, 80)]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.phishingIndicators?.length > 0) {
    y = addSectionTitle(doc, `Phishing Indicators (${result.phishingIndicators.length})`, y);
    autoTable(doc, {
      startY: y,
      head: [["Severity", "Description", "Evidence"]],
      body: result.phishingIndicators.map((p: any) => [p.severity.toUpperCase(), p.description, (p.evidence || "").substring(0, 60)]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      columnStyles: { 2: { cellWidth: 60 } },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const sev = data.cell.raw?.toString().toLowerCase();
          const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
          if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.iocs?.length > 0) {
    y = addSectionTitle(doc, `Indicators of Compromise (${result.iocs.length})`, y);
    autoTable(doc, {
      startY: y,
      head: [["Type", "Value", "Context"]],
      body: result.iocs.map((ioc: any) => [ioc.type.toUpperCase(), ioc.value.substring(0, 60), (ioc.context || "").substring(0, 40)]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-Email-Analysis-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateTrojanAnalysisReportPDF(result: any) {
  const doc = new jsPDF();
  addHeader(doc, "Trojan Analysis Report", `Family: ${result.family || "Unknown"}`);

  let y = 52;
  y = addSectionTitle(doc, "Analysis Summary", y);

  autoTable(doc, {
    startY: y,
    head: [["Metric", "Value"]],
    body: [
      ["Family", result.family || "Unknown"],
      ["Category", result.category || "N/A"],
      ["Risk Score", `${result.riskScore || 0}/100`],
      ["Detection Rate", result.detectionRate || "N/A"],
      ["First Seen", result.firstSeen || "N/A"],
      ["Last Seen", result.lastSeen || "N/A"],
    ],
    theme: "grid",
    headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
    bodyStyles: { fontSize: 8, textColor: COLORS.text },
    margin: { left: 14, right: 14 },
  });

  y = (doc as any).lastAutoTable.finalY + 12;

  if (result.description) {
    y = checkPageBreak(doc, y, 20);
    y = addSectionTitle(doc, "Description", y);
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.text);
    doc.text(result.description, 14, y, { maxWidth: 180 });
    y += 15;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.c2Infrastructure?.length > 0) {
    y = addSectionTitle(doc, "C2 Infrastructure", y);
    autoTable(doc, {
      startY: y,
      head: [["C2 Address"]],
      body: result.c2Infrastructure.map((c2: string) => [c2]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text, font: "courier" },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;
  }

  y = checkPageBreak(doc, y, 40);

  if (result.mitreTechniques?.length > 0) {
    y = addSectionTitle(doc, "MITRE ATT&CK Techniques", y);
    autoTable(doc, {
      startY: y,
      head: [["Technique"]],
      body: result.mitreTechniques.map((t: any) => [typeof t === "string" ? t : `${t.id} - ${t.name}`]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-Trojan-Analysis-${result.family || "unknown"}-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generatePasswordAuditReportPDF(analysis: any, breachResult?: any, policyResult?: any) {
  const doc = new jsPDF();
  addHeader(doc, "Password Security Audit Report", "Strength Analysis & Compliance Check");

  let y = 52;

  if (analysis) {
    y = addSectionTitle(doc, "Strength Analysis", y);

    autoTable(doc, {
      startY: y,
      head: [["Metric", "Value"]],
      body: [
        ["Score", `${analysis.score}/100`],
        ["Strength", analysis.strength],
        ["Entropy", `${analysis.entropy} bits`],
        ["Length", String(analysis.composition?.length || 0)],
        ["Unique Characters", String(analysis.composition?.uniqueChars || 0)],
        ["NIST Compliant", analysis.nistCompliance?.compliant ? "Yes" : "No"],
        ["Common Password", analysis.isCommon ? "Yes" : "No"],
      ],
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });

    y = (doc as any).lastAutoTable.finalY + 12;
    y = checkPageBreak(doc, y, 40);

    if (analysis.crackTime) {
      y = addSectionTitle(doc, "Time to Crack Estimates", y);
      autoTable(doc, {
        startY: y,
        head: [["Scenario", "Estimated Time"]],
        body: [
          ["Online (throttled)", analysis.crackTime.onlineThrottled],
          ["Online (unthrottled)", analysis.crackTime.onlineUnthrottled],
          ["Offline (slow hash)", analysis.crackTime.offlineSlow],
          ["Offline (fast hash)", analysis.crackTime.offlineFast],
          ["GPU Cluster", analysis.crackTime.gpuCluster],
        ],
        theme: "grid",
        headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
        bodyStyles: { fontSize: 8, textColor: COLORS.text },
        margin: { left: 14, right: 14 },
      });
      y = (doc as any).lastAutoTable.finalY + 12;
    }

    y = checkPageBreak(doc, y, 40);

    if (analysis.weaknesses?.length > 0) {
      y = addSectionTitle(doc, "Weaknesses", y);
      analysis.weaknesses.forEach((w: string, i: number) => {
        y = checkPageBreak(doc, y, 8);
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.critical);
        doc.text(`${i + 1}. ${w}`, 18, y, { maxWidth: 170 });
        y += 7;
      });
      y += 5;
    }

    if (analysis.suggestions?.length > 0) {
      y = checkPageBreak(doc, y, 20);
      y = addSectionTitle(doc, "Suggestions", y);
      analysis.suggestions.forEach((s: string, i: number) => {
        y = checkPageBreak(doc, y, 8);
        doc.setFontSize(8);
        doc.setTextColor(...COLORS.green);
        doc.text(`${i + 1}. ${s}`, 18, y, { maxWidth: 170 });
        y += 7;
      });
    }
  }

  if (breachResult) {
    y = checkPageBreak(doc, y, 30);
    y = addSectionTitle(doc, "Breach Exposure", y);
    doc.setFontSize(9);
    doc.setTextColor(...(breachResult.breached ? COLORS.critical : COLORS.green));
    doc.text(breachResult.breached ? "PASSWORD FOUND IN BREACHES" : "Not found in known breaches", 14, y);
    y += 6;
    doc.setFontSize(8);
    doc.setTextColor(...COLORS.text);
    doc.text(breachResult.message || "", 14, y, { maxWidth: 180 });
    y += 10;
  }

  if (policyResult) {
    y = checkPageBreak(doc, y, 40);
    y = addSectionTitle(doc, `Policy Audit (Grade: ${policyResult.grade})`, y);
    autoTable(doc, {
      startY: y,
      head: [["Status", "Rule", "Category", "Recommendation"]],
      body: policyResult.findings.map((f: any) => [f.status.toUpperCase(), f.rule, f.category, f.recommendation.substring(0, 60)]),
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
      bodyStyles: { fontSize: 7, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 0) {
          const status = data.cell.raw?.toString().toLowerCase();
          if (status === "pass") data.cell.styles.textColor = COLORS.green;
          if (status === "warning") data.cell.styles.textColor = COLORS.medium;
          if (status === "fail") data.cell.styles.textColor = COLORS.critical;
          data.cell.styles.fontStyle = "bold";
        }
      },
    });
  }

  addFooter(doc);
  doc.save(`AegisAI360-Password-Audit-${new Date().toISOString().split("T")[0]}.pdf`);
}

export function generateMobilePentestReportPDF(results: any, testType: string) {
  const doc = new jsPDF();
  const subtitle = testType === "permissions" ? "Permission Analysis" : testType === "api" ? "API Security Test" : testType === "owasp" ? "OWASP Mobile Top 10" : "Device CVE Lookup";
  addHeader(doc, "Mobile Penetration Test Report", subtitle);

  let y = 52;
  y = addSectionTitle(doc, "Test Summary", y);

  if (testType === "permissions" && results) {
    autoTable(doc, {
      startY: y,
      head: [["Metric", "Value"]],
      body: [
        ["Total Permissions", String(results.summary?.total || 0)],
        ["Dangerous Permissions", String(results.summary?.dangerous || 0)],
        ["Risk Score", String(results.overallRiskScore || 0)],
        ["Risk Level", (results.riskLevel || "N/A").toUpperCase()],
      ],
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;

    if (results.permissions?.length > 0) {
      y = checkPageBreak(doc, y, 40);
      y = addSectionTitle(doc, "Permission Details", y);
      autoTable(doc, {
        startY: y,
        head: [["Permission", "Level", "Category", "Privacy Impact", "Score"]],
        body: results.permissions.map((p: any) => [
          (p.permission || "").replace("android.permission.", ""),
          p.protectionLevel || "N/A",
          p.dataAccessCategory || "N/A",
          (p.privacyImpact || "N/A").toUpperCase(),
          String(p.riskScore || 0),
        ]),
        theme: "grid",
        headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
        bodyStyles: { fontSize: 7, textColor: COLORS.text },
        margin: { left: 14, right: 14 },
      });
    }
  } else if (testType === "api" && results) {
    autoTable(doc, {
      startY: y,
      head: [["Metric", "Value"]],
      body: [
        ["Overall Grade", results.overallGrade || "N/A"],
        ["SSL/TLS Grade", results.ssl?.grade || "N/A"],
        ["HSTS Enabled", results.hsts?.enabled ? "Yes" : "No"],
        ["Rate Limited", results.rateLimiting?.detected ? "Yes" : "No"],
        ["Scan Duration", `${results.scanDuration || 0}ms`],
      ],
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;

    if (results.securityHeaders?.length > 0) {
      y = checkPageBreak(doc, y, 40);
      y = addSectionTitle(doc, "Security Headers", y);
      autoTable(doc, {
        startY: y,
        head: [["Header", "Status", "Value"]],
        body: results.securityHeaders.map((h: any) => [h.header, h.status?.toUpperCase() || "N/A", h.present ? (h.value || "").substring(0, 40) : "Not Set"]),
        theme: "grid",
        headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
        bodyStyles: { fontSize: 7, textColor: COLORS.text },
        margin: { left: 14, right: 14 },
      });
    }
  } else if (testType === "owasp" && results) {
    autoTable(doc, {
      startY: y,
      head: [["Metric", "Value"]],
      body: [
        ["Overall Score", `${results.overallScore || 0}/100`],
        ["Risk Level", (results.riskLevel || "N/A").toUpperCase()],
        ["Pass", String(results.passCount || 0)],
        ["Fail", String(results.failCount || 0)],
        ["Warnings", String(results.warningCount || 0)],
      ],
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;

    if (results.results?.length > 0) {
      y = checkPageBreak(doc, y, 40);
      y = addSectionTitle(doc, "OWASP Test Results", y);
      autoTable(doc, {
        startY: y,
        head: [["Status", "ID", "Title", "Severity"]],
        body: results.results.map((r: any) => [r.status?.toUpperCase() || "N/A", r.id || "N/A", r.title || "N/A", (r.severity || "N/A").toUpperCase()]),
        theme: "grid",
        headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
        bodyStyles: { fontSize: 7, textColor: COLORS.text },
        margin: { left: 14, right: 14 },
        didParseCell: (data: any) => {
          if (data.section === "body" && data.column.index === 3) {
            const sev = data.cell.raw?.toString().toLowerCase();
            const colorMap: Record<string, [number, number, number]> = { critical: COLORS.critical, high: COLORS.high, medium: COLORS.medium, low: COLORS.low };
            if (colorMap[sev]) { data.cell.styles.textColor = colorMap[sev]; data.cell.styles.fontStyle = "bold"; }
          }
        },
      });
    }
  } else if (testType === "device-cve" && results) {
    autoTable(doc, {
      startY: y,
      head: [["Metric", "Value"]],
      body: [
        ["OS", `${results.osType || "N/A"} ${results.version || ""}`],
        ["Total CVEs", String(results.totalFound || 0)],
        ["Critical", String(results.criticalCount || 0)],
        ["High", String(results.highCount || 0)],
        ["Medium", String(results.mediumCount || 0)],
        ["Low", String(results.lowCount || 0)],
        ["Recommendation", (results.recommendation || "N/A").substring(0, 80)],
      ],
      theme: "grid",
      headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8, textColor: COLORS.text },
      margin: { left: 14, right: 14 },
    });
    y = (doc as any).lastAutoTable.finalY + 12;

    if (results.vulnerabilities?.length > 0) {
      y = checkPageBreak(doc, y, 40);
      y = addSectionTitle(doc, "Vulnerabilities", y);
      autoTable(doc, {
        startY: y,
        head: [["CVE ID", "CVSS", "Severity", "Patched", "Description"]],
        body: results.vulnerabilities.slice(0, 50).map((v: any) => [
          v.cveId || "N/A",
          String(v.cvssScore || "N/A"),
          (v.severity || "N/A").toUpperCase(),
          v.patchAvailable ? "Yes" : "No",
          (v.description || "").substring(0, 60),
        ]),
        theme: "grid",
        headStyles: { fillColor: COLORS.dark, textColor: COLORS.white, fontSize: 8, fontStyle: "bold" },
        bodyStyles: { fontSize: 7, textColor: COLORS.text },
        columnStyles: { 4: { cellWidth: 60 } },
        margin: { left: 14, right: 14 },
      });
    }
  }

  addFooter(doc);
  doc.save(`AegisAI360-Mobile-Pentest-${testType}-${new Date().toISOString().split("T")[0]}.pdf`);
}
