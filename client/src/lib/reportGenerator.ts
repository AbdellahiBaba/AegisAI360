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
