import { storage } from "./storage";

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  category: string;
  status: "pass" | "fail" | "partial";
  score: number;
  maxScore: number;
  evidence: string;
  remediation: string;
}

export interface FrameworkAssessment {
  framework: string;
  frameworkFullName: string;
  version: string;
  overallScore: number;
  maxScore: number;
  percentage: number;
  grade: string;
  categories: { name: string; score: number; maxScore: number; percentage: number }[];
  controls: ComplianceControl[];
  gaps: { control: ComplianceControl; priority: "critical" | "high" | "medium" | "low" }[];
  lastAssessed: string;
}

export interface FrameworkSummary {
  id: string;
  name: string;
  fullName: string;
  version: string;
  description: string;
  controlCount: number;
  categoryCount: number;
}

const FRAMEWORKS: Record<string, FrameworkSummary> = {
  "nist-csf": {
    id: "nist-csf",
    name: "NIST CSF",
    fullName: "NIST Cybersecurity Framework",
    version: "2.0",
    description: "Voluntary framework for managing and reducing cybersecurity risk",
    controlCount: 18,
    categoryCount: 6,
  },
  "iso-27001": {
    id: "iso-27001",
    name: "ISO 27001",
    fullName: "ISO/IEC 27001 Information Security",
    version: "2022",
    description: "International standard for information security management systems",
    controlCount: 16,
    categoryCount: 5,
  },
  "soc2": {
    id: "soc2",
    name: "SOC 2",
    fullName: "SOC 2 Type II",
    version: "2017",
    description: "Trust services criteria for service organizations",
    controlCount: 15,
    categoryCount: 5,
  },
  "gdpr": {
    id: "gdpr",
    name: "GDPR",
    fullName: "General Data Protection Regulation",
    version: "2018",
    description: "EU regulation on data protection and privacy",
    controlCount: 14,
    categoryCount: 5,
  },
  "pci-dss": {
    id: "pci-dss",
    name: "PCI DSS",
    fullName: "Payment Card Industry Data Security Standard",
    version: "4.0",
    description: "Security standard for organizations handling credit card data",
    controlCount: 16,
    categoryCount: 6,
  },
  "hipaa": {
    id: "hipaa",
    name: "HIPAA",
    fullName: "Health Insurance Portability and Accountability Act",
    version: "2013",
    description: "US regulation for protecting health information",
    controlCount: 15,
    categoryCount: 5,
  },
};

function gradeFromPercentage(pct: number): string {
  if (pct >= 95) return "A+";
  if (pct >= 90) return "A";
  if (pct >= 85) return "A-";
  if (pct >= 80) return "B+";
  if (pct >= 75) return "B";
  if (pct >= 70) return "B-";
  if (pct >= 65) return "C+";
  if (pct >= 60) return "C";
  if (pct >= 55) return "C-";
  if (pct >= 50) return "D";
  return "F";
}

function gapPriority(control: ComplianceControl): "critical" | "high" | "medium" | "low" {
  if (control.score === 0 && control.maxScore >= 10) return "critical";
  if (control.score === 0) return "high";
  if (control.score < control.maxScore * 0.5) return "high";
  if (control.score < control.maxScore * 0.75) return "medium";
  return "low";
}

interface PlatformData {
  agentCount: number;
  eventCount: number;
  incidentCount: number;
  policyCount: number;
  enabledPolicyCount: number;
  playbookCount: number;
  enabledPlaybookCount: number;
  alertRuleCount: number;
  enabledAlertRuleCount: number;
  firewallRuleCount: number;
  quarantineCount: number;
  assetCount: number;
  threatIntelCount: number;
  honeypotEventCount: number;
  auditLogCount: number;
}

async function gatherPlatformData(orgId: number): Promise<PlatformData> {
  const [agents, events, incidents, policies, playbooks, alertRules, firewallRules, quarantine, assets, threatIntel, honeypot, auditLogs] = await Promise.all([
    storage.getAgentsByOrg(orgId).catch(() => []),
    storage.getSecurityEvents(orgId).catch(() => []),
    storage.getIncidents(orgId).catch(() => []),
    storage.getSecurityPolicies(orgId).catch(() => []),
    storage.getResponsePlaybooks(orgId).catch(() => []),
    storage.getAlertRules(orgId).catch(() => []),
    storage.getFirewallRules(orgId).catch(() => []),
    storage.getQuarantineItems(orgId).catch(() => []),
    storage.getAssets(orgId).catch(() => []),
    storage.getThreatIntel(orgId).catch(() => []),
    storage.getHoneypotEvents(orgId).catch(() => []),
    storage.getAuditLogs(orgId).catch(() => []),
  ]);

  return {
    agentCount: agents.length,
    eventCount: events.length,
    incidentCount: incidents.length,
    policyCount: policies.length,
    enabledPolicyCount: policies.filter((p: any) => p.enabled).length,
    playbookCount: playbooks.length,
    enabledPlaybookCount: playbooks.filter((p: any) => p.enabled).length,
    alertRuleCount: alertRules.length,
    enabledAlertRuleCount: alertRules.filter((r: any) => r.enabled).length,
    firewallRuleCount: firewallRules.length,
    quarantineCount: quarantine.length,
    assetCount: assets.length,
    threatIntelCount: threatIntel.length,
    honeypotEventCount: honeypot.length,
    auditLogCount: auditLogs.length,
  };
}

function assessControl(id: string, name: string, description: string, category: string, maxScore: number, data: PlatformData, condition: (d: PlatformData) => number, remediation: string, evidenceFn: (d: PlatformData) => string): ComplianceControl {
  const rawScore = Math.min(condition(data), maxScore);
  const score = Math.round(rawScore * 10) / 10;
  const status: "pass" | "fail" | "partial" = score >= maxScore ? "pass" : score > 0 ? "partial" : "fail";
  return { id, name, description, category, status, score, maxScore, evidence: evidenceFn(data), remediation };
}

function buildNistControls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("ID.AM-1", "Asset Inventory", "Physical devices and systems are inventoried", "Identify", 10, data, d => Math.min(d.assetCount + d.agentCount, 10), "Deploy endpoint agents to all assets and maintain a complete asset inventory", d => `${d.assetCount} assets, ${d.agentCount} agents registered`),
    assessControl("ID.AM-2", "Software Inventory", "Software platforms and applications are inventoried", "Identify", 10, data, d => d.agentCount >= 1 ? (d.agentCount >= 5 ? 10 : 5 + d.agentCount) : 0, "Deploy agents with software inventory scanning enabled", d => `${d.agentCount} agents collecting software data`),
    assessControl("ID.RA-1", "Risk Assessment", "Asset vulnerabilities are identified and documented", "Identify", 10, data, d => d.eventCount > 0 ? (d.eventCount >= 10 ? 10 : 5 + Math.min(d.eventCount, 5)) : 0, "Run regular vulnerability scans and document findings", d => `${d.eventCount} security events tracked`),
    assessControl("PR.AC-1", "Access Control", "Identities and credentials are issued, managed, and verified", "Protect", 10, data, d => d.enabledPolicyCount >= 2 ? 10 : d.enabledPolicyCount * 5, "Define and enforce access control policies for all users", d => `${d.enabledPolicyCount} active access policies`),
    assessControl("PR.AC-3", "Network Access", "Remote access is managed", "Protect", 10, data, d => d.firewallRuleCount >= 3 ? 10 : d.firewallRuleCount >= 1 ? 5 + d.firewallRuleCount : 0, "Configure firewall rules and network access policies", d => `${d.firewallRuleCount} firewall rules active`),
    assessControl("PR.DS-1", "Data Protection", "Data-at-rest is protected", "Protect", 10, data, d => d.enabledPolicyCount >= 1 && d.quarantineCount >= 0 ? Math.min(d.enabledPolicyCount * 3 + 2, 10) : 0, "Enable encryption policies and data loss prevention rules", d => `${d.enabledPolicyCount} policies, ${d.quarantineCount} items quarantined`),
    assessControl("PR.IP-1", "Security Configuration", "Baseline configurations are created and maintained", "Protect", 10, data, d => d.policyCount >= 3 ? 10 : d.policyCount >= 1 ? d.policyCount * 3 : 0, "Establish and enforce baseline security configurations", d => `${d.policyCount} security policies defined`),
    assessControl("PR.AT-1", "Security Awareness", "Users are informed and trained", "Protect", 10, data, d => d.auditLogCount >= 10 ? 7 : d.auditLogCount >= 1 ? 4 : 0, "Implement security awareness training program and track completion", d => `${d.auditLogCount} audit actions logged`),
    assessControl("DE.AE-1", "Anomaly Detection", "A baseline of network operations is established", "Detect", 10, data, d => d.alertRuleCount >= 3 ? 10 : d.alertRuleCount >= 1 ? d.alertRuleCount * 3 : 0, "Configure alert rules to detect anomalous network behavior", d => `${d.alertRuleCount} alert rules configured`),
    assessControl("DE.CM-1", "Continuous Monitoring", "The network is monitored to detect cybersecurity events", "Detect", 10, data, d => d.agentCount >= 1 && d.enabledAlertRuleCount >= 1 ? Math.min(d.agentCount * 2 + d.enabledAlertRuleCount * 2, 10) : 0, "Deploy monitoring agents and enable continuous alerting", d => `${d.agentCount} agents, ${d.enabledAlertRuleCount} active alert rules`),
    assessControl("DE.CM-4", "Malware Detection", "Malicious code is detected", "Detect", 10, data, d => d.quarantineCount >= 1 || d.agentCount >= 1 ? Math.min(5 + d.quarantineCount + d.agentCount * 2, 10) : 0, "Deploy anti-malware solutions across all endpoints", d => `${d.quarantineCount} threats quarantined, ${d.agentCount} agents deployed`),
    assessControl("DE.CM-7", "Honeypot Monitoring", "Monitoring for unauthorized activity", "Detect", 10, data, d => d.honeypotEventCount >= 1 ? 10 : 0, "Deploy honeypot sensors to detect unauthorized access attempts", d => `${d.honeypotEventCount} honeypot events captured`),
    assessControl("DE.DP-4", "Threat Intelligence", "Event detection information is communicated", "Detect", 10, data, d => d.threatIntelCount >= 5 ? 10 : d.threatIntelCount >= 1 ? d.threatIntelCount * 2 : 0, "Subscribe to threat intelligence feeds and integrate indicators", d => `${d.threatIntelCount} threat intel indicators`),
    assessControl("RS.RP-1", "Incident Response Plan", "Response plan is executed during or after an incident", "Respond", 10, data, d => d.enabledPlaybookCount >= 2 ? 10 : d.enabledPlaybookCount >= 1 ? 6 : 0, "Create and enable automated response playbooks", d => `${d.enabledPlaybookCount} active playbooks`),
    assessControl("RS.AN-1", "Incident Analysis", "Notifications from detection systems are investigated", "Respond", 10, data, d => d.incidentCount >= 1 ? Math.min(5 + d.incidentCount, 10) : 0, "Establish incident investigation procedures and track all incidents", d => `${d.incidentCount} incidents documented`),
    assessControl("RS.MI-1", "Incident Mitigation", "Incidents are contained", "Respond", 10, data, d => d.firewallRuleCount >= 1 && d.quarantineCount >= 1 ? 10 : (d.firewallRuleCount >= 1 || d.quarantineCount >= 1) ? 5 : 0, "Enable automated containment through firewall rules and quarantine", d => `${d.firewallRuleCount} firewall rules, ${d.quarantineCount} quarantined items`),
    assessControl("RC.RP-1", "Recovery Planning", "Recovery plan is executed during or after a cybersecurity incident", "Recover", 10, data, d => d.playbookCount >= 1 ? Math.min(d.playbookCount * 3, 10) : 0, "Develop recovery playbooks with defined procedures", d => `${d.playbookCount} recovery playbooks available`),
    assessControl("RC.CO-1", "Recovery Communication", "Public relations and reputation are managed", "Recover", 10, data, d => d.auditLogCount >= 5 ? 7 : d.auditLogCount >= 1 ? 4 : 0, "Establish communication plan for security incidents", d => `${d.auditLogCount} audit events for accountability`),
  ];
}

function buildISO27001Controls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("A.5.1", "Information Security Policies", "Management direction for information security", "Organizational Controls", 10, data, d => d.policyCount >= 3 ? 10 : d.policyCount * 3, "Develop comprehensive information security policies", d => `${d.policyCount} policies defined`),
    assessControl("A.5.2", "Security Roles & Responsibilities", "Defined roles and responsibilities", "Organizational Controls", 10, data, d => d.auditLogCount >= 5 ? 8 : d.auditLogCount >= 1 ? 5 : 0, "Define and assign security roles with documented responsibilities", d => `${d.auditLogCount} audit entries tracking user actions`),
    assessControl("A.5.7", "Threat Intelligence", "Information about threats collected and analyzed", "Organizational Controls", 10, data, d => d.threatIntelCount >= 5 ? 10 : d.threatIntelCount * 2, "Integrate threat intelligence feeds and maintain IOC databases", d => `${d.threatIntelCount} threat indicators tracked`),
    assessControl("A.6.1", "Personnel Screening", "Background verification checks on candidates", "People Controls", 10, data, d => d.policyCount >= 1 ? 5 : 0, "Implement personnel screening policies and procedures", d => `${d.policyCount} policies covering personnel security`),
    assessControl("A.7.1", "Physical Security", "Physical security perimeters are defined", "Physical Controls", 10, data, d => d.assetCount >= 1 ? 5 : 0, "Define physical security controls for all facilities", d => `${d.assetCount} assets tracked for physical security`),
    assessControl("A.8.1", "Endpoint Security", "User endpoint devices are protected", "Technological Controls", 10, data, d => d.agentCount >= 3 ? 10 : d.agentCount >= 1 ? d.agentCount * 3 : 0, "Deploy endpoint security agents to all user devices", d => `${d.agentCount} endpoint agents deployed`),
    assessControl("A.8.5", "Secure Authentication", "Secure authentication technologies are used", "Technological Controls", 10, data, d => d.enabledPolicyCount >= 2 ? 10 : d.enabledPolicyCount * 4, "Enable multi-factor authentication and enforce password policies", d => `${d.enabledPolicyCount} authentication policies enabled`),
    assessControl("A.8.7", "Malware Protection", "Protection against malware is implemented", "Technological Controls", 10, data, d => d.quarantineCount >= 1 || d.agentCount >= 1 ? Math.min(5 + d.agentCount * 2, 10) : 0, "Deploy real-time malware scanning and automated quarantine", d => `${d.agentCount} agents, ${d.quarantineCount} threats quarantined`),
    assessControl("A.8.8", "Vulnerability Management", "Information about technical vulnerabilities is obtained", "Technological Controls", 10, data, d => d.eventCount >= 5 ? 10 : d.eventCount >= 1 ? d.eventCount * 2 : 0, "Perform regular vulnerability assessments and patch management", d => `${d.eventCount} security events analyzed`),
    assessControl("A.8.15", "Logging", "Logs that record activities and events are produced", "Technological Controls", 10, data, d => d.auditLogCount >= 10 ? 10 : d.auditLogCount >= 1 ? Math.min(d.auditLogCount, 10) : 0, "Enable comprehensive logging across all systems", d => `${d.auditLogCount} audit log entries`),
    assessControl("A.8.16", "Monitoring Activities", "Networks and systems are monitored for anomalous behavior", "Technological Controls", 10, data, d => d.enabledAlertRuleCount >= 2 ? 10 : d.enabledAlertRuleCount * 4, "Configure active monitoring rules and anomaly detection", d => `${d.enabledAlertRuleCount} active monitoring rules`),
    assessControl("A.8.20", "Network Security", "Networks and network devices are secured", "Technological Controls", 10, data, d => d.firewallRuleCount >= 2 ? 10 : d.firewallRuleCount * 4, "Implement network segmentation and firewall rules", d => `${d.firewallRuleCount} network security rules`),
    assessControl("A.8.23", "Web Filtering", "Web access is managed to reduce exposure", "Technological Controls", 10, data, d => d.firewallRuleCount >= 1 ? 7 : 0, "Configure URL filtering and web access policies", d => `${d.firewallRuleCount} filtering rules configured`),
    assessControl("A.8.24", "Cryptography", "Rules for effective use of cryptography are defined", "Technological Controls", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Define and enforce encryption standards for data in transit and at rest", d => `${d.enabledPolicyCount} encryption-related policies`),
    assessControl("A.5.24", "Incident Management Planning", "Approach to managing incidents is planned", "Organizational Controls", 10, data, d => d.enabledPlaybookCount >= 2 ? 10 : d.enabledPlaybookCount >= 1 ? 6 : 0, "Create incident response playbooks with defined escalation paths", d => `${d.enabledPlaybookCount} incident response playbooks`),
    assessControl("A.5.26", "Incident Response", "Information security incidents are responded to", "Organizational Controls", 10, data, d => d.incidentCount >= 1 ? Math.min(5 + d.incidentCount * 2, 10) : 0, "Establish formal incident response procedures", d => `${d.incidentCount} incidents handled`),
  ];
}

function buildSOC2Controls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("CC1.1", "Control Environment", "COSO principle: demonstrates commitment to integrity", "Common Criteria", 10, data, d => d.policyCount >= 2 ? 10 : d.policyCount * 5, "Establish a formal code of conduct and ethics policy", d => `${d.policyCount} governance policies`),
    assessControl("CC2.1", "Communication & Information", "Internal and external communication is established", "Common Criteria", 10, data, d => d.auditLogCount >= 5 ? 8 : d.auditLogCount >= 1 ? 5 : 0, "Implement formal communication channels for security matters", d => `${d.auditLogCount} audit records`),
    assessControl("CC3.1", "Risk Assessment", "Entity specifies objectives to identify and assess risks", "Common Criteria", 10, data, d => d.eventCount >= 5 ? 10 : d.eventCount >= 1 ? d.eventCount * 2 : 0, "Conduct formal risk assessments at regular intervals", d => `${d.eventCount} events analyzed for risk`),
    assessControl("CC5.1", "Control Activities", "Entity selects and develops control activities", "Common Criteria", 10, data, d => d.enabledPolicyCount >= 2 && d.enabledAlertRuleCount >= 1 ? 10 : (d.enabledPolicyCount + d.enabledAlertRuleCount) * 2, "Implement security controls aligned with identified risks", d => `${d.enabledPolicyCount} policies, ${d.enabledAlertRuleCount} alert rules`),
    assessControl("CC6.1", "Logical Access", "Logical access security software and infrastructure", "Security", 10, data, d => d.firewallRuleCount >= 2 ? 10 : d.firewallRuleCount * 4, "Implement access controls including firewalls and authentication", d => `${d.firewallRuleCount} access control rules`),
    assessControl("CC6.6", "Threat Management", "System boundaries are protected against threats", "Security", 10, data, d => d.agentCount >= 1 && d.firewallRuleCount >= 1 ? Math.min(d.agentCount * 2 + d.firewallRuleCount * 2, 10) : 0, "Deploy boundary protection and threat detection systems", d => `${d.agentCount} agents, ${d.firewallRuleCount} firewall rules`),
    assessControl("CC6.8", "Malware Prevention", "Controls to prevent or detect unauthorized software", "Security", 10, data, d => d.quarantineCount >= 1 || d.agentCount >= 2 ? Math.min(5 + d.agentCount * 2, 10) : d.agentCount >= 1 ? 4 : 0, "Deploy anti-malware controls with automated quarantine", d => `${d.agentCount} agents, ${d.quarantineCount} quarantined`),
    assessControl("CC7.1", "Monitoring", "Detection and monitoring procedures are in place", "Security", 10, data, d => d.enabledAlertRuleCount >= 2 ? 10 : d.enabledAlertRuleCount * 4, "Enable continuous monitoring with alert rules", d => `${d.enabledAlertRuleCount} monitoring rules active`),
    assessControl("CC7.2", "Anomaly Detection", "Anomalies are identified and evaluated", "Security", 10, data, d => d.alertRuleCount >= 3 ? 10 : d.alertRuleCount * 3, "Configure anomaly detection rules and investigation workflows", d => `${d.alertRuleCount} detection rules`),
    assessControl("CC7.3", "Incident Evaluation", "Security incidents are evaluated to determine response", "Security", 10, data, d => d.incidentCount >= 1 ? Math.min(5 + d.incidentCount * 2, 10) : 0, "Establish incident classification and response procedures", d => `${d.incidentCount} incidents evaluated`),
    assessControl("CC7.4", "Incident Response", "Security incidents are responded to", "Security", 10, data, d => d.enabledPlaybookCount >= 1 ? Math.min(d.enabledPlaybookCount * 4, 10) : 0, "Enable automated response playbooks for common incident types", d => `${d.enabledPlaybookCount} response playbooks`),
    assessControl("CC8.1", "Change Management", "Changes to systems are authorized and tested", "Security", 10, data, d => d.auditLogCount >= 10 ? 8 : d.auditLogCount >= 1 ? 4 : 0, "Implement formal change management procedures with audit trail", d => `${d.auditLogCount} audit entries tracking changes`),
    assessControl("A1.1", "Availability Controls", "Processing capacity and availability are maintained", "Availability", 10, data, d => d.agentCount >= 2 ? 10 : d.agentCount >= 1 ? 6 : 0, "Monitor system availability through deployed agents", d => `${d.agentCount} agents monitoring availability`),
    assessControl("PI1.1", "Processing Integrity", "System processing is complete and accurate", "Processing Integrity", 10, data, d => d.auditLogCount >= 5 ? 7 : d.auditLogCount >= 1 ? 4 : 0, "Implement data validation and processing controls", d => `${d.auditLogCount} processing audit records`),
    assessControl("C1.1", "Confidentiality", "Confidential information is protected", "Confidentiality", 10, data, d => d.enabledPolicyCount >= 1 && d.firewallRuleCount >= 1 ? 10 : (d.enabledPolicyCount + d.firewallRuleCount) * 3, "Define data classification and enforce access restrictions", d => `${d.enabledPolicyCount} policies, ${d.firewallRuleCount} access rules`),
  ];
}

function buildGDPRControls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("Art.5", "Data Processing Principles", "Personal data is processed lawfully and transparently", "Data Principles", 10, data, d => d.policyCount >= 2 ? 10 : d.policyCount * 4, "Document lawful basis for all personal data processing", d => `${d.policyCount} data processing policies`),
    assessControl("Art.6", "Lawfulness of Processing", "Processing has a valid legal basis", "Data Principles", 10, data, d => d.policyCount >= 1 ? 7 : 0, "Map all processing activities to legal bases", d => `${d.policyCount} policies covering legal basis`),
    assessControl("Art.13", "Transparency", "Data subjects are informed about processing", "Data Subject Rights", 10, data, d => d.policyCount >= 1 ? 6 : 0, "Publish clear privacy notices and maintain records of processing", d => `${d.policyCount} transparency policies`),
    assessControl("Art.17", "Right to Erasure", "Mechanism for data deletion requests", "Data Subject Rights", 10, data, d => d.enabledPolicyCount >= 1 ? 5 : 0, "Implement automated data deletion procedures", d => `${d.enabledPolicyCount} data retention policies`),
    assessControl("Art.25", "Data Protection by Design", "Data protection is integrated into processing", "Security Measures", 10, data, d => d.enabledPolicyCount >= 2 ? 10 : d.enabledPolicyCount * 4, "Integrate privacy controls into system design and development", d => `${d.enabledPolicyCount} active data protection policies`),
    assessControl("Art.30", "Records of Processing", "Records of processing activities are maintained", "Accountability", 10, data, d => d.auditLogCount >= 10 ? 10 : d.auditLogCount >= 1 ? Math.min(d.auditLogCount, 10) : 0, "Maintain comprehensive records of all data processing activities", d => `${d.auditLogCount} audit log entries`),
    assessControl("Art.32.1a", "Encryption", "Encryption of personal data", "Security Measures", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Implement encryption for personal data at rest and in transit", d => `${d.enabledPolicyCount} encryption-related policies`),
    assessControl("Art.32.1b", "Confidentiality", "Ability to ensure ongoing confidentiality", "Security Measures", 10, data, d => d.firewallRuleCount >= 2 ? 10 : d.firewallRuleCount * 4, "Enforce access controls and network segmentation", d => `${d.firewallRuleCount} confidentiality controls`),
    assessControl("Art.32.1c", "Availability & Resilience", "Ability to restore availability after incidents", "Security Measures", 10, data, d => d.enabledPlaybookCount >= 1 ? Math.min(d.enabledPlaybookCount * 4, 10) : 0, "Develop disaster recovery and business continuity plans", d => `${d.enabledPlaybookCount} recovery playbooks`),
    assessControl("Art.32.1d", "Security Testing", "Regular testing and evaluation of security measures", "Security Measures", 10, data, d => d.eventCount >= 5 ? 8 : d.eventCount >= 1 ? 4 : 0, "Conduct regular security assessments and penetration tests", d => `${d.eventCount} security events from testing`),
    assessControl("Art.33", "Breach Notification", "Supervisory authority notification within 72 hours", "Breach Response", 10, data, d => d.enabledPlaybookCount >= 1 && d.enabledAlertRuleCount >= 1 ? 10 : (d.enabledPlaybookCount + d.enabledAlertRuleCount) * 3, "Establish breach notification procedures with automated alerting", d => `${d.enabledPlaybookCount} playbooks, ${d.enabledAlertRuleCount} alert rules`),
    assessControl("Art.34", "Data Subject Notification", "Communicating breaches to affected data subjects", "Breach Response", 10, data, d => d.enabledPlaybookCount >= 1 ? 6 : 0, "Prepare data subject notification templates and procedures", d => `${d.enabledPlaybookCount} communication playbooks`),
    assessControl("Art.35", "Data Protection Impact Assessment", "DPIAs are conducted for high-risk processing", "Accountability", 10, data, d => d.policyCount >= 2 ? 7 : d.policyCount >= 1 ? 4 : 0, "Conduct DPIAs for all high-risk processing activities", d => `${d.policyCount} policies guiding impact assessments`),
    assessControl("Art.37", "Data Protection Officer", "DPO is designated where required", "Accountability", 10, data, d => d.policyCount >= 1 ? 5 : 0, "Appoint a Data Protection Officer and define responsibilities", d => `${d.policyCount} governance policies in place`),
  ];
}

function buildPCIDSSControls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("Req.1.1", "Network Security Controls", "Network security controls are defined and implemented", "Network Security", 10, data, d => d.firewallRuleCount >= 3 ? 10 : d.firewallRuleCount * 3, "Install and maintain network security controls", d => `${d.firewallRuleCount} network security rules`),
    assessControl("Req.1.3", "Network Access Restriction", "Network access to cardholder data environment is restricted", "Network Security", 10, data, d => d.firewallRuleCount >= 2 ? 10 : d.firewallRuleCount * 4, "Restrict network access to card data environment", d => `${d.firewallRuleCount} access restriction rules`),
    assessControl("Req.2.2", "Secure Configuration", "System components are configured securely", "Secure Configuration", 10, data, d => d.enabledPolicyCount >= 2 ? 10 : d.enabledPolicyCount * 4, "Apply secure configurations to all system components", d => `${d.enabledPolicyCount} configuration policies`),
    assessControl("Req.3.4", "Data Protection", "PAN is secured wherever it is stored", "Data Protection", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Implement strong encryption for stored cardholder data", d => `${d.enabledPolicyCount} data protection policies`),
    assessControl("Req.5.2", "Anti-Malware", "Malicious software is prevented or detected", "Malware Protection", 10, data, d => d.agentCount >= 1 ? Math.min(d.agentCount * 3 + 2, 10) : 0, "Deploy anti-malware solutions on all applicable systems", d => `${d.agentCount} agents with malware detection`),
    assessControl("Req.5.3", "Malware Scanning", "Anti-malware mechanisms are active and maintained", "Malware Protection", 10, data, d => d.quarantineCount >= 1 || d.agentCount >= 2 ? 10 : d.agentCount >= 1 ? 5 : 0, "Enable real-time malware scanning and quarantine", d => `${d.agentCount} agents, ${d.quarantineCount} threats quarantined`),
    assessControl("Req.6.3", "Vulnerability Management", "Security vulnerabilities are identified and addressed", "Vulnerability Management", 10, data, d => d.eventCount >= 5 ? 10 : d.eventCount >= 1 ? d.eventCount * 2 : 0, "Establish vulnerability identification and remediation process", d => `${d.eventCount} vulnerabilities tracked`),
    assessControl("Req.7.1", "Access Restriction", "Access to system components is limited by business need", "Access Control", 10, data, d => d.enabledPolicyCount >= 2 ? 10 : d.enabledPolicyCount * 4, "Implement role-based access control with least privilege", d => `${d.enabledPolicyCount} access policies`),
    assessControl("Req.8.3", "Strong Authentication", "Strong authentication is established for users and admins", "Authentication", 10, data, d => d.enabledPolicyCount >= 1 ? 7 : 0, "Enforce multi-factor authentication for all access", d => `${d.enabledPolicyCount} authentication policies`),
    assessControl("Req.9.1", "Physical Access", "Physical access to cardholder data is restricted", "Physical Security", 10, data, d => d.assetCount >= 1 ? 5 : 0, "Implement physical access controls to sensitive areas", d => `${d.assetCount} assets tracked`),
    assessControl("Req.10.1", "Audit Logging", "Audit logs capture all access to system components", "Logging & Monitoring", 10, data, d => d.auditLogCount >= 10 ? 10 : d.auditLogCount >= 1 ? Math.min(d.auditLogCount, 10) : 0, "Enable comprehensive audit logging for all system access", d => `${d.auditLogCount} audit log entries`),
    assessControl("Req.10.4", "Log Monitoring", "Audit logs are reviewed to identify anomalies", "Logging & Monitoring", 10, data, d => d.enabledAlertRuleCount >= 2 ? 10 : d.enabledAlertRuleCount * 4, "Implement automated log review and alerting", d => `${d.enabledAlertRuleCount} monitoring rules`),
    assessControl("Req.11.3", "Vulnerability Scanning", "External and internal vulnerabilities are regularly tested", "Security Testing", 10, data, d => d.eventCount >= 3 ? 8 : d.eventCount >= 1 ? 4 : 0, "Conduct quarterly vulnerability scans and annual penetration tests", d => `${d.eventCount} scan findings`),
    assessControl("Req.11.5", "Intrusion Detection", "Network intrusions and file changes are detected and responded to", "Security Testing", 10, data, d => d.honeypotEventCount >= 1 || d.enabledAlertRuleCount >= 2 ? 10 : d.enabledAlertRuleCount * 3, "Deploy intrusion detection/prevention systems", d => `${d.honeypotEventCount} intrusion events, ${d.enabledAlertRuleCount} detection rules`),
    assessControl("Req.12.1", "Security Policy", "Information security policy is established and maintained", "Security Policy", 10, data, d => d.policyCount >= 3 ? 10 : d.policyCount * 3, "Maintain comprehensive information security policy", d => `${d.policyCount} security policies`),
    assessControl("Req.12.10", "Incident Response", "Security incidents are responded to immediately", "Security Policy", 10, data, d => d.enabledPlaybookCount >= 2 ? 10 : d.enabledPlaybookCount >= 1 ? 6 : 0, "Establish and test incident response plan", d => `${d.enabledPlaybookCount} response playbooks`),
  ];
}

function buildHIPAAControls(data: PlatformData): ComplianceControl[] {
  return [
    assessControl("164.308.a1", "Security Management Process", "Implement policies to prevent, detect, contain, and correct violations", "Administrative Safeguards", 10, data, d => d.policyCount >= 2 ? 10 : d.policyCount * 4, "Implement comprehensive security management policies", d => `${d.policyCount} security policies`),
    assessControl("164.308.a3", "Workforce Security", "Implement policies for authorization and supervision", "Administrative Safeguards", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Establish workforce security policies and access procedures", d => `${d.enabledPolicyCount} workforce policies`),
    assessControl("164.308.a4", "Information Access Management", "Authorize access to ePHI", "Administrative Safeguards", 10, data, d => d.firewallRuleCount >= 1 && d.enabledPolicyCount >= 1 ? 10 : (d.firewallRuleCount + d.enabledPolicyCount) * 3, "Implement access management procedures for ePHI", d => `${d.firewallRuleCount} access rules, ${d.enabledPolicyCount} policies`),
    assessControl("164.308.a5", "Security Awareness", "Security awareness and training program", "Administrative Safeguards", 10, data, d => d.auditLogCount >= 5 ? 6 : d.auditLogCount >= 1 ? 3 : 0, "Establish security awareness training for all workforce members", d => `${d.auditLogCount} tracked user actions`),
    assessControl("164.308.a6", "Security Incident Procedures", "Address security incidents", "Administrative Safeguards", 10, data, d => d.enabledPlaybookCount >= 1 ? Math.min(d.enabledPlaybookCount * 4, 10) : 0, "Implement incident response and reporting procedures", d => `${d.enabledPlaybookCount} incident response playbooks`),
    assessControl("164.308.a7", "Contingency Plan", "Establish policies for responding to emergencies", "Administrative Safeguards", 10, data, d => d.playbookCount >= 2 ? 8 : d.playbookCount >= 1 ? 5 : 0, "Develop data backup, disaster recovery, and emergency mode plans", d => `${d.playbookCount} contingency playbooks`),
    assessControl("164.308.a8", "Evaluation", "Perform periodic technical and non-technical evaluations", "Administrative Safeguards", 10, data, d => d.eventCount >= 5 ? 8 : d.eventCount >= 1 ? 4 : 0, "Conduct periodic security evaluations", d => `${d.eventCount} evaluation findings`),
    assessControl("164.310.a1", "Facility Access Controls", "Limit physical access to electronic information systems", "Physical Safeguards", 10, data, d => d.assetCount >= 1 ? 5 : 0, "Implement facility access controls and procedures", d => `${d.assetCount} facility assets tracked`),
    assessControl("164.310.d1", "Device and Media Controls", "Govern receipt and removal of hardware and media", "Physical Safeguards", 10, data, d => d.assetCount >= 1 && d.enabledPolicyCount >= 1 ? 8 : d.assetCount >= 1 ? 4 : 0, "Establish device and media disposal and reuse policies", d => `${d.assetCount} devices tracked, ${d.enabledPolicyCount} policies`),
    assessControl("164.312.a1", "Access Control", "Allow only authorized access to ePHI", "Technical Safeguards", 10, data, d => d.firewallRuleCount >= 2 ? 10 : d.firewallRuleCount * 4, "Implement unique user identification, emergency access, and auto-logoff", d => `${d.firewallRuleCount} access control rules`),
    assessControl("164.312.b", "Audit Controls", "Record and examine activity in systems containing ePHI", "Technical Safeguards", 10, data, d => d.auditLogCount >= 10 ? 10 : d.auditLogCount >= 1 ? Math.min(d.auditLogCount, 10) : 0, "Implement hardware, software, and procedural audit mechanisms", d => `${d.auditLogCount} audit records`),
    assessControl("164.312.c1", "Integrity Controls", "Protect ePHI from improper alteration or destruction", "Technical Safeguards", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Implement electronic mechanisms to corroborate data integrity", d => `${d.enabledPolicyCount} integrity policies`),
    assessControl("164.312.d", "Authentication", "Verify identity of persons seeking access to ePHI", "Technical Safeguards", 10, data, d => d.enabledPolicyCount >= 1 ? 7 : 0, "Implement entity authentication procedures", d => `${d.enabledPolicyCount} authentication policies`),
    assessControl("164.312.e1", "Transmission Security", "Guard against unauthorized access to ePHI during transmission", "Technical Safeguards", 10, data, d => d.enabledPolicyCount >= 1 ? 6 : 0, "Implement encryption and integrity controls for data in transit", d => `${d.enabledPolicyCount} transmission security policies`),
    assessControl("164.316.b1", "Documentation", "Maintain policies and procedures in written form", "Documentation", 10, data, d => d.policyCount >= 3 ? 10 : d.policyCount * 3, "Maintain and regularly update all required documentation", d => `${d.policyCount} documented policies`),
  ];
}

function buildAssessment(framework: string, controls: ComplianceControl[]): FrameworkAssessment {
  const fwMeta = FRAMEWORKS[framework];
  const overallScore = controls.reduce((s, c) => s + c.score, 0);
  const maxScore = controls.reduce((s, c) => s + c.maxScore, 0);
  const percentage = maxScore > 0 ? Math.round((overallScore / maxScore) * 100) : 0;

  const categoryMap = new Map<string, { score: number; maxScore: number }>();
  for (const c of controls) {
    const existing = categoryMap.get(c.category) || { score: 0, maxScore: 0 };
    existing.score += c.score;
    existing.maxScore += c.maxScore;
    categoryMap.set(c.category, existing);
  }

  const categories = Array.from(categoryMap.entries()).map(([name, { score, maxScore }]) => ({
    name,
    score,
    maxScore,
    percentage: maxScore > 0 ? Math.round((score / maxScore) * 100) : 0,
  }));

  const gaps = controls
    .filter(c => c.status !== "pass")
    .map(c => ({ control: c, priority: gapPriority(c) }))
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return order[a.priority] - order[b.priority];
    });

  return {
    framework: fwMeta.id,
    frameworkFullName: fwMeta.fullName,
    version: fwMeta.version,
    overallScore,
    maxScore,
    percentage,
    grade: gradeFromPercentage(percentage),
    categories,
    controls,
    gaps,
    lastAssessed: new Date().toISOString(),
  };
}

export function getFrameworks(): FrameworkSummary[] {
  return Object.values(FRAMEWORKS);
}

export async function assessFramework(framework: string, orgId: number): Promise<FrameworkAssessment> {
  const data = await gatherPlatformData(orgId);

  let controls: ComplianceControl[];
  switch (framework) {
    case "nist-csf": controls = buildNistControls(data); break;
    case "iso-27001": controls = buildISO27001Controls(data); break;
    case "soc2": controls = buildSOC2Controls(data); break;
    case "gdpr": controls = buildGDPRControls(data); break;
    case "pci-dss": controls = buildPCIDSSControls(data); break;
    case "hipaa": controls = buildHIPAAControls(data); break;
    default: throw new Error(`Unknown framework: ${framework}`);
  }

  return buildAssessment(framework, controls);
}

export async function getOverallScore(orgId: number): Promise<{ frameworks: { id: string; name: string; percentage: number; grade: string }[]; overall: number; overallGrade: string }> {
  const frameworkIds = Object.keys(FRAMEWORKS);
  const results = await Promise.all(frameworkIds.map(f => assessFramework(f, orgId)));

  const frameworks = results.map(r => ({
    id: r.framework,
    name: FRAMEWORKS[r.framework].name,
    percentage: r.percentage,
    grade: r.grade,
  }));

  const overall = frameworks.length > 0 ? Math.round(frameworks.reduce((s, f) => s + f.percentage, 0) / frameworks.length) : 0;

  return { frameworks, overall, overallGrade: gradeFromPercentage(overall) };
}
