import { storage } from "./storage";

const DEFAULT_ALERT_RULES = [
  {
    name: "SSH Brute Force Detection",
    conditions: JSON.stringify([
      { field: "event_type", operator: "equals", value: "intrusion_attempt" },
      { field: "description", operator: "contains", value: "brute force" }
    ]),
    severity: "high",
    actions: JSON.stringify(["block_source", "create_incident", "notify"]),
  },
  {
    name: "Ransomware Detection",
    conditions: JSON.stringify([
      { field: "severity", operator: "equals", value: "critical" },
      { field: "event_type", operator: "equals", value: "malware" },
      { field: "description", operator: "contains", value: "ransomware" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["auto_quarantine", "block_source", "create_incident", "notify"]),
  },
  {
    name: "SQL Injection Attempt",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "sql injection" }
    ]),
    severity: "high",
    actions: JSON.stringify(["block_source", "create_incident", "notify"]),
  },
  {
    name: "XSS Attack Detection",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "xss" }
    ]),
    severity: "high",
    actions: JSON.stringify(["block_source", "notify"]),
  },
  {
    name: "Port Scan Detection",
    conditions: JSON.stringify([
      { field: "event_type", operator: "equals", value: "reconnaissance" },
      { field: "description", operator: "contains", value: "scan" }
    ]),
    severity: "medium",
    actions: JSON.stringify(["block_source", "notify"]),
  },
  {
    name: "Data Exfiltration Alert",
    conditions: JSON.stringify([
      { field: "event_type", operator: "equals", value: "data_exfiltration" },
      { field: "severity", operator: "severity_gte", value: "high" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["create_incident", "block_source", "notify"]),
  },
  {
    name: "Phishing Email Detection",
    conditions: JSON.stringify([
      { field: "event_type", operator: "equals", value: "malware" },
      { field: "source", operator: "contains", value: "email" }
    ]),
    severity: "high",
    actions: JSON.stringify(["auto_quarantine", "create_incident", "notify"]),
  },
  {
    name: "Lateral Movement Detection",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "lateral" },
      { field: "severity", operator: "severity_gte", value: "high" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["block_source", "create_incident"]),
  },
  {
    name: "Privilege Escalation",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "privilege escalation" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["create_incident", "notify"]),
  },
  {
    name: "C2 Beacon Detection",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "c2" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["auto_sinkhole", "block_source", "create_incident"]),
  },
  {
    name: "Zero-Day Exploit",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "zero-day" }
    ]),
    severity: "critical",
    actions: JSON.stringify(["create_incident", "notify", "block_source"]),
  },
  {
    name: "Unauthorized Access Attempt",
    conditions: JSON.stringify([
      { field: "description", operator: "contains", value: "unauthorized" },
      { field: "severity", operator: "severity_gte", value: "medium" }
    ]),
    severity: "high",
    actions: JSON.stringify(["create_incident", "notify"]),
  },
];

const DEFAULT_PLAYBOOKS = [
  {
    name: "Ransomware Containment",
    description: "Automated response for ransomware outbreaks: isolate infected hosts, kill malicious processes, quarantine files, block lateral movement, and notify incident response team.",
    triggerConditions: "severity=critical AND event_type=malware AND description contains ransomware",
    actions: "isolate_host, kill_process, quarantine_file, block_lateral, notify_ir, forensic_snapshot",
  },
  {
    name: "Phishing Response",
    description: "Handle phishing campaign detection: quarantine malicious emails, block sender domains, reset compromised credentials, and scan affected endpoints.",
    triggerConditions: "event_type=malware AND source contains email",
    actions: "quarantine_email, block_sender, reset_credentials, scan_endpoints, notify_users",
  },
  {
    name: "Brute Force Mitigation",
    description: "Respond to brute force attacks: block source IP, lock targeted accounts, force password resets, enable MFA, and alert administrators.",
    triggerConditions: "event_type=intrusion_attempt AND description contains brute force",
    actions: "block_source_ip, lock_account, reset_password, enable_mfa, notify_admin",
  },
  {
    name: "Data Exfiltration Response",
    description: "Counter data exfiltration attempts: isolate the source host, block destination IPs, capture network traffic for analysis, and notify legal team.",
    triggerConditions: "event_type=data_exfiltration AND severity_gte high",
    actions: "isolate_host, block_destination, capture_traffic, create_forensic_image, notify_legal",
  },
  {
    name: "Malware Outbreak",
    description: "Handle widespread malware infections: quarantine detected files, isolate network segments, scan all endpoints, update threat signatures.",
    triggerConditions: "event_type=malware AND severity_gte high",
    actions: "quarantine_files, isolate_network_segment, scan_all_endpoints, update_signatures, notify_ir",
  },
  {
    name: "Insider Threat Response",
    description: "Respond to insider threat indicators: disable suspicious accounts, revoke access tokens, capture audit logs, preserve evidence chain.",
    triggerConditions: "description contains unauthorized AND source=Internal",
    actions: "disable_account, revoke_access, capture_logs, preserve_evidence, notify_management",
  },
];

export async function seedDefaultRules(orgId: number) {
  try {
    const existingRules = await storage.getAlertRules(orgId);
    if (existingRules.length === 0) {
      for (const rule of DEFAULT_ALERT_RULES) {
        await storage.createAlertRule({
          ...rule,
          organizationId: orgId,
          enabled: true,
        });
      }
      console.log(`Seeded ${DEFAULT_ALERT_RULES.length} alert rules for org ${orgId}`);
    }

    const existingPlaybooks = await storage.getResponsePlaybooks(orgId);
    if (existingPlaybooks.length === 0) {
      for (const playbook of DEFAULT_PLAYBOOKS) {
        await storage.createResponsePlaybook({
          ...playbook,
          organizationId: orgId,
          enabled: true,
        });
      }
      console.log(`Seeded ${DEFAULT_PLAYBOOKS.length} playbooks for org ${orgId}`);
    }
  } catch (error) {
    console.log(`Rule seeding skipped for org ${orgId}: ${(error as Error).message}`);
  }
}

export async function seedAllOrganizations() {
  try {
    const orgs = await storage.getAllOrganizations();
    for (const org of orgs) {
      await seedDefaultRules(org.id);
    }
  } catch (error) {
    console.log("Global rule seeding skipped");
  }
}
