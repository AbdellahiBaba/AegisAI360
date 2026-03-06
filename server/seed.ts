import { storage } from "./storage";

export async function seedDatabase() {
  const eventCount = await storage.getEventCount();
  if (eventCount > 0) return;

  console.log("Seeding database with initial data...");

  const org = await storage.createOrganization({
    name: "Demo Organization",
    slug: "demo-org",
    plan: "professional",
    maxUsers: 25,
  });

  const orgId = org.id;

  const events = [
    { eventType: "intrusion_attempt", severity: "critical", source: "IDS", sourceIp: "185.220.101.34", destinationIp: "10.0.1.15", port: 22, protocol: "SSH", description: "SSH brute force attack - 847 failed attempts in 5 minutes", status: "investigating", techniqueId: "T1078", tactic: "Initial Access" },
    { eventType: "malware", severity: "critical", source: "Endpoint", sourceIp: "10.0.2.45", destinationIp: "198.51.100.23", port: 443, protocol: "HTTPS", description: "Trojan.GenericKD.46589321 detected in downloaded executable", status: "new", techniqueId: "T1059", tactic: "Execution" },
    { eventType: "data_exfiltration", severity: "critical", source: "DLP", sourceIp: "10.0.3.78", destinationIp: "203.0.113.45", port: 443, protocol: "HTTPS", description: "Anomalous 2.3GB data transfer to external endpoint detected", status: "new", techniqueId: "T1048", tactic: "Exfiltration" },
    { eventType: "intrusion_attempt", severity: "high", source: "IDS", sourceIp: "45.33.32.156", destinationIp: "10.0.1.100", port: 443, protocol: "HTTPS", description: "Possible C2 beacon - periodic encrypted connections every 300s", status: "investigating", techniqueId: "T1071", tactic: "Command and Control" },
    { eventType: "anomaly", severity: "high", source: "ML Engine", sourceIp: "10.0.4.12", destinationIp: "172.16.0.50", port: 3389, protocol: "RDP", description: "Lateral movement detected - unusual RDP connections from development workstation", status: "new", techniqueId: "T1021", tactic: "Lateral Movement" },
    { eventType: "malware", severity: "high", source: "Sandbox", sourceIp: "10.0.2.90", destinationIp: null, port: null, protocol: "N/A", description: "Fileless malware indicators - suspicious PowerShell encoded command execution", status: "investigating", techniqueId: "T1059", tactic: "Execution" },
    { eventType: "intrusion_attempt", severity: "high", source: "WAF", sourceIp: "198.51.100.89", destinationIp: "10.0.5.10", port: 443, protocol: "HTTPS", description: "SQL injection attempt on /api/users endpoint - payload blocked", status: "resolved", techniqueId: "T1190", tactic: "Initial Access" },
    { eventType: "malware", severity: "high", source: "Email Gateway", sourceIp: "203.0.113.67", destinationIp: "10.0.1.200", port: 25, protocol: "SMTP", description: "Spear phishing email with weaponized .docx attachment quarantined", status: "resolved", techniqueId: "T1566", tactic: "Initial Access" },
    { eventType: "anomaly", severity: "medium", source: "SIEM", sourceIp: "10.0.1.55", destinationIp: null, port: null, protocol: "N/A", description: "Privilege escalation - user escalated to root via CVE-2024-1086 exploit", status: "new", techniqueId: "T1548", tactic: "Privilege Escalation" },
    { eventType: "reconnaissance", severity: "medium", source: "Firewall", sourceIp: "185.220.101.78", destinationIp: "10.0.0.1", port: 0, protocol: "TCP", description: "Sequential port scan detected - 1024 ports scanned in 30 seconds", status: "dismissed", techniqueId: "T1046", tactic: "Discovery" },
    { eventType: "policy_violation", severity: "medium", source: "DLP", sourceIp: "10.0.3.30", destinationIp: "104.18.32.7", port: 443, protocol: "HTTPS", description: "Classified document uploaded to unauthorized cloud storage (Dropbox)", status: "investigating", techniqueId: "T1567", tactic: "Exfiltration" },
    { eventType: "intrusion_attempt", severity: "medium", source: "WAF", sourceIp: "45.33.32.200", destinationIp: "10.0.5.10", port: 80, protocol: "HTTP", description: "Cross-site scripting (XSS) reflected attack attempt blocked", status: "resolved", techniqueId: "T1189", tactic: "Initial Access" },
    { eventType: "anomaly", severity: "medium", source: "Network Monitor", sourceIp: "10.0.4.88", destinationIp: "8.8.8.8", port: 53, protocol: "DNS", description: "DNS tunneling suspected - high volume of TXT record queries to single domain", status: "new", techniqueId: "T1071", tactic: "Command and Control" },
    { eventType: "policy_violation", severity: "low", source: "Endpoint", sourceIp: "10.0.2.15", destinationIp: null, port: null, protocol: "N/A", description: "Unauthorized USB mass storage device connected to secure workstation", status: "resolved", techniqueId: "T1091", tactic: "Initial Access" },
    { eventType: "anomaly", severity: "low", source: "ML Engine", sourceIp: "10.0.1.120", destinationIp: null, port: null, protocol: "N/A", description: "Unusual login time - user authenticated at 03:47 AM outside normal pattern", status: "dismissed", techniqueId: "T1078", tactic: "Initial Access" },
    { eventType: "reconnaissance", severity: "low", source: "Honeypot", sourceIp: "198.51.100.150", destinationIp: "10.0.9.5", port: 8080, protocol: "HTTP", description: "Automated vulnerability scanner interaction with web honeypot", status: "dismissed", techniqueId: "T1595", tactic: "Reconnaissance" },
    { eventType: "policy_violation", severity: "info", source: "Endpoint", sourceIp: "10.0.3.60", destinationIp: null, port: null, protocol: "N/A", description: "Software installation attempted without admin approval - application blocked", status: "resolved" },
    { eventType: "anomaly", severity: "info", source: "Network Monitor", sourceIp: "10.0.1.5", destinationIp: "10.0.1.1", port: 123, protocol: "NTP", description: "NTP synchronization deviation detected - clock drift exceeds 500ms", status: "resolved" },
    { eventType: "intrusion_attempt", severity: "critical", source: "IDS", sourceIp: "203.0.113.99", destinationIp: "10.0.5.25", port: 445, protocol: "SMB", description: "EternalBlue exploit attempt detected targeting SMB service", status: "resolved", techniqueId: "T1210", tactic: "Lateral Movement" },
    { eventType: "malware", severity: "critical", source: "Endpoint", sourceIp: "10.0.2.70", destinationIp: null, port: null, protocol: "N/A", description: "Ransomware behavior detected - rapid file encryption across network shares", status: "investigating", techniqueId: "T1486", tactic: "Impact" },
  ];

  for (const event of events) {
    await storage.createSecurityEvent({ ...event, organizationId: orgId } as any);
  }

  const incidentsList = [
    { title: "Active SSH Brute Force Campaign", description: "Multiple external IPs targeting SSH services across the network. Over 2,000 failed attempts in the last hour.", severity: "critical", status: "investigating", assignee: "Sarah Chen" },
    { title: "Potential Data Exfiltration - Finance Dept", description: "Large volume data transfer detected from finance department workstation to unknown external IP.", severity: "critical", status: "open", assignee: "Mike Torres" },
    { title: "Fileless Malware on DEV-WS-045", description: "PowerShell-based fileless malware detected on development workstation. Endpoint isolated.", severity: "high", status: "contained", assignee: "Alex Kim" },
    { title: "Phishing Campaign Targeting Executives", description: "Coordinated spear phishing campaign identified targeting C-suite executives.", severity: "high", status: "investigating", assignee: "Jordan Lee" },
    { title: "Web Application Vulnerability Scan", description: "Automated vulnerability scanning detected against public-facing web applications.", severity: "medium", status: "resolved", assignee: "Sarah Chen" },
  ];

  for (const inc of incidentsList) {
    await storage.createIncident({ ...inc, organizationId: orgId });
  }

  const threatIntelList = [
    { indicatorType: "ip", value: "185.220.101.34", threatType: "apt", severity: "critical", source: "AbuseIPDB", description: "Known Tor exit node associated with APT29 operations", active: true },
    { indicatorType: "ip", value: "203.0.113.45", threatType: "c2", severity: "critical", source: "AlienVault OTX", description: "Active C2 server - Cobalt Strike beacon infrastructure", active: true },
    { indicatorType: "domain", value: "malicious-update.com", threatType: "malware", severity: "high", source: "VirusTotal", description: "Malware distribution domain - trojanized software updates", active: true },
    { indicatorType: "hash", value: "a1b2c3d4e5f6789012345678abcdef01", threatType: "ransomware", severity: "critical", source: "MalwareBazaar", description: "SHA256 hash of LockBit 3.0 ransomware variant", active: true },
    { indicatorType: "domain", value: "exfil-data.xyz", threatType: "c2", severity: "high", source: "Threat Intelligence Platform", description: "Data exfiltration endpoint used by FIN7 group", active: true },
    { indicatorType: "url", value: "https://login-verify.phishing-site.com/auth", threatType: "phishing", severity: "high", source: "PhishTank", description: "Active credential harvesting page impersonating Microsoft 365", active: true },
    { indicatorType: "ip", value: "45.33.32.156", threatType: "botnet", severity: "medium", source: "Shodan", description: "IP associated with Mirai botnet C2 infrastructure", active: true },
    { indicatorType: "email", value: "ceo-urgent@spoofed-domain.com", threatType: "phishing", severity: "medium", source: "Internal Report", description: "Business email compromise attempt - CEO impersonation", active: true },
    { indicatorType: "hash", value: "98765432abcdef0123456789fedcba10", threatType: "malware", severity: "medium", source: "VirusTotal", description: "SHA256 of PowerShell dropper - fileless malware stage 1", active: true },
    { indicatorType: "domain", value: "safe-legit-update.net", threatType: "malware", severity: "low", source: "URLhaus", description: "Previously used for drive-by downloads - currently inactive", active: false },
  ];

  for (const intel of threatIntelList) {
    await storage.createThreatIntel({ ...intel, organizationId: orgId });
  }

  const policiesList = [
    { name: "Network Perimeter Defense", description: "Monitor and block unauthorized inbound/outbound connections. All traffic must pass through IDS/IPS inspection.", tier: "protect", enabled: true },
    { name: "Endpoint Malware Prevention", description: "Real-time file scanning, behavioral analysis, and process monitoring on all endpoints.", tier: "protect", enabled: true },
    { name: "Data Loss Prevention", description: "Monitor and prevent unauthorized transfer of classified or sensitive data.", tier: "lockdown", enabled: true },
    { name: "Privileged Access Monitoring", description: "Enhanced monitoring of all privileged account activities. Alert on unusual sudo/admin usage.", tier: "critical", enabled: true },
    { name: "Email Security Gateway", description: "Scan all inbound and outbound email for malicious attachments and phishing indicators.", tier: "protect", enabled: true },
    { name: "USB Device Control", description: "Restrict USB mass storage device usage on secure workstations.", tier: "observe", enabled: false },
  ];

  for (const policy of policiesList) {
    await storage.createSecurityPolicy({ ...policy, organizationId: orgId });
  }

  const assetsList = [
    { name: "DC-01", type: "server", ipAddress: "10.0.1.5", os: "Windows Server 2022", status: "online", riskScore: 15 },
    { name: "WEB-PROD-01", type: "server", ipAddress: "10.0.5.10", os: "Ubuntu 22.04", status: "online", riskScore: 45 },
    { name: "DB-PROD-01", type: "server", ipAddress: "10.0.3.100", os: "CentOS 8", status: "online", riskScore: 25 },
    { name: "FW-EDGE-01", type: "firewall", ipAddress: "10.0.0.1", os: "pfSense 2.7", status: "online", riskScore: 10 },
    { name: "DEV-WS-045", type: "workstation", ipAddress: "10.0.4.12", os: "Windows 11", status: "isolated", riskScore: 85 },
    { name: "MAIL-GW-01", type: "server", ipAddress: "10.0.1.200", os: "Linux", status: "online", riskScore: 30 },
    { name: "FIN-WS-012", type: "workstation", ipAddress: "10.0.3.78", os: "Windows 11", status: "online", riskScore: 70 },
    { name: "SIEM-01", type: "server", ipAddress: "10.0.1.55", os: "Ubuntu 22.04", status: "online", riskScore: 5 },
    { name: "VPN-GW-01", type: "appliance", ipAddress: "10.0.0.5", os: "OpenVPN AS", status: "online", riskScore: 20 },
    { name: "SWITCH-CORE-01", type: "network", ipAddress: "10.0.0.2", os: "Cisco IOS", status: "online", riskScore: 8 },
  ];

  for (const asset of assetsList) {
    await storage.createAsset({ ...asset, organizationId: orgId });
  }

  const honeypotEventsList = [
    { honeypotName: "SSH-Trap-01", attackerIp: "185.220.101.50", service: "SSH", action: "brute_force", payload: "root:admin123", country: "RU", sessionId: "sess001" },
    { honeypotName: "HTTP-Decoy-01", attackerIp: "45.33.32.100", service: "HTTP", action: "directory_traversal", payload: "GET /../../etc/passwd", country: "CN", sessionId: "sess002" },
    { honeypotName: "SMB-Honeypot-01", attackerIp: "203.0.113.88", service: "SMB", action: "share_enumeration", payload: "net share /all", country: "KR", sessionId: "sess003" },
    { honeypotName: "SSH-Trap-01", attackerIp: "198.51.100.44", service: "SSH", action: "login_attempt", payload: "admin:password", country: "BR", sessionId: "sess004" },
    { honeypotName: "HTTP-Decoy-01", attackerIp: "185.220.101.77", service: "HTTP", action: "sql_injection", payload: "' OR 1=1 --", country: "RU", sessionId: "sess005" },
    { honeypotName: "RDP-Trap-01", attackerIp: "172.16.0.99", service: "RDP", action: "login_attempt", payload: "Administrator:P@ssw0rd", country: "UA", sessionId: "sess006" },
  ];

  for (const hp of honeypotEventsList) {
    await storage.createHoneypotEvent({ ...hp, organizationId: orgId });
  }

  const quarantineList = [
    { fileName: "invoice_final.exe", fileHash: "abc123def456", threat: "Trojan.GenericKD.46589321", sourceAsset: "FIN-WS-012", action: "quarantined", status: "quarantined", quarantinedBy: "Auto-Scan" },
    { fileName: "update_patch.ps1", fileHash: "789ghi012jkl", threat: "PowerShell.Suspicious.Encoded", sourceAsset: "DEV-WS-045", action: "quarantined", status: "quarantined", quarantinedBy: "Sandbox" },
    { fileName: "report.docm", fileHash: "mno345pqr678", threat: "Macro.Downloader.Gen", sourceAsset: "MAIL-GW-01", action: "quarantined", status: "quarantined", quarantinedBy: "Email Gateway" },
  ];

  for (const q of quarantineList) {
    await storage.createQuarantineItem({ ...q, organizationId: orgId });
  }

  const playbooksList = [
    { name: "Ransomware Containment", description: "Immediate isolation of affected hosts, block lateral movement, preserve forensic evidence, notify incident response team.", triggerConditions: "severity=critical AND eventType=malware AND description CONTAINS 'ransomware'", actions: "isolate_host,block_lateral,preserve_evidence,notify_ir", enabled: true },
    { name: "Phishing Response", description: "Quarantine suspicious emails, block sender domain, scan all recipients for indicators, force password reset for clicked users.", triggerConditions: "eventType=malware AND source=Email Gateway", actions: "quarantine_email,block_domain,scan_recipients,password_reset", enabled: true },
    { name: "Brute Force Mitigation", description: "Temporarily block source IP, enable enhanced logging, notify SOC analyst, check for successful auth.", triggerConditions: "eventType=intrusion_attempt AND description CONTAINS 'brute force'", actions: "block_ip_temp,enhanced_logging,notify_analyst,check_auth", enabled: true },
    { name: "Data Exfiltration Prevention", description: "Block outbound connection, isolate source host, capture traffic for analysis, escalate to management.", triggerConditions: "eventType=data_exfiltration AND severity IN (critical,high)", actions: "block_outbound,isolate_host,capture_traffic,escalate", enabled: false },
  ];

  for (const pb of playbooksList) {
    await storage.createResponsePlaybook({ ...pb, organizationId: orgId });
  }

  console.log("Database seeded successfully");
}
