import { storage } from "./storage";

export async function seedDatabase() {
  const eventCount = await storage.getEventCount();
  if (eventCount > 0) return;

  console.log("Seeding database with initial data...");

  const now = Date.now();
  const hours = (h: number) => new Date(now - h * 60 * 60 * 1000);

  const events = [
    { eventType: "intrusion_attempt", severity: "critical", source: "IDS", sourceIp: "185.220.101.34", destinationIp: "10.0.1.15", port: 22, protocol: "SSH", description: "SSH brute force attack - 847 failed attempts in 5 minutes", status: "investigating", createdAt: hours(0.5) },
    { eventType: "malware", severity: "critical", source: "Endpoint", sourceIp: "10.0.2.45", destinationIp: "198.51.100.23", port: 443, protocol: "HTTPS", description: "Trojan.GenericKD.46589321 detected in downloaded executable", status: "new", createdAt: hours(1) },
    { eventType: "data_exfiltration", severity: "critical", source: "DLP", sourceIp: "10.0.3.78", destinationIp: "203.0.113.45", port: 443, protocol: "HTTPS", description: "Anomalous 2.3GB data transfer to external endpoint detected", status: "new", createdAt: hours(2) },
    { eventType: "intrusion_attempt", severity: "high", source: "IDS", sourceIp: "45.33.32.156", destinationIp: "10.0.1.100", port: 443, protocol: "HTTPS", description: "Possible C2 beacon - periodic encrypted connections every 300s", status: "investigating", createdAt: hours(3) },
    { eventType: "anomaly", severity: "high", source: "ML Engine", sourceIp: "10.0.4.12", destinationIp: "172.16.0.50", port: 3389, protocol: "RDP", description: "Lateral movement detected - unusual RDP connections from development workstation", status: "new", createdAt: hours(3.5) },
    { eventType: "malware", severity: "high", source: "Sandbox", sourceIp: "10.0.2.90", destinationIp: null, port: null, protocol: "N/A", description: "Fileless malware indicators - suspicious PowerShell encoded command execution", status: "investigating", createdAt: hours(4) },
    { eventType: "intrusion_attempt", severity: "high", source: "WAF", sourceIp: "198.51.100.89", destinationIp: "10.0.5.10", port: 443, protocol: "HTTPS", description: "SQL injection attempt on /api/users endpoint - payload blocked", status: "resolved", createdAt: hours(5) },
    { eventType: "malware", severity: "high", source: "Email Gateway", sourceIp: "203.0.113.67", destinationIp: "10.0.1.200", port: 25, protocol: "SMTP", description: "Spear phishing email with weaponized .docx attachment quarantined", status: "resolved", createdAt: hours(6) },
    { eventType: "anomaly", severity: "medium", source: "SIEM", sourceIp: "10.0.1.55", destinationIp: null, port: null, protocol: "N/A", description: "Privilege escalation - user escalated to root via CVE-2024-1086 exploit", status: "new", createdAt: hours(7) },
    { eventType: "reconnaissance", severity: "medium", source: "Firewall", sourceIp: "185.220.101.78", destinationIp: "10.0.0.1", port: 0, protocol: "TCP", description: "Sequential port scan detected - 1024 ports scanned in 30 seconds", status: "dismissed", createdAt: hours(8) },
    { eventType: "policy_violation", severity: "medium", source: "DLP", sourceIp: "10.0.3.30", destinationIp: "104.18.32.7", port: 443, protocol: "HTTPS", description: "Classified document uploaded to unauthorized cloud storage (Dropbox)", status: "investigating", createdAt: hours(9) },
    { eventType: "intrusion_attempt", severity: "medium", source: "WAF", sourceIp: "45.33.32.200", destinationIp: "10.0.5.10", port: 80, protocol: "HTTP", description: "Cross-site scripting (XSS) reflected attack attempt blocked", status: "resolved", createdAt: hours(10) },
    { eventType: "anomaly", severity: "medium", source: "Network Monitor", sourceIp: "10.0.4.88", destinationIp: "8.8.8.8", port: 53, protocol: "DNS", description: "DNS tunneling suspected - high volume of TXT record queries to single domain", status: "new", createdAt: hours(11) },
    { eventType: "policy_violation", severity: "low", source: "Endpoint", sourceIp: "10.0.2.15", destinationIp: null, port: null, protocol: "N/A", description: "Unauthorized USB mass storage device connected to secure workstation", status: "resolved", createdAt: hours(12) },
    { eventType: "anomaly", severity: "low", source: "ML Engine", sourceIp: "10.0.1.120", destinationIp: null, port: null, protocol: "N/A", description: "Unusual login time - user authenticated at 03:47 AM outside normal pattern", status: "dismissed", createdAt: hours(13) },
    { eventType: "reconnaissance", severity: "low", source: "Honeypot", sourceIp: "198.51.100.150", destinationIp: "10.0.9.5", port: 8080, protocol: "HTTP", description: "Automated vulnerability scanner interaction with web honeypot", status: "dismissed", createdAt: hours(14) },
    { eventType: "policy_violation", severity: "info", source: "Endpoint", sourceIp: "10.0.3.60", destinationIp: null, port: null, protocol: "N/A", description: "Software installation attempted without admin approval - application blocked", status: "resolved", createdAt: hours(15) },
    { eventType: "anomaly", severity: "info", source: "Network Monitor", sourceIp: "10.0.1.5", destinationIp: "10.0.1.1", port: 123, protocol: "NTP", description: "NTP synchronization deviation detected - clock drift exceeds 500ms", status: "resolved", createdAt: hours(16) },
    { eventType: "intrusion_attempt", severity: "critical", source: "IDS", sourceIp: "203.0.113.99", destinationIp: "10.0.5.25", port: 445, protocol: "SMB", description: "EternalBlue exploit attempt detected targeting SMB service", status: "resolved", createdAt: hours(18) },
    { eventType: "malware", severity: "critical", source: "Endpoint", sourceIp: "10.0.2.70", destinationIp: null, port: null, protocol: "N/A", description: "Ransomware behavior detected - rapid file encryption across network shares", status: "investigating", createdAt: hours(20) },
  ];

  for (const event of events) {
    const { createdAt, ...rest } = event;
    await storage.createSecurityEvent(rest as any);
  }

  const incidentsList = [
    { title: "Active SSH Brute Force Campaign", description: "Multiple external IPs targeting SSH services across the network. Over 2,000 failed attempts in the last hour. Primary sources traced to Tor exit nodes.", severity: "critical", status: "investigating", assignee: "Sarah Chen" },
    { title: "Potential Data Exfiltration - Finance Dept", description: "Large volume data transfer detected from finance department workstation to unknown external IP. Data classification review in progress.", severity: "critical", status: "open", assignee: "Mike Torres" },
    { title: "Fileless Malware on DEV-WS-045", description: "PowerShell-based fileless malware detected on development workstation. Memory-only payload executing encoded commands. Endpoint isolated.", severity: "high", status: "contained", assignee: "Alex Kim" },
    { title: "Phishing Campaign Targeting Executives", description: "Coordinated spear phishing campaign identified targeting C-suite executives. 5 emails blocked, 2 delivered before detection. Recipients notified.", severity: "high", status: "investigating", assignee: "Jordan Lee" },
    { title: "Web Application Vulnerability Scan", description: "Automated vulnerability scanning detected against public-facing web applications. WAF rules updated to block identified patterns.", severity: "medium", status: "resolved", assignee: "Sarah Chen" },
  ];

  for (const inc of incidentsList) {
    await storage.createIncident(inc);
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
    await storage.createThreatIntel(intel);
  }

  const policiesList = [
    { name: "Network Perimeter Defense", description: "Monitor and block unauthorized inbound/outbound connections. All traffic must pass through IDS/IPS inspection. Block known malicious IPs automatically.", tier: "protect", enabled: true },
    { name: "Endpoint Malware Prevention", description: "Real-time file scanning, behavioral analysis, and process monitoring on all endpoints. Automatic quarantine of detected threats.", tier: "protect", enabled: true },
    { name: "Data Loss Prevention", description: "Monitor and prevent unauthorized transfer of classified or sensitive data. Block uploads to unapproved cloud storage services.", tier: "lockdown", enabled: true },
    { name: "Privileged Access Monitoring", description: "Enhanced monitoring of all privileged account activities. Alert on unusual sudo/admin usage patterns. Require MFA for all elevated access.", tier: "critical", enabled: true },
    { name: "Email Security Gateway", description: "Scan all inbound and outbound email for malicious attachments, phishing links, and social engineering indicators.", tier: "protect", enabled: true },
    { name: "USB Device Control", description: "Restrict USB mass storage device usage on secure workstations. Allow only approved devices through whitelist.", tier: "observe", enabled: false },
  ];

  for (const policy of policiesList) {
    await storage.createSecurityPolicy(policy);
  }

  console.log("Database seeded successfully");
}
