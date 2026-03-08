import { storage } from "./storage";

const ATTACKER_IPS = [
  "185.220.101.34", "45.155.205.233", "194.26.29.65", "103.75.201.4",
  "5.188.87.194", "91.240.118.172", "193.42.33.7", "45.95.169.22",
  "185.56.80.65", "212.70.149.18",
];

const C2_DOMAINS = [
  "malicious-update.evil.com", "c2-beacon.darknet.io", "exfil-data.shadow.net",
  "payload-drop.attack.org", "reverse-shell.hack.me",
];

function randomIp(): string {
  return ATTACKER_IPS[Math.floor(Math.random() * ATTACKER_IPS.length)];
}

function randomDomain(): string {
  return C2_DOMAINS[Math.floor(Math.random() * C2_DOMAINS.length)];
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function createEvent(orgId: number, event: {
  eventType: string;
  severity: string;
  source: string;
  sourceIp?: string;
  destinationIp?: string;
  port?: number;
  protocol?: string;
  description: string;
  techniqueId?: string;
  tactic?: string;
}) {
  return storage.createSecurityEvent({
    organizationId: orgId,
    ...event,
  });
}

export async function simulateBruteForce(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const targetIp = "10.0.1.50";
  let count = 0;

  for (let i = 0; i < 15; i++) {
    await createEvent(orgId, {
      eventType: "intrusion_attempt",
      severity: i < 10 ? "medium" : "high",
      source: "SSH Server",
      sourceIp: attackerIp,
      destinationIp: targetIp,
      port: 22,
      protocol: "SSH",
      description: `SSH brute force attempt #${i + 1} from ${attackerIp} - Failed login for user ${["root", "admin", "ubuntu", "deploy"][i % 4]}`,
      techniqueId: "T1078",
      tactic: "Initial Access",
    });
    count++;
    await delay(200);
  }

  await createEvent(orgId, {
    eventType: "intrusion_attempt",
    severity: "critical",
    source: "SSH Server",
    sourceIp: attackerIp,
    destinationIp: targetIp,
    port: 22,
    protocol: "SSH",
    description: `SSH brute force attack detected - ${count} failed attempts from ${attackerIp} in rapid succession`,
    techniqueId: "T1078",
    tactic: "Initial Access",
  });
  count++;

  return { eventsCreated: count, description: `SSH Brute Force from ${attackerIp}: ${count} events generated` };
}

export async function simulateRansomware(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const c2Domain = randomDomain();
  let count = 0;

  await createEvent(orgId, {
    eventType: "malware",
    severity: "high",
    source: "Endpoint Protection",
    sourceIp: "10.0.2.15",
    description: `Suspicious executable detected: invoice_final.exe - potential ransomware dropper`,
    techniqueId: "T1204",
    tactic: "Execution",
  });
  count++;
  await delay(300);

  await createEvent(orgId, {
    eventType: "malware",
    severity: "critical",
    source: "Endpoint Protection",
    sourceIp: "10.0.2.15",
    destinationIp: attackerIp,
    description: `C2 beacon detected to ${c2Domain} (${attackerIp}) - ransomware command and control communication`,
    techniqueId: "T1071",
    tactic: "Command and Control",
  });
  count++;
  await delay(300);

  const encryptedFiles = ["documents/finance_q4.xlsx", "database/backup.sql", "shared/contracts.pdf"];
  for (const file of encryptedFiles) {
    await createEvent(orgId, {
      eventType: "malware",
      severity: "critical",
      source: "File Integrity Monitor",
      sourceIp: "10.0.2.15",
      description: `Ransomware file encryption detected: ${file} - rapid encryption pattern consistent with LockBit 3.0`,
      techniqueId: "T1486",
      tactic: "Impact",
    });
    count++;
    await delay(200);
  }

  await createEvent(orgId, {
    eventType: "data_exfiltration",
    severity: "critical",
    source: "Network Monitor",
    sourceIp: "10.0.2.15",
    destinationIp: attackerIp,
    protocol: "HTTPS",
    description: `Large data transfer (4.2GB) to external IP ${attackerIp} - ransomware data exfiltration before encryption`,
    techniqueId: "T1041",
    tactic: "Exfiltration",
  });
  count++;

  return { eventsCreated: count, description: `Ransomware Outbreak: ${count} events - dropper, C2, encryption, and exfiltration` };
}

export async function simulatePhishing(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const domains = ["secure-login-verify.com", "accounts-security-alert.net", "microsoft365-update.org"];
  let count = 0;

  for (const domain of domains) {
    await createEvent(orgId, {
      eventType: "malware",
      severity: "high",
      source: "Email Gateway",
      sourceIp: randomIp(),
      description: `Phishing email detected from ${domain} - malicious attachment: security_update.docm`,
      techniqueId: "T1566",
      tactic: "Initial Access",
    });
    count++;
    await delay(250);
  }

  await createEvent(orgId, {
    eventType: "malware",
    severity: "critical",
    source: "Email Gateway",
    sourceIp: randomIp(),
    description: `Spear phishing campaign targeting executives - 12 emails from spoofed CFO address with credential harvesting links`,
    techniqueId: "T1566.001",
    tactic: "Initial Access",
  });
  count++;

  await createEvent(orgId, {
    eventType: "intrusion_attempt",
    severity: "high",
    source: "Web Proxy",
    sourceIp: "10.0.3.22",
    description: `User clicked phishing link - credentials submitted to fake login page at accounts-security-alert.net`,
    techniqueId: "T1078",
    tactic: "Credential Access",
  });
  count++;

  return { eventsCreated: count, description: `Phishing Campaign: ${count} events - malicious emails and credential theft` };
}

export async function simulatePortScan(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443];
  let count = 0;

  for (const port of ports) {
    await createEvent(orgId, {
      eventType: "reconnaissance",
      severity: "medium",
      source: "IDS",
      sourceIp: attackerIp,
      destinationIp: "10.0.0.1",
      port,
      protocol: "TCP",
      description: `Port scan detected - SYN probe on port ${port} from ${attackerIp}`,
      techniqueId: "T1046",
      tactic: "Discovery",
    });
    count++;
    await delay(100);
  }

  await createEvent(orgId, {
    eventType: "reconnaissance",
    severity: "high",
    source: "IDS",
    sourceIp: attackerIp,
    description: `Network scan sweep completed - ${ports.length} ports probed from ${attackerIp} in rapid succession`,
    techniqueId: "T1046",
    tactic: "Discovery",
  });
  count++;

  return { eventsCreated: count, description: `Port Scan Sweep from ${attackerIp}: ${count} events across ${ports.length} ports` };
}

export async function simulateDataExfiltration(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  let count = 0;

  await createEvent(orgId, {
    eventType: "anomaly",
    severity: "medium",
    source: "DLP",
    sourceIp: "10.0.4.10",
    description: `Unusual database query pattern detected - bulk SELECT on customer_records table (500K+ rows)`,
    techniqueId: "T1213",
    tactic: "Collection",
  });
  count++;
  await delay(300);

  await createEvent(orgId, {
    eventType: "data_exfiltration",
    severity: "high",
    source: "Network Monitor",
    sourceIp: "10.0.4.10",
    destinationIp: attackerIp,
    protocol: "DNS",
    description: `DNS tunneling detected - encoded data exfiltration via DNS queries to suspicious domain`,
    techniqueId: "T1048",
    tactic: "Exfiltration",
  });
  count++;
  await delay(300);

  await createEvent(orgId, {
    eventType: "data_exfiltration",
    severity: "critical",
    source: "Network Monitor",
    sourceIp: "10.0.4.10",
    destinationIp: attackerIp,
    protocol: "HTTPS",
    port: 443,
    description: `Large data exfiltration detected - 2.3GB transferred to ${attackerIp} via encrypted channel`,
    techniqueId: "T1041",
    tactic: "Exfiltration",
  });
  count++;

  return { eventsCreated: count, description: `Data Exfiltration: ${count} events - collection, DNS tunneling, and bulk transfer` };
}

export async function simulateAPT(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const c2Domain = randomDomain();
  let count = 0;

  const killChain = [
    {
      eventType: "reconnaissance", severity: "medium", source: "IDS",
      description: `Network reconnaissance from ${attackerIp} - OSINT enumeration and infrastructure probing`,
      techniqueId: "T1595", tactic: "Reconnaissance",
    },
    {
      eventType: "intrusion_attempt", severity: "high", source: "WAF",
      description: `Exploit attempt against web application - CVE-2024-3094 XZ Utils backdoor exploitation from ${attackerIp}`,
      techniqueId: "T1190", tactic: "Initial Access",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Persistence mechanism established - scheduled task created for PowerShell reverse shell to ${c2Domain}`,
      techniqueId: "T1059.001", tactic: "Execution",
    },
    {
      eventType: "anomaly", severity: "high", source: "AD Monitor",
      description: `Privilege escalation detected - service account elevated to Domain Admin via Kerberoasting`,
      techniqueId: "T1558", tactic: "Privilege Escalation",
    },
    {
      eventType: "intrusion_attempt", severity: "critical", source: "Network Monitor",
      description: `Lateral movement via PsExec - attacker moving from 10.0.2.15 to domain controller 10.0.1.1`,
      techniqueId: "T1021", tactic: "Lateral Movement",
    },
    {
      eventType: "anomaly", severity: "high", source: "File Integrity Monitor",
      description: `Credential dumping detected - LSASS memory access from suspicious process on domain controller`,
      techniqueId: "T1003", tactic: "Credential Access",
    },
    {
      eventType: "data_exfiltration", severity: "critical", source: "DLP",
      description: `Sensitive data staging detected - classified documents compressed and encrypted for exfiltration`,
      techniqueId: "T1560", tactic: "Collection",
    },
    {
      eventType: "data_exfiltration", severity: "critical", source: "Network Monitor",
      description: `APT data exfiltration - 8.7GB transferred to ${attackerIp} via steganography-embedded HTTPS traffic`,
      techniqueId: "T1041", tactic: "Exfiltration",
    },
  ];

  for (const event of killChain) {
    await createEvent(orgId, {
      ...event,
      sourceIp: event.tactic === "Reconnaissance" || event.tactic === "Initial Access" ? attackerIp : "10.0.2.15",
      destinationIp: event.tactic === "Exfiltration" ? attackerIp : "10.0.1.1",
    });
    count++;
    await delay(400);
  }

  return { eventsCreated: count, description: `APT Kill Chain: ${count} events - full attack lifecycle from recon to exfiltration` };
}

export async function simulateSupplyChain(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const c2Domain = randomDomain();
  let count = 0;

  const events = [
    {
      eventType: "anomaly", severity: "medium", source: "Package Monitor",
      description: `Compromised npm package detected: event-stream@3.3.6 - unexpected dependency flatmap-stream added`,
      techniqueId: "T1195.002", tactic: "Initial Access",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Backdoor payload activated from node_modules/flatmap-stream - obfuscated code executing post-install script`,
      techniqueId: "T1059.007", tactic: "Execution",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Persistence established via cron job - backdoor writes to /etc/cron.d/sysupdate pointing to compromised binary`,
      techniqueId: "T1053.003", tactic: "Persistence",
    },
    {
      eventType: "anomaly", severity: "high", source: "Process Monitor",
      description: `Suspicious child process spawned from node - /tmp/.cache/sysupdate executing with elevated privileges`,
      techniqueId: "T1055", tactic: "Defense Evasion",
    },
    {
      eventType: "anomaly", severity: "high", source: "File Integrity Monitor",
      description: `Credential harvesting detected - .env files and AWS credentials read by compromised process`,
      techniqueId: "T1552.001", tactic: "Credential Access",
    },
    {
      eventType: "data_exfiltration", severity: "critical", source: "Network Monitor",
      description: `Data exfiltration via HTTPS POST to ${c2Domain} (${attackerIp}) - API keys, database credentials, and environment variables sent`,
      techniqueId: "T1041", tactic: "Exfiltration",
    },
  ];

  for (const event of events) {
    await createEvent(orgId, {
      ...event,
      sourceIp: event.tactic === "Initial Access" ? attackerIp : "10.0.5.20",
      destinationIp: event.tactic === "Exfiltration" ? attackerIp : undefined,
    });
    count++;
    await delay(300);
  }

  return { eventsCreated: count, description: `Supply Chain Attack: ${count} events - compromised package, backdoor, credential theft, exfiltration` };
}

export async function simulateInsiderThreat(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  let count = 0;

  const events = [
    {
      eventType: "anomaly", severity: "low", source: "IAM Monitor",
      description: `Off-hours login detected - user jsmith authenticated at 02:47 AM from unusual workstation WS-FINANCE-03`,
      techniqueId: "T1078", tactic: "Initial Access",
    },
    {
      eventType: "anomaly", severity: "medium", source: "AD Monitor",
      description: `Privilege abuse detected - user jsmith accessing restricted file shares: \\\\fileserver\\executive-compensation, \\\\fileserver\\m-and-a`,
      techniqueId: "T1078.002", tactic: "Privilege Escalation",
    },
    {
      eventType: "anomaly", severity: "medium", source: "DLP",
      description: `Unauthorized access to sensitive database - user jsmith querying customer_pii table with SELECT * (450K rows returned)`,
      techniqueId: "T1213", tactic: "Collection",
    },
    {
      eventType: "anomaly", severity: "high", source: "DLP",
      description: `Bulk file download detected - user jsmith downloaded 2,847 files from confidential project repository in 12 minutes`,
      techniqueId: "T1530", tactic: "Collection",
    },
    {
      eventType: "anomaly", severity: "high", source: "Email Gateway",
      description: `Data staging via email - user jsmith sent 14 emails with encrypted ZIP attachments to personal email address`,
      techniqueId: "T1048.002", tactic: "Exfiltration",
    },
    {
      eventType: "data_exfiltration", severity: "critical", source: "USB Monitor",
      description: `USB mass storage device connected - 32GB drive mounted, 28.4GB of sensitive files copied including trade secrets and client data`,
      techniqueId: "T1052.001", tactic: "Exfiltration",
    },
    {
      eventType: "anomaly", severity: "critical", source: "IAM Monitor",
      description: `Anti-forensics detected - user jsmith clearing browser history, deleting recent files, and wiping Recycle Bin`,
      techniqueId: "T1070.004", tactic: "Defense Evasion",
    },
  ];

  for (const event of events) {
    await createEvent(orgId, {
      ...event,
      sourceIp: "10.0.3.45",
    });
    count++;
    await delay(350);
  }

  return { eventsCreated: count, description: `Insider Threat: ${count} events - unauthorized access, bulk download, USB exfiltration, anti-forensics` };
}

export async function simulateZeroDay(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const c2Domain = randomDomain();
  let count = 0;

  const events = [
    {
      eventType: "intrusion_attempt", severity: "high", source: "WAF",
      description: `Unknown exploit payload detected - novel HTTP deserialization attack bypassing WAF signatures on /api/v2/auth endpoint`,
      techniqueId: "T1190", tactic: "Initial Access",
    },
    {
      eventType: "malware", severity: "critical", source: "Endpoint Protection",
      description: `Zero-day exploitation successful - arbitrary code execution achieved via memory corruption in libxml2 (no CVE assigned)`,
      techniqueId: "T1203", tactic: "Execution",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Kernel-level rootkit installed - modified system call table entries for sys_read, sys_getdents64 to hide attacker processes`,
      techniqueId: "T1014", tactic: "Defense Evasion",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Persistence via modified init system - systemd service 'syshealth-monitor' created pointing to /usr/lib/.hidden/beacon`,
      techniqueId: "T1543.002", tactic: "Persistence",
    },
    {
      eventType: "anomaly", severity: "high", source: "AD Monitor",
      description: `Golden Ticket attack detected - forged Kerberos TGT used to access domain controller with KRBTGT hash`,
      techniqueId: "T1558.001", tactic: "Credential Access",
    },
    {
      eventType: "intrusion_attempt", severity: "critical", source: "Network Monitor",
      description: `Lateral movement via WMI - attacker pivoting from web server to database servers using stolen domain admin credentials`,
      techniqueId: "T1047", tactic: "Lateral Movement",
    },
    {
      eventType: "data_exfiltration", severity: "critical", source: "Network Monitor",
      description: `Covert channel exfiltration - data encoded in ICMP echo request payloads to ${attackerIp}, 3.2GB transferred over 6 hours`,
      techniqueId: "T1048.003", tactic: "Exfiltration",
    },
  ];

  for (const event of events) {
    await createEvent(orgId, {
      ...event,
      sourceIp: event.tactic === "Initial Access" ? attackerIp : "10.0.1.25",
      destinationIp: event.tactic === "Exfiltration" || event.tactic === "Lateral Movement" ? attackerIp : "10.0.1.1",
    });
    count++;
    await delay(400);
  }

  return { eventsCreated: count, description: `Zero-Day Exploit: ${count} events - novel exploit, rootkit, golden ticket, covert exfiltration` };
}

export async function simulateCryptojacking(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  const attackerIp = randomIp();
  const miningPool = "stratum+tcp://pool.minexmr.com:4444";
  let count = 0;

  const events = [
    {
      eventType: "intrusion_attempt", severity: "medium", source: "WAF",
      description: `Exploit attempt on exposed Docker API - unauthenticated access to /v1.24/containers/create endpoint from ${attackerIp}`,
      techniqueId: "T1190", tactic: "Initial Access",
    },
    {
      eventType: "malware", severity: "high", source: "Container Runtime",
      description: `Malicious container deployed - image alpine:latest pulled and executed with --privileged flag, downloading XMRig miner`,
      techniqueId: "T1610", tactic: "Execution",
    },
    {
      eventType: "anomaly", severity: "high", source: "Performance Monitor",
      description: `CPU usage spike detected - all 16 cores at 98% utilization on server db-prod-03, process: /tmp/.X11-unix/xmrig`,
      techniqueId: "T1496", tactic: "Impact",
    },
    {
      eventType: "anomaly", severity: "medium", source: "Performance Monitor",
      description: `Memory pressure alert - 94% RAM utilization on db-prod-03, legitimate services experiencing OOM kills`,
      techniqueId: "T1496", tactic: "Impact",
    },
    {
      eventType: "anomaly", severity: "high", source: "Network Monitor",
      description: `Cryptocurrency mining traffic detected - outbound connection to ${miningPool} using Stratum protocol on port 4444`,
      techniqueId: "T1571", tactic: "Command and Control",
    },
    {
      eventType: "malware", severity: "high", source: "Endpoint Protection",
      description: `Miner persistence mechanism - crontab modified to restart XMRig on reboot, watchdog script kills competing miners`,
      techniqueId: "T1053.003", tactic: "Persistence",
    },
    {
      eventType: "anomaly", severity: "critical", source: "Network Monitor",
      description: `Lateral mining propagation - miner spreading to 4 additional servers via SSH key reuse: db-prod-04, web-01, web-02, cache-01`,
      techniqueId: "T1021.004", tactic: "Lateral Movement",
    },
  ];

  for (const event of events) {
    await createEvent(orgId, {
      ...event,
      sourceIp: event.tactic === "Initial Access" ? attackerIp : "10.0.6.30",
      destinationIp: event.tactic === "Command and Control" ? attackerIp : undefined,
    });
    count++;
    await delay(300);
  }

  return { eventsCreated: count, description: `Cryptojacking: ${count} events - container exploit, XMRig deployment, CPU spike, lateral spread` };
}

export async function simulateDDoS(orgId: number): Promise<{ eventsCreated: number; description: string }> {
  let count = 0;

  const botnetIps = [
    "203.0.113.10", "198.51.100.22", "192.0.2.44", "203.0.113.55",
    "198.51.100.77", "192.0.2.88", "203.0.113.99", "198.51.100.111",
  ];

  await createEvent(orgId, {
    eventType: "reconnaissance", severity: "medium", source: "IDS",
    sourceIp: botnetIps[0],
    destinationIp: "10.0.0.5",
    description: `Unusual traffic pattern detected - SYN flood probe from ${botnetIps[0]} testing rate limits on web server`,
    techniqueId: "T1498", tactic: "Impact",
  });
  count++;
  await delay(200);

  for (const ip of botnetIps) {
    await createEvent(orgId, {
      eventType: "intrusion_attempt", severity: "high", source: "Load Balancer",
      sourceIp: ip,
      destinationIp: "10.0.0.5",
      port: 443,
      protocol: "HTTPS",
      description: `Volumetric DDoS traffic - ${Math.floor(Math.random() * 50 + 30)}Gbps flood from botnet node ${ip} targeting HTTPS endpoint`,
      techniqueId: "T1498.001", tactic: "Impact",
    });
    count++;
    await delay(150);
  }

  await createEvent(orgId, {
    eventType: "anomaly", severity: "critical", source: "Network Monitor",
    destinationIp: "10.0.0.5",
    description: `Bandwidth saturation - inbound traffic exceeds 400Gbps, upstream ISP link at 100% capacity`,
    techniqueId: "T1498", tactic: "Impact",
  });
  count++;
  await delay(200);

  await createEvent(orgId, {
    eventType: "anomaly", severity: "critical", source: "Application Monitor",
    sourceIp: "10.0.0.5",
    description: `Service degradation - HTTP response times exceeded 30s, 78% of requests returning 503, connection pool exhausted`,
    techniqueId: "T1499.001", tactic: "Impact",
  });
  count++;
  await delay(200);

  await createEvent(orgId, {
    eventType: "anomaly", severity: "high", source: "DNS Monitor",
    description: `DNS amplification component detected - spoofed DNS queries generating 50x amplified responses toward target infrastructure`,
    techniqueId: "T1498.002", tactic: "Impact",
  });
  count++;
  await delay(200);

  await createEvent(orgId, {
    eventType: "anomaly", severity: "critical", source: "Infrastructure Monitor",
    description: `Cascading failure - database connection timeouts causing auth service, API gateway, and CDN origin to become unavailable`,
    techniqueId: "T1499", tactic: "Impact",
  });
  count++;

  return { eventsCreated: count, description: `DDoS Attack: ${count} events - volumetric flood from ${botnetIps.length} botnet nodes, service degradation, cascading failure` };
}

export const SCENARIOS: Record<string, {
  name: string;
  description: string;
  mitre: string[];
  fn: (orgId: number) => Promise<{ eventsCreated: number; description: string }>;
}> = {
  brute_force: { name: "SSH Brute Force Attack", description: "Simulates 15+ rapid SSH login attempts from a single IP", mitre: ["T1078"], fn: simulateBruteForce },
  ransomware: { name: "Ransomware Outbreak", description: "Simulates ransomware dropper, C2 beacon, file encryption, and data exfiltration", mitre: ["T1204", "T1071", "T1486", "T1041"], fn: simulateRansomware },
  phishing: { name: "Phishing Campaign", description: "Simulates targeted phishing emails with malicious attachments and credential harvesting", mitre: ["T1566", "T1566.001", "T1078"], fn: simulatePhishing },
  port_scan: { name: "Port Scan Sweep", description: "Simulates network reconnaissance scanning across common service ports", mitre: ["T1046"], fn: simulatePortScan },
  data_exfil: { name: "Data Exfiltration", description: "Simulates data collection, DNS tunneling, and bulk encrypted data transfer", mitre: ["T1213", "T1048", "T1041"], fn: simulateDataExfiltration },
  apt: { name: "APT Kill Chain", description: "Simulates a full Advanced Persistent Threat: recon, exploit, persistence, lateral movement, exfiltration", mitre: ["T1595", "T1190", "T1059.001", "T1558", "T1021", "T1003", "T1560", "T1041"], fn: simulateAPT },
  supply_chain: { name: "Supply Chain Attack", description: "Simulates compromised package dependency leading to backdoor installation and credential theft", mitre: ["T1195.002", "T1059.007", "T1053.003", "T1055", "T1552.001", "T1041"], fn: simulateSupplyChain },
  insider_threat: { name: "Insider Threat", description: "Simulates malicious insider with unauthorized data access, privilege abuse, and bulk data exfiltration", mitre: ["T1078", "T1078.002", "T1213", "T1530", "T1048.002", "T1052.001", "T1070.004"], fn: simulateInsiderThreat },
  zero_day: { name: "Zero-Day Exploit", description: "Simulates unknown vulnerability exploitation with rootkit deployment and covert channel exfiltration", mitre: ["T1190", "T1203", "T1014", "T1543.002", "T1558.001", "T1047", "T1048.003"], fn: simulateZeroDay },
  cryptojacking: { name: "Cryptojacking", description: "Simulates cryptocurrency miner deployment via container exploit with lateral propagation", mitre: ["T1190", "T1610", "T1496", "T1571", "T1053.003", "T1021.004"], fn: simulateCryptojacking },
  ddos: { name: "DDoS Attack", description: "Simulates distributed denial-of-service with volumetric flood, bandwidth saturation, and service degradation", mitre: ["T1498", "T1498.001", "T1498.002", "T1499", "T1499.001"], fn: simulateDDoS },
};
