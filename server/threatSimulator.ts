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

export const SCENARIOS: Record<string, {
  name: string;
  description: string;
  fn: (orgId: number) => Promise<{ eventsCreated: number; description: string }>;
}> = {
  brute_force: { name: "SSH Brute Force Attack", description: "Simulates 15+ rapid SSH login attempts from a single IP", fn: simulateBruteForce },
  ransomware: { name: "Ransomware Outbreak", description: "Simulates ransomware dropper, C2 beacon, file encryption, and data exfiltration", fn: simulateRansomware },
  phishing: { name: "Phishing Campaign", description: "Simulates targeted phishing emails with malicious attachments and credential harvesting", fn: simulatePhishing },
  port_scan: { name: "Port Scan Sweep", description: "Simulates network reconnaissance scanning across common service ports", fn: simulatePortScan },
  data_exfil: { name: "Data Exfiltration", description: "Simulates data collection, DNS tunneling, and bulk encrypted data transfer", fn: simulateDataExfiltration },
  apt: { name: "APT Kill Chain", description: "Simulates a full Advanced Persistent Threat: recon, exploit, persistence, lateral movement, exfiltration", fn: simulateAPT },
};
