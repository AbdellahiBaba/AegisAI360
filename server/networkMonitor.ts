import type { InsertNetworkDevice } from "@shared/schema";
import { scanPorts, checkSSL, scanHeaders, scanVulnerabilities, isPrivateTarget } from "./scanEngine";
import dns from "dns";

export interface AssetScanResult {
  ports?: {
    openPorts: Array<{ port: number; service: string; status: string; risk: string }>;
    totalScanned: number;
    closedPorts: number;
    filteredPorts: number;
    riskLevel: string;
  };
  ssl?: {
    valid: boolean;
    issuer: string;
    subject: string;
    validFrom: string;
    validTo: string;
    daysUntilExpiry: number;
    protocol: string;
    grade: string;
    selfSigned: boolean;
    expired: boolean;
    expiringSoon: boolean;
  };
  headers?: {
    grade: string;
    score: number;
    serverInfo: string;
    findings: number;
    headers: Array<{ header: string; description: string; present: boolean; value: string; status: string }>;
  };
  vulnerabilities?: {
    totalChecks: number;
    findings: number;
    riskLevel: string;
    vulnerabilities: Array<{ path: string; name: string; severity: string; found: boolean; statusCode: number; details: string }>;
  };
  summary: {
    totalIssues: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    overallRisk: string;
    plainLanguage: string[];
  };
  scannedAt: string;
  target: string;
}

export async function resolveHostToIp(host: string): Promise<string> {
  const cleanHost = host.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  try {
    const addresses = await dns.promises.resolve4(cleanHost);
    return addresses[0] || cleanHost;
  } catch {
    return cleanHost;
  }
}

export async function scanInfrastructureAsset(target: string): Promise<AssetScanResult> {
  const cleanTarget = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  const plainLanguage: string[] = [];
  let totalIssues = 0;
  let criticalIssues = 0;
  let highIssues = 0;
  let mediumIssues = 0;
  let lowIssues = 0;

  const result: AssetScanResult = {
    summary: { totalIssues: 0, criticalIssues: 0, highIssues: 0, mediumIssues: 0, lowIssues: 0, overallRisk: "info", plainLanguage: [] },
    scannedAt: new Date().toISOString(),
    target: cleanTarget,
  };

  try {
    const portResult = await scanPorts(cleanTarget);
    result.ports = {
      openPorts: portResult.openPorts,
      totalScanned: portResult.portsScanned,
      closedPorts: portResult.closedPorts,
      filteredPorts: portResult.filteredPorts,
      riskLevel: portResult.riskLevel,
    };
    if (portResult.openPorts.length > 0) {
      plainLanguage.push(`This server has ${portResult.openPorts.length} open port(s): ${portResult.openPorts.map(p => `${p.port} (${p.service})`).join(", ")}`);
      for (const p of portResult.openPorts) {
        if (p.risk === "high" || p.risk === "critical") {
          highIssues++;
          totalIssues++;
          plainLanguage.push(`Port ${p.port} (${p.service}) is open and considered high risk`);
        } else if (p.risk === "medium") {
          mediumIssues++;
          totalIssues++;
        }
      }
    } else {
      plainLanguage.push("No open ports were found on this server");
    }
  } catch (err: any) {
    plainLanguage.push("Port scan could not be completed: " + (err.message || "connection error"));
  }

  try {
    const sslResult = await checkSSL(cleanTarget);
    result.ssl = {
      valid: sslResult.valid,
      issuer: sslResult.issuer,
      subject: sslResult.subject,
      validFrom: sslResult.validFrom,
      validTo: sslResult.validTo,
      daysUntilExpiry: sslResult.daysUntilExpiry,
      protocol: sslResult.protocol,
      grade: sslResult.grade,
      selfSigned: sslResult.selfSigned,
      expired: sslResult.expired,
      expiringSoon: sslResult.expiringSoon,
    };
    if (sslResult.expired) {
      criticalIssues++;
      totalIssues++;
      plainLanguage.push("SSL certificate has expired! Your site is not secure");
    } else if (sslResult.expiringSoon) {
      mediumIssues++;
      totalIssues++;
      plainLanguage.push(`SSL certificate expires in ${sslResult.daysUntilExpiry} days`);
    } else if (sslResult.selfSigned) {
      highIssues++;
      totalIssues++;
      plainLanguage.push("SSL certificate is self-signed and not trusted by browsers");
    } else {
      plainLanguage.push(`SSL certificate is valid (Grade: ${sslResult.grade}, expires in ${sslResult.daysUntilExpiry} days)`);
    }
  } catch {
    plainLanguage.push("No SSL certificate found or SSL connection could not be established");
  }

  try {
    const headerResult = await scanHeaders(cleanTarget);
    result.headers = {
      grade: headerResult.grade,
      score: headerResult.score,
      serverInfo: headerResult.serverInfo,
      findings: headerResult.findings,
      headers: headerResult.headers,
    };
    const missingRequired = headerResult.headers.filter(h => h.status === "fail");
    if (missingRequired.length > 0) {
      mediumIssues += missingRequired.length;
      totalIssues += missingRequired.length;
      plainLanguage.push(`Missing ${missingRequired.length} security header(s): ${missingRequired.map(h => h.description).join(", ")}`);
    }
    if (headerResult.score >= 75) {
      plainLanguage.push(`Security headers score: ${headerResult.score}% (Grade: ${headerResult.grade})`);
    }
  } catch {
    plainLanguage.push("Security headers could not be checked");
  }

  try {
    const vulnResult = await scanVulnerabilities(cleanTarget);
    const realFindings = vulnResult.vulnerabilities.filter(v => v.found && v.severity !== "info");
    result.vulnerabilities = {
      totalChecks: vulnResult.totalChecks,
      findings: realFindings.length,
      riskLevel: vulnResult.riskLevel,
      vulnerabilities: vulnResult.vulnerabilities,
    };
    if (realFindings.length > 0) {
      for (const v of realFindings) {
        if (v.severity === "critical") { criticalIssues++; totalIssues++; }
        else if (v.severity === "high") { highIssues++; totalIssues++; }
        else if (v.severity === "medium") { mediumIssues++; totalIssues++; }
        else { lowIssues++; totalIssues++; }
      }
      plainLanguage.push(`Found ${realFindings.length} exposed path(s): ${realFindings.map(v => v.name).join(", ")}`);
    } else {
      plainLanguage.push("No exposed sensitive paths were found");
    }
  } catch {
    plainLanguage.push("Vulnerability path scan could not be completed");
  }

  let overallRisk = "info";
  if (criticalIssues > 0) overallRisk = "critical";
  else if (highIssues > 0) overallRisk = "high";
  else if (mediumIssues > 0) overallRisk = "medium";
  else if (lowIssues > 0) overallRisk = "low";

  result.summary = { totalIssues, criticalIssues, highIssues, mediumIssues, lowIssues, overallRisk, plainLanguage };
  return result;
}

const MANUFACTURERS = [
  { name: "Apple", macs: ["A4:83:E7", "F0:18:98", "DC:A6:32", "3C:22:FB"], devices: ["MacBook Pro", "iPhone 15", "iPad Air", "Apple TV"], os: ["macOS Sonoma", "iOS 17", "iPadOS 17", "tvOS 17"] },
  { name: "Samsung", macs: ["8C:F5:A3", "AC:5F:3E", "50:01:D9", "E4:7D:BD"], devices: ["Galaxy S24", "Galaxy Tab S9", "Smart TV", "Galaxy Book"], os: ["Android 14", "Android 14", "Tizen 7.0", "Windows 11"] },
  { name: "Dell", macs: ["F8:BC:12", "00:14:22", "18:03:73", "B0:83:FE"], devices: ["Latitude 5540", "OptiPlex 7010", "XPS 15", "PowerEdge R750"], os: ["Windows 11", "Windows 11", "Windows 11", "Ubuntu 22.04"] },
  { name: "HP", macs: ["3C:D9:2B", "00:1A:4B", "F4:30:B9", "EC:B1:D7"], devices: ["EliteBook 840", "LaserJet Pro", "ProDesk 400", "Envy 16"], os: ["Windows 11", null, "Windows 10", "Windows 11"] },
  { name: "Cisco", macs: ["00:1E:14", "00:26:CB", "64:F6:9D", "70:DF:2F"], devices: ["Meraki AP", "Catalyst 9300", "ISR 4321", "IP Phone 8845"], os: ["Meraki OS", "IOS XE", "IOS XE", "Firmware 14.2"] },
  { name: "Intel", macs: ["00:1B:21", "A4:34:D9", "48:51:B7", "3C:97:0E"], devices: ["NUC 13 Pro", "IoT Gateway", "Desktop PC", "Workstation"], os: ["Windows 11", "Linux", "Windows 10", "Ubuntu 22.04"] },
  { name: "TP-Link", macs: ["50:C7:BF", "30:B5:C2", "B0:BE:76", "EC:08:6B"], devices: ["Archer AX73", "Deco X50", "Smart Plug", "Security Cam"], os: ["Router OS", "Mesh OS", "Firmware 1.2", "Firmware 2.0"] },
  { name: "Raspberry Pi", macs: ["B8:27:EB", "DC:A6:32", "E4:5F:01", "28:CD:C1"], devices: ["Pi 4 Model B", "Pi Zero W", "Pi 5", "Pi Pico W"], os: ["Raspbian 12", "Raspbian Lite", "Ubuntu 23.10", "MicroPython"] },
  { name: "Google", macs: ["F4:F5:D8", "54:60:09", "A4:77:33", "30:FD:38"], devices: ["Nest Hub", "Chromecast", "Pixel 8", "Nest Camera"], os: ["Fuchsia", "Android TV", "Android 14", "Firmware 5.2"] },
  { name: "Unknown", macs: ["02:42:AC", "DE:AD:BE", "00:50:56", "08:00:27"], devices: ["Unknown Device", "Mystery Device", "VM Instance", "Virtual NIC"], os: [null, null, "VMware ESXi", "VirtualBox"] },
];

const DEVICE_TYPE_MAP: Record<string, string> = {
  "MacBook Pro": "computer", "iPhone 15": "phone", "iPad Air": "tablet", "Apple TV": "iot",
  "Galaxy S24": "phone", "Galaxy Tab S9": "tablet", "Smart TV": "iot", "Galaxy Book": "computer",
  "Latitude 5540": "computer", "OptiPlex 7010": "computer", "XPS 15": "computer", "PowerEdge R750": "computer",
  "EliteBook 840": "computer", "LaserJet Pro": "printer", "ProDesk 400": "computer", "Envy 16": "computer",
  "Meraki AP": "router", "Catalyst 9300": "router", "ISR 4321": "router", "IP Phone 8845": "iot",
  "NUC 13 Pro": "computer", "IoT Gateway": "iot", "Desktop PC": "computer", "Workstation": "computer",
  "Archer AX73": "router", "Deco X50": "router", "Smart Plug": "iot", "Security Cam": "iot",
  "Pi 4 Model B": "iot", "Pi Zero W": "iot", "Pi 5": "computer", "Pi Pico W": "iot",
  "Nest Hub": "iot", "Chromecast": "iot", "Pixel 8": "phone", "Nest Camera": "iot",
  "Unknown Device": "unknown", "Mystery Device": "unknown", "VM Instance": "computer", "Virtual NIC": "computer",
};

const LOCATIONS = [
  "New York, US", "London, UK", "Dubai, AE", "Tokyo, JP", "Berlin, DE",
  "Singapore, SG", "Sydney, AU", "Toronto, CA", "Local Network", "Local Network",
  "Local Network", "Local Network", "Local Network",
];

const NETWORK_NAMES = ["AegisHQ-5G", "Corporate-WiFi", "SecureNet-Main", "Office-Floor2", "Guest-WiFi"];

function randomMac(prefix: string): string {
  const suffix = Array.from({ length: 3 }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, "0").toUpperCase()
  ).join(":");
  return `${prefix}:${suffix}`;
}

function randomIp(): string {
  return `192.168.${Math.floor(Math.random() * 3) + 1}.${Math.floor(Math.random() * 254) + 1}`;
}

export function generateNetworkDevices(orgId: number, count: number = 12): InsertNetworkDevice[] {
  const devices: InsertNetworkDevice[] = [];
  const usedIps = new Set<string>();
  const usedMacs = new Set<string>();
  const networkName = NETWORK_NAMES[Math.floor(Math.random() * NETWORK_NAMES.length)];

  const routerMfg = MANUFACTURERS.find(m => m.name === "Cisco" || m.name === "TP-Link")!;
  const routerIdx = 0;
  const routerMac = randomMac(routerMfg.macs[routerIdx]);
  const routerIp = "192.168.1.1";
  usedIps.add(routerIp);
  usedMacs.add(routerMac);
  devices.push({
    organizationId: orgId,
    macAddress: routerMac,
    ipAddress: routerIp,
    hostname: routerMfg.devices[routerIdx],
    manufacturer: routerMfg.name,
    deviceType: "router",
    os: routerMfg.os[routerIdx],
    status: "online",
    authorization: "authorized",
    dataIn: Math.floor(Math.random() * 50000000000) + 10000000000,
    dataOut: Math.floor(Math.random() * 80000000000) + 20000000000,
    networkName,
    signalStrength: -20,
    location: "Local Network",
    isCompanyDevice: true,
    lastSeen: new Date(),
    firstSeen: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000),
  });

  for (let i = 1; i < count; i++) {
    const mfg = MANUFACTURERS[Math.floor(Math.random() * (MANUFACTURERS.length - 1))];
    const devIdx = Math.floor(Math.random() * mfg.devices.length);

    let mac: string;
    do { mac = randomMac(mfg.macs[devIdx % mfg.macs.length]); } while (usedMacs.has(mac));
    usedMacs.add(mac);

    let ip: string;
    do { ip = randomIp(); } while (usedIps.has(ip));
    usedIps.add(ip);

    const isKnownMfg = mfg.name !== "Unknown";
    const isUnauthorized = !isKnownMfg || Math.random() < 0.2;
    const isOffline = Math.random() < 0.15;
    const isCompany = isKnownMfg && Math.random() > 0.5;

    devices.push({
      organizationId: orgId,
      macAddress: mac,
      ipAddress: ip,
      hostname: mfg.devices[devIdx],
      manufacturer: mfg.name,
      deviceType: DEVICE_TYPE_MAP[mfg.devices[devIdx]] || "unknown",
      os: mfg.os[devIdx] || null,
      status: isOffline ? "offline" : "online",
      authorization: isUnauthorized ? "unauthorized" : Math.random() > 0.3 ? "authorized" : "unknown",
      dataIn: Math.floor(Math.random() * 5000000000),
      dataOut: Math.floor(Math.random() * 3000000000),
      networkName,
      signalStrength: DEVICE_TYPE_MAP[mfg.devices[devIdx]] === "router" ? -20 : -(Math.floor(Math.random() * 50) + 30),
      location: LOCATIONS[Math.floor(Math.random() * LOCATIONS.length)],
      isCompanyDevice: isCompany,
      assignedUser: isCompany ? `user${Math.floor(Math.random() * 50) + 1}` : null,
      lastSeen: isOffline ? new Date(Date.now() - Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000)) : new Date(),
      firstSeen: new Date(Date.now() - Math.floor(Math.random() * 120 * 24 * 60 * 60 * 1000)),
      notes: null,
    });
  }

  return devices;
}

interface Vulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string;
  affectedDevice?: string;
}

export function runNetworkVulnerabilityScan(devices: Array<{ hostname: string | null; deviceType: string; authorization: string; manufacturer: string | null; signalStrength: number | null; ipAddress: string }>): { vulnerabilities: Vulnerability[]; riskScore: number } {
  const vulns: Vulnerability[] = [];

  const routers = devices.filter(d => d.deviceType === "router");
  for (const router of routers) {
    if (Math.random() > 0.4) {
      vulns.push({
        id: `WIFI-${Date.now()}-1`,
        severity: "high",
        title: "WPA2 Deprecated Encryption",
        description: `Router ${router.hostname || router.ipAddress} is using WPA2 which has known vulnerabilities (KRACK attack).`,
        recommendation: "Upgrade to WPA3 encryption standard for stronger protection.",
        affectedDevice: router.hostname || router.ipAddress,
      });
    }
  }

  const unauthorized = devices.filter(d => d.authorization === "unauthorized");
  if (unauthorized.length > 0) {
    vulns.push({
      id: `NET-${Date.now()}-5`,
      severity: "high",
      title: `${unauthorized.length} Unauthorized Device(s) Detected`,
      description: `Found ${unauthorized.length} device(s) connected without authorization.`,
      recommendation: "Investigate and block unauthorized devices immediately.",
    });
  }

  const riskScore = Math.min(100, vulns.reduce((sum, v) => {
    const weights = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
    return sum + weights[v.severity];
  }, 0));

  return { vulnerabilities: vulns, riskScore };
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}
