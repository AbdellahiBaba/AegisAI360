import type { InsertNetworkDevice } from "@shared/schema";

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
    if (Math.random() > 0.5) {
      vulns.push({
        id: `WIFI-${Date.now()}-2`,
        severity: "critical",
        title: "Default Admin Credentials Detected",
        description: `Router ${router.hostname || router.ipAddress} appears to be using default manufacturer credentials.`,
        recommendation: "Change the default admin password immediately.",
        affectedDevice: router.hostname || router.ipAddress,
      });
    }
    if (Math.random() > 0.6) {
      vulns.push({
        id: `WIFI-${Date.now()}-3`,
        severity: "medium",
        title: "UPnP Enabled",
        description: `Router ${router.hostname || router.ipAddress} has UPnP enabled, which can be exploited.`,
        recommendation: "Disable UPnP unless specifically required.",
        affectedDevice: router.hostname || router.ipAddress,
      });
    }
    if (Math.random() > 0.7) {
      vulns.push({
        id: `WIFI-${Date.now()}-4`,
        severity: "medium",
        title: "WPS Enabled",
        description: `WPS is enabled on ${router.hostname || router.ipAddress}, susceptible to brute-force attacks.`,
        recommendation: "Disable WPS and use WPA3 passphrase authentication.",
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
      description: `Found ${unauthorized.length} device(s) connected to the network without authorization: ${unauthorized.map(d => d.hostname || d.ipAddress).join(", ")}`,
      recommendation: "Investigate and block unauthorized devices immediately.",
    });
  }

  const unknownMfg = devices.filter(d => d.manufacturer === "Unknown");
  if (unknownMfg.length > 0) {
    vulns.push({
      id: `NET-${Date.now()}-6`,
      severity: "medium",
      title: "Unidentified Device Manufacturer",
      description: `${unknownMfg.length} device(s) with unknown manufacturers detected, which may indicate spoofed MAC addresses.`,
      recommendation: "Verify device identity and consider MAC address filtering.",
    });
  }

  const weakSignal = devices.filter(d => d.signalStrength !== null && d.signalStrength < -70);
  if (weakSignal.length > 0) {
    vulns.push({
      id: `NET-${Date.now()}-7`,
      severity: "low",
      title: "Devices with Weak Signal Detected",
      description: `${weakSignal.length} device(s) have weak WiFi signal, which may indicate they are connecting from outside the expected area.`,
      recommendation: "Verify physical proximity of weak-signal devices.",
    });
  }

  const iotDevices = devices.filter(d => d.deviceType === "iot");
  if (iotDevices.length > 2) {
    vulns.push({
      id: `IOT-${Date.now()}-8`,
      severity: "medium",
      title: "Multiple IoT Devices on Main Network",
      description: `${iotDevices.length} IoT devices are on the main network. IoT devices often lack security updates.`,
      recommendation: "Isolate IoT devices on a separate VLAN or guest network.",
    });
  }

  if (Math.random() > 0.5) {
    vulns.push({
      id: `NET-${Date.now()}-9`,
      severity: "info",
      title: "DNS Configuration Review",
      description: "Network DNS is configured to use ISP defaults which may leak browsing data.",
      recommendation: "Configure DNS to use encrypted DNS (DoH/DoT) with a privacy-focused provider.",
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
