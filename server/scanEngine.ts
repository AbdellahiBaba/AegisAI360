import net from "net";
import dns from "dns";
import tls from "tls";
import https from "https";
import http from "http";

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/,
  /^fd/,
  /^localhost$/i,
];

export function isPrivateTarget(target: string): boolean {
  const host = target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  return PRIVATE_IP_RANGES.some((r) => r.test(host));
}

const COMMON_PORTS: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
  993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 3306: "MySQL",
  3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
  8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
  9200: "Elasticsearch", 27017: "MongoDB",
};

const HIGH_RISK_PORTS = [23, 445, 1433, 3389, 5900, 6379, 9200, 27017];
const MEDIUM_RISK_PORTS = [21, 25, 110, 143, 3306, 5432, 8080, 8888];

interface PortResult {
  port: number;
  service: string;
  status: "open" | "closed" | "filtered";
  risk: "critical" | "high" | "medium" | "low" | "info";
}

function checkPort(host: string, port: number, timeout = 3000): Promise<PortResult> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const service = COMMON_PORTS[port] || "Unknown";
    let risk: PortResult["risk"] = "info";

    socket.setTimeout(timeout);
    socket.on("connect", () => {
      if (HIGH_RISK_PORTS.includes(port)) risk = "high";
      else if (MEDIUM_RISK_PORTS.includes(port)) risk = "medium";
      else risk = "low";
      socket.destroy();
      resolve({ port, service, status: "open", risk });
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ port, service, status: "filtered", risk: "info" });
    });
    socket.on("error", () => {
      socket.destroy();
      resolve({ port, service, status: "closed", risk: "info" });
    });
    socket.connect(port, host);
  });
}

export async function scanPorts(target: string, ports?: number[]): Promise<{
  target: string;
  portsScanned: number;
  openPorts: PortResult[];
  closedPorts: number;
  filteredPorts: number;
  results: PortResult[];
  riskLevel: string;
}> {
  const portsToScan = ports || Object.keys(COMMON_PORTS).map(Number);
  const batchSize = 10;
  const allResults: PortResult[] = [];

  for (let i = 0; i < portsToScan.length; i += batchSize) {
    const batch = portsToScan.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(p => checkPort(target, p)));
    allResults.push(...batchResults);
  }

  const openPorts = allResults.filter(r => r.status === "open");
  const closedPorts = allResults.filter(r => r.status === "closed").length;
  const filteredPorts = allResults.filter(r => r.status === "filtered").length;

  let riskLevel = "info";
  if (openPorts.some(p => p.risk === "critical")) riskLevel = "critical";
  else if (openPorts.some(p => p.risk === "high")) riskLevel = "high";
  else if (openPorts.some(p => p.risk === "medium")) riskLevel = "medium";
  else if (openPorts.length > 0) riskLevel = "low";

  return {
    target,
    portsScanned: portsToScan.length,
    openPorts,
    closedPorts,
    filteredPorts,
    results: allResults,
    riskLevel,
  };
}

export async function lookupDNS(domain: string): Promise<{
  domain: string;
  records: Record<string, string[]>;
  totalRecords: number;
}> {
  const resolver = new dns.promises.Resolver();
  resolver.setServers(["8.8.8.8", "1.1.1.1"]);

  const records: Record<string, string[]> = {};
  const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] as const;

  for (const type of types) {
    try {
      let result: any[];
      switch (type) {
        case "A": result = await resolver.resolve4(domain); break;
        case "AAAA": result = await resolver.resolve6(domain); break;
        case "MX":
          const mx = await resolver.resolveMx(domain);
          result = mx.map(r => `${r.priority} ${r.exchange}`);
          break;
        case "NS": result = await resolver.resolveNs(domain); break;
        case "TXT":
          const txt = await resolver.resolveTxt(domain);
          result = txt.map(r => r.join(""));
          break;
        case "CNAME": result = await resolver.resolveCname(domain); break;
      }
      if (result && result.length > 0) records[type] = result.map(String);
    } catch {
    }
  }

  const totalRecords = Object.values(records).reduce((sum, arr) => sum + arr.length, 0);
  return { domain, records, totalRecords };
}

export async function checkSSL(host: string, port = 443): Promise<{
  host: string;
  valid: boolean;
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  protocol: string;
  cipher: string;
  selfSigned: boolean;
  expired: boolean;
  expiringSoon: boolean;
  grade: string;
}> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 10000,
    }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol() || "unknown";
      const authorized = socket.authorized;

      if (!cert || !cert.subject) {
        socket.destroy();
        return reject(new Error("No certificate found"));
      }

      const validFrom = cert.valid_from;
      const validTo = cert.valid_to;
      const now = new Date();
      const expiryDate = new Date(validTo);
      const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      const expired = daysUntilExpiry < 0;
      const expiringSoon = daysUntilExpiry >= 0 && daysUntilExpiry <= 30;
      const selfSigned = cert.issuer?.O === cert.subject?.O && !authorized;

      let grade = "A";
      if (expired) grade = "F";
      else if (selfSigned) grade = "D";
      else if (expiringSoon) grade = "C";
      else if (protocol === "TLSv1" || protocol === "TLSv1.1") grade = "C";
      else if (!authorized) grade = "B";

      socket.destroy();
      resolve({
        host,
        valid: !expired && authorized,
        issuer: `${cert.issuer?.O || ""} (${cert.issuer?.CN || ""})`,
        subject: cert.subject?.CN || "",
        validFrom,
        validTo,
        daysUntilExpiry,
        protocol,
        cipher: cipher?.name || "unknown",
        selfSigned,
        expired,
        expiringSoon,
        grade,
      });
    });

    socket.on("error", (err) => {
      socket.destroy();
      reject(err);
    });
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    });
  });
}

const SECURITY_HEADERS = [
  { name: "Strict-Transport-Security", required: true, description: "HSTS" },
  { name: "Content-Security-Policy", required: true, description: "CSP" },
  { name: "X-Content-Type-Options", required: true, description: "MIME Sniffing Protection" },
  { name: "X-Frame-Options", required: true, description: "Clickjacking Protection" },
  { name: "X-XSS-Protection", required: false, description: "XSS Filter (legacy)" },
  { name: "Referrer-Policy", required: true, description: "Referrer Control" },
  { name: "Permissions-Policy", required: false, description: "Feature Policy" },
  { name: "X-Permitted-Cross-Domain-Policies", required: false, description: "Cross Domain Policy" },
];

interface HeaderResult {
  header: string;
  description: string;
  present: boolean;
  value: string;
  status: "pass" | "fail" | "warning";
}

export async function scanHeaders(targetUrl: string): Promise<{
  url: string;
  headers: HeaderResult[];
  grade: string;
  score: number;
  serverInfo: string;
  findings: number;
}> {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl.startsWith("http") ? targetUrl : `https://${targetUrl}`);
    const client = url.protocol === "https:" ? https : http;

    const req = client.request(url, { method: "HEAD", timeout: 10000 }, (res) => {
      const responseHeaders = res.headers;
      const results: HeaderResult[] = [];
      let score = 0;
      const maxScore = SECURITY_HEADERS.length;

      for (const header of SECURITY_HEADERS) {
        const headerLower = header.name.toLowerCase();
        const value = responseHeaders[headerLower];
        const present = !!value;

        let status: HeaderResult["status"] = "fail";
        if (present) {
          status = "pass";
          score++;
        } else if (!header.required) {
          status = "warning";
          score += 0.5;
        }

        results.push({
          header: header.name,
          description: header.description,
          present,
          value: Array.isArray(value) ? value.join(", ") : (value || "Not set"),
          status,
        });
      }

      const percentage = Math.round((score / maxScore) * 100);
      let grade = "F";
      if (percentage >= 90) grade = "A";
      else if (percentage >= 75) grade = "B";
      else if (percentage >= 60) grade = "C";
      else if (percentage >= 40) grade = "D";

      const serverInfo = (responseHeaders["server"] as string) || "Not disclosed";
      const findings = results.filter(r => r.status !== "pass").length;

      resolve({ url: targetUrl, headers: results, grade, score: percentage, serverInfo, findings });
    });

    req.on("error", (err) => reject(err));
    req.on("timeout", () => { req.destroy(); reject(new Error("Request timed out")); });
    req.end();
  });
}

const VULN_PATHS = [
  { path: "/.env", name: "Environment File", severity: "critical" as const },
  { path: "/.git/config", name: "Git Repository", severity: "critical" as const },
  { path: "/.git/HEAD", name: "Git HEAD", severity: "critical" as const },
  { path: "/wp-admin/", name: "WordPress Admin", severity: "high" as const },
  { path: "/phpmyadmin/", name: "phpMyAdmin", severity: "high" as const },
  { path: "/admin/", name: "Admin Panel", severity: "medium" as const },
  { path: "/administrator/", name: "Administrator Panel", severity: "medium" as const },
  { path: "/server-status", name: "Apache Server Status", severity: "high" as const },
  { path: "/server-info", name: "Apache Server Info", severity: "high" as const },
  { path: "/.htpasswd", name: "htpasswd File", severity: "critical" as const },
  { path: "/.htaccess", name: "htaccess File", severity: "high" as const },
  { path: "/robots.txt", name: "Robots.txt", severity: "info" as const },
  { path: "/sitemap.xml", name: "Sitemap", severity: "info" as const },
  { path: "/crossdomain.xml", name: "Cross-Domain Policy", severity: "medium" as const },
  { path: "/backup/", name: "Backup Directory", severity: "critical" as const },
  { path: "/api/swagger", name: "Swagger Docs", severity: "medium" as const },
  { path: "/api/docs", name: "API Documentation", severity: "medium" as const },
  { path: "/.DS_Store", name: "Mac DS_Store", severity: "medium" as const },
  { path: "/wp-config.php.bak", name: "WP Config Backup", severity: "critical" as const },
  { path: "/debug/", name: "Debug Endpoint", severity: "high" as const },
];

interface VulnResult {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  found: boolean;
  statusCode: number;
  details: string;
}

function checkVulnPath(baseUrl: string, vulnPath: typeof VULN_PATHS[0]): Promise<VulnResult> {
  return new Promise((resolve) => {
    const fullUrl = new URL(vulnPath.path, baseUrl.startsWith("http") ? baseUrl : `https://${baseUrl}`);
    const client = fullUrl.protocol === "https:" ? https : http;

    const req = client.request(fullUrl, { method: "GET", timeout: 5000 }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk.toString().slice(0, 500); });
      res.on("end", () => {
        const found = res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 400;
        let details = `HTTP ${res.statusCode}`;
        if (found && vulnPath.severity !== "info") {
          details = `Accessible (HTTP ${res.statusCode}) - potential security risk`;
        } else if (found) {
          details = `Present (HTTP ${res.statusCode})`;
        } else {
          details = `Not accessible (HTTP ${res.statusCode})`;
        }
        resolve({
          path: vulnPath.path,
          name: vulnPath.name,
          severity: found && vulnPath.severity !== "info" ? vulnPath.severity : "info",
          found,
          statusCode: res.statusCode || 0,
          details,
        });
      });
    });

    req.on("error", () => {
      resolve({
        path: vulnPath.path,
        name: vulnPath.name,
        severity: "info",
        found: false,
        statusCode: 0,
        details: "Connection failed",
      });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({
        path: vulnPath.path,
        name: vulnPath.name,
        severity: "info",
        found: false,
        statusCode: 0,
        details: "Request timed out",
      });
    });
    req.end();
  });
}

export async function scanVulnerabilities(targetUrl: string): Promise<{
  target: string;
  totalChecks: number;
  vulnerabilities: VulnResult[];
  riskLevel: string;
  findings: number;
}> {
  const batchSize = 5;
  const allResults: VulnResult[] = [];

  for (let i = 0; i < VULN_PATHS.length; i += batchSize) {
    const batch = VULN_PATHS.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(v => checkVulnPath(targetUrl, v)));
    allResults.push(...batchResults);
  }

  const vulnerabilities = allResults.filter(r => r.found && r.severity !== "info");
  let riskLevel = "info";
  if (vulnerabilities.some(v => v.severity === "critical")) riskLevel = "critical";
  else if (vulnerabilities.some(v => v.severity === "high")) riskLevel = "high";
  else if (vulnerabilities.some(v => v.severity === "medium")) riskLevel = "medium";
  else if (vulnerabilities.length > 0) riskLevel = "low";

  return {
    target: targetUrl,
    totalChecks: VULN_PATHS.length,
    vulnerabilities: allResults,
    riskLevel,
    findings: vulnerabilities.length,
  };
}
