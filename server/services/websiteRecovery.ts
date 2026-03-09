import dns from "dns";
import net from "net";
import { URL } from "url";

const BLOCKED_HOSTNAMES = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "metadata.google.internal", "169.254.169.254"];

function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase().replace(/\[|\]/g, "");
    if (normalized === "::1" || normalized === "::") return true;
    if (normalized.startsWith("fe80")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("ff")) return true;
    if (normalized.startsWith("::ffff:")) {
      const v4 = normalized.slice(7);
      if (net.isIPv4(v4)) return isPrivateIP(v4);
    }
    return false;
  }
  return false;
}

function isBlockedHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(lower)) return true;
  if (net.isIP(lower)) return isPrivateIP(lower);
  return false;
}

export interface RecoveryFinding {
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  timestamp: number;
}

export interface RecoveryPhase {
  name: string;
  status: "pending" | "running" | "complete" | "error";
  progress: number;
  findings: RecoveryFinding[];
}

export interface RecoveryOperation {
  id: string;
  userId: number;
  organizationId: number;
  targetUrl: string;
  status: "running" | "complete" | "error";
  startedAt: number;
  completedAt?: number;
  phases: RecoveryPhase[];
  logs: string[];
  summary?: {
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
    adminPanelsFound: string[];
    techStack: string[];
    openPorts: number[];
    exposedFiles: string[];
    vulnerabilities: string[];
    recommendations: string[];
  };
}

const activeOperations = new Map<string, RecoveryOperation>();

export function getOperation(id: string, organizationId: number): RecoveryOperation | undefined {
  const op = activeOperations.get(id);
  if (op && op.organizationId === organizationId) return op;
  return undefined;
}

export function getAllOperations(organizationId: number): RecoveryOperation[] {
  return Array.from(activeOperations.values())
    .filter(o => o.organizationId === organizationId)
    .sort((a, b) => b.startedAt - a.startedAt);
}

const COMMON_PORTS = [21, 22, 25, 53, 80, 443, 993, 995, 2082, 2083, 2086, 2087, 3306, 5432, 8080, 8443, 8888, 9090];

const ADMIN_PATHS = [
  "/admin", "/wp-admin", "/wp-login.php", "/administrator", "/cpanel", "/phpmyadmin",
  "/login", "/dashboard", "/panel", "/manage", "/cms", "/backend", "/control",
  "/admin/login", "/user/login", "/auth/login", "/signin", "/portal",
  "/webmail", "/plesk", "/directadmin", "/whm",
];

const SENSITIVE_PATHS = [
  "/.env", "/.git/config", "/.svn/entries", "/.htaccess", "/.htpasswd",
  "/wp-config.php", "/wp-config.php.bak", "/config.php", "/config.php.bak",
  "/web.config", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
  "/phpinfo.php", "/info.php", "/server-status", "/server-info",
  "/.DS_Store", "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
  "/database.sql", "/dump.sql", "/.env.backup", "/.env.local",
  "/api/v1", "/api/v2", "/api/docs", "/swagger.json", "/api-docs",
];

const DEFAULT_CREDENTIALS = [
  { username: "admin", password: "admin" },
  { username: "admin", password: "password" },
  { username: "admin", password: "123456" },
  { username: "root", password: "root" },
  { username: "root", password: "toor" },
  { username: "administrator", password: "administrator" },
  { username: "admin", password: "admin123" },
  { username: "test", password: "test" },
  { username: "user", password: "user" },
  { username: "demo", password: "demo" },
];

function generateId(): string {
  return `wr_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

async function resolveDNS(hostname: string): Promise<{ ips: string[]; mx: string[]; ns: string[]; txt: string[] }> {
  const result = { ips: [] as string[], mx: [] as string[], ns: [] as string[], txt: [] as string[] };
  try {
    result.ips = await new Promise<string[]>((resolve, reject) => dns.resolve4(hostname, (err, addrs) => err ? resolve([]) : resolve(addrs)));
    const ip6 = await new Promise<string[]>((resolve) => dns.resolve6(hostname, (err, addrs) => err ? resolve([]) : resolve(addrs)));
    result.ips.push(...ip6);
    const mxRecords = await new Promise<dns.MxRecord[]>((resolve) => dns.resolveMx(hostname, (err, addrs) => err ? resolve([]) : resolve(addrs)));
    result.mx = mxRecords.map(r => `${r.exchange} (priority: ${r.priority})`);
    result.ns = await new Promise<string[]>((resolve) => dns.resolveNs(hostname, (err, addrs) => err ? resolve([]) : resolve(addrs)));
    const txtRecords = await new Promise<string[][]>((resolve) => dns.resolveTxt(hostname, (err, addrs) => err ? resolve([]) : resolve(addrs)));
    result.txt = txtRecords.map(r => r.join(""));
  } catch {}
  return result;
}

async function checkPort(host: string, port: number, timeout = 3000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.on("connect", () => { socket.destroy(); resolve(true); });
    socket.on("timeout", () => { socket.destroy(); resolve(false); });
    socket.on("error", () => { socket.destroy(); resolve(false); });
    socket.connect(port, host);
  });
}

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 8000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal, redirect: "manual" });
    return resp;
  } finally {
    clearTimeout(timer);
  }
}

function addLog(op: RecoveryOperation, msg: string) {
  const ts = new Date().toISOString().slice(11, 19);
  op.logs.push(`[${ts}] ${msg}`);
}

function addFinding(phase: RecoveryPhase, finding: Omit<RecoveryFinding, "timestamp">) {
  phase.findings.push({ ...finding, timestamp: Date.now() });
}

export async function startRecoveryOperation(targetUrl: string, userId: number, organizationId: number): Promise<string> {
  let parsed: URL;
  try {
    parsed = new URL(targetUrl);
  } catch {
    throw new Error("Invalid URL format");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP/HTTPS URLs are supported");
  }
  if (isBlockedHost(parsed.hostname)) {
    throw new Error("Target URL points to a blocked/internal host");
  }

  const resolvedIPs = await new Promise<string[]>((resolve) => {
    dns.resolve4(parsed.hostname, (err, addrs) => err ? resolve([]) : resolve(addrs));
  });
  if (resolvedIPs.some(isPrivateIP)) {
    throw new Error("Target URL resolves to a private IP address");
  }

  const resolvedIPv6 = await new Promise<string[]>((resolve) => {
    dns.resolve6(parsed.hostname, (err, addrs) => err ? resolve([]) : resolve(addrs));
  });
  if (resolvedIPv6.some(isPrivateIP)) {
    throw new Error("Target URL resolves to a private IPv6 address");
  }

  const id = generateId();
  const op: RecoveryOperation = {
    id,
    userId,
    organizationId,
    targetUrl,
    status: "running",
    startedAt: Date.now(),
    phases: [
      { name: "Reconnaissance", status: "pending", progress: 0, findings: [] },
      { name: "Discovery", status: "pending", progress: 0, findings: [] },
      { name: "Vulnerability Assessment", status: "pending", progress: 0, findings: [] },
      { name: "Recovery Attempts", status: "pending", progress: 0, findings: [] },
      { name: "Report Generation", status: "pending", progress: 0, findings: [] },
    ],
    logs: [],
  };

  activeOperations.set(id, op);
  runRecoveryPipeline(op, parsed).catch(() => {});
  return id;
}

async function runRecoveryPipeline(op: RecoveryOperation, parsed: URL) {
  try {
    await runReconnaissance(op, parsed);
    await runDiscovery(op, parsed);
    await runVulnerabilityAssessment(op, parsed);
    await runRecoveryAttempts(op, parsed);
    await generateReport(op);
    op.status = "complete";
    op.completedAt = Date.now();
  } catch (err: any) {
    addLog(op, `Pipeline error: ${err.message}`);
    op.status = "error";
    op.completedAt = Date.now();
  }
}

async function runReconnaissance(op: RecoveryOperation, parsed: URL) {
  const phase = op.phases[0];
  phase.status = "running";
  addLog(op, "Starting reconnaissance phase...");

  addLog(op, `Resolving DNS for ${parsed.hostname}...`);
  const dnsResult = await resolveDNS(parsed.hostname);
  phase.progress = 20;

  if (dnsResult.ips.length > 0) {
    addFinding(phase, { category: "DNS", severity: "info", title: "IP Addresses", detail: `Resolved IPs: ${dnsResult.ips.join(", ")}` });
  }
  if (dnsResult.mx.length > 0) {
    addFinding(phase, { category: "DNS", severity: "info", title: "Mail Servers", detail: `MX records: ${dnsResult.mx.join(", ")}` });
  }
  if (dnsResult.ns.length > 0) {
    addFinding(phase, { category: "DNS", severity: "info", title: "Name Servers", detail: `NS records: ${dnsResult.ns.join(", ")}` });
  }
  if (dnsResult.txt.length > 0) {
    const spf = dnsResult.txt.find(t => t.startsWith("v=spf"));
    const dmarc = dnsResult.txt.find(t => t.startsWith("v=DMARC"));
    if (spf) addFinding(phase, { category: "DNS", severity: "info", title: "SPF Record", detail: spf });
    if (dmarc) addFinding(phase, { category: "DNS", severity: "info", title: "DMARC Record", detail: dmarc });
  }

  addLog(op, "Scanning common ports...");
  phase.progress = 40;
  const targetIP = dnsResult.ips[0] || parsed.hostname;
  const openPorts: number[] = [];
  const portResults = await Promise.allSettled(
    COMMON_PORTS.map(async (port) => {
      const isOpen = await checkPort(targetIP, port, 3000);
      if (isOpen) openPorts.push(port);
      return { port, isOpen };
    })
  );
  if (openPorts.length > 0) {
    addFinding(phase, { category: "Ports", severity: "info", title: "Open Ports", detail: `Found ${openPorts.length} open ports: ${openPorts.sort((a, b) => a - b).join(", ")}` });
    const criticalPorts = openPorts.filter(p => [21, 22, 3306, 5432].includes(p));
    if (criticalPorts.length > 0) {
      addFinding(phase, { category: "Ports", severity: "high", title: "Critical Services Exposed", detail: `Potentially dangerous ports open: ${criticalPorts.join(", ")} (FTP/SSH/Database)` });
    }
  }
  phase.progress = 60;

  addLog(op, "Fetching HTTP headers and tech fingerprint...");
  const techStack: string[] = [];
  try {
    const resp = await fetchWithTimeout(parsed.toString(), { method: "HEAD" });
    const server = resp.headers.get("server");
    const poweredBy = resp.headers.get("x-powered-by");
    const generator = resp.headers.get("x-generator");

    if (server) { techStack.push(`Server: ${server}`); addFinding(phase, { category: "Tech", severity: "info", title: "Web Server", detail: server }); }
    if (poweredBy) { techStack.push(`Powered By: ${poweredBy}`); addFinding(phase, { category: "Tech", severity: "low", title: "Server Technology Exposed", detail: `X-Powered-By: ${poweredBy}` }); }
    if (generator) { techStack.push(`Generator: ${generator}`); addFinding(phase, { category: "Tech", severity: "info", title: "Site Generator", detail: generator }); }

    try {
      const htmlResp = await fetchWithTimeout(parsed.toString());
      const html = await htmlResp.text();
      if (html.includes("wp-content") || html.includes("wp-includes")) { techStack.push("CMS: WordPress"); addFinding(phase, { category: "Tech", severity: "info", title: "CMS Detected", detail: "WordPress detected" }); }
      else if (html.includes("Joomla")) { techStack.push("CMS: Joomla"); addFinding(phase, { category: "Tech", severity: "info", title: "CMS Detected", detail: "Joomla detected" }); }
      else if (html.includes("Drupal")) { techStack.push("CMS: Drupal"); addFinding(phase, { category: "Tech", severity: "info", title: "CMS Detected", detail: "Drupal detected" }); }
      else if (html.includes("shopify")) { techStack.push("Platform: Shopify"); addFinding(phase, { category: "Tech", severity: "info", title: "Platform Detected", detail: "Shopify detected" }); }

      const metaGen = html.match(/<meta\s+name=["']generator["']\s+content=["']([^"']+)["']/i);
      if (metaGen) { techStack.push(`Generator: ${metaGen[1]}`); addFinding(phase, { category: "Tech", severity: "info", title: "Generator Meta Tag", detail: metaGen[1] }); }
    } catch {}
  } catch (err: any) {
    addFinding(phase, { category: "Connection", severity: "medium", title: "Connection Failed", detail: `Could not connect to target: ${err.message}` });
  }
  phase.progress = 100;
  phase.status = "complete";
  addLog(op, `Reconnaissance complete. Found ${phase.findings.length} items.`);
  (op as any)._techStack = techStack;
  (op as any)._openPorts = openPorts;
}

async function runDiscovery(op: RecoveryOperation, parsed: URL) {
  const phase = op.phases[1];
  phase.status = "running";
  addLog(op, "Starting discovery phase...");

  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  const adminPanelsFound: string[] = [];
  const exposedFiles: string[] = [];

  addLog(op, "Scanning for admin panels...");
  let checked = 0;
  for (const path of ADMIN_PATHS) {
    checked++;
    phase.progress = Math.floor((checked / (ADMIN_PATHS.length + SENSITIVE_PATHS.length)) * 100);
    try {
      const resp = await fetchWithTimeout(`${baseUrl}${path}`, { method: "GET" }, 5000);
      if (resp.status === 200 || resp.status === 301 || resp.status === 302) {
        const redirectUrl = resp.headers.get("location") || "";
        adminPanelsFound.push(path);
        const severity = resp.status === 200 ? "high" : "medium";
        addFinding(phase, {
          category: "Admin Panel",
          severity,
          title: `Admin Panel Found: ${path}`,
          detail: `Status ${resp.status}${redirectUrl ? ` -> ${redirectUrl}` : ""}. Accessible admin interface discovered.`,
        });
        addLog(op, `Found admin panel: ${path} (${resp.status})`);
      }
    } catch {}
  }

  addLog(op, "Scanning for sensitive files...");
  for (const path of SENSITIVE_PATHS) {
    checked++;
    phase.progress = Math.floor((checked / (ADMIN_PATHS.length + SENSITIVE_PATHS.length)) * 100);
    try {
      const resp = await fetchWithTimeout(`${baseUrl}${path}`, { method: "GET" }, 5000);
      if (resp.status === 200) {
        const contentType = resp.headers.get("content-type") || "";
        const contentLength = parseInt(resp.headers.get("content-length") || "0", 10);
        exposedFiles.push(path);
        let severity: RecoveryFinding["severity"] = "medium";
        if (path.includes(".env") || path.includes("config") || path.includes(".sql") || path.includes("backup")) severity = "critical";
        else if (path.includes(".git") || path.includes(".svn") || path.includes(".htpasswd")) severity = "critical";
        addFinding(phase, {
          category: "Exposed File",
          severity,
          title: `Sensitive File Exposed: ${path}`,
          detail: `File is publicly accessible (${contentType}, ${contentLength > 0 ? contentLength + " bytes" : "unknown size"})`,
        });
        addLog(op, `CRITICAL: Exposed file found at ${path}`);
      }
    } catch {}
  }

  addLog(op, "Checking robots.txt for hidden paths...");
  try {
    const robotsResp = await fetchWithTimeout(`${baseUrl}/robots.txt`);
    if (robotsResp.status === 200) {
      const robotsTxt = await robotsResp.text();
      const disallowed = robotsTxt.match(/Disallow:\s*(.+)/gi);
      if (disallowed && disallowed.length > 0) {
        addFinding(phase, {
          category: "Robots.txt",
          severity: "low",
          title: "Robots.txt Disallowed Paths",
          detail: `Found ${disallowed.length} disallowed paths: ${disallowed.slice(0, 10).map(d => d.replace("Disallow:", "").trim()).join(", ")}`,
        });
      }
    }
  } catch {}

  phase.progress = 100;
  phase.status = "complete";
  addLog(op, `Discovery complete. Found ${adminPanelsFound.length} admin panels, ${exposedFiles.length} exposed files.`);
  (op as any)._adminPanels = adminPanelsFound;
  (op as any)._exposedFiles = exposedFiles;
}

async function runVulnerabilityAssessment(op: RecoveryOperation, parsed: URL) {
  const phase = op.phases[2];
  phase.status = "running";
  addLog(op, "Starting vulnerability assessment...");

  const baseUrl = `${parsed.protocol}//${parsed.host}`;

  addLog(op, "Checking security headers...");
  phase.progress = 10;
  try {
    const resp = await fetchWithTimeout(baseUrl);
    const securityHeaders: Record<string, { present: boolean; value: string | null }> = {};
    const headerChecks = [
      "strict-transport-security", "content-security-policy", "x-frame-options",
      "x-content-type-options", "x-xss-protection", "referrer-policy",
      "permissions-policy", "cross-origin-opener-policy",
    ];

    for (const h of headerChecks) {
      const val = resp.headers.get(h);
      securityHeaders[h] = { present: !!val, value: val };
    }

    const missing = headerChecks.filter(h => !securityHeaders[h].present);
    if (missing.length > 0) {
      addFinding(phase, {
        category: "Headers",
        severity: missing.includes("strict-transport-security") || missing.includes("content-security-policy") ? "high" : "medium",
        title: "Missing Security Headers",
        detail: `Missing: ${missing.join(", ")}`,
      });
    }

    const present = headerChecks.filter(h => securityHeaders[h].present);
    if (present.length > 0) {
      addFinding(phase, {
        category: "Headers",
        severity: "info",
        title: "Security Headers Present",
        detail: present.map(h => `${h}: ${securityHeaders[h].value}`).join("; "),
      });
    }
  } catch {}
  phase.progress = 30;

  addLog(op, "Testing HTTP methods...");
  const dangerousMethods = ["PUT", "DELETE", "TRACE", "CONNECT"];
  for (const method of dangerousMethods) {
    try {
      const resp = await fetchWithTimeout(baseUrl, { method }, 5000);
      if (resp.status !== 405 && resp.status !== 501 && resp.status !== 403) {
        addFinding(phase, {
          category: "HTTP Methods",
          severity: "high",
          title: `Dangerous HTTP Method Allowed: ${method}`,
          detail: `${method} request returned status ${resp.status} instead of 405/403`,
        });
      }
    } catch {}
  }
  phase.progress = 50;

  addLog(op, "Checking CORS policy...");
  try {
    const resp = await fetchWithTimeout(baseUrl, {
      headers: { "Origin": "https://evil-attacker.com" },
    });
    const acao = resp.headers.get("access-control-allow-origin");
    if (acao === "*") {
      addFinding(phase, { category: "CORS", severity: "high", title: "Wildcard CORS Policy", detail: "Access-Control-Allow-Origin is set to * (allows any origin)" });
    } else if (acao === "https://evil-attacker.com") {
      addFinding(phase, { category: "CORS", severity: "critical", title: "CORS Reflects Origin", detail: "Server reflects arbitrary origins — any website can make authenticated requests" });
    }
  } catch {}
  phase.progress = 70;

  addLog(op, "Testing for directory listing...");
  const dirPaths = ["/images/", "/uploads/", "/assets/", "/static/", "/files/", "/media/"];
  for (const dirPath of dirPaths) {
    try {
      const resp = await fetchWithTimeout(`${baseUrl}${dirPath}`, {}, 5000);
      if (resp.status === 200) {
        const body = await resp.text();
        if (body.includes("Index of") || body.includes("Directory listing") || body.includes("<pre>") && body.includes("Parent Directory")) {
          addFinding(phase, {
            category: "Directory Listing",
            severity: "medium",
            title: `Directory Listing Enabled: ${dirPath}`,
            detail: "Directory contents are publicly browsable — could expose sensitive files",
          });
        }
      }
    } catch {}
  }
  phase.progress = 90;

  addLog(op, "Checking for debug mode indicators...");
  try {
    const resp = await fetchWithTimeout(`${baseUrl}/this-page-does-not-exist-${Date.now()}`);
    if (resp.status >= 400) {
      const body = await resp.text();
      if (body.includes("Traceback") || body.includes("Stack Trace") || body.includes("Debug Mode") || body.includes("DJANGO_SETTINGS") || body.includes("Laravel") && body.includes("Exception")) {
        addFinding(phase, { category: "Debug", severity: "critical", title: "Debug Mode Enabled", detail: "Application is running with debug/error details exposed — leaks internal information" });
      }
    }
  } catch {}

  phase.progress = 100;
  phase.status = "complete";
  addLog(op, `Vulnerability assessment complete. Found ${phase.findings.length} items.`);
}

async function runRecoveryAttempts(op: RecoveryOperation, parsed: URL) {
  const phase = op.phases[3];
  phase.status = "running";
  addLog(op, "Starting recovery attempts...");

  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  const adminPanels: string[] = (op as any)._adminPanels || [];

  addLog(op, "Testing default credentials on discovered login pages...");
  let attemptCount = 0;
  const totalAttempts = adminPanels.length * DEFAULT_CREDENTIALS.length;
  for (const panel of adminPanels.slice(0, 5)) {
    for (const cred of DEFAULT_CREDENTIALS) {
      attemptCount++;
      phase.progress = Math.floor((attemptCount / Math.max(totalAttempts, 1)) * 70);
      try {
        const resp = await fetchWithTimeout(`${baseUrl}${panel}`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `username=${encodeURIComponent(cred.username)}&password=${encodeURIComponent(cred.password)}&email=${encodeURIComponent(cred.username)}&login=1`,
        }, 5000);
        if (resp.status === 302 || resp.status === 301) {
          const loc = resp.headers.get("location") || "";
          if (!loc.includes("login") && !loc.includes("error") && !loc.includes("failed")) {
            addFinding(phase, {
              category: "Credentials",
              severity: "critical",
              title: `Default Credentials Work: ${panel}`,
              detail: `Credentials ${cred.username}:${cred.password} accepted — redirected to ${loc}`,
            });
            addLog(op, `CRITICAL: Default credentials work at ${panel}: ${cred.username}:${cred.password}`);
          }
        }
      } catch {}
    }
  }

  addLog(op, "Checking for password reset endpoints...");
  phase.progress = 75;
  const resetPaths = ["/forgot-password", "/password/reset", "/wp-login.php?action=lostpassword", "/password-reset", "/auth/forgot", "/reset-password", "/account/recover"];
  for (const rp of resetPaths) {
    try {
      const resp = await fetchWithTimeout(`${baseUrl}${rp}`, {}, 5000);
      if (resp.status === 200) {
        addFinding(phase, {
          category: "Recovery",
          severity: "medium",
          title: `Password Reset Found: ${rp}`,
          detail: "Password reset endpoint is accessible — can be used for legitimate account recovery",
        });
      }
    } catch {}
  }

  addLog(op, "Scanning for backup files...");
  phase.progress = 85;
  const backupPatterns = [
    `/backup-${parsed.hostname}.zip`, `/backup-${parsed.hostname}.tar.gz`,
    `/${parsed.hostname}.sql`, `/site-backup.zip`, `/full-backup.zip`,
    "/backup/", "/backups/", "/old/", "/bak/",
  ];
  for (const bp of backupPatterns) {
    try {
      const resp = await fetchWithTimeout(`${baseUrl}${bp}`, { method: "HEAD" }, 5000);
      if (resp.status === 200) {
        const size = resp.headers.get("content-length");
        addFinding(phase, {
          category: "Backup",
          severity: "critical",
          title: `Backup File Found: ${bp}`,
          detail: `Backup accessible at ${bp}${size ? ` (${(parseInt(size) / 1024 / 1024).toFixed(2)} MB)` : ""}`,
        });
        addLog(op, `CRITICAL: Backup file found at ${bp}`);
      }
    } catch {}
  }

  phase.progress = 100;
  phase.status = "complete";
  addLog(op, `Recovery attempts complete. Found ${phase.findings.length} items.`);
}

async function generateReport(op: RecoveryOperation) {
  const phase = op.phases[4];
  phase.status = "running";
  addLog(op, "Generating recovery report...");
  phase.progress = 50;

  const allFindings = op.phases.flatMap(p => p.findings);
  const adminPanels: string[] = (op as any)._adminPanels || [];
  const techStack: string[] = (op as any)._techStack || [];
  const openPorts: number[] = (op as any)._openPorts || [];
  const exposedFiles: string[] = (op as any)._exposedFiles || [];

  const recommendations: string[] = [];
  const criticalFindings = allFindings.filter(f => f.severity === "critical");
  const highFindings = allFindings.filter(f => f.severity === "high");

  if (criticalFindings.some(f => f.category === "Credentials")) {
    recommendations.push("URGENT: Change all default credentials immediately on all admin panels");
  }
  if (criticalFindings.some(f => f.category === "Exposed File")) {
    recommendations.push("URGENT: Remove or restrict access to all exposed configuration and backup files");
  }
  if (criticalFindings.some(f => f.category === "Debug")) {
    recommendations.push("Disable debug mode in production environment immediately");
  }
  if (criticalFindings.some(f => f.category === "CORS")) {
    recommendations.push("Fix CORS policy to only allow trusted origins");
  }
  if (criticalFindings.some(f => f.category === "Backup")) {
    recommendations.push("URGENT: Remove publicly accessible backup files and secure backup directories");
  }
  if (highFindings.some(f => f.category === "Headers")) {
    recommendations.push("Implement missing security headers (HSTS, CSP, X-Frame-Options)");
  }
  if (highFindings.some(f => f.category === "Ports")) {
    recommendations.push("Close unnecessary ports and restrict database access to trusted IPs only");
  }
  if (highFindings.some(f => f.category === "HTTP Methods")) {
    recommendations.push("Disable dangerous HTTP methods (PUT, DELETE, TRACE) on the web server");
  }
  if (adminPanels.length > 0) {
    recommendations.push("Restrict admin panel access using IP whitelisting or VPN");
  }
  recommendations.push("Enable Web Application Firewall (WAF) for ongoing protection");
  recommendations.push("Set up regular automated security scanning and monitoring");
  recommendations.push("Implement multi-factor authentication on all admin accounts");
  recommendations.push("Create and test an incident response plan");

  op.summary = {
    totalFindings: allFindings.length,
    criticalCount: criticalFindings.length,
    highCount: highFindings.length,
    mediumCount: allFindings.filter(f => f.severity === "medium").length,
    lowCount: allFindings.filter(f => f.severity === "low").length,
    infoCount: allFindings.filter(f => f.severity === "info").length,
    adminPanelsFound: adminPanels,
    techStack,
    openPorts,
    exposedFiles,
    vulnerabilities: [...criticalFindings, ...highFindings].map(f => f.title),
    recommendations,
  };

  phase.progress = 100;
  phase.status = "complete";
  addLog(op, "Recovery report generated successfully.");
  addFinding(phase, {
    category: "Report",
    severity: "info",
    title: "Recovery Report Complete",
    detail: `Total findings: ${allFindings.length} (${criticalFindings.length} critical, ${highFindings.length} high, ${op.summary.mediumCount} medium). ${recommendations.length} recommendations generated.`,
  });
}
