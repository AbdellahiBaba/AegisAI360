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
  { path: "/.env", name: "Environment File", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove .env from web root. Add to .gitignore. Use environment variables via hosting platform.", remediationSnippet: "# Nginx\nlocation ~ /\\.env { deny all; return 404; }\n# Apache\n<Files .env>\n  Require all denied\n</Files>" },
  { path: "/.git/config", name: "Git Repository", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Remove .git directory from production. Block access via web server config.", remediationSnippet: "# Nginx\nlocation ~ /\\.git { deny all; return 404; }\n# Apache\nRedirectMatch 404 /\\.git" },
  { path: "/.git/HEAD", name: "Git HEAD", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Remove .git directory from production deployments.", remediationSnippet: "# Nginx\nlocation ~ /\\.git { deny all; return 404; }" },
  { path: "/wp-admin/", name: "WordPress Admin", severity: "high" as const, owaspCategory: "A01:2021 Broken Access Control", cweId: "CWE-284", remediation: "Restrict wp-admin access by IP. Use two-factor authentication. Rename login URL.", remediationSnippet: "# Nginx\nlocation /wp-admin/ {\n  allow 10.0.0.0/8;\n  deny all;\n}" },
  { path: "/phpmyadmin/", name: "phpMyAdmin", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-284", remediation: "Remove phpMyAdmin from production. If needed, restrict to internal IPs and add authentication.", remediationSnippet: "# Nginx\nlocation /phpmyadmin/ {\n  allow 127.0.0.1;\n  deny all;\n}" },
  { path: "/admin/", name: "Admin Panel", severity: "medium" as const, owaspCategory: "A01:2021 Broken Access Control", cweId: "CWE-284", remediation: "Ensure admin panel requires authentication. Restrict by IP if possible.", remediationSnippet: "# Nginx\nlocation /admin/ {\n  auth_basic \"Admin Area\";\n  auth_basic_user_file /etc/nginx/.htpasswd;\n}" },
  { path: "/administrator/", name: "Administrator Panel", severity: "medium" as const, owaspCategory: "A01:2021 Broken Access Control", cweId: "CWE-284", remediation: "Restrict administrator panel access. Add IP allowlisting and multi-factor auth.", remediationSnippet: "" },
  { path: "/server-status", name: "Apache Server Status", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Disable mod_status in production or restrict to localhost.", remediationSnippet: "# Apache\n<Location /server-status>\n  Require local\n</Location>" },
  { path: "/server-info", name: "Apache Server Info", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Disable mod_info in production or restrict to localhost.", remediationSnippet: "# Apache\n<Location /server-info>\n  Require local\n</Location>" },
  { path: "/.htpasswd", name: "htpasswd File", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Move .htpasswd outside web root. Block access via server config.", remediationSnippet: "# Apache\n<Files .htpasswd>\n  Require all denied\n</Files>" },
  { path: "/.htaccess", name: "htaccess File", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Ensure .htaccess files are not publicly readable.", remediationSnippet: "# Apache\n<Files .htaccess>\n  Require all denied\n</Files>" },
  { path: "/robots.txt", name: "Robots.txt", severity: "info" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Review robots.txt for sensitive path disclosure. Do not list internal paths.", remediationSnippet: "" },
  { path: "/sitemap.xml", name: "Sitemap", severity: "info" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Ensure sitemap does not expose internal or restricted URLs.", remediationSnippet: "" },
  { path: "/crossdomain.xml", name: "Cross-Domain Policy", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-942", remediation: "Restrict crossdomain.xml to specific trusted domains. Avoid wildcard (*) access.", remediationSnippet: '<?xml version="1.0"?>\n<cross-domain-policy>\n  <allow-access-from domain="trusted.example.com"/>\n</cross-domain-policy>' },
  { path: "/backup/", name: "Backup Directory", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-530", remediation: "Remove backup directory from web root. Store backups outside the document root.", remediationSnippet: "# Nginx\nlocation /backup/ { deny all; return 404; }" },
  { path: "/api/swagger", name: "Swagger Docs", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Disable Swagger UI in production or restrict access with authentication.", remediationSnippet: "" },
  { path: "/api/docs", name: "API Documentation", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Restrict API docs to authenticated users or disable in production.", remediationSnippet: "" },
  { path: "/.DS_Store", name: "Mac DS_Store", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Remove .DS_Store files. Add to .gitignore. Block access via server config.", remediationSnippet: "# Nginx\nlocation ~ /\\.DS_Store { deny all; return 404; }" },
  { path: "/wp-config.php.bak", name: "WP Config Backup", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-530", remediation: "Remove backup files from web root. Never leave .bak or .old files in production.", remediationSnippet: "# Nginx\nlocation ~* \\.(bak|old|orig|save|swp|temp)$ { deny all; return 404; }" },
  { path: "/debug/", name: "Debug Endpoint", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-489", remediation: "Disable debug endpoints in production. Remove or restrict access.", remediationSnippet: "" },
  { path: "/wp-login.php", name: "WordPress Login", severity: "medium" as const, owaspCategory: "A07:2021 Identification and Authentication Failures", cweId: "CWE-307", remediation: "Rate limit login attempts. Use CAPTCHA and 2FA. Consider renaming login URL.", remediationSnippet: "# Nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=wp_login:10m rate=1r/s;\nlocation /wp-login.php {\n  limit_req zone=wp_login burst=3;\n}" },
  { path: "/wp-content/debug.log", name: "WordPress Debug Log", severity: "critical" as const, owaspCategory: "A09:2021 Security Logging and Monitoring Failures", cweId: "CWE-532", remediation: "Disable WP_DEBUG_LOG in production. Remove debug.log from web root.", remediationSnippet: "// wp-config.php\ndefine('WP_DEBUG', false);\ndefine('WP_DEBUG_LOG', false);" },
  { path: "/wp-includes/", name: "WordPress Includes", severity: "low" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Block direct access to wp-includes directory.", remediationSnippet: "# Nginx\nlocation /wp-includes/ {\n  internal;\n}" },
  { path: "/xmlrpc.php", name: "WordPress XML-RPC", severity: "high" as const, owaspCategory: "A07:2021 Identification and Authentication Failures", cweId: "CWE-307", remediation: "Disable XML-RPC if not needed. It enables brute-force amplification attacks.", remediationSnippet: "# Nginx\nlocation = /xmlrpc.php { deny all; return 404; }\n# Apache\n<Files xmlrpc.php>\n  Require all denied\n</Files>" },
  { path: "/install.php", name: "Installer Script", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-489", remediation: "Remove installation scripts after setup is complete.", remediationSnippet: "" },
  { path: "/setup.php", name: "Setup Script", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-489", remediation: "Remove setup scripts after installation is complete.", remediationSnippet: "" },
  { path: "/config.php", name: "Config File", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Move configuration files outside web root or block direct access.", remediationSnippet: "# Nginx\nlocation ~ /config\\.php$ { deny all; return 404; }" },
  { path: "/web.config", name: "IIS Config", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Ensure web.config is not directly accessible. IIS should block by default.", remediationSnippet: "" },
  { path: "/composer.json", name: "Composer Config", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove package manager files from production. They reveal dependency versions.", remediationSnippet: "# Nginx\nlocation ~ /(composer\\.json|composer\\.lock|package\\.json) { deny all; return 404; }" },
  { path: "/package.json", name: "NPM Package", severity: "medium" as const, owaspCategory: "A06:2021 Vulnerable and Outdated Components", cweId: "CWE-200", remediation: "Remove package.json from production web root to prevent dependency disclosure.", remediationSnippet: "" },
  { path: "/.env.local", name: "Local Environment", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove .env.local from production. Use hosting platform environment variables.", remediationSnippet: "" },
  { path: "/.env.production", name: "Production Environment", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Never expose production environment files via web server.", remediationSnippet: "" },
  { path: "/phpinfo.php", name: "PHP Info", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove phpinfo() files from production. They expose server configuration details.", remediationSnippet: "" },
  { path: "/info.php", name: "PHP Info Alt", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove diagnostic PHP files from production.", remediationSnippet: "" },
  { path: "/elmah.axd", name: "ELMAH Error Log", severity: "high" as const, owaspCategory: "A09:2021 Security Logging and Monitoring Failures", cweId: "CWE-532", remediation: "Restrict ELMAH access or disable in production.", remediationSnippet: "" },
  { path: "/trace.axd", name: "ASP.NET Trace", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Disable tracing in production web.config.", remediationSnippet: '<configuration>\n  <system.web>\n    <trace enabled="false" />\n  </system.web>\n</configuration>' },
  { path: "/actuator", name: "Spring Actuator", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Restrict Spring Actuator endpoints. Only expose /health and /info publicly.", remediationSnippet: "# application.properties\nmanagement.endpoints.web.exposure.include=health,info\nmanagement.endpoints.web.base-path=/internal/actuator" },
  { path: "/actuator/env", name: "Spring Env", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Never expose /actuator/env publicly. It reveals environment variables and secrets.", remediationSnippet: "" },
  { path: "/console", name: "H2 Console", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-489", remediation: "Disable H2 console in production.", remediationSnippet: "# application.properties\nspring.h2.console.enabled=false" },
  { path: "/graphql", name: "GraphQL Endpoint", severity: "medium" as const, owaspCategory: "A01:2021 Broken Access Control", cweId: "CWE-200", remediation: "Disable GraphQL introspection in production. Implement rate limiting.", remediationSnippet: "" },
  { path: "/.well-known/openid-configuration", name: "OpenID Config", severity: "info" as const, owaspCategory: "A07:2021 Identification and Authentication Failures", cweId: "CWE-200", remediation: "Review OpenID configuration for proper security settings.", remediationSnippet: "" },
  { path: "/cgi-bin/", name: "CGI Bin", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove CGI scripts if not needed. Restrict access to cgi-bin directory.", remediationSnippet: "" },
  { path: "/api/v1/", name: "API v1 Root", severity: "info" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Ensure API root does not expose sensitive metadata.", remediationSnippet: "" },
  { path: "/.svn/entries", name: "SVN Repository", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Remove .svn directory from production deployments.", remediationSnippet: "# Nginx\nlocation ~ /\\.svn { deny all; return 404; }" },
  { path: "/.hg/", name: "Mercurial Repository", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-538", remediation: "Remove .hg directory from production deployments.", remediationSnippet: "# Nginx\nlocation ~ /\\.hg { deny all; return 404; }" },
  { path: "/wp-json/wp/v2/users", name: "WordPress User Enum", severity: "high" as const, owaspCategory: "A01:2021 Broken Access Control", cweId: "CWE-200", remediation: "Disable user enumeration via REST API. Restrict wp-json user endpoint.", remediationSnippet: "// functions.php\nadd_filter('rest_endpoints', function($endpoints) {\n  unset($endpoints['/wp/v2/users']);\n  return $endpoints;\n});" },
  { path: "/drupal/", name: "Drupal Root", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Ensure Drupal admin paths are restricted and up to date.", remediationSnippet: "" },
  { path: "/user/login", name: "Drupal Login", severity: "medium" as const, owaspCategory: "A07:2021 Identification and Authentication Failures", cweId: "CWE-307", remediation: "Implement login rate limiting and CAPTCHA for Drupal login.", remediationSnippet: "" },
  { path: "/CHANGELOG.txt", name: "Drupal Changelog", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove CHANGELOG.txt to prevent version disclosure.", remediationSnippet: "" },
  { path: "/jmx-console/", name: "JBoss JMX Console", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-284", remediation: "Restrict JMX console access. Disable in production.", remediationSnippet: "" },
  { path: "/manager/html", name: "Tomcat Manager", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-284", remediation: "Restrict Tomcat manager to localhost. Use strong credentials.", remediationSnippet: '<!-- server.xml -->\n<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\\.0\\.0\\.1"/>' },
  { path: "/solr/", name: "Apache Solr", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-284", remediation: "Restrict Solr admin access. Enable authentication.", remediationSnippet: "" },
  { path: "/.aws/credentials", name: "AWS Credentials", severity: "critical" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-798", remediation: "Never store AWS credentials in web root. Use IAM roles or environment variables.", remediationSnippet: "" },
  { path: "/docker-compose.yml", name: "Docker Compose", severity: "high" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove Docker configuration files from production web root.", remediationSnippet: "" },
  { path: "/Dockerfile", name: "Dockerfile", severity: "medium" as const, owaspCategory: "A05:2021 Security Misconfiguration", cweId: "CWE-200", remediation: "Remove Dockerfile from production web root.", remediationSnippet: "" },
];

interface VulnResult {
  path: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  found: boolean;
  statusCode: number;
  details: string;
  owaspCategory: string;
  cweId: string;
  remediation: string;
  remediationSnippet: string;
  riskScore: number;
}

const SEVERITY_RISK_SCORES: Record<string, number> = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 3.0,
  info: 0.0,
};

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
        const effectiveSeverity = found && vulnPath.severity !== "info" ? vulnPath.severity : "info";
        resolve({
          path: vulnPath.path,
          name: vulnPath.name,
          severity: effectiveSeverity,
          found,
          statusCode: res.statusCode || 0,
          details,
          owaspCategory: vulnPath.owaspCategory,
          cweId: vulnPath.cweId,
          remediation: vulnPath.remediation,
          remediationSnippet: vulnPath.remediationSnippet,
          riskScore: found ? SEVERITY_RISK_SCORES[effectiveSeverity] || 0 : 0,
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
        owaspCategory: vulnPath.owaspCategory,
        cweId: vulnPath.cweId,
        remediation: vulnPath.remediation,
        remediationSnippet: vulnPath.remediationSnippet,
        riskScore: 0,
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
        owaspCategory: vulnPath.owaspCategory,
        cweId: vulnPath.cweId,
        remediation: vulnPath.remediation,
        remediationSnippet: vulnPath.remediationSnippet,
        riskScore: 0,
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
