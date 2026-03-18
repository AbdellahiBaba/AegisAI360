import { Router, Request, Response } from "express";
import { startCrashTest, getCrashJob, stopCrashTest } from "./webCrashEngine";
import { startSQLiScan, getSQLiJob, stopSQLiScan } from "./sqlInjectionEngine";
import { startAuthTest, getAuthJob, stopAuthTest } from "./authTesterEngine";
import { startInjectionScan, getInjectionJob, stopInjectionScan } from "./scriptInjectionEngine";
import { startStressTest, getStressJob, stopStressTest } from "./httpStressEngine";
import { startFtpAttack, getFtpJob, stopFtpAttack } from "./ftpAttackEngine";
import { startProtocolAttack, getProtocolJob, stopProtocolAttack } from "./protocolSuiteEngine";
import { startWirelessAttack, stopWirelessAttack, getWirelessJob, listWirelessJobs, checkTools, checkAllTools, WirelessTechnique } from "./wirelessEngine";

const router = Router();

// ══════════════════════════════════════════════════════════════════════════
// SHARED REPORT HELPERS
// ══════════════════════════════════════════════════════════════════════════
const AEGIS_VERSION = "3.0.0";

function buildMeta(tool: string, target: string, technique: string, startTime: number, endTime?: number) {
  const dur = Math.floor(((endTime ?? Date.now()) - startTime) / 1000);
  return {
    tool, version: AEGIS_VERSION, platform: "AegisAI360 SOC Platform — FAHADERA LLC",
    reportGeneratedAt: new Date().toISOString(),
    scanStarted: new Date(startTime).toISOString(),
    scanEnded: endTime ? new Date(endTime).toISOString() : new Date().toISOString(),
    durationSeconds: dur,
    durationHuman: dur >= 60 ? `${Math.floor(dur / 60)}m ${dur % 60}s` : `${dur}s`,
    target, technique,
    disclaimer: "For authorized testing only. Unauthorized use is illegal and violates CFAA/GDPR/ECPA and equivalent laws.",
  };
}

function riskLevel(score: number): string {
  if (score >= 80) return "CRITICAL";
  if (score >= 60) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "LOW";
  return "INFORMATIONAL";
}

const REMEDIATION: Record<string, { title: string; cvss: string; cwe: string[]; owasp: string; fix: string[]; references: string[] }> = {
  // Auth
  "sqli-bypass":      { title: "SQL Injection Authentication Bypass", cvss: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)", cwe: ["CWE-89", "CWE-287"], owasp: "A03:2021 – Injection", fix: ["Replace string concatenation in login queries with parameterized statements (PreparedStatement/bind params).", "Apply input validation and block SQL metacharacters (', --, ;, /*, UNION).", "Deploy WAF rules for SQL injection patterns.", "Enable database audit logging for anomalous queries.", "Consider using an ORM that enforces parameterized queries by default."], references: ["https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"] },
  "nosql-inject":     { title: "NoSQL / LDAP / XPath Injection Auth Bypass", cvss: "9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)", cwe: ["CWE-943", "CWE-90"], owasp: "A03:2021 – Injection", fix: ["Validate and sanitize all query inputs. Reject objects and arrays where scalar values are expected.", "Use $type assertions in MongoDB query schemas.", "Implement strict JSON schema validation before queries.", "Escape LDAP special characters: (, ), *, \\, NUL, /.", "Use ORM/ODM layers that prevent operator injection."], references: ["https://owasp.org/www-project-top-ten/", "https://cwe.mitre.org/data/definitions/943.html"] },
  "lockout-bypass":   { title: "Account Lockout Mechanism Bypass via IP Rotation", cvss: "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)", cwe: ["CWE-307", "CWE-799"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Implement lockout tied to account identity, not just IP address.", "Use device fingerprinting and browser challenge (CAPTCHA) after N failed attempts.", "Deploy distributed rate-limiting with Redis/Memcached across all proxy headers.", "Reject or normalize X-Forwarded-For / X-Real-IP in rate-limit calculations.", "Alert on credential stuffing patterns (many different IPs, few accounts)."], references: ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/307.html"] },
  "rate-limit-check": { title: "Absent or Insufficient Rate Limiting on Authentication", cvss: "7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)", cwe: ["CWE-307", "CWE-770"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Implement per-account and per-IP rate limiting on all authentication endpoints.", "Return 429 Too Many Requests after threshold and include Retry-After header.", "Use exponential backoff with jitter for subsequent attempts.", "Implement CAPTCHA after 5 consecutive failures.", "Log and alert on high-frequency authentication attempts."], references: ["https://cwe.mitre.org/data/definitions/307.html"] },
  "jwt-attack":       { title: "JWT Token Vulnerability (alg:none / Weak Secret / RS→HS Confusion)", cvss: "8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)", cwe: ["CWE-347", "CWE-327"], owasp: "A02:2021 – Cryptographic Failures", fix: ["Explicitly whitelist allowed JWT algorithms server-side. Reject alg:none unconditionally.", "Use a strong, randomly-generated secret (≥256 bits) for HMAC algorithms.", "Prefer asymmetric algorithms (RS256, ES256) for service-to-service tokens.", "Validate all JWT claims: iss, aud, exp, nbf.", "Store JWTs in HttpOnly cookies, not localStorage.", "Implement token rotation and short expiry (15 minutes for access tokens)."], references: ["https://portswigger.net/web-security/jwt", "https://cwe.mitre.org/data/definitions/347.html"] },
  "session-security": { title: "Insecure Session Management (Cookie Flags / Fixation)", cvss: "6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)", cwe: ["CWE-384", "CWE-614"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies.", "Regenerate session ID immediately after successful authentication.", "Implement absolute and idle session timeout.", "Invalidate all server-side sessions on logout.", "Use __Secure- and __Host- cookie prefixes for critical cookies."], references: ["https://owasp.org/www-community/attacks/Session_fixation", "https://cwe.mitre.org/data/definitions/384.html"] },
  "user-enum":        { title: "Username Enumeration via Response Differences", cvss: "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)", cwe: ["CWE-204", "CWE-208"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Return identical responses (body length, timing, HTTP status) for valid and invalid usernames.", "Add artificial time delay to normalize response timing.", "Do not disclose whether a specific email is registered in error messages.", "Implement generic error message: 'Invalid username or password'.", "Rate-limit probing attempts."], references: ["https://owasp.org/www-project-web-security-testing-guide/", "https://cwe.mitre.org/data/definitions/204.html"] },
  "password-spray":   { title: "Password Spray Attack — Account Enumeration or Weak Passwords", cvss: "7.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)", cwe: ["CWE-521", "CWE-307"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Enforce password complexity and minimum length (≥12 characters).", "Block commonly used passwords using a known-breached-password list (Have I Been Pwned API).", "Implement CAPTCHA after N failed attempts.", "Monitor for password spray patterns: many accounts, few passwords, low request rate.", "Require MFA for all accounts."], references: ["https://attack.mitre.org/techniques/T1110/003/", "https://cwe.mitre.org/data/definitions/521.html"] },
  "mfa-bypass":       { title: "Multi-Factor Authentication Bypass", cvss: "8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)", cwe: ["CWE-304", "CWE-287"], owasp: "A07:2021 – Identification and Authentication Failures", fix: ["Validate MFA state server-side before granting access. Never rely on client-side state.", "Rate-limit OTP attempts: max 5 tries, then re-issue.", "Use time-limited OTPs (30s window, TOTP standard).", "Implement step-up authentication for sensitive operations.", "Bind MFA tokens to device fingerprint or trusted device list."], references: ["https://owasp.org/www-project-cheat-sheets/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html"] },
  // Injection
  "executed":               { title: "Server-Side Script Execution (XSS/Eval/Injection)", cvss: "9.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)", cwe: ["CWE-79", "CWE-94"], owasp: "A03:2021 – Injection", fix: ["Implement output encoding for all user-supplied data in all HTML contexts (HTML, attribute, JS, CSS, URL).", "Deploy a strict Content-Security-Policy (default-src 'none'; script-src 'self').", "Use DOMPurify for client-side sanitization.", "Validate all inputs server-side against an allowlist.", "Enable X-XSS-Protection and X-Content-Type-Options headers."], references: ["https://owasp.org/www-community/attacks/xss/", "https://cwe.mitre.org/data/definitions/79.html"] },
  "reflected_unescaped":    { title: "Reflected XSS — Unescaped User Input in Response", cvss: "6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)", cwe: ["CWE-79"], owasp: "A03:2021 – Injection", fix: ["HTML-encode all reflected values: & → &amp;, < → &lt;, > → &gt;, \" → &quot;, ' → &#39;.", "Use template engines with auto-escaping enabled.", "Set Content-Type: text/html with explicit charset.", "Implement CSP to block inline script execution.", "Consider using SRI (Subresource Integrity) for external scripts."], references: ["https://portswigger.net/web-security/cross-site-scripting/reflected", "https://cwe.mitre.org/data/definitions/79.html"] },
  "ssti_hit":               { title: "Server-Side Template Injection (SSTI) — Remote Code Execution", cvss: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)", cwe: ["CWE-94", "CWE-1336"], owasp: "A03:2021 – Injection", fix: ["Never pass user-controlled data as a template string. Always use template data model (render(template, {user: data})).", "Sandbox template engines using a security manager or container.", "Validate and reject template metacharacters: {{, }}, ${, #{, <%.", "Run the template engine in a restricted sandbox (no __class__, no subprocess, no os).", "Update template engine to the latest version. Pin dependencies."], references: ["https://portswigger.net/research/server-side-template-injection", "https://cwe.mitre.org/data/definitions/94.html"] },
  "cmdi_hit":               { title: "OS Command Injection — Remote Code Execution", cvss: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)", cwe: ["CWE-78", "CWE-77"], owasp: "A03:2021 – Injection", fix: ["Never pass user input to shell commands (exec, system, popen, subprocess).", "Use language-native APIs instead of shell: fs.readFile() not exec('cat').", "If shell calls are unavoidable, use an allowlist of permitted commands and arguments.", "Escape all arguments with shellescape(). Never concatenate directly.", "Run the application process with minimal OS permissions (non-root, no SUID)."], references: ["https://owasp.org/www-community/attacks/Command_Injection", "https://cwe.mitre.org/data/definitions/78.html"] },
  "redirect_hit":           { title: "Open Redirect Vulnerability", cvss: "6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)", cwe: ["CWE-601"], owasp: "A01:2021 – Broken Access Control", fix: ["Implement a server-side allowlist of valid redirect destinations.", "Reject any redirect URL that does not match the allowlist.", "Use relative paths for internal redirects instead of absolute URLs.", "Display a warning page for off-site redirects.", "Log and alert on redirect parameter manipulation attempts."], references: ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet", "https://cwe.mitre.org/data/definitions/601.html"] },
  "waf_bypassed":           { title: "Web Application Firewall (WAF) Bypass Achieved", cvss: "7.5 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)", cwe: ["CWE-693"], owasp: "A05:2021 – Security Misconfiguration", fix: ["Switch from blocklist to positive security model (allowlist) in WAF rules.", "Normalize request encoding before WAF inspection (double-decode, unicode normalize).", "Enable detection for obfuscated payloads: case variation, null bytes, comment injection.", "Regularly review and update WAF rules against latest bypass techniques.", "Layer WAF with server-side input validation — do not rely on WAF as the only defense."], references: ["https://owasp.org/www-project-web-application-firewall/", "https://cwe.mitre.org/data/definitions/693.html"] },
  // SQLi
  "vulnerable":             { title: "Confirmed SQL Injection Vulnerability", cvss: "9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)", cwe: ["CWE-89"], owasp: "A03:2021 – Injection", fix: ["Replace all dynamic SQL string concatenation with parameterized queries or prepared statements.", "Use an ORM (Hibernate, SQLAlchemy, Sequelize) that enforces safe query building.", "Apply least privilege to database accounts — application user should not have DROP/ALTER/SHELL privilege.", "Implement a WAF rule to block SQL metacharacters in query parameters.", "Enable database activity monitoring (DAM) to alert on anomalous queries.", "Conduct a full code review of all database interaction points."], references: ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "https://cwe.mitre.org/data/definitions/89.html"] },
  "potential":              { title: "Potential SQL Injection (Requires Verification)", cvss: "7.3 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)", cwe: ["CWE-89", "CWE-20"], owasp: "A03:2021 – Injection", fix: ["Review flagged endpoints for dynamic SQL construction.", "Apply parameterized queries to all identified query construction points.", "Add input validation with strict type checking.", "Review error handling — suppress database error details in production.", "Run SAST (static analysis) tools on all database interaction code."], references: ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"] },
  // FTP
  "vuln":                   { title: "FTP Vulnerability Detected", cvss: "8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)", cwe: ["CWE-321", "CWE-319"], owasp: "A05:2021 – Security Misconfiguration", fix: ["Disable anonymous FTP access unless strictly required.", "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS).", "Restrict FTP access to specific IP ranges using firewall rules.", "Disable PORT mode (active FTP). Allow only PASV mode.", "Audit and harden FTP daemon configuration. Chroot all FTP sessions.", "Disable SITE EXEC and other dangerous FTP commands."], references: ["https://www.ncsc.gov.uk/guidance/using-ftp-securely", "https://cwe.mitre.org/data/definitions/319.html"] },
};

function getRemediation(status: string, technique?: string) {
  const key = status === "bypassed" ? (technique ?? "sqli-bypass") : (status as string);
  return REMEDIATION[key] ?? REMEDIATION["potential"] ?? {
    title: "Security Finding",
    cvss: "N/A", cwe: ["CWE-200"], owasp: "A05:2021 – Security Misconfiguration",
    fix: ["Review the flagged endpoint and apply appropriate security controls."],
    references: ["https://owasp.org/www-project-top-ten/"],
  };
}

const CRASH_TECHNIQUES = [
  "all", "large-payload", "null-byte", "header-overflow", "http-smuggling",
  "redos", "path-traversal", "malformed-http", "ssi-injection", "xml-bomb",
  "slow-read", "format-string",
];
const SQLI_TECHNIQUES = ["all", "error-based", "union", "boolean-blind", "time-based"];
const AUTH_TECHNIQUES = [
  "all", "default-creds", "sqli-bypass", "nosql-inject", "ldap-xpath",
  "lockout-bypass", "rate-limit-check", "jwt-attack", "session-security",
  "user-enum", "password-spray", "mfa-bypass", "content-type-switch",
];
const INJECT_TECHNIQUES = ["all", "xss-reflected", "polyglot", "xss-headers", "ssti", "cmdi", "html-injection", "prototype-pollution", "csti", "css-injection", "log-injection", "ldap-injection", "xpath-injection", "nosql-injection", "open-redirect", "host-header", "xxe", "graphql"];
const FTP_TECHNIQUES = ["all", "banner-grab", "anonymous-login", "default-creds", "path-traversal", "command-injection", "site-commands", "pasv-flood", "bounce-attack", "directory-listing", "connection-flood"];
const PROTOCOL_TECHNIQUES = ["all", "ssh", "smtp", "snmp", "redis", "mongodb", "telnet", "rdp", "mysql", "smb", "memcached", "ldap", "vnc"];
const STRESS_TECHNIQUES = ["http-flood", "post-flood", "mixed-flood", "slowloris", "tls-flood", "pipeline-flood", "conn-exhaust", "cache-buster", "redirect-exhaust", "combined"];

router.post("/crash/start", (req: Request, res: Response) => {
  const { target, port, path, technique, threads, duration } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!CRASH_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${CRASH_TECHNIQUES.join(", ")}` });
  try {
    const job = startCrashTest({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || 80)),
      path: String(path || "/").trim(),
      technique: String(technique),
      threads: Math.min(32, Math.max(1, parseInt(threads) || 4)),
      duration: Math.min(300, Math.max(5, parseInt(duration) || 30)),
    });
    return res.json({ jobId: job.id, startTime: job.startTime, endTime: job.endTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/crash/status/:id", (req: Request, res: Response) => {
  const job = getCrashJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  const elapsed = Math.floor((Date.now() - job.startTime) / 1000);
  return res.json({
    jobId: job.id, active: job.active, elapsed,
    progressPct: Math.min(100, Math.floor((elapsed / job.config.duration) * 100)),
    results: job.results.slice(-50),
    totalResults: job.results.length,
    crashIndicators: job.results.filter((r) => r.status === "crash_indicator").length,
    config: { technique: job.config.technique, target: job.config.target, duration: job.config.duration },
    trafficLog: (job.trafficLog ?? []).slice(-300),
  });
});

router.delete("/crash/stop/:id", (req: Request, res: Response) => {
  const ok = stopCrashTest(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

router.post("/sqli/start", (req: Request, res: Response) => {
  const { target, port, path, method, paramName, technique, duration } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!paramName) return res.status(400).json({ error: "paramName required" });
  if (!SQLI_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${SQLI_TECHNIQUES.join(", ")}` });
  try {
    const job = startSQLiScan({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || 80)),
      path: String(path || "/").trim(),
      method: method === "POST" ? "POST" : "GET",
      paramName: String(paramName).trim(),
      technique: String(technique),
      duration: Math.min(600, Math.max(10, parseInt(duration) || 60)),
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/sqli/status/:id", (req: Request, res: Response) => {
  const job = getSQLiJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: "Job not found or completed" });
  }
  return res.json({
    jobId: job.id, active: job.active,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    results: job.results.slice(-100),
    totalResults: job.results.length,
    summary: job.summary,
    dbTypeDetected: job.dbTypeDetected,
    config: { target: job.config.target, paramName: job.config.paramName, technique: job.config.technique },
    trafficLog: (job.trafficLog ?? []).slice(-300),
    extractedData: job.extractedData ?? [],
    extractionPhase: job.extractionPhase ?? false,
    extractionLog: (job.extractionLog ?? []).slice(-100),
  });
});

router.delete("/sqli/stop/:id", (req: Request, res: Response) => {
  const ok = stopSQLiScan(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

router.get("/sqli/download/:id", (req: Request, res: Response) => {
  const job = getSQLiJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found — results expire after 30 minutes" });
  const target = `${job.config.target}:${job.config.port}${job.config.path}`;
  const vulns = job.results.filter(r => r.status === "vulnerable");
  const potentials = job.results.filter(r => r.status === "potential");
  const criticalCount = vulns.length;
  const overallRisk = criticalCount > 0 ? 90 : potentials.length > 0 ? 55 : 10;
  const findings = [...vulns, ...potentials].map((r, i) => {
    const rem = getRemediation(r.status);
    return {
      findingId: `SQLI-${String(i + 1).padStart(3, "0")}`,
      ...rem,
      status: r.status,
      technique: r.technique,
      parameter: job.config.paramName,
      payload: r.payload,
      proofOfConcept: `curl -sk "http://${job.config.target}:${job.config.port}${job.config.path}?${job.config.paramName}=${encodeURIComponent(r.payload)}"`,
      serverResponseCode: r.statusCode,
      responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      extractedData: (r as any).extractedValue ?? null,
      databaseType: job.dbTypeDetected ?? "unknown",
      timestamp: new Date(r.timestamp).toISOString(),
    };
  });
  const report = {
    meta: buildMeta("AegisAI360 SQL Injection Scanner", target, job.config.technique, job.startTime, job.endTime),
    executiveSummary: {
      overallRiskLevel: riskLevel(overallRisk),
      overallRiskScore: overallRisk,
      confirmedVulnerabilities: vulns.length,
      potentialVulnerabilities: potentials.length,
      totalTestsRun: job.summary.tested,
      databaseTypeDetected: job.dbTypeDetected ?? "not detected",
      dataExtracted: (job.extractedData ?? []).length > 0,
      keyFindings: criticalCount > 0
        ? [`CONFIRMED: SQL injection on parameter '${job.config.paramName}' at ${target}`, `Database type: ${job.dbTypeDetected ?? "unknown"}`, `${job.extractedData?.length ?? 0} data records extracted`]
        : potentials.length > 0
          ? [`POTENTIAL: ${potentials.length} suspicious responses warrant manual review`]
          : ["No SQL injection vulnerabilities detected in tested payloads"],
    },
    scanConfiguration: {
      target: job.config.target, port: job.config.port, path: job.config.path,
      parameter: job.config.paramName, technique: job.config.technique,
      payloadsTested: job.summary.tested,
    },
    statistics: {
      ...job.summary,
      byTechnique: job.results.reduce((acc, r) => { acc[r.technique] = (acc[r.technique] || 0) + 1; return acc; }, {} as Record<string, number>),
      statusBreakdown: job.results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {} as Record<string, number>),
      avgResponseMs: job.results.length ? Math.round(job.results.reduce((s, r) => s + (r.responseTime ?? 0), 0) / job.results.length) : 0,
    },
    detailedFindings: findings,
    extractedData: job.extractedData ?? [],
    extractionLog: job.extractionLog ?? [],
    allResults: job.results.map(r => ({
      technique: r.technique, status: r.status,
      payload: r.payload,
      statusCode: r.statusCode, responseTimeMs: r.responseTime,
      evidence: r.evidence ?? "",
      timestamp: new Date(r.timestamp).toISOString(),
    })),
    trafficLog: job.trafficLog ?? [],
    remediationPriority: findings.length > 0 ? {
      immediate: ["Apply parameterized queries to all identified injection points", "Restrict database user privileges", "Enable WAF SQL injection rules"],
      shortTerm: ["Conduct full codebase SAST scan for SQL concatenation patterns", "Implement database activity monitoring (DAM)", "Review all query-building code"],
      longTerm: ["Migrate all database interactions to a vetted ORM", "Implement regular automated security regression testing", "Train developers on secure SQL practices"],
    } : null,
  };
  const filename = `sqli-report-${job.config.target}-${job.id.slice(0, 8)}.json`;
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/json");
  return res.json(report);
});

router.post("/auth/start", (req: Request, res: Response) => {
  const { target, port, loginPath, usernameField, passwordField, technique, customUsers, customPasswords } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!AUTH_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${AUTH_TECHNIQUES.join(", ")}` });
  try {
    const job = startAuthTest({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || 80)),
      loginPath: String(loginPath || "/login").trim(),
      usernameField: String(usernameField || "username").trim(),
      passwordField: String(passwordField || "password").trim(),
      technique: String(technique),
      customUsers: Array.isArray(customUsers) ? customUsers.map(String) : undefined,
      customPasswords: Array.isArray(customPasswords) ? customPasswords.map(String) : undefined,
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/auth/status/:id", (req: Request, res: Response) => {
  const job = getAuthJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  return res.json({
    jobId: job.id, active: job.active,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    results: job.results.slice(-100),
    totalResults: job.results.length,
    summary: job.summary,
    config: { target: job.config.target, loginPath: job.config.loginPath, technique: job.config.technique },
    trafficLog: (job.trafficLog ?? []).slice(-300),
  });
});

router.delete("/auth/stop/:id", (req: Request, res: Response) => {
  const ok = stopAuthTest(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

// ─── Auto Parameter Probe — discovers real param names from target ────────
router.post("/inject/probe-params", async (req: Request, res: Response) => {
  const { target, port, path } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  const portNum = Math.min(65535, Math.max(1, parseInt(port) || 80));
  const urlPath = String(path || "/").trim();
  const isHttps = portNum === 443;

  // Common param suggestions with confidence based on path heuristics
  const HEURISTIC_PARAMS: Record<string, string[]> = {
    search:  ["q", "query", "s", "search", "term", "keyword", "text", "find"],
    login:   ["username", "user", "email", "password", "pass", "login", "auth"],
    api:     ["id", "key", "token", "data", "payload", "input", "value", "field"],
    comment: ["comment", "body", "text", "content", "message", "post"],
    upload:  ["file", "filename", "path", "dir", "folder", "url"],
    redirect:["url", "next", "redirect", "return", "goto", "redir", "dest", "target"],
    user:    ["id", "uid", "user_id", "username", "name", "handle"],
    product: ["id", "pid", "product_id", "sku", "category", "sort"],
    page:    ["page", "p", "offset", "limit", "count", "start", "per_page"],
    cmd:     ["cmd", "exec", "command", "run", "execute", "shell", "arg"],
    template:["template", "view", "tpl", "theme", "lang", "locale"],
  };

  const pathLower = urlPath.toLowerCase();
  const suggestions: Array<{ param: string; confidence: "high" | "medium" | "low"; source: string }> = [];
  const seen = new Set<string>();
  const addSuggestion = (param: string, confidence: "high" | "medium" | "low", source: string) => {
    if (!seen.has(param)) { seen.add(param); suggestions.push({ param, confidence, source }); }
  };

  // Apply heuristics
  for (const [key, params] of Object.entries(HEURISTIC_PARAMS)) {
    if (pathLower.includes(key)) params.forEach((p) => addSuggestion(p, "high", `path contains '${key}'`));
  }

  // Try to probe the target and parse HTML
  let probeData: { fromHtml: string[]; fromQuery: string[] } = { fromHtml: [], fromQuery: [] };
  try {
    const mod = isHttps ? await import("https") : await import("http");
    probeData = await new Promise<typeof probeData>((resolve) => {
      const reqOpts = {
        hostname: target, port: portNum, path: urlPath,
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Accept": "text/html,*/*" },
        timeout: 6000, rejectUnauthorized: false,
      };
      const r = mod.default.request(reqOpts, (resp: any) => {
        let body = "";
        resp.on("data", (c: Buffer) => { body += c.toString().slice(0, 8000); });
        resp.on("end", () => {
          const fromHtml: string[] = [];
          // Parse <input name="..."> and <textarea name="...">
          const inputMatches = body.matchAll(/(?:<input|<textarea)[^>]*?\bname=["']?([a-zA-Z0-9_\-\.]+)["']?/gi);
          for (const m of inputMatches) if (m[1] && !["submit", "button", "csrf", "_token"].includes(m[1].toLowerCase())) fromHtml.push(m[1]);
          // Parse <form action="...?param=">
          const actionMatches = body.matchAll(/action=["'][^"']*\?([^"'#&]+)/gi);
          for (const m of actionMatches) {
            m[1].split("&").forEach((kv) => { const k = kv.split("=")[0]; if (k) fromHtml.push(k); });
          }
          // Parse JSON keys in response
          const jsonMatches = body.matchAll(/"([a-zA-Z_][a-zA-Z0-9_]{1,20})":/g);
          const fromQuery: string[] = [];
          for (const m of jsonMatches) fromQuery.push(m[1]);
          resolve({ fromHtml: [...new Set(fromHtml)].slice(0, 10), fromQuery: [...new Set(fromQuery)].slice(0, 10) });
        });
      });
      r.on("timeout", () => { r.destroy(); resolve({ fromHtml: [], fromQuery: [] }); });
      r.on("error", () => resolve({ fromHtml: [], fromQuery: [] }));
      r.end();
    });
  } catch {}

  probeData.fromHtml.forEach((p) => addSuggestion(p, "high", "auto-detected from HTML form"));
  probeData.fromQuery.forEach((p) => addSuggestion(p, "medium", "detected from JSON/API response"));

  // Fallback common params if nothing found
  if (suggestions.length === 0) {
    ["q", "id", "input", "data", "search", "query", "url", "name", "value", "cmd"].forEach((p) => addSuggestion(p, "low", "common parameter"));
  }

  return res.json({ suggestions: suggestions.slice(0, 15), probed: probeData.fromHtml.length > 0 });
});

router.post("/inject/start", (req: Request, res: Response) => {
  const { target, port, path, method, paramName, technique, jsonMode } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!paramName) return res.status(400).json({ error: "paramName required" });
  if (!INJECT_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${INJECT_TECHNIQUES.join(", ")}` });
  try {
    const job = startInjectionScan({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || 80)),
      path: String(path || "/").trim(),
      method: method === "POST" ? "POST" : "GET",
      paramName: String(paramName).trim(),
      technique: String(technique),
      jsonMode: Boolean(jsonMode),
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/inject/status/:id", (req: Request, res: Response) => {
  const job = getInjectionJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  return res.json({
    jobId: job.id, active: job.active,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    results: job.results.slice(-100),
    totalResults: job.results.length,
    summary: job.summary,
    config: { target: job.config.target, paramName: job.config.paramName, technique: job.config.technique },
    trafficLog: (job.trafficLog ?? []).slice(-400),
    learning: job.learning,
  });
});

router.delete("/inject/stop/:id", (req: Request, res: Response) => {
  const ok = stopInjectionScan(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

router.get("/inject/download/:id", (req: Request, res: Response) => {
  const job = getInjectionJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found — results expire after 30 minutes" });
  const target = `${job.config.target}:${job.config.port}${job.config.path}`;
  const CRITICAL_STATUSES = ["executed", "ssti_hit", "cmdi_hit", "waf_bypassed", "oob_hit", "redirect_hit", "reflected_unescaped"];
  const critical = job.results.filter(r => CRITICAL_STATUSES.includes(r.status));
  const highRisk = job.results.filter(r => r.severity === "high" && !CRITICAL_STATUSES.includes(r.status));
  const riskScore = Math.min(100, critical.length * 25 + highRisk.length * 8 + (job.summary.bypassed ?? 0) * 10);
  const findings = critical.map((r, i) => {
    const rem = getRemediation(r.status);
    return {
      findingId: `INJECT-${String(i + 1).padStart(3, "0")}`,
      ...rem,
      status: r.status,
      severity: r.severity,
      technique: r.technique,
      parameter: job.config.paramName,
      payloadFull: r.payload,
      proofOfConcept: job.config.method === "GET"
        ? `curl -sk "http://${job.config.target}:${job.config.port}${job.config.path}?${job.config.paramName}=${encodeURIComponent(r.payload)}"`
        : `curl -sk -X POST "http://${job.config.target}:${job.config.port}${job.config.path}" -d "${job.config.paramName}=${encodeURIComponent(r.payload)}"`,
      serverResponseCode: r.statusCode,
      responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      decodedEvidenceFull: (r as any).decodedEvidence ?? "",
      wafDetected: r.wafDetected ?? false,
      bypassTechniqueUsed: r.bypassUsed ?? null,
      autoRetried: r.retried ?? false,
      timestamp: new Date(r.timestamp).toISOString(),
    };
  });
  const report = {
    meta: buildMeta("AegisAI360 Script Injection Tester (18-Vector Engine)", target, job.config.technique, job.startTime, job.endTime),
    executiveSummary: {
      overallRiskLevel: riskLevel(riskScore),
      overallRiskScore: riskScore,
      confirmedExecutions: job.summary.executed,
      reflectedXss: job.summary.reflected,
      wafBypasses: job.summary.bypassed,
      totalTestsRun: job.summary.tested,
      wafEncountered: job.summary.wafBlocked > 0,
      parameter: job.config.paramName,
      engineLearnings: job.learning?.workingBypass?.length ?? 0,
      keyFindings: critical.length > 0
        ? critical.slice(0, 5).map(r => `${r.status.toUpperCase().replace(/_/g, " ")} via ${r.technique} — ${r.payload.slice(0, 80)}`)
        : ["No confirmed injection vectors found in tested payloads"],
    },
    scanConfiguration: {
      target: job.config.target, port: job.config.port, path: job.config.path,
      parameter: job.config.paramName, method: job.config.method,
      technique: job.config.technique, jsonMode: job.config.jsonMode,
    },
    engineIntelligence: {
      adaptiveEngine: true,
      wafBypassTechniquesLearned: job.learning?.workingBypass ?? [],
      blockedStatusCodes: job.learning?.blockedCodes ?? [],
      wafSignaturesDetected: job.learning?.wafSignatures ?? [],
      avgResponseTimeMs: job.learning?.avgResponseMs ?? null,
      adaptiveTimeoutApplied: job.learning?.adaptiveTimeoutMs ?? null,
      autoTimeoutRecoveries: job.summary.timeouts ?? 0,
    },
    statistics: {
      ...job.summary,
      byTechnique: job.results.reduce((acc, r) => { acc[r.technique] = (acc[r.technique] || 0) + 1; return acc; }, {} as Record<string, number>),
      bySeverity: job.results.reduce((acc, r) => { acc[r.severity] = (acc[r.severity] || 0) + 1; return acc; }, {} as Record<string, number>),
      byStatus: job.results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {} as Record<string, number>),
      avgResponseMs: job.results.length ? Math.round(job.results.reduce((s, r) => s + (r.responseTime ?? 0), 0) / job.results.length) : 0,
    },
    detailedFindings: findings,
    highRiskResults: highRisk.map(r => ({
      technique: r.technique, status: r.status, severity: r.severity,
      payloadFull: r.payload, statusCode: r.statusCode, responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "", decodedEvidence: (r as any).decodedEvidence ?? "",
      timestamp: new Date(r.timestamp).toISOString(),
    })),
    allResults: job.results.map(r => ({
      technique: r.technique, status: r.status, severity: r.severity,
      payloadFull: r.payload,
      statusCode: r.statusCode, responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      decodedEvidence: (r as any).decodedEvidence ?? "",
      wafDetected: r.wafDetected ?? false,
      bypassUsed: r.bypassUsed ?? null,
      retried: r.retried ?? false,
      timestamp: new Date(r.timestamp).toISOString(),
    })),
    trafficLog: job.trafficLog ?? [],
    remediationPriority: findings.length > 0 ? {
      immediate: ["Sanitize and encode all user inputs before rendering in HTML/JSON/JS contexts.", "Apply context-aware output encoding (HTML, attribute, JavaScript, CSS, URL).", "Implement a strict Content-Security-Policy header."],
      shortTerm: ["Audit all endpoints that reflect user input in responses.", "Deploy WAF rules with positive security model for known injection vectors.", "Review template engine configuration — disable dangerous features."],
      longTerm: ["Integrate SAST/DAST into CI/CD pipeline to catch injection on every commit.", "Implement security regression testing for all injection categories.", "Conduct developer security training on injection prevention."],
    } : null,
  };
  const filename = `inject-report-${job.config.target}-${job.id.slice(0, 8)}.json`;
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/json");
  return res.json(report);
});

// ─── Auth Tester Download ──────────────────────────────────────────────────
router.get("/auth/download/:id", (req: Request, res: Response) => {
  const job = getAuthJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found — results expire after 30 minutes" });
  const target = `${job.config.target}:${job.config.port}${job.config.loginPath}`;
  const CRITICAL_STATUSES = ["bypassed", "found", "nosql_bypass", "mfa_bypass", "lockout_bypass"];
  const criticals = job.results.filter(r => CRITICAL_STATUSES.includes(r.status));
  const jwtVulns = job.results.filter(r => r.status === "jwt_vuln");
  const sessionVulns = job.results.filter(r => r.status === "session_vuln");
  const enumFinds = job.results.filter(r => r.status === "enum_found" || r.status === "timing_vuln");
  const allHighRisk = [...criticals, ...jwtVulns, ...sessionVulns, ...enumFinds];
  const riskScore = job.summary.riskScore;
  const findings = allHighRisk.map((r, i) => {
    const rem = getRemediation(r.status === "bypassed" || r.status === "lockout_bypass" ? r.technique : r.status);
    return {
      findingId: `AUTH-${String(i + 1).padStart(3, "0")}`,
      ...rem,
      status: r.status,
      technique: r.technique,
      credential: r.status !== "jwt_vuln" && r.status !== "session_vuln" && r.username ? { username: r.username, password: r.password } : undefined,
      serverResponseCode: r.statusCode,
      responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      proofOfConcept: r.curlCommand ?? (r.username ? `curl -sk -X POST "http://${target}" -d "${job.config.usernameField}=${encodeURIComponent(r.username)}&${job.config.passwordField}=${encodeURIComponent(r.password)}"` : undefined),
      timestamp: new Date(r.timestamp).toISOString(),
    };
  });
  // Group results by module
  const byModule: Record<string, typeof job.results> = {};
  for (const r of job.results) {
    if (!byModule[r.technique]) byModule[r.technique] = [];
    byModule[r.technique].push(r);
  }
  const moduleReports = Object.entries(byModule).map(([technique, results]) => ({
    module: technique,
    totalTested: results.length,
    criticalHits: results.filter(r => CRITICAL_STATUSES.includes(r.status)).length,
    statusBreakdown: results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {} as Record<string, number>),
    avgResponseMs: results.length ? Math.round(results.reduce((s, r) => s + (r.responseTime ?? 0), 0) / results.length) : 0,
    results: results.map(r => ({
      status: r.status, username: r.username, password: r.password,
      statusCode: r.statusCode, responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      curlCommand: r.curlCommand ?? null,
      timestamp: new Date(r.timestamp).toISOString(),
    })),
  }));
  const report = {
    meta: buildMeta("AegisAI360 Authentication Security Tester v3.0", target, job.config.technique, job.startTime),
    executiveSummary: {
      overallRiskLevel: riskLevel(riskScore),
      overallRiskScore: riskScore,
      authenticationBypasses: job.summary.bypassed,
      credentialsFound: job.summary.found,
      jwtVulnerabilities: job.summary.jwtVulns,
      sessionVulnerabilities: job.summary.sessionVulns,
      usernameEnumeration: job.summary.enumFound,
      lockoutDetected: job.summary.lockoutDetected,
      totalTestsRun: job.summary.tested,
      loginPath: job.config.loginPath,
      credentialFields: { username: job.config.usernameField, password: job.config.passwordField },
      keyFindings: criticals.length > 0
        ? criticals.slice(0, 5).map(r => `${r.status.toUpperCase().replace(/_/g, " ")}: ${r.username}/${r.password} via ${r.technique}`)
        : jwtVulns.length > 0
          ? jwtVulns.map(r => `JWT VULNERABILITY: ${r.evidence?.slice(0, 100) ?? r.technique}`)
          : ["No authentication bypass detected — further manual testing recommended"],
    },
    scanConfiguration: {
      target: job.config.target, port: job.config.port, loginPath: job.config.loginPath,
      usernameField: job.config.usernameField, passwordField: job.config.passwordField,
      technique: job.config.technique,
      customUsers: job.config.customUsers ?? [],
      customPasswords: job.config.customPasswords ?? [],
    },
    statistics: {
      ...job.summary,
      byTechnique: byModule,
      statusBreakdown: job.results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {} as Record<string, number>),
      avgResponseMs: job.results.length ? Math.round(job.results.reduce((s, r) => s + (r.responseTime ?? 0), 0) / job.results.length) : 0,
    },
    detailedFindings: findings,
    moduleBreakdown: moduleReports,
    allResults: job.results.map(r => ({
      technique: r.technique, status: r.status,
      username: r.username, password: r.password,
      statusCode: r.statusCode, responseTimeMs: r.responseTime,
      evidenceFull: r.evidence ?? "",
      curlCommand: r.curlCommand ?? null,
      timestamp: new Date(r.timestamp).toISOString(),
    })),
    trafficLog: job.trafficLog ?? [],
    remediationPriority: allHighRisk.length > 0 ? {
      immediate: ["Disable or fix the identified authentication bypass immediately.", "Rotate all credentials that may have been exposed.", "Force logout all active sessions and invalidate all tokens."],
      shortTerm: ["Implement MFA across all accounts.", "Audit login endpoint for SQL/NoSQL injection.", "Harden session management (cookie flags, rotation, timeout)."],
      longTerm: ["Deploy SIEM alerts for authentication anomalies.", "Conduct regular penetration testing of authentication flows.", "Implement a bug bounty program or regular red team exercises."],
    } : null,
  };
  const filename = `auth-report-${job.config.target}-${job.id.slice(0, 8)}.json`;
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/json");
  return res.json(report);
});

// ─── Stress Tester Download ────────────────────────────────────────────────
router.get("/stress/download/:id", (req: Request, res: Response) => {
  const job = getStressJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or expired" });
  const target = `${job.config.useHttps ? "https" : "http"}://${job.config.target}:${job.config.port}${job.config.path}`;
  const m = job.metrics;
  const totalReqs = m.requestsSent;
  const errorRate = totalReqs > 0 ? ((m.requestsFailed / totalReqs) * 100).toFixed(1) : "0.0";
  const avgLat = m.latencyCount > 0 ? Math.round(m.latencySum / m.latencyCount) : 0;
  const elapsed = Math.floor((Date.now() - job.startTime) / 1000);
  const rr = job.resilienceReport;
  const report = {
    meta: buildMeta("AegisAI360 HTTP Stress & Resilience Tester", target, job.config.technique, job.startTime, job.endTime),
    executiveSummary: {
      testType: job.config.rampMode ? "Ramp Mode — Resilience Analysis" : "Fixed Load Stress Test",
      targetHandledLoad: Number(errorRate) < 5,
      maxObservedRps: m.peakRps,
      maxSustainableRps: rr?.maxSustainableRps ?? m.peakRps,
      breakingPointRps: rr?.breakingPointRps ?? null,
      breakingPointConcurrency: rr?.breakingPointConcurrency ?? null,
      overallErrorRate: `${errorRate}%`,
      avgLatencyMs: avgLat,
      p95LatencyMs: m.latencyBucket.p95,
      p99LatencyMs: m.latencyBucket.p99,
      assessment: Number(errorRate) > 20
        ? "DEGRADED — Target showed significant error rate under test load. Availability risk confirmed."
        : Number(errorRate) > 5
          ? "STRESSED — Elevated error rate observed. Capacity planning recommended."
          : m.peakRps > 0
            ? "STABLE — Target handled test load within acceptable error tolerance."
            : "INSUFFICIENT DATA — Test may not have completed.",
    },
    scanConfiguration: {
      target: job.config.target, port: job.config.port, path: job.config.path,
      technique: job.config.technique, concurrency: job.config.concurrency,
      durationSeconds: job.config.duration, useHttps: job.config.useHttps,
      rampMode: job.config.rampMode,
      rampStartConcurrency: job.config.rampStartConcurrency,
      rampStepPct: job.config.rampStepPct, rampStepSecs: job.config.rampStepSecs,
    },
    performanceMetrics: {
      requestsSent: totalReqs,
      requestsSucceeded: m.requestsSuccess,
      requestsFailed: m.requestsFailed,
      errorRatePct: errorRate,
      peakRps: m.peakRps,
      rpsHistory: m.rpsWindow,
      latency: {
        avgMs: avgLat, minMs: m.latencyBucket.min, maxMs: m.latencyBucket.max,
        p50Ms: m.latencyBucket.p50, p75Ms: m.latencyBucket.p75,
        p95Ms: m.latencyBucket.p95, p99Ms: m.latencyBucket.p99,
      },
      bandwidth: { bytesOut: m.bytesOut, bytesIn: m.bytesIn },
      errorBreakdown: {
        connectionRefused: m.errorsConnRefused, timeout: m.errorsTimeout,
        reset: m.errorsReset, other: m.errorsOther,
      },
      statusCodes: m.statusCodes,
      tlsHandshakes: m.tlsHandshakes,
      peakOpenConnections: m.connectionsOpen,
      testDurationSeconds: elapsed,
    },
    resilienceAnalysis: rr ? {
      maxSustainableRps: rr.maxSustainableRps,
      breakingPointRps: rr.breakingPointRps,
      breakingPointConcurrency: rr.breakingPointConcurrency,
      breakingPointErrorRatePct: rr.breakingPointErrorRate,
      p95AtBreakingPointMs: rr.p95AtBreaking,
      rampSnapshots: rr.snapshots,
      interpretation: rr.breakingPointRps > 0
        ? `Target becomes unreliable above ${rr.breakingPointRps} req/s (${rr.breakingPointConcurrency} concurrent users). Consider scaling infrastructure or adding caching/rate limiting.`
        : `Target handled all ${rr.maxSustainableRps} req/s sustainably throughout ramp test.`,
    } : null,
    recommendations: [
      ...(Number(errorRate) > 5 ? ["Scale horizontally (add instances) or vertically (increase resources) to handle peak load.", "Implement circuit breakers and graceful degradation for high-traffic scenarios."] : []),
      ...(m.latencyBucket.p95 > 2000 ? ["Investigate slow queries, N+1 problems, and unoptimized API calls.", "Add caching layers (Redis, CDN) for frequently-accessed resources."] : []),
      "Implement request rate limiting to prevent DoS from single sources.",
      "Configure auto-scaling policies based on CPU/memory thresholds.",
      "Use a load balancer with health checks to automatically remove degraded instances.",
      "Enable connection pooling for database connections.",
    ],
    trafficLog: job.log ?? [],
    rampSnapshots: job.rampSnapshots ?? [],
  };
  const filename = `stress-report-${job.config.target}-${job.id.slice(0, 8)}.json`;
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/json");
  return res.json(report);
});

// ─── FTP Attack Download ───────────────────────────────────────────────────
router.get("/ftp/download/:id", (req: Request, res: Response) => {
  const job = getFtpJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or expired" });
  const target = `ftp://${job.config.target}:${job.config.port}`;
  const vulnResults = job.results.filter(r => r.status === "vuln");
  const riskScore = Math.min(100, vulnResults.length * 20 + (job.summary.vulns > 3 ? 20 : 0));
  const findings = vulnResults.map((r, i) => {
    const rem = getRemediation("vuln");
    return {
      findingId: `FTP-${String(i + 1).padStart(3, "0")}`,
      ...rem,
      status: r.status,
      technique: r.technique,
      detail: r.detail,
      dataExtracted: r.data ?? null,
      timestamp: new Date(r.timestamp).toISOString(),
    };
  });
  // Group by technique
  const byTechnique = job.results.reduce((acc, r) => {
    if (!acc[r.technique]) acc[r.technique] = { total: 0, vulns: 0, results: [] as typeof job.results };
    acc[r.technique].total++;
    if (r.status === "vuln") acc[r.technique].vulns++;
    acc[r.technique].results.push(r);
    return acc;
  }, {} as Record<string, { total: number; vulns: number; results: typeof job.results }>);
  const report = {
    meta: buildMeta("AegisAI360 FTP Attack Suite", target, job.config.technique, job.startTime),
    executiveSummary: {
      overallRiskLevel: riskLevel(riskScore),
      overallRiskScore: riskScore,
      vulnerabilitiesFound: job.summary.vulns,
      totalTestsRun: job.summary.tested,
      serverBanner: job.summary.serverBanner ?? "not captured",
      serverType: job.summary.serverType ?? "unknown",
      anonymousAccessEnabled: job.results.some(r => r.technique === "anonymous-login" && r.status === "vuln"),
      credentialsBroken: job.results.filter(r => r.technique === "default-creds" && r.status === "vuln").length,
      pathTraversalConfirmed: job.results.some(r => r.technique === "path-traversal" && r.status === "vuln"),
      keyFindings: vulnResults.length > 0
        ? vulnResults.slice(0, 5).map(r => `${r.technique.toUpperCase().replace(/-/g, " ")}: ${r.detail ?? r.evidence?.slice(0, 80) ?? "Vulnerability confirmed"}`)
        : ["No FTP vulnerabilities confirmed — server appears hardened for tested techniques"],
    },
    scanConfiguration: {
      target: job.config.target, port: job.config.port, technique: job.config.technique,
      duration: job.config.duration,
    },
    statistics: {
      ...job.summary,
      byTechnique: Object.fromEntries(Object.entries(byTechnique).map(([k, v]) => [k, { total: v.total, vulns: v.vulns }])),
      statusBreakdown: job.results.reduce((acc, r) => { acc[r.status] = (acc[r.status] || 0) + 1; return acc; }, {} as Record<string, number>),
    },
    detailedFindings: findings,
    techniqueBreakdown: Object.entries(byTechnique).map(([technique, data]) => ({
      technique, totalTested: data.total, vulnerabilitiesFound: data.vulns,
      results: data.results.map(r => ({
        status: r.status, detail: r.detail,
        dataExtracted: r.data ?? null,
        timestamp: new Date(r.timestamp).toISOString(),
      })),
    })),
    allResults: job.results.map(r => ({
      technique: r.technique, status: r.status,
      detail: r.detail, dataExtracted: r.data ?? null,
      timestamp: new Date(r.timestamp).toISOString(),
    })),
    trafficLog: job.trafficLog,
    remediationPriority: vulnResults.length > 0 ? {
      immediate: ["Disable anonymous FTP access immediately if not required.", "Change all default FTP credentials.", "Block external FTP access via firewall if not needed."],
      shortTerm: ["Replace FTP with SFTP (SSH) or FTPS (TLS). Disable plaintext FTP.", "Chroot all FTP sessions to prevent directory traversal.", "Disable dangerous FTP commands: SITE EXEC, PORT, PASV abuse."],
      longTerm: ["Audit all file transfer mechanisms and enforce encryption in transit.", "Implement FTP activity logging and SIEM alerting for anomalous access.", "Consider replacing FTP entirely with a secure file transfer solution (SFTP/SCP/HTTPS)."],
    } : null,
  };
  const filename = `ftp-report-${job.config.target}-${job.id.slice(0, 8)}.json`;
  res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
  res.setHeader("Content-Type", "application/json");
  return res.json(report);
});

router.post("/stress/start", (req: Request, res: Response) => {
  const { target, port, path, technique, concurrency, duration, useHttps, rampMode, rampStartConcurrency, rampStepPct, rampStepSecs } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!STRESS_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${STRESS_TECHNIQUES.join(", ")}` });
  try {
    const job = startStressTest({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || (useHttps ? 443 : 80))),
      path: String(path || "/").trim(),
      technique: String(technique),
      concurrency: Math.min(256, Math.max(1, parseInt(concurrency) || 16)),
      duration: Math.min(600, Math.max(5, parseInt(duration) || 60)),
      useHttps: !!useHttps,
      rampMode: !!rampMode,
      rampStartConcurrency: Math.min(32, Math.max(1, parseInt(rampStartConcurrency) || 2)),
      rampStepPct: Math.min(100, Math.max(10, parseInt(rampStepPct) || 25)),
      rampStepSecs: Math.min(60, Math.max(5, parseInt(rampStepSecs) || 10)),
    });
    return res.json({ jobId: job.id, startTime: job.startTime, endTime: job.endTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/stress/status/:id", (req: Request, res: Response) => {
  const job = getStressJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  const elapsed = Math.floor((Date.now() - job.startTime) / 1000);
  return res.json({
    jobId: job.id, active: job.active, elapsed,
    durationSecs: job.config.duration,
    progressPct: Math.min(100, Math.floor((elapsed / job.config.duration) * 100)),
    metrics: job.metrics,
    config: { target: job.config.target, technique: job.config.technique, concurrency: job.config.concurrency, useHttps: job.config.useHttps, rampMode: job.config.rampMode },
    trafficLog: (job.log ?? []).slice(-300),
    rampSnapshots: job.rampSnapshots ?? [],
    resilienceReport: job.resilienceReport ?? null,
  });
});

router.delete("/stress/stop/:id", (req: Request, res: Response) => {
  const ok = stopStressTest(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

// ─── FTP Attack Suite ─────────────────────────────────────────────────────────
router.post("/ftp/start", (req: Request, res: Response) => {
  const { target, port, technique, duration, customUsers, customPasswords } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!FTP_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${FTP_TECHNIQUES.join(", ")}` });
  try {
    const job = startFtpAttack({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || 21)),
      technique: String(technique),
      duration: Math.min(300, Math.max(5, parseInt(duration) || 60)),
      customUsers: Array.isArray(customUsers) ? customUsers.map(String) : undefined,
      customPasswords: Array.isArray(customPasswords) ? customPasswords.map(String) : undefined,
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/ftp/status/:id", (req: Request, res: Response) => {
  const job = getFtpJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  return res.json({
    jobId: job.id, active: job.active,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    results: job.results.slice(-100),
    totalResults: job.results.length,
    summary: job.summary,
    config: { target: job.config.target, port: job.config.port, technique: job.config.technique },
    trafficLog: (job.trafficLog ?? []).slice(-300),
  });
});

router.delete("/ftp/stop/:id", (req: Request, res: Response) => {
  const ok = stopFtpAttack(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

// ─── Protocol Suite Attacker ──────────────────────────────────────────────────
router.post("/protocol/start", (req: Request, res: Response) => {
  const { target, technique, customPorts } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!PROTOCOL_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${PROTOCOL_TECHNIQUES.join(", ")}` });
  try {
    const job = startProtocolAttack({
      target: String(target).trim(),
      technique: String(technique),
      customPorts: customPorts && typeof customPorts === "object" ? customPorts : undefined,
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/protocol/status/:id", (req: Request, res: Response) => {
  const job = getProtocolJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found or completed" });
  return res.json({
    jobId: job.id, active: job.active,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    results: job.results.slice(-200),
    totalResults: job.results.length,
    summary: job.summary,
    config: { target: job.config.target, technique: job.config.technique },
    trafficLog: (job.trafficLog ?? []).slice(-300),
  });
});

router.delete("/protocol/stop/:id", (req: Request, res: Response) => {
  const ok = stopProtocolAttack(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

// ─── Wireless Attack Suite ───────────────────────────────────────────────────

const WIRELESS_TECHNIQUES: WirelessTechnique[] = [
  "scan", "handshake", "deauth", "evil-twin", "pmkid", "wps-pin", "karma",
];

router.get("/wireless/tools", (_req: Request, res: Response) => {
  try {
    return res.json({ tools: checkAllTools() });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/wireless/tools/:technique", (req: Request, res: Response) => {
  const technique = req.params.technique as WirelessTechnique;
  if (!WIRELESS_TECHNIQUES.includes(technique)) {
    return res.status(400).json({ error: `technique must be one of: ${WIRELESS_TECHNIQUES.join(", ")}` });
  }
  try {
    return res.json({ tools: checkTools(technique) });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.post("/wireless/start", (req: Request, res: Response) => {
  const { technique, iface, bssid, ssid, channel, clientMac, wordlist, duration } = req.body;
  if (!technique) return res.status(400).json({ error: "technique required" });
  if (!WIRELESS_TECHNIQUES.includes(technique)) {
    return res.status(400).json({ error: `technique must be one of: ${WIRELESS_TECHNIQUES.join(", ")}` });
  }
  if (!iface) return res.status(400).json({ error: "iface (wireless interface) required" });
  try {
    const job = startWirelessAttack({
      technique: technique as WirelessTechnique,
      iface: String(iface).trim(),
      bssid: bssid ? String(bssid).trim() : undefined,
      ssid: ssid ? String(ssid).trim() : undefined,
      channel: channel ? String(channel).trim() : undefined,
      clientMac: clientMac ? String(clientMac).trim() : undefined,
      wordlist: wordlist ? String(wordlist).trim() : undefined,
      duration: Math.min(600, Math.max(5, parseInt(duration) || 60)),
    });
    return res.json({ jobId: job.id, startTime: job.startTime });
  } catch (e: any) {
    return res.status(500).json({ error: e.message });
  }
});

router.get("/wireless/status/:id", (req: Request, res: Response) => {
  const job = getWirelessJob(req.params.id);
  if (!job) return res.status(404).json({ error: "Job not found" });
  return res.json({
    jobId: job.id,
    active: job.active,
    exitCode: job.exitCode,
    signal: job.signal,
    elapsed: Math.floor((Date.now() - job.startTime) / 1000),
    output: job.output.slice(-400),
    totalLines: job.output.length,
    config: {
      technique: job.config.technique,
      iface: job.config.iface,
      bssid: job.config.bssid,
      ssid: job.config.ssid,
      channel: job.config.channel,
      duration: job.config.duration,
    },
  });
});

router.delete("/wireless/stop/:id", (req: Request, res: Response) => {
  const ok = stopWirelessAttack(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
});

router.get("/wireless/jobs", (_req: Request, res: Response) => {
  return res.json({ jobs: listWirelessJobs() });
});

export default router;
