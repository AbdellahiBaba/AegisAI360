import { Router, Request, Response } from "express";
import { startCrashTest, getCrashJob, stopCrashTest } from "./webCrashEngine";
import { startSQLiScan, getSQLiJob, stopSQLiScan } from "./sqlInjectionEngine";
import { startAuthTest, getAuthJob, stopAuthTest } from "./authTesterEngine";
import { startInjectionScan, getInjectionJob, stopInjectionScan } from "./scriptInjectionEngine";
import { startStressTest, getStressJob, stopStressTest } from "./httpStressEngine";
import { startFtpAttack, getFtpJob, stopFtpAttack } from "./ftpAttackEngine";
import { startProtocolAttack, getProtocolJob, stopProtocolAttack } from "./protocolSuiteEngine";

const router = Router();

const CRASH_TECHNIQUES = [
  "all", "large-payload", "null-byte", "header-overflow", "http-smuggling",
  "redos", "path-traversal", "malformed-http", "ssi-injection", "xml-bomb",
  "slow-read", "format-string",
];
const SQLI_TECHNIQUES = ["all", "error-based", "union", "boolean-blind", "time-based"];
const AUTH_TECHNIQUES = ["all", "default-creds", "sqli-bypass", "lockout-bypass", "rate-limit-check"];
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
  });
});

router.delete("/sqli/stop/:id", (req: Request, res: Response) => {
  const ok = stopSQLiScan(req.params.id);
  return ok ? res.json({ success: true }) : res.status(404).json({ error: "Not found" });
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

router.post("/stress/start", (req: Request, res: Response) => {
  const { target, port, path, technique, concurrency, duration, useHttps } = req.body;
  if (!target) return res.status(400).json({ error: "target required" });
  if (!STRESS_TECHNIQUES.includes(technique)) return res.status(400).json({ error: `technique must be one of: ${STRESS_TECHNIQUES.join(", ")}` });
  try {
    const job = startStressTest({
      target: String(target).trim(),
      port: Math.min(65535, Math.max(1, parseInt(port) || (useHttps ? 443 : 80))),
      path: String(path || "/").trim(),
      technique: String(technique),
      concurrency: Math.min(128, Math.max(1, parseInt(concurrency) || 16)),
      duration: Math.min(600, Math.max(5, parseInt(duration) || 60)),
      useHttps: !!useHttps,
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
    config: { target: job.config.target, technique: job.config.technique, concurrency: job.config.concurrency, useHttps: job.config.useHttps },
    trafficLog: (job.log ?? []).slice(-300),
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

export default router;
