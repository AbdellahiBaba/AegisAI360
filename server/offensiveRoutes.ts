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
