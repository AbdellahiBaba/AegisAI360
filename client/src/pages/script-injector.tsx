import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import { Code, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, Terminal, Flame, ChevronDown, ChevronRight, Brain, Repeat, Shield, Target, Zap, BookOpen, HelpCircle } from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all",                 name: "Full Injection Suite (18 techniques)", desc: "Runs all attack vectors: reflected XSS, polyglot, header XSS, SSTI, cmdi, HTML, prototype pollution, CSTI, CSS, log, LDAP, XPath, NoSQL, open redirect, host header, XXE, GraphQL injection" },
  { id: "xss-reflected",       name: "Reflected XSS (40 payloads)",           desc: "40 real XSS payloads via URL/POST params — detects unescaped reflection, script execution, WAF bypass variants" },
  { id: "polyglot",            name: "Polyglot Injection (15 payloads)",       desc: "Context-free payloads that break out of HTML, JS, attribute, CSS, and URL contexts simultaneously — highest WAF evasion" },
  { id: "xss-headers",         name: "XSS via HTTP Headers (12 headers)",      desc: "Injects into X-Forwarded-For, Referer, User-Agent, X-Original-URL, X-Host, Origin, X-Forwarded-Host — detects header reflection" },
  { id: "ssti",                name: "Template Injection SSTI (20 engines)",   desc: "Jinja2, Twig, FreeMarker, ERB, Thymeleaf, Groovy, SpEL, Razor — detects if {{7*7}} evaluates or if OS commands execute" },
  { id: "cmdi",                name: "Command Injection (24 variants)",         desc: "; id, | id, $(id), backticks, newline bypass, brace expansion, OOB network callback — confirms OS command execution" },
  { id: "html-injection",      name: "HTML Injection (10 payloads)",            desc: "Raw HTML tags, form hijacking, base tag override, meta refresh — detects UI redressing and phishing surface" },
  { id: "prototype-pollution", name: "Prototype Pollution (12 payloads)",       desc: "__proto__[isAdmin]=true, constructor[prototype], defineGetter — detects server-side prototype chain poisoning" },
  { id: "csti",                name: "Client-Side Template Injection (13)",     desc: "AngularJS, Vue.js, Handlebars CSTI — detects if template engine evaluates attacker expressions" },
  { id: "css-injection",       name: "CSS Injection (8 payloads)",              desc: "@import url(), expression(), -moz-binding, charset exfiltration — detects data theft via CSS" },
  { id: "log-injection",       name: "CRLF / Log Injection (8 payloads)",       desc: "\\r\\n CRLF sequences, header injection, Set-Cookie injection, response splitting" },
  { id: "ldap-injection",      name: "LDAP Injection (10 payloads)",            desc: "*)(|(password=*), admin)(&, objectClass bypass — detects input passed to LDAP filter" },
  { id: "xpath-injection",     name: "XPath Injection (9 payloads)",            desc: "' or '1'='1, //user traversal, XPathException detection" },
  { id: "nosql-injection",     name: "NoSQL Injection (12 payloads)",           desc: "MongoDB $gt/$ne/$where/$regex/$or operators — auth bypass and data extraction" },
  { id: "open-redirect",       name: "Open Redirect (15 payloads)",             desc: "//evil.com, %2F%2F, backslash bypass, protocol-relative URLs, javascript: scheme" },
  { id: "host-header",         name: "Host Header Injection (9 payloads)",      desc: "Cache poisoning, password reset poisoning, SSRF via manipulated Host header" },
  { id: "xxe",                 name: "XXE / XML Injection (5 payloads)",        desc: "/etc/passwd read, SSRF via external entity, blind OOB XXE via DTD parameter entities" },
  { id: "graphql",             name: "GraphQL Introspection / Injection",       desc: "__schema introspection, sensitive field exposure, SQL/NoSQL injection via GraphQL variables" },
];

const SEVERITY_CONFIG: Record<string, { label: string; cls: string }> = {
  critical: { label: "CRITICAL", cls: "border-severity-critical/50 text-severity-critical bg-severity-critical/5" },
  high:     { label: "HIGH",     cls: "border-severity-high/50 text-severity-high bg-severity-high/5" },
  medium:   { label: "MEDIUM",   cls: "border-severity-medium/50 text-severity-medium bg-severity-medium/5" },
  info:     { label: "INFO",     cls: "border-border/30 text-muted-foreground" },
};

const STATUS_LABEL: Record<string, string> = {
  executed:            "SCRIPT EXECUTED",
  ssti_hit:            "SSTI CONFIRMED",
  cmdi_hit:            "CMDI CONFIRMED",
  waf_bypassed:        "WAF BYPASSED",
  oob_hit:             "OOB HIT",
  redirect_hit:        "OPEN REDIRECT",
  reflected_unescaped: "REFLECTED (UNESCAPED)",
  reflected_escaped:   "REFLECTED (ESCAPED)",
  waf_blocked:         "WAF BLOCKED",
  not_reflected:       "Not Reflected",
  error:               "Error",
};

interface InjectionResult {
  technique: string;
  payload: string;
  status: string;
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  severity: string;
  timestamp: number;
  retried?: boolean;
  bypassUsed?: string;
  wafDetected?: boolean;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  results: InjectionResult[];
  totalResults: number;
  summary: { executed: number; reflected: number; tested: number; wafBlocked: number; bypassed: number };
  config: { target: string; paramName: string; technique: string };
  trafficLog?: string[];
  learning?: { workingBypass: string[]; blockedCodes: number[]; wafSignatures: string[] };
}

const GUIDE_STEPS = [
  {
    icon: Target,
    title: "Set Your Target",
    content: [
      "Enter the hostname/IP of the app you own or have written authorization to test.",
      "Set the port: 80 for HTTP, 443 for HTTPS, or any custom port your app listens on.",
      "Set the endpoint path — the URL that processes user input (e.g. /search, /api/query, /login).",
    ],
    tip: "Start with a staging/dev environment. Never test on production without approval.",
  },
  {
    icon: Zap,
    title: "Choose Attack Vector",
    content: [
      "Full Suite tests all 18 injection categories and is the most thorough option.",
      "For REST APIs accepting JSON, enable JSON Mode — payloads are sent as JSON body fields.",
      "If you're focused on a specific area (e.g. only template injection) pick that technique.",
    ],
    tip: "Use Polyglot as your first targeted test — it breaks multiple contexts simultaneously.",
  },
  {
    icon: Code,
    title: "Configure the Injection Point",
    content: [
      "Set the parameter name that receives user input (q, search, username, id, etc.).",
      "For nested JSON, use dot notation: user.profile.name injects into the 'name' field.",
      "Choose GET to inject via URL query string, POST to inject via request body.",
    ],
    tip: "If you don't know the parameter name, try common ones: q, s, query, input, data, cmd.",
  },
  {
    icon: Brain,
    title: "Understanding Adaptive Retry",
    content: [
      "The engine detects WAF/firewall blocks (HTTP 403/406/429 or WAF body signatures).",
      "When blocked, it automatically mutates the payload using 20 bypass techniques.",
      "Successful bypass techniques are learned and prioritized in subsequent tests.",
    ],
    tip: "Watch the Traffic Console — bypass attempts appear in real-time as '• Retry #N with bypass [technique-name]'.",
  },
  {
    icon: CheckCircle,
    title: "Interpreting Results",
    content: [
      "CRITICAL / EXECUTED = the payload ran in the server — immediate vulnerability confirmed.",
      "WAF BYPASSED = the engine evaded the firewall and the payload was processed.",
      "REFLECTED (UNESCAPED) = payload echoed back in raw form — likely exploitable XSS.",
      "REFLECTED (ESCAPED) = payload encoded — safer, but may still be vulnerable in JS context.",
      "WAF BLOCKED = server blocked the payload; bypass attempts also failed.",
    ],
    tip: "Focus on CRITICAL findings first. REFLECTED results indicate injection points worth manual follow-up.",
  },
];

export default function ScriptInjectorPage() {
  useDocumentTitle("Script Injection Tester");
  const { toast } = useToast();
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [path, setPath] = useState("/search");
  const [method, setMethod] = useState("GET");
  const [paramName, setParamName] = useState("q");
  const [technique, setTechnique] = useState("all");
  const [jsonMode, setJsonMode] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const [guideStep, setGuideStep] = useState(0);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    const res = await fetch(`/api/offensive/inject/status/${id}`);
    if (res.status === 404) {
      stopPolling(); setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null);
      const issues = data.summary.executed + data.summary.reflected;
      toast({
        title: "Injection Scan Complete",
        description: issues > 0
          ? `${data.summary.executed} executed + ${data.summary.reflected} reflected vulnerabilities found! (${data.summary.bypassed} WAF bypasses)`
          : `No injection points found in ${data.summary.tested} tests`,
        variant: issues > 0 ? "destructive" : "default",
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/inject/start", {
        target, port: parseInt(port) || 80, path, method, paramName, technique, jsonMode,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Injection Scan Started", description: `Adaptive engine targeting ${paramName} on ${target}:${port}${path}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 1000);
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    } finally {
      setLaunching(false);
    }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/inject/stop/${jobId}`, { method: "DELETE" });
    stopPolling(); setJobId(null);
    toast({ title: "Scan Stopped" });
  };

  const isRunning = !!jobId && status?.active;
  const criticalResults = status?.results.filter((r) =>
    r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" ||
    r.status === "waf_bypassed" || r.status === "oob_hit" || r.status === "redirect_hit" ||
    r.status === "reflected_unescaped"
  ) ?? [];

  const GuideIcon = GUIDE_STEPS[guideStep].icon;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
            <Code className="w-5 h-5 text-primary" />
            Script Injection Tester
          </h1>
          <p className="text-xs text-muted-foreground">
            18-vector adaptive injection engine with WAF bypass learning, smart retry, and real-time traffic analysis
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          className="text-xs gap-1.5 shrink-0"
          onClick={() => setGuideOpen(!guideOpen)}
          data-testid="button-toggle-guide"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          {guideOpen ? "Hide Guide" : "How to Use"}
        </Button>
      </div>

      {guideOpen && (
        <Card className="border-primary/30 bg-primary/5">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-primary" />
                Step-by-Step Injection Testing Guide
              </CardTitle>
              <div className="flex gap-1">
                {GUIDE_STEPS.map((_, i) => (
                  <button
                    key={i}
                    onClick={() => setGuideStep(i)}
                    data-testid={`button-guide-step-${i}`}
                    className={`w-6 h-6 rounded text-[10px] font-mono font-bold transition-all ${guideStep === i ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-primary/20"}`}
                  >
                    {i + 1}
                  </button>
                ))}
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 shrink-0">
                <GuideIcon className="w-5 h-5 text-primary" />
              </div>
              <div className="space-y-2 flex-1">
                <h3 className="text-sm font-semibold">Step {guideStep + 1}: {GUIDE_STEPS[guideStep].title}</h3>
                <ul className="space-y-1.5">
                  {GUIDE_STEPS[guideStep].content.map((line, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                      <ChevronRight className="w-3 h-3 text-primary mt-0.5 shrink-0" />
                      {line}
                    </li>
                  ))}
                </ul>
                <div className="flex items-start gap-2 p-2 rounded bg-amber-500/10 border border-amber-500/20">
                  <Zap className="w-3 h-3 text-amber-500 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-amber-400">{GUIDE_STEPS[guideStep].tip}</p>
                </div>
              </div>
            </div>
            <div className="flex justify-between">
              <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => setGuideStep((s) => Math.max(0, s - 1))} disabled={guideStep === 0} data-testid="button-guide-prev">
                Previous
              </Button>
              <span className="text-[10px] text-muted-foreground self-center">{guideStep + 1} / {GUIDE_STEPS.length}</span>
              <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => setGuideStep((s) => Math.min(GUIDE_STEPS.length - 1, s + 1))} disabled={guideStep === GUIDE_STEPS.length - 1} data-testid="button-guide-next">
                Next
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool injects real malicious payloads and OS command vectors. Use only on systems you own or have written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Injection Vector</CardTitle></CardHeader>
            <CardContent className="space-y-1">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-inject-tech-${t.id}`}
                  className={`w-full text-left p-2 rounded-md border text-xs transition-all ${technique === t.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                  <div className="font-semibold text-[11px]">{t.name}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5 leading-snug">{t.desc}</div>
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Target Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Target Host</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-inject-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-inject-port" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Endpoint Path</Label>
                  <Input value={path} onChange={(e) => setPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-inject-path" placeholder="/search or /api/query" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Method</Label>
                  <Select value={method} onValueChange={setMethod} disabled={isRunning}>
                    <SelectTrigger className="h-8 text-xs" data-testid="select-inject-method"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Injection Parameter</Label>
                  <Input value={paramName} onChange={(e) => setParamName(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-inject-param" placeholder="q, search, input, cmd, user.name..." />
                  <p className="text-[10px] text-muted-foreground">Payload injected as: ?<span className="text-primary font-mono">{paramName}</span>=&lt;PAYLOAD&gt;</p>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">JSON Mode</Label>
                  <button
                    onClick={() => !isRunning && setJsonMode(!jsonMode)}
                    disabled={isRunning}
                    data-testid="button-toggle-json-mode"
                    className={`w-full h-8 rounded-md border text-xs font-mono font-semibold transition-all ${jsonMode ? "border-primary bg-primary/10 text-primary" : "border-border/50 text-muted-foreground hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}
                  >
                    {jsonMode ? "JSON ON" : "JSON OFF"}
                  </button>
                  <p className="text-[10px] text-muted-foreground">For REST APIs</p>
                </div>
              </div>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                    <span className="text-xs font-mono font-semibold">{isRunning ? "INJECTING — ADAPTIVE ENGINE ACTIVE" : "SCAN COMPLETE"}</span>
                  </div>
                  <div className="grid grid-cols-5 gap-1.5 text-xs font-mono">
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.executed ?? 0) > 0 ? "text-severity-critical" : "text-foreground"}`}>{status?.summary.executed ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">EXECUTED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.reflected ?? 0) > 0 ? "text-severity-high" : "text-foreground"}`}>{status?.summary.reflected ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">REFLECTED</div>
                    </div>
                    <div className="text-center">
                      <div className="text-base font-bold">{status?.summary.tested ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">TESTED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.wafBlocked ?? 0) > 0 ? "text-amber-500" : "text-foreground"}`}>{status?.summary.wafBlocked ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">WAF BLOCKS</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.bypassed ?? 0) > 0 ? "text-emerald-500" : "text-foreground"}`}>{status?.summary.bypassed ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">BYPASSED</div>
                    </div>
                  </div>
                  {status?.learning && status.learning.workingBypass.length > 0 && (
                    <div className="flex items-start gap-2 p-2 rounded bg-emerald-500/10 border border-emerald-500/20">
                      <Brain className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[10px] text-emerald-400 font-semibold">Engine Learned {status.learning.workingBypass.length} Bypass Technique(s)</p>
                        <p className="text-[10px] text-muted-foreground">{status.learning.workingBypass.join(" · ")}</p>
                      </div>
                    </div>
                  )}
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1" data-testid="button-launch-inject">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Flame className="w-4 h-4 me-2" />Launch Adaptive Injection Scan</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-inject">
                      <Square className="w-4 h-4 me-2" />Stop Scan
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          {criticalResults.length > 0 && (
            <Card className="border-severity-critical/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-severity-critical flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Confirmed Injection Points ({criticalResults.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {criticalResults.map((r, i) => {
                  const sev = SEVERITY_CONFIG[r.severity] ?? SEVERITY_CONFIG.info;
                  return (
                    <div key={i} className={`p-3 border rounded-md space-y-1.5 ${sev.cls}`}>
                      <div className="flex items-center justify-between flex-wrap gap-1">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-[9px] ${sev.cls}`}>{sev.label}</Badge>
                          <span className="text-[10px] font-mono font-semibold">{STATUS_LABEL[r.status] ?? r.status}</span>
                          {r.retried && (
                            <Badge variant="outline" className="text-[9px] border-emerald-500/50 text-emerald-400 bg-emerald-500/5">
                              <Repeat className="w-2.5 h-2.5 mr-1" />WAF BYPASSED
                            </Badge>
                          )}
                          {r.bypassUsed && (
                            <span className="text-[9px] font-mono text-emerald-400">via {r.bypassUsed}</span>
                          )}
                        </div>
                        <span className="text-[10px] font-mono text-muted-foreground">{r.technique} · {r.responseTime}ms</span>
                      </div>
                      <div className="text-[10px] font-mono bg-black/20 rounded p-1.5 break-all">{r.payload.slice(0, 200)}</div>
                      {r.evidence && <div className="text-[10px] text-muted-foreground bg-muted/20 rounded p-1.5 max-h-28 overflow-y-auto leading-relaxed">{r.evidence}</div>}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {status && status.results.length > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">All Test Results</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-64 overflow-y-auto">
                  {[...status.results].reverse().map((r, i) => {
                    const sev = SEVERITY_CONFIG[r.severity] ?? SEVERITY_CONFIG.info;
                    const isCrit = r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" || r.status === "waf_bypassed" || r.status === "reflected_unescaped";
                    const isWafBlock = r.status === "waf_blocked";
                    return (
                      <div key={i} className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${isCrit ? sev.cls : isWafBlock ? "border-amber-500/30 bg-amber-500/5" : "border-border/30"}`}>
                        <div className="flex items-center gap-1.5 min-w-0">
                          <Badge variant="outline" className={`text-[8px] py-0 shrink-0 ${sev.cls}`}>{sev.label}</Badge>
                          {r.wafDetected && <Shield className="w-3 h-3 text-amber-500 shrink-0" />}
                          {r.retried && <Repeat className="w-3 h-3 text-emerald-400 shrink-0" />}
                          <span className="font-mono text-[10px] truncate">{r.payload.slice(0, 60)}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0 text-[10px] font-mono text-muted-foreground">
                          <span className="hidden sm:inline">{r.technique}</span>
                          {r.statusCode && <span>HTTP {r.statusCode}</span>}
                          {r.responseTime && <span>{r.responseTime}ms</span>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {status && (
            <TrafficConsole
              trafficLog={status.trafficLog ?? []}
              active={isRunning}
              title="Script Injection — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
