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
import {
  Code, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, Terminal,
  Flame, ChevronDown, ChevronRight, Brain, Repeat, Shield, Target, Zap, BookOpen,
  HelpCircle, Cpu, Wifi, WifiOff, Search, Sparkles, Unlock, Eye, Download,
} from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all",                 name: "Full Injection Suite (18 techniques)", desc: "Runs all attack vectors: reflected XSS, polyglot, header XSS, SSTI, cmdi, HTML, prototype pollution, CSTI, CSS, log, LDAP, XPath, NoSQL, open redirect, host header, XXE, GraphQL injection" },
  { id: "xss-reflected",       name: "Reflected XSS (40 payloads)",           desc: "40 real cookie-stealing/exfil payloads — detects unescaped reflection, script execution, WAF bypass" },
  { id: "polyglot",            name: "Polyglot Injection (15 payloads)",       desc: "Context-free payloads that break out of HTML, JS, attribute, CSS, and URL contexts simultaneously" },
  { id: "xss-headers",         name: "XSS via HTTP Headers (12 headers)",      desc: "Injects into X-Forwarded-For, Referer, User-Agent, X-Original-URL, X-Host, Origin, X-Forwarded-Host" },
  { id: "ssti",                name: "Template Injection SSTI (20 engines)",   desc: "Jinja2, FreeMarker, Spring SpEL, Twig, Velocity, Smarty — real RCE chains, file reads, OS command execution" },
  { id: "cmdi",                name: "Command Injection (32 variants)",         desc: "id/whoami/uname, /etc/passwd+shadow reads, reverse shells (bash/python/perl/ruby), cron persistence, SSH key injection" },
  { id: "html-injection",      name: "HTML Injection (10 payloads)",            desc: "Raw HTML tags, credential form hijacking, base tag override, meta refresh — UI redressing" },
  { id: "prototype-pollution", name: "Prototype Pollution (12 payloads)",       desc: "__proto__[isAdmin]=true, AST injection gadgets, shell gadgets — server-side prototype chain poisoning" },
  { id: "csti",                name: "Client-Side Template Injection (13)",     desc: "AngularJS/Vue.js/Handlebars — real cookie exfil, process.env leak, child_process RCE via Handlebars" },
  { id: "css-injection",       name: "CSS Injection (8 payloads)",              desc: "CSRF token theft via attribute selectors, @import SSRF, expression() IE execution" },
  { id: "log-injection",       name: "CRLF / Log Injection (8 payloads)",       desc: "\\r\\n CRLF sequences, header injection, Set-Cookie injection, response splitting" },
  { id: "ldap-injection",      name: "LDAP Injection (10 payloads)",            desc: "*)(|(password=*), admin)(&, objectClass bypass — detects input passed to LDAP filter" },
  { id: "xpath-injection",     name: "XPath Injection (9 payloads)",            desc: "' or '1'='1, //user traversal, XPathException detection" },
  { id: "nosql-injection",     name: "NoSQL Injection (12 payloads)",           desc: "MongoDB $gt/$ne/$where/$regex/$or operators — auth bypass and data extraction" },
  { id: "open-redirect",       name: "Open Redirect (15 payloads)",             desc: "//evil.com, %2F%2F, backslash bypass, protocol-relative URLs, javascript: cookie steal" },
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
  error:               "Connection Error",
};

interface ParamSuggestion {
  param: string;
  confidence: "high" | "medium" | "low";
  source: string;
}

interface InjectionResult {
  technique: string;
  payload: string;
  status: string;
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  decodedEvidence?: string;
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
  summary: { executed: number; reflected: number; tested: number; wafBlocked: number; bypassed: number; timeouts?: number; errors?: number };
  config: { target: string; paramName: string; technique: string };
  trafficLog?: string[];
  learning?: { workingBypass: string[]; blockedCodes: number[]; wafSignatures: string[]; avgResponseMs?: number; consecutiveErrors?: number; adaptiveTimeoutMs?: number };
}

const GUIDE_STEPS = [
  {
    icon: Target,
    title: "Set Your Target",
    content: [
      "Enter the hostname/IP of the app you own or have written authorization to test.",
      "Set the port: 80 for HTTP, 443 for HTTPS, or any custom port your app listens on.",
      "Set the endpoint path — the URL that processes user input (e.g. /search, /api/query, /login).",
      "Once target and path are set, the engine auto-probes for real parameter names.",
    ],
    tip: "Start with a staging/dev environment. Never test on production without approval.",
  },
  {
    icon: Sparkles,
    title: "Auto-Detected Parameters",
    content: [
      "After entering target + path, the engine probes the page and detects real input parameter names.",
      "Green badges show HIGH confidence params (found in HTML form inputs).",
      "Yellow badges show MEDIUM confidence (path-heuristic suggestions).",
      "Click any suggestion to instantly apply it as the injection parameter.",
    ],
    tip: "HTML-parsed params are the most accurate. Always prefer HIGH confidence suggestions.",
  },
  {
    icon: Zap,
    title: "Choose Attack Vector",
    content: [
      "Full Suite tests all 18 injection categories and is the most thorough option.",
      "For REST APIs accepting JSON, enable JSON Mode — payloads are sent as JSON body fields.",
      "If focused on a specific area (e.g. template injection) pick that technique.",
    ],
    tip: "Use Polyglot as your first targeted test — it breaks multiple contexts simultaneously.",
  },
  {
    icon: Brain,
    title: "Adaptive Engine Intelligence",
    content: [
      "The engine detects WAF/firewall blocks and automatically mutates payloads using 20 bypass techniques.",
      "On timeout or socket hang up, it rebuilds the attack in milliseconds — no manual retry needed.",
      "It probes with HEAD to check if the target is alive, then adjusts the timeout window automatically.",
      "Successful bypass techniques are learned and prioritized in subsequent tests.",
    ],
    tip: "Watch the Traffic Console — recovery events show as '! Rebuilding attack in adaptive mode'.",
  },
  {
    icon: Eye,
    title: "Reading Decoded Results",
    content: [
      "CRITICAL / EXECUTED = payload ran on the server — immediate vulnerability confirmed.",
      "REFLECTED (UNESCAPED) = payload echoed back raw — exploitable XSS if served in a browser.",
      "CMDI CONFIRMED / SSTI CONFIRMED = OS command or template expression evaluated — full RCE.",
      "DECODED OUTPUT shows the response after stripping URL encoding, HTML entities, and Base64.",
    ],
    tip: "Look for decoded evidence that reveals sensitive data: uid=, root:, /etc/passwd entries, JWT tokens.",
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
  const [completedJobId, setCompletedJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const [guideStep, setGuideStep] = useState(0);
  const [paramSuggestions, setParamSuggestions] = useState<ParamSuggestion[]>([]);
  const [probing, setProbing] = useState(false);
  const [probed, setProbed] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const probeTimerRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  // Auto-probe for parameter names when target/path changes
  const probeParams = useCallback(async (t: string, po: string, pa: string) => {
    if (!t || !pa) return;
    setProbing(true);
    setProbed(false);
    try {
      const res = await fetch("/api/offensive/inject/probe-params", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: t, port: parseInt(po) || 80, path: pa }),
      });
      if (res.ok) {
        const data = await res.json();
        setParamSuggestions(data.suggestions ?? []);
        setProbed(data.probed);
        if (data.suggestions?.length > 0 && !data.probed) {
          setParamName(data.suggestions[0].param);
        } else if (data.probed && data.suggestions?.length > 0) {
          setParamName(data.suggestions[0].param);
        }
      }
    } catch {}
    setProbing(false);
  }, []);

  useEffect(() => {
    if (probeTimerRef.current) clearTimeout(probeTimerRef.current);
    probeTimerRef.current = setTimeout(() => probeParams(target, port, path), 800);
    return () => { if (probeTimerRef.current) clearTimeout(probeTimerRef.current); };
  }, [target, port, path, probeParams]);

  const pollStatus = useCallback(async (id: string) => {
    const res = await fetch(`/api/offensive/inject/status/${id}`);
    if (res.status === 404) {
      stopPolling(); setJobId(null); setCompletedJobId(id);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null); setCompletedJobId(id);
      const issues = data.summary.executed + data.summary.reflected;
      toast({
        title: "Injection Scan Complete",
        description: issues > 0
          ? `${data.summary.executed} executed + ${data.summary.reflected} reflected vulnerabilities found (${data.summary.bypassed} WAF bypasses)`
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
    const id = jobId;
    await fetch(`/api/offensive/inject/stop/${id}`, { method: "DELETE" });
    stopPolling(); setJobId(null); setCompletedJobId(id);
    toast({ title: "Scan Stopped" });
  };

  const downloadResults = () => {
    const id = completedJobId || jobId;
    if (!id) return;
    const link = document.createElement("a");
    link.href = `/api/offensive/inject/download/${id}`;
    link.download = `xss-inject-results-${target}-${id.slice(0, 8)}.json`;
    link.click();
  };

  const isRunning = !!(jobId && status?.active);
  const criticalResults = status?.results.filter((r) =>
    r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" ||
    r.status === "waf_bypassed" || r.status === "oob_hit" || r.status === "redirect_hit" ||
    r.status === "reflected_unescaped"
  ) ?? [];

  const GuideIcon = GUIDE_STEPS[guideStep].icon;

  const confidenceColor = (c: string) =>
    c === "high" ? "border-emerald-500/60 text-emerald-400 bg-emerald-500/10" :
    c === "medium" ? "border-amber-500/60 text-amber-400 bg-amber-500/10" :
    "border-border/50 text-muted-foreground";

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
            <Code className="w-5 h-5 text-primary" />
            Script Injection Tester
          </h1>
          <p className="text-xs text-muted-foreground">
            18-vector adaptive injection engine — auto-detects parameters, rebuilds attacks on timeout, decodes all captured output
          </p>
        </div>
        <Button
          variant="outline" size="sm" className="text-xs gap-1.5 shrink-0"
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
                  <button key={i} onClick={() => setGuideStep(i)} data-testid={`button-guide-step-${i}`}
                    className={`w-6 h-6 rounded text-[10px] font-mono font-bold transition-all ${guideStep === i ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground hover:bg-primary/20"}`}>
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
              <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => setGuideStep((s) => Math.max(0, s - 1))} disabled={guideStep === 0} data-testid="button-guide-prev">Previous</Button>
              <span className="text-[10px] text-muted-foreground self-center">{guideStep + 1} / {GUIDE_STEPS.length}</span>
              <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => setGuideStep((s) => Math.min(GUIDE_STEPS.length - 1, s + 1))} disabled={guideStep === GUIDE_STEPS.length - 1} data-testid="button-guide-next">Next</Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool injects real malicious payloads including cookie stealers, reverse shells, and OS command injection. Use only on systems you own or have written authorization to test.
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

              {/* Auto-Param Detection */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs">Injection Parameter</Label>
                  <div className="flex items-center gap-1.5 text-[10px]">
                    {probing
                      ? <><Activity className="w-3 h-3 animate-spin text-primary" /><span className="text-muted-foreground">Probing target...</span></>
                      : probed
                        ? <><Wifi className="w-3 h-3 text-emerald-400" /><span className="text-emerald-400">Live params detected</span></>
                        : paramSuggestions.length > 0
                          ? <><Search className="w-3 h-3 text-amber-400" /><span className="text-amber-400">Heuristic suggestions</span></>
                          : null
                    }
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <div className="col-span-2 space-y-1.5">
                    <Input
                      value={paramName} onChange={(e) => setParamName(e.target.value)}
                      className="h-8 text-xs font-mono" disabled={isRunning}
                      data-testid="input-inject-param"
                      placeholder="q, search, input, cmd, user.name..."
                    />
                    {paramSuggestions.length > 0 && !isRunning && (
                      <div className="flex flex-wrap gap-1">
                        {paramSuggestions.slice(0, 10).map((s) => (
                          <button
                            key={s.param}
                            onClick={() => setParamName(s.param)}
                            title={s.source}
                            data-testid={`button-param-suggest-${s.param}`}
                            className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-semibold transition-all hover:opacity-80 ${s.param === paramName ? "ring-1 ring-primary" : ""} ${confidenceColor(s.confidence)}`}
                          >
                            {s.param}
                          </button>
                        ))}
                      </div>
                    )}
                    <p className="text-[10px] text-muted-foreground">
                      Payload injected as: ?<span className="text-primary font-mono">{paramName}</span>=&lt;PAYLOAD&gt;
                    </p>
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
              </div>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-2">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                    <span className="text-xs font-mono font-semibold">
                      {isRunning ? "INJECTING — ADAPTIVE ENGINE ACTIVE" : "SCAN COMPLETE"}
                    </span>
                    {status?.learning?.adaptiveTimeoutMs && status.learning.adaptiveTimeoutMs > 12000 && (
                      <Badge variant="outline" className="text-[8px] border-amber-500/50 text-amber-400">
                        TIMEOUT ADAPTED: {status.learning.adaptiveTimeoutMs}ms
                      </Badge>
                    )}
                  </div>
                  <div className="grid grid-cols-7 gap-1 text-xs font-mono">
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
                      <div className="text-[9px] text-muted-foreground">BLOCKED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.bypassed ?? 0) > 0 ? "text-emerald-500" : "text-foreground"}`}>{status?.summary.bypassed ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">BYPASSED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.timeouts ?? 0) > 0 ? "text-amber-400" : "text-foreground"}`}>{status?.summary.timeouts ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">TIMEOUTS</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.errors ?? 0) > 3 ? "text-severity-high" : "text-foreground"}`}>{status?.summary.errors ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">ERRORS</div>
                    </div>
                  </div>

                  {status?.learning && (
                    <div className="space-y-1.5">
                      {status.learning.workingBypass.length > 0 && (
                        <div className="flex items-start gap-2 p-2 rounded bg-emerald-500/10 border border-emerald-500/20">
                          <Brain className="w-3 h-3 text-emerald-400 shrink-0 mt-0.5" />
                          <div>
                            <p className="text-[10px] text-emerald-400 font-semibold">Engine Learned {status.learning.workingBypass.length} Bypass Technique(s)</p>
                            <p className="text-[10px] text-muted-foreground">{status.learning.workingBypass.join(" · ")}</p>
                          </div>
                        </div>
                      )}
                      {status.learning.avgResponseMs && status.learning.avgResponseMs > 0 ? (
                        <div className="flex items-center gap-3 text-[10px] font-mono text-muted-foreground px-1">
                          <span><Cpu className="w-2.5 h-2.5 inline mr-1 text-primary" />Avg RTT: {status.learning.avgResponseMs}ms</span>
                          {(status.summary.timeouts ?? 0) > 0 && <span><Repeat className="w-2.5 h-2.5 inline mr-1 text-amber-400" />Auto-rebuilt {status.summary.timeouts} timeout(s)</span>}
                        </div>
                      ) : null}
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
                {(completedJobId || (!isRunning && status && status.totalResults > 0)) && (
                  <Button variant="outline" onClick={downloadResults} data-testid="button-download-inject" className="gap-2">
                    <Download className="w-4 h-4" />
                    Download Report
                  </Button>
                )}
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
                    <div key={i} className={`p-3 border rounded-md space-y-2 ${sev.cls}`} data-testid={`card-injection-result-${i}`}>
                      <div className="flex items-center justify-between flex-wrap gap-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className={`text-[9px] ${sev.cls}`}>{sev.label}</Badge>
                          <span className="text-[10px] font-mono font-semibold">{STATUS_LABEL[r.status] ?? r.status}</span>
                          {r.retried && (
                            <Badge variant="outline" className="text-[9px] border-emerald-500/50 text-emerald-400 bg-emerald-500/5">
                              <Repeat className="w-2.5 h-2.5 mr-1" />WAF BYPASSED
                            </Badge>
                          )}
                          {r.bypassUsed && <span className="text-[9px] font-mono text-emerald-400">via {r.bypassUsed}</span>}
                        </div>
                        <span className="text-[10px] font-mono text-muted-foreground">{r.technique} · {r.responseTime}ms</span>
                      </div>

                      {/* Payload */}
                      <div>
                        <p className="text-[9px] text-muted-foreground uppercase tracking-wider mb-0.5">Injected Payload</p>
                        <div className="text-[10px] font-mono bg-black/30 rounded p-1.5 break-all border border-border/20">{r.payload.slice(0, 300)}</div>
                      </div>

                      {/* Raw evidence */}
                      {r.evidence && (
                        <div>
                          <p className="text-[9px] text-muted-foreground uppercase tracking-wider mb-0.5">Server Response Evidence</p>
                          <div className="text-[10px] text-muted-foreground bg-muted/20 rounded p-1.5 max-h-24 overflow-y-auto leading-relaxed border border-border/20">{r.evidence}</div>
                        </div>
                      )}

                      {/* Decoded output */}
                      {r.decodedEvidence && r.decodedEvidence !== r.evidence && (
                        <div>
                          <p className="text-[9px] text-emerald-400 uppercase tracking-wider mb-0.5 flex items-center gap-1">
                            <Unlock className="w-2.5 h-2.5" /> Decoded Output
                          </p>
                          <div className="text-[10px] font-mono text-emerald-300 bg-emerald-500/5 rounded p-1.5 max-h-24 overflow-y-auto leading-relaxed border border-emerald-500/20 break-all">{r.decodedEvidence}</div>
                        </div>
                      )}
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
                    const isErr = r.status === "error";
                    return (
                      <div key={i} data-testid={`row-result-${i}`}
                        className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${isCrit ? sev.cls : isWafBlock ? "border-amber-500/30 bg-amber-500/5" : isErr ? "border-border/20 opacity-50" : "border-border/30"}`}>
                        <div className="flex items-center gap-1.5 min-w-0">
                          <Badge variant="outline" className={`text-[8px] py-0 shrink-0 ${sev.cls}`}>{sev.label}</Badge>
                          {r.wafDetected && <Shield className="w-3 h-3 text-amber-500 shrink-0" />}
                          {r.retried && <Repeat className="w-3 h-3 text-emerald-400 shrink-0" />}
                          {r.decodedEvidence && <Unlock className="w-3 h-3 text-emerald-400 shrink-0" title="Decoded output available" />}
                          <span className="font-mono text-[10px] truncate">{r.payload.slice(0, 60)}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0 text-[10px] font-mono text-muted-foreground">
                          <span className="hidden sm:inline">{r.technique}</span>
                          {r.statusCode ? <span>HTTP {r.statusCode}</span> : isErr ? <span className="text-severity-medium">CONN ERR</span> : null}
                          {r.responseTime ? <span>{r.responseTime}ms</span> : null}
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
