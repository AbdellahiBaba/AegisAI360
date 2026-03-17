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
import { Code, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, Terminal, Flame } from "lucide-react";

const TECHNIQUES = [
  { id: "all", name: "Full Injection Suite (12 techniques)", desc: "Runs all techniques: reflected XSS, header XSS, SSTI, command injection, HTML injection, prototype pollution, CSTI, CSS injection, log injection, LDAP injection, XPath injection, NoSQL injection" },
  { id: "xss-reflected", name: "Reflected XSS (27 payloads)", desc: "Sends 27 real XSS payloads via URL/POST params — detects if scripts are reflected unescaped and would execute in browser" },
  { id: "xss-headers", name: "XSS via HTTP Headers", desc: "Injects script payloads into X-Forwarded-For, Referer, User-Agent, Accept-Language headers — detects if server reflects them into responses" },
  { id: "ssti", name: "Template Injection (SSTI)", desc: "Tests Jinja2, Twig, FreeMarker, ERB, Thymeleaf, Groovy — detects if {{7*7}} evaluates to 49 (template engine is executing user input)" },
  { id: "cmdi", name: "Command Injection (13 variants)", desc: "Injects ;id, |id, $(id), `id`, ;cat /etc/passwd, && id — confirms OS command execution if uid= or root: appears in response" },
  { id: "html-injection", name: "HTML Injection", desc: "Injects raw HTML tags into parameters — detects if the app renders them for phishing/UI redressing" },
  { id: "prototype-pollution", name: "Prototype Pollution (9 payloads)", desc: "Sends __proto__[isAdmin]=true, constructor[prototype][isAdmin]=true and 7 variants — detects if server merges attacker-controlled object properties into the prototype chain" },
  { id: "csti", name: "Client-Side Template Injection (CSTI)", desc: "Tests AngularJS {{constructor.constructor('alert(1)')()}}, Vue.js, Handlebars server-side SSTI — detects if template engine evaluates injected expressions" },
  { id: "css-injection", name: "CSS Injection (7 payloads)", desc: "Tests @import url(), expression(), behavior:url() — detects if attacker-controlled CSS can exfiltrate data or execute code in Internet Explorer" },
  { id: "log-injection", name: "CRLF / Log Injection (6 payloads)", desc: "Injects \\r\\n sequences into parameters — detects CRLF injection allowing log forging, HTTP response splitting, and header injection" },
  { id: "ldap-injection", name: "LDAP Injection (8 payloads)", desc: "Injects *)(|(password=*), admin)(&, *)(uid=*))(|(uid=* — detects if input is passed to LDAP filter queries allowing authentication bypass and directory extraction" },
  { id: "xpath-injection", name: "XPath Injection (7 payloads)", desc: "Injects ' or '1'='1, //user[...] traversal — detects if input is embedded in XPath expressions allowing full XML tree extraction" },
  { id: "nosql-injection", name: "NoSQL Injection (9 payloads)", desc: "Sends MongoDB operators {$gt:''}, {$ne:null}, {$where:...}, {$regex:.*} — detects if JSON operators bypass authentication or extract database records" },
];

const SEVERITY_CONFIG: Record<string, { label: string; cls: string }> = {
  critical: { label: "CRITICAL", cls: "border-severity-critical/50 text-severity-critical bg-severity-critical/5" },
  high: { label: "HIGH", cls: "border-severity-high/50 text-severity-high bg-severity-high/5" },
  medium: { label: "MEDIUM", cls: "border-severity-medium/50 text-severity-medium bg-severity-medium/5" },
  info: { label: "INFO", cls: "border-border/30 text-muted-foreground" },
};

const STATUS_LABEL: Record<string, string> = {
  executed: "SCRIPT EXECUTED",
  ssti_hit: "SSTI CONFIRMED",
  cmdi_hit: "CMDI CONFIRMED",
  reflected_unescaped: "REFLECTED (UNESCAPED)",
  reflected_escaped: "REFLECTED (ESCAPED)",
  not_reflected: "Not Reflected",
  error: "Error",
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
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  results: InjectionResult[];
  totalResults: number;
  summary: { executed: number; reflected: number; tested: number };
  config: { target: string; paramName: string; technique: string };
}

export default function ScriptInjectorPage() {
  useDocumentTitle("Script Injection Tester");
  const { toast } = useToast();
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [path, setPath] = useState("/search");
  const [method, setMethod] = useState("GET");
  const [paramName, setParamName] = useState("q");
  const [technique, setTechnique] = useState("all");
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
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
          ? `${data.summary.executed} executed + ${data.summary.reflected} reflected vulnerabilities found!`
          : `No injection points found in ${data.summary.tested} tests`,
        variant: issues > 0 ? "destructive" : "default",
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/inject/start", {
        target, port: parseInt(port) || 80, path, method, paramName, technique,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Injection Scan Started", description: `Testing ${paramName} on ${target}:${port}${path}` });
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
  const criticalResults = status?.results.filter((r) => r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" || r.status === "reflected_unescaped") ?? [];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Code className="w-5 h-5 text-primary" />
          Script Injection Tester
        </h1>
        <p className="text-xs text-muted-foreground">Real XSS, SSTI, command injection, and HTML injection — sends actual payloads and detects execution or unescaped reflection in your app</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool injects real malicious scripts and OS command payloads into the target endpoint. Use only on systems you own or have written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Injection Type</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-inject-tech-${t.id}`}
                  className={`w-full text-left p-2.5 rounded-md border text-xs transition-all ${technique === t.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                  <div className="font-semibold">{t.name}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{t.desc}</div>
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

              <div className="space-y-1">
                <Label className="text-xs">Injection Parameter</Label>
                <Input value={paramName} onChange={(e) => setParamName(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-inject-param" placeholder="q, search, input, cmd..." />
                <p className="text-[10px] text-muted-foreground">Payloads will be injected as: ?<span className="text-primary font-mono">{paramName}</span>=&lt;PAYLOAD&gt;</p>
              </div>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">{isRunning ? "INJECTING" : "COMPLETE"}</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs font-mono">
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
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1" data-testid="button-launch-inject">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Flame className="w-4 h-4 me-2" />Launch Injection Scan</>}
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
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline" className={`text-[9px] ${sev.cls}`}>{sev.label}</Badge>
                          <span className="text-[10px] font-mono font-semibold">{STATUS_LABEL[r.status] ?? r.status}</span>
                        </div>
                        <span className="text-[10px] font-mono text-muted-foreground">{r.technique} · {r.responseTime}ms</span>
                      </div>
                      <div className="text-[10px] font-mono bg-black/20 rounded p-1.5 break-all">{r.payload.slice(0, 150)}</div>
                      {r.evidence && <div className="text-[10px] text-muted-foreground bg-muted/20 rounded p-1.5 max-h-24 overflow-y-auto">{r.evidence}</div>}
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
                    const isCrit = r.status === "executed" || r.status === "ssti_hit" || r.status === "cmdi_hit" || r.status === "reflected_unescaped";
                    return (
                      <div key={i} className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${isCrit ? sev.cls : "border-border/30"}`}>
                        <div className="flex items-center gap-2 min-w-0">
                          <Badge variant="outline" className={`text-[8px] py-0 shrink-0 ${sev.cls}`}>{sev.label}</Badge>
                          <span className="font-mono text-[10px] truncate">{r.payload.slice(0, 50)}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0 text-[10px] font-mono text-muted-foreground">
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
        </div>
      </div>
    </div>
  );
}
