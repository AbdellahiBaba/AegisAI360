import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import { Database, AlertTriangle, Activity, Square, ChevronRight, ShieldAlert, CheckCircle, XCircle } from "lucide-react";

const TECHNIQUES = [
  { id: "all", name: "All Techniques", desc: "Run error-based, UNION, boolean-blind, and time-based in sequence" },
  { id: "error-based", name: "Error-Based", desc: "Injects payloads that trigger database error messages — confirms SQLi and reveals DB type/version" },
  { id: "union", name: "UNION-Based", desc: "Extends SELECT with UNION statements to retrieve data from additional tables (user(), database(), version())" },
  { id: "boolean-blind", name: "Boolean Blind", desc: "Detects SQLi when no error is shown — compares TRUE/FALSE condition responses to confirm parameter vulnerability" },
  { id: "time-based", name: "Time-Based Blind", desc: "Injects SLEEP(5)/WAITFOR DELAY — confirms SQLi when response is delayed, even with no output" },
];

interface SQLiResult {
  technique: string;
  payload: string;
  status: "vulnerable" | "potential" | "not_vulnerable" | "error";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  dbType?: string;
  timestamp: number;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  results: SQLiResult[];
  totalResults: number;
  summary: { vulnerable: number; potential: number; tested: number };
  dbTypeDetected?: string;
  config: { target: string; paramName: string; technique: string };
}

const STATUS_COLOR: Record<string, string> = {
  vulnerable: "border-severity-critical/50 bg-severity-critical/5 text-severity-critical",
  potential: "border-severity-high/50 bg-severity-high/5 text-severity-high",
  not_vulnerable: "border-border/30",
  error: "border-border/20 opacity-60",
};

export default function SQLiTesterPage() {
  useDocumentTitle("SQL Injection Tester");
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
    const res = await fetch(`/api/offensive/sqli/status/${id}`);
    if (res.status === 404) {
      stopPolling(); setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null);
      toast({
        title: "SQLi Scan Complete",
        description: data.summary.vulnerable > 0
          ? `${data.summary.vulnerable} VULNERABLE parameter(s) found!${data.dbTypeDetected ? ` DB: ${data.dbTypeDetected}` : ""}`
          : `No SQL injection found in ${data.summary.tested} tests`,
        variant: data.summary.vulnerable > 0 ? "destructive" : "default",
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/sqli/start", { target, port: parseInt(port) || 80, path, method, paramName, technique, duration: 120 });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: "SQLi Scan Started", description: `Testing ${paramName} on ${target}:${port}${path}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 1000);
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    } finally {
      setLaunching(false);
    }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/sqli/stop/${jobId}`, { method: "DELETE" });
    stopPolling(); setJobId(null);
    toast({ title: "Scan Stopped" });
  };

  const isRunning = !!jobId && status?.active;
  const selectedTech = TECHNIQUES.find((t) => t.id === technique);
  const vulnResults = status?.results.filter((r) => r.status === "vulnerable") ?? [];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Database className="w-5 h-5 text-primary" />
          SQL Injection Tester
        </h1>
        <p className="text-xs text-muted-foreground">Real SQLi detection — error-based, UNION, boolean-blind, time-based — identifies vulnerable parameters and database type</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool sends real SQL injection payloads to the target endpoint. Use only on systems you own or have written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Technique</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-sqli-tech-${t.id}`}
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
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-sqli-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-sqli-port" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Endpoint Path</Label>
                  <Input value={path} onChange={(e) => setPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-sqli-path" placeholder="/search or /api/items" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Method</Label>
                  <Select value={method} onValueChange={setMethod} disabled={isRunning}>
                    <SelectTrigger className="h-8 text-xs" data-testid="select-sqli-method"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-1">
                <Label className="text-xs">Parameter Name to Inject</Label>
                <Input value={paramName} onChange={(e) => setParamName(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-sqli-param" placeholder="id, q, user, search..." />
                <p className="text-[10px] text-muted-foreground">The parameter that will receive injection payloads (e.g., ?<span className="text-primary font-mono">{paramName}</span>=PAYLOAD)</p>
              </div>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">{isRunning ? "SCANNING" : "COMPLETE"}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      {status?.summary.vulnerable ? (
                        <span className="text-severity-critical font-bold">{status.summary.vulnerable} VULNERABLE</span>
                      ) : null}
                      {status?.dbTypeDetected && <Badge variant="outline" className="text-[9px]">{status.dbTypeDetected}</Badge>}
                      <span className="text-muted-foreground">{status?.summary.tested ?? 0} tested</span>
                    </div>
                  </div>
                  {isRunning && <Progress value={(status?.elapsed ?? 0) / 1.2} className="h-1.5" />}
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1" data-testid="button-launch-sqli">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Database className="w-4 h-4 me-2" />Start SQLi Scan</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-sqli">
                      <Square className="w-4 h-4 me-2" />Stop Scan
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          {vulnResults.length > 0 && (
            <Card className="border-severity-critical/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-severity-critical flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Confirmed Vulnerabilities ({vulnResults.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {vulnResults.map((r, i) => (
                  <div key={i} className="p-3 border border-severity-critical/30 rounded-md bg-severity-critical/5 space-y-1">
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="text-[9px] border-severity-critical/50 text-severity-critical">VULNERABLE — {r.technique}</Badge>
                      <div className="text-[10px] font-mono text-muted-foreground">{r.responseTime}ms{r.dbType ? ` · ${r.dbType}` : ""}</div>
                    </div>
                    <div className="text-[10px] font-mono text-muted-foreground bg-muted/30 rounded p-1.5 break-all">Payload: {r.payload}</div>
                    {r.evidence && <div className="text-[10px] font-mono text-severity-critical bg-severity-critical/5 rounded p-1.5 max-h-20 overflow-y-auto break-all">{r.evidence.slice(0, 300)}</div>}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {status && status.results.length > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">All Test Results</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-64 overflow-y-auto">
                  {[...status.results].reverse().map((r, i) => (
                    <div key={i} className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${STATUS_COLOR[r.status] || ""}`}>
                      <div className="flex items-center gap-2 min-w-0">
                        {r.status === "vulnerable" ? <ShieldAlert className="w-3.5 h-3.5 shrink-0" /> : r.status === "potential" ? <AlertTriangle className="w-3.5 h-3.5 shrink-0" /> : <CheckCircle className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />}
                        <span className="font-mono truncate text-[10px]">{r.payload.slice(0, 60)}</span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0 text-[10px] font-mono text-muted-foreground">
                        <span>{r.technique}</span>
                        {r.statusCode && <span>HTTP {r.statusCode}</span>}
                        {r.responseTime && <span>{r.responseTime}ms</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
