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
import {
  Database, AlertTriangle, Activity, Square, ChevronRight, ShieldAlert,
  CheckCircle, Download, Table2, Loader2, Eye,
} from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all",          name: "All Techniques",   desc: "Run error-based, UNION, boolean-blind, and time-based in sequence" },
  { id: "error-based",  name: "Error-Based",       desc: "Injects payloads that trigger database error messages — confirms SQLi and reveals DB type/version" },
  { id: "union",        name: "UNION-Based",       desc: "Extends SELECT with UNION statements to retrieve data from additional tables (user(), database(), version())" },
  { id: "boolean-blind",name: "Boolean Blind",     desc: "Detects SQLi when no error is shown — compares TRUE/FALSE condition responses to confirm parameter vulnerability" },
  { id: "time-based",   name: "Time-Based Blind",  desc: "Injects SLEEP(5)/WAITFOR DELAY — confirms SQLi when response is delayed, even with no output" },
];

interface SQLiResult {
  technique: string; payload: string;
  status: "vulnerable" | "potential" | "not_vulnerable" | "error";
  statusCode?: number; responseTime?: number; evidence?: string; dbType?: string; timestamp: number;
}

interface ExtractedRecord { label: string; value: string; payload: string; technique: string; }

interface JobStatus {
  jobId: string; active: boolean; elapsed: number;
  results: SQLiResult[]; totalResults: number;
  summary: { vulnerable: number; potential: number; tested: number };
  dbTypeDetected?: string;
  config: { target: string; paramName: string; technique: string };
  trafficLog?: string[];
  extractedData?: ExtractedRecord[];
  extractionPhase?: boolean;
  extractionLog?: string[];
}

const STATUS_COLOR: Record<string, string> = {
  vulnerable:     "border-severity-critical/50 bg-severity-critical/5 text-severity-critical",
  potential:      "border-severity-high/50 bg-severity-high/5 text-severity-high",
  not_vulnerable: "border-border/30",
  error:          "border-border/20 opacity-60",
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
      stopPolling();
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling();
      toast({
        title: "SQLi Scan Complete",
        description: data.summary.vulnerable > 0
          ? `${data.summary.vulnerable} VULNERABLE parameter(s)!${data.dbTypeDetected ? ` DB: ${data.dbTypeDetected}` : ""}${(data.extractedData?.length ?? 0) > 0 ? ` — ${data.extractedData!.length} DB values extracted` : ""}`
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
    } finally { setLaunching(false); }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/sqli/stop/${jobId}`, { method: "DELETE" });
    stopPolling();
    toast({ title: "Scan Stopped" });
  };

  const downloadResults = () => {
    if (!jobId) return;
    const link = document.createElement("a");
    link.href = `/api/offensive/sqli/download/${jobId}`;
    link.download = `sqli-results-${target}-${jobId.slice(0, 8)}.json`;
    link.click();
  };

  const isRunning = !!(jobId && status?.active);
  const extracting = status?.extractionPhase ?? false;
  const selectedTech = TECHNIQUES.find((t) => t.id === technique);
  const vulnResults = status?.results.filter((r) => r.status === "vulnerable") ?? [];
  const extractedData = status?.extractedData ?? [];
  const canDownload = !!jobId && !isRunning && status && status.totalResults > 0;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Database className="w-5 h-5 text-primary" />
          SQL Injection Tester
        </h1>
        <p className="text-xs text-muted-foreground">Real SQLi detection — error-based, UNION, boolean-blind, time-based — identifies vulnerable parameters, detects DB type, and extracts real database data</p>
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
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">
                        {extracting ? "EXTRACTING DATA" : isRunning ? "SCANNING" : "COMPLETE"}
                      </span>
                      {extracting && <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />}
                    </div>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      {status?.summary.vulnerable ? (
                        <span className="text-severity-critical font-bold">{status.summary.vulnerable} VULNERABLE</span>
                      ) : null}
                      {status?.dbTypeDetected && <Badge variant="outline" className="text-[9px]">{status.dbTypeDetected}</Badge>}
                      <span className="text-muted-foreground">{status?.summary.tested ?? 0} tested</span>
                      {(extractedData.length > 0) && (
                        <Badge variant="outline" className="text-[9px] border-green-500/50 text-green-400">{extractedData.length} DB values extracted</Badge>
                      )}
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
                {canDownload && (
                  <Button variant="outline" onClick={downloadResults} data-testid="button-download-sqli" className="gap-2">
                    <Download className="w-4 h-4" />
                    Download Report
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Extracted Data Panel */}
          {extractedData.length > 0 && (
            <Card className="border-green-500/30 bg-green-500/5">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-green-400 flex items-center gap-2">
                  <Table2 className="w-4 h-4" />
                  Extracted Database Data ({extractedData.length} values)
                  <Button variant="ghost" size="sm" onClick={downloadResults} className="ml-auto h-6 text-[10px] gap-1.5 text-green-400 hover:text-green-300">
                    <Download className="w-3 h-3" />
                    Download JSON
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {extractedData.map((rec, i) => (
                    <div key={i} className="p-2.5 rounded-md border border-green-500/20 bg-background space-y-1" data-testid={`extracted-row-${i}`}>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[9px] border-green-500/50 text-green-400">{rec.label}</Badge>
                        <Badge variant="outline" className="text-[9px] border-border/40 text-muted-foreground">{rec.technique}</Badge>
                      </div>
                      <div className="font-mono text-xs text-green-300 bg-muted/30 rounded p-2 max-h-32 overflow-y-auto break-all" data-testid={`extracted-value-${i}`}>
                        {rec.value}
                      </div>
                      <div className="text-[10px] text-muted-foreground font-mono truncate">via: {rec.payload.slice(0, 80)}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Extraction log while extracting */}
          {extracting && status?.extractionLog && status.extractionLog.length > 0 && (
            <Card className="border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-primary" />
                  Data Extraction in Progress
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-0.5 font-mono text-[10px] text-muted-foreground max-h-32 overflow-y-auto">
                  {status.extractionLog.slice(-20).map((line, i) => (
                    <div key={i} className={line.includes("FOUND") ? "text-green-400" : ""}>{line}</div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Confirmed vulnerabilities */}
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
                    {r.evidence && (
                      <div className="text-[10px] font-mono text-severity-critical bg-severity-critical/5 rounded p-1.5 max-h-32 overflow-y-auto break-all">
                        {r.evidence.slice(0, 600)}
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {/* All test results */}
          {status && status.results.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider flex items-center justify-between">
                  <span>All Test Results</span>
                  <span className="font-normal text-muted-foreground">{status.totalResults} total</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-64 overflow-y-auto">
                  {[...status.results].reverse().map((r, i) => (
                    <div key={i} className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${STATUS_COLOR[r.status] || ""}`}>
                      <div className="flex items-center gap-2 min-w-0">
                        {r.status === "vulnerable"
                          ? <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
                          : r.status === "potential"
                            ? <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                            : <CheckCircle className="w-3.5 h-3.5 shrink-0 text-muted-foreground" />}
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

          {status && (
            <TrafficConsole
              trafficLog={status.trafficLog ?? []}
              active={isRunning}
              title="SQLi Tester — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
