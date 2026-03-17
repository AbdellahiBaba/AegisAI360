import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import { Bomb, AlertTriangle, Activity, Shield, ChevronRight, Square, CheckCircle, XCircle, AlertCircle, Clock } from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all", name: "Full Suite", desc: "Run all crash techniques in sequence" },
  { id: "large-payload", name: "Large Payload (10MB POST)", desc: "Sends a 10MB POST body to exhaust memory and crash HTTP parsers" },
  { id: "null-byte", name: "Null Byte Injection", desc: "Injects %00 null bytes in URL path — crashes naive C-based parsers" },
  { id: "header-overflow", name: "Header Overflow (100 headers × 8KB)", desc: "Sends 100 oversized headers — crashes servers with small header buffers" },
  { id: "http-smuggling", name: "HTTP Request Smuggling", desc: "CL.TE attack — sends conflicting Content-Length + Transfer-Encoding to desync the server and smuggle requests to /admin" },
  { id: "redos", name: "ReDoS (Regex Denial)", desc: "Sends a pathological regex pattern designed to cause catastrophic backtracking and CPU lockup" },
  { id: "path-traversal", name: "Path Traversal (5 variants)", desc: "Tests /../../../etc/passwd in 5 encoding variants to detect directory traversal and file leakage" },
  { id: "malformed-http", name: "Malformed HTTP (5 variants)", desc: "Sends raw malformed HTTP requests — invalid methods, version 9.9, binary garbage — to crash raw HTTP parsers" },
  { id: "ssi-injection", name: "SSI Injection", desc: "Injects Server-Side Include directives to execute commands via vulnerable template engines" },
  { id: "xml-bomb", name: "XML Bomb (Billion Laughs)", desc: "Sends a recursive XML entity expansion attack — collapses parsers that load entire document into memory" },
  { id: "slow-read", name: "Slow Read Attack", desc: "Opens connection, requests large range, reads very slowly — tests server resource timeout enforcement" },
  { id: "format-string", name: "Format String Attack", desc: "Injects %s %x %n format specifiers — crashes applications passing user input to printf-like functions" },
];

interface TestResult {
  technique: string;
  status: string;
  statusCode?: number;
  responseTime?: number;
  responseSnippet?: string;
  detail: string;
  timestamp: number;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  progressPct: number;
  results: TestResult[];
  totalResults: number;
  crashIndicators: number;
  config: { technique: string; target: string; duration: number };
  trafficLog?: string[];
}

const STATUS_ICON: Record<string, JSX.Element> = {
  crash_indicator: <AlertCircle className="w-3.5 h-3.5 text-severity-critical" />,
  anomaly: <AlertTriangle className="w-3.5 h-3.5 text-severity-high" />,
  sent: <CheckCircle className="w-3.5 h-3.5 text-status-online" />,
  error: <XCircle className="w-3.5 h-3.5 text-muted-foreground" />,
  timeout: <Clock className="w-3.5 h-3.5 text-severity-medium" />,
};

export default function WebCrashTesterPage() {
  useDocumentTitle("Web App Crash Tester");
  const { toast } = useToast();
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [path, setPath] = useState("/");
  const [technique, setTechnique] = useState("all");
  const [threads, setThreads] = useState(4);
  const [duration, setDuration] = useState(30);
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    const res = await fetch(`/api/offensive/crash/status/${id}`);
    if (res.status === 404) { stopPolling(); setJobId(null); return; }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null);
      toast({ title: "Test Complete", description: `${data.crashIndicators} crash indicators found in ${data.totalResults} requests` });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/crash/start", { target, port: parseInt(port) || 80, path, technique, threads, duration });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Crash Test Launched", description: `${technique} → ${target}:${port}${path}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 800);
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    } finally {
      setLaunching(false);
    }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/crash/stop/${jobId}`, { method: "DELETE" });
    stopPolling(); setJobId(null);
    toast({ title: "Test Stopped" });
  };

  const isRunning = !!jobId && status?.active;
  const selectedTech = TECHNIQUES.find((t) => t.id === technique);

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Bomb className="w-5 h-5 text-primary" />
          Web App Crash Tester
        </h1>
        <p className="text-xs text-muted-foreground">Real HTTP-level crash techniques — null bytes, payload flooding, request smuggling, XML bombs, ReDoS, malformed HTTP, path traversal</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-crash-disclaimer">
          <span className="font-semibold">Authorized Testing Only</span> — This tool sends real malicious HTTP requests to the target. Use only on systems you own or have written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1 space-y-3">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Technique</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-crash-tech-${t.id}`}
                  className={`w-full text-left p-2.5 rounded-md border text-xs transition-all ${technique === t.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                  <div className="font-semibold">{t.name}</div>
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">{selectedTech?.name} — Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              {selectedTech && <p className="text-xs text-muted-foreground">{selectedTech.desc}</p>}
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Target</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-crash-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-crash-port" placeholder="80" />
                </div>
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Path</Label>
                <Input value={path} onChange={(e) => setPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-crash-path" placeholder="/" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label className="text-xs">Duration: <span className="text-primary font-mono">{duration}s</span></Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={300} step={5} disabled={isRunning} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Threads: <span className="text-primary font-mono">{threads}</span></Label>
                  <Slider value={[threads]} onValueChange={([v]) => setThreads(v)} min={1} max={32} step={1} disabled={isRunning} />
                </div>
              </div>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">{isRunning ? `TESTING ${status?.config.target}` : "COMPLETE"}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs font-mono">
                      <span className="text-severity-critical font-bold">{status?.crashIndicators ?? 0} crashes</span>
                      <span className="text-muted-foreground">{status?.totalResults ?? 0} total</span>
                    </div>
                  </div>
                  <Progress value={status?.progressPct ?? 0} className="h-1.5" />
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1" data-testid="button-launch-crash">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Bomb className="w-4 h-4 me-2" />Launch Attack</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-crash">
                      <Square className="w-4 h-4 me-2" />Stop
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          {status && status.results.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider">Live Results</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-1.5 max-h-80 overflow-y-auto">
                  {[...status.results].reverse().map((r, i) => (
                    <div key={i} data-testid={`result-crash-${i}`}
                      className={`p-2 rounded-md border text-xs ${r.status === "crash_indicator" ? "border-severity-critical/40 bg-severity-critical/5" : r.status === "anomaly" ? "border-severity-high/40 bg-severity-high/5" : "border-border/30"}`}>
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {STATUS_ICON[r.status] || <CheckCircle className="w-3.5 h-3.5" />}
                          <span className="font-mono font-semibold">{r.technique}</span>
                        </div>
                        <div className="flex items-center gap-2 text-muted-foreground text-[10px]">
                          {r.statusCode && <span>HTTP {r.statusCode}</span>}
                          {r.responseTime && <span>{r.responseTime}ms</span>}
                        </div>
                      </div>
                      {(r.detail || r.responseSnippet) && (
                        <div className="mt-1 text-[10px] font-mono text-muted-foreground truncate">
                          {r.detail || r.responseSnippet?.slice(0, 120)}
                        </div>
                      )}
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
              title="Web Crash Tester — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
