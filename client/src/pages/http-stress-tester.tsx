import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import { Flame, AlertTriangle, Activity, Square, Wifi, Zap, Shield, Server, TrendingUp, Clock } from "lucide-react";

const TECHNIQUES = [
  { id: "combined", name: "Combined Attack (Max Power)", desc: "Simultaneously runs HTTP flood + Slowloris + TLS/pipeline flood using all concurrency threads — maximum server stress" },
  { id: "http-flood", name: "HTTP GET Flood", desc: "Fires concurrent HTTP GET requests with randomized User-Agents, paths, and headers — exhausts worker threads and file descriptors" },
  { id: "post-flood", name: "POST Body Flood", desc: "Sends continuous random-body POST requests (512–4096 bytes each) — exhausts request parsers and upload buffers" },
  { id: "mixed-flood", name: "Mixed-Method Flood", desc: "Randomizes GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS with spoofed X-Forwarded-For IPs — bypasses simple IP-based rate limiting" },
  { id: "slowloris", name: "Slowloris (Connection Starvation)", desc: "Opens hundreds of TCP/TLS connections and trickles partial HTTP headers every 15s — holds connections open without completing requests, exhausts max-connection limits" },
  { id: "tls-flood", name: "TLS Handshake Flood (HTTPS only)", desc: "Opens and immediately closes TLS connections — forces continuous CPU-intensive RSA/ECDHE key exchange, collapses TLS session pools" },
  { id: "pipeline-flood", name: "HTTP Pipelining Flood", desc: "Sends 32 HTTP requests over a single TCP connection in one write — exploits HTTP/1.1 pipeline depth limits, exhausts response queues" },
  { id: "conn-exhaust", name: "Connection Pool Exhaustion", desc: "Maintains thousands of simultaneous open keep-alive connections with active reads — fills the server's connection pool, refusing new connections" },
  { id: "cache-buster", name: "Cache Buster (CDN/Proxy bypass)", desc: "Sends requests with unique query strings + no-cache headers — forces origin server to handle every request even behind a CDN or reverse proxy" },
  { id: "redirect-exhaust", name: "Redirect Chain Exhaustion", desc: "Follows redirect chains up to 20 hops deep — each hop is a new server request, multiplying load per client connection" },
];

interface Metrics {
  requestsSent: number;
  requestsSuccess: number;
  requestsFailed: number;
  bytesOut: number;
  bytesIn: number;
  errorsConnRefused: number;
  errorsTimeout: number;
  errorsReset: number;
  errorsOther: number;
  statusCodes: Record<string, number>;
  latencySum: number;
  latencyCount: number;
  tlsHandshakes: number;
  connectionsOpen: number;
  peakRps: number;
  rpsWindow: number[];
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  durationSecs: number;
  progressPct: number;
  metrics: Metrics;
  config: { target: string; technique: string; concurrency: number; useHttps: boolean };
}

function fmtBytes(b: number) {
  if (b < 1024) return `${b}B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)}KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)}MB`;
  return `${(b / 1073741824).toFixed(2)}GB`;
}

function currentRps(m: Metrics): number {
  if (!m.rpsWindow.length) return 0;
  return m.rpsWindow[m.rpsWindow.length - 1] ?? 0;
}

function avgLatency(m: Metrics): number {
  if (!m.latencyCount) return 0;
  return Math.round(m.latencySum / m.latencyCount);
}

export default function HttpStressTesterPage() {
  useDocumentTitle("HTTP/HTTPS Stress Tester");
  const { toast } = useToast();
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [path, setPath] = useState("/");
  const [useHttps, setUseHttps] = useState(false);
  const [technique, setTechnique] = useState("combined");
  const [concurrency, setConcurrency] = useState(16);
  const [duration, setDuration] = useState(60);
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    const res = await fetch(`/api/offensive/stress/status/${id}`);
    if (res.status === 404) {
      stopPolling(); setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null);
      const m = data.metrics;
      toast({
        title: "Stress Test Complete",
        description: `${m.requestsSent.toLocaleString()} requests in ${data.elapsed}s — peak ${m.peakRps} req/s — ${m.requestsFailed} failures`,
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/stress/start", {
        target, port: parseInt(port) || (useHttps ? 443 : 80),
        path, technique, concurrency, duration, useHttps,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Stress Test Launched", description: `${technique} → ${useHttps ? "https" : "http"}://${target}:${port}${path}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 600);
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    } finally { setLaunching(false); }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/stress/stop/${jobId}`, { method: "DELETE" });
    stopPolling(); setJobId(null);
    toast({ title: "Test Stopped" });
  };

  const isRunning = !!jobId && status?.active;
  const m = status?.metrics;
  const rps = m ? currentRps(m) : 0;
  const avgLat = m ? avgLatency(m) : 0;
  const errorRate = m && m.requestsSent > 0 ? ((m.requestsFailed / m.requestsSent) * 100).toFixed(1) : "0";
  const selectedTech = TECHNIQUES.find((t) => t.id === technique);

  const toggleHttps = (v: boolean) => {
    setUseHttps(v);
    if (v && port === "80") setPort("443");
    if (!v && port === "443") setPort("80");
  };

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Flame className="w-5 h-5 text-primary" />
          HTTP/HTTPS Resilience Stress Tester
        </h1>
        <p className="text-xs text-muted-foreground">10 real attack techniques — HTTP flood, Slowloris, TLS storm, connection exhaustion, pipeline flood, cache busting — live throughput metrics</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool launches real protocol-level attacks against the target. Use only on systems you own or have explicit written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Attack Mode</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-stress-tech-${t.id}`}
                  className={`w-full text-left p-2.5 rounded-md border text-xs transition-all ${technique === t.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                  <div className="font-semibold">{t.name}</div>
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">{selectedTech?.name ?? "Configuration"}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {selectedTech && <p className="text-xs text-muted-foreground border-l-2 border-primary/40 pl-2">{selectedTech.desc}</p>}

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Target Host</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-stress-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-stress-port" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Path</Label>
                  <Input value={path} onChange={(e) => setPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-stress-path" placeholder="/" />
                </div>
                <div className="flex items-end gap-2 pb-0.5">
                  <div className="space-y-1 w-full">
                    <Label className="text-xs">HTTPS</Label>
                    <div className="flex items-center gap-2 h-8">
                      <Switch checked={useHttps} onCheckedChange={toggleHttps} disabled={isRunning} data-testid="switch-stress-https" />
                      <span className="text-xs font-mono text-muted-foreground">{useHttps ? "TLS" : "Plain"}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label className="text-xs">Concurrency: <span className="text-primary font-mono font-bold">{concurrency}</span> threads</Label>
                  <Slider value={[concurrency]} onValueChange={([v]) => setConcurrency(v)} min={1} max={128} step={1} disabled={isRunning} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Duration: <span className="text-primary font-mono font-bold">{duration}s</span></Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={600} step={5} disabled={isRunning} />
                </div>
              </div>

              {(isRunning || status) && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-severity-critical animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-bold">{isRunning ? `ATTACKING ${status?.config.target}` : "COMPLETE"}</span>
                    </div>
                    <span className="text-xs font-mono text-muted-foreground">{status?.elapsed ?? 0}s / {status?.durationSecs ?? duration}s</span>
                  </div>
                  <Progress value={status?.progressPct ?? 0} className="h-1.5" />

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono text-primary">{rps.toLocaleString()}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Req/s Now</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{m?.peakRps.toLocaleString() ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Peak Req/s</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{m?.requestsSent.toLocaleString() ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Total Sent</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className={`text-sm font-bold font-mono ${parseFloat(errorRate) > 20 ? "text-severity-critical" : parseFloat(errorRate) > 5 ? "text-severity-high" : "text-status-online"}`}>{errorRate}%</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Error Rate</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{avgLat ? `${avgLat}ms` : "—"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Avg Latency</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{m ? fmtBytes(m.bytesOut) : "0B"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Bytes Out</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{m ? fmtBytes(m.bytesIn) : "0B"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Bytes In</div>
                    </div>
                    <div className="p-2 rounded-md border border-border/40 bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{m?.connectionsOpen.toLocaleString() ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Open Conns</div>
                    </div>
                  </div>

                  {m && Object.keys(m.statusCodes).length > 0 && (
                    <div className="p-2 rounded-md border border-border/30 bg-muted/10">
                      <div className="text-[9px] uppercase text-muted-foreground mb-1.5 font-semibold">HTTP Status Codes</div>
                      <div className="flex flex-wrap gap-1.5">
                        {Object.entries(m.statusCodes).sort(([a], [b]) => parseInt(a) - parseInt(b)).map(([code, count]) => (
                          <Badge key={code} variant="outline" className={`text-[9px] font-mono ${parseInt(code) >= 500 ? "border-severity-critical/50 text-severity-critical" : parseInt(code) >= 400 ? "border-severity-high/50 text-severity-high" : parseInt(code) >= 300 ? "border-severity-medium/50 text-severity-medium" : "border-status-online/50 text-status-online"}`}>
                            {code}: {count.toLocaleString()}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {m && (m.errorsConnRefused + m.errorsTimeout + m.errorsReset + m.errorsOther) > 0 && (
                    <div className="p-2 rounded-md border border-severity-critical/20 bg-severity-critical/5">
                      <div className="text-[9px] uppercase text-severity-critical mb-1.5 font-semibold">Error Breakdown</div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 text-[10px] font-mono">
                        {m.errorsConnRefused > 0 && <div>ECONNREFUSED: <span className="text-severity-critical font-bold">{m.errorsConnRefused}</span></div>}
                        {m.errorsTimeout > 0 && <div>Timeout: <span className="text-severity-high font-bold">{m.errorsTimeout}</span></div>}
                        {m.errorsReset > 0 && <div>ECONNRESET: <span className="text-severity-medium font-bold">{m.errorsReset}</span></div>}
                        {m.errorsOther > 0 && <div>Other: <span className="text-muted-foreground font-bold">{m.errorsOther}</span></div>}
                      </div>
                    </div>
                  )}

                  {m && m.tlsHandshakes > 0 && (
                    <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-2">
                      <Shield className="w-3 h-3" />
                      <span>{m.tlsHandshakes.toLocaleString()} TLS handshakes completed</span>
                    </div>
                  )}
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1 bg-severity-critical hover:bg-severity-critical/90 text-white" data-testid="button-launch-stress">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Flame className="w-4 h-4 me-2" />Launch Stress Test</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-stress">
                      <Square className="w-4 h-4 me-2" />Stop Test
                    </Button>
                }
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
