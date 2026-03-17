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
import {
  Flame, AlertTriangle, Activity, Square, Shield, Server, TrendingUp, Clock,
  Target, Zap, BarChart3, ArrowUp, CheckCircle, AlertCircle, RefreshCw,
} from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "combined",       name: "Combined (Max Power)",          desc: "HTTP flood + Slowloris + TLS/pipeline simultaneously — all threads, maximum saturation" },
  { id: "http-flood",     name: "HTTP GET Flood",                desc: "Concurrent GET requests with randomized User-Agent, paths, headers — exhausts worker threads and file descriptors" },
  { id: "post-flood",     name: "POST Body Flood",               desc: "Random-body POST requests (512–4096 bytes) — exhausts request parsers and upload buffers" },
  { id: "mixed-flood",    name: "Mixed-Method Flood",            desc: "GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS with spoofed X-Forwarded-For — bypasses IP-based rate limiting" },
  { id: "slowloris",      name: "Slowloris (Connection Starve)", desc: "Hundreds of TCP connections with partial headers every 15s — holds threads open until limit exhausted" },
  { id: "tls-flood",      name: "TLS Handshake Flood",           desc: "Opens/closes TLS connections — forces continuous RSA/ECDHE key exchange, collapses TLS session pools" },
  { id: "pipeline-flood", name: "HTTP Pipelining Flood",         desc: "32 requests per TCP connection in one write — exploits pipeline depth limits, exhausts response queues" },
  { id: "conn-exhaust",   name: "Connection Pool Exhaustion",    desc: "Thousands of simultaneous keep-alive connections with active reads — fills connection pool" },
  { id: "cache-buster",   name: "Cache Buster (CDN bypass)",     desc: "Unique query strings + no-cache headers — forces origin to handle every request even behind CDN" },
  { id: "redirect-exhaust", name: "Redirect Chain Exhaustion",  desc: "Follows redirect chains up to 20 hops — multiplies server load per client connection" },
];

interface LatencyBucket { p50: number; p75: number; p95: number; p99: number; min: number; max: number; }
interface RampSnapshot { concurrency: number; rps: number; avgLatencyMs: number; errorRatePct: number; elapsedSecs: number; }
interface ResilienceReport { maxSustainableRps: number; breakingPointRps: number; breakingPointConcurrency: number; breakingPointErrorRate: number; p95AtBreaking: number; snapshots: RampSnapshot[]; }

interface Metrics {
  requestsSent: number; requestsSuccess: number; requestsFailed: number;
  bytesOut: number; bytesIn: number;
  errorsConnRefused: number; errorsTimeout: number; errorsReset: number; errorsOther: number;
  statusCodes: Record<string, number>;
  latencySum: number; latencyCount: number;
  latencyBucket: LatencyBucket;
  tlsHandshakes: number; connectionsOpen: number;
  peakRps: number; rpsWindow: number[];
  windowStart: number; windowCount: number;
  currentConcurrency: number;
}

interface JobStatus {
  jobId: string; active: boolean; elapsed: number; durationSecs: number; progressPct: number;
  metrics: Metrics;
  config: { target: string; technique: string; concurrency: number; useHttps: boolean; rampMode?: boolean };
  trafficLog?: string[];
  rampSnapshots?: RampSnapshot[];
  resilienceReport?: ResilienceReport;
}

interface SelfTestStats {
  totalReceived: number; currentRps: number; peakRps: number;
  rpsHistory: number[]; methodCounts: Record<string, number>; uptimeSecs: number;
}

function fmtBytes(b: number) {
  if (b < 1024) return `${b}B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)}KB`;
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)}MB`;
  return `${(b / 1073741824).toFixed(2)}GB`;
}
function currentRps(m: Metrics): number { return m.rpsWindow.length > 0 ? m.rpsWindow[m.rpsWindow.length - 1] ?? 0 : 0; }
function avgLatency(m: Metrics): number { return m.latencyCount ? Math.round(m.latencySum / m.latencyCount) : 0; }

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

  // Ramp mode
  const [rampMode, setRampMode] = useState(false);
  const [rampStartConc, setRampStartConc] = useState(2);
  const [rampStepPct, setRampStepPct] = useState(25);
  const [rampStepSecs, setRampStepSecs] = useState(10);

  // Self-test
  const [selfTestMode, setSelfTestMode] = useState(false);
  const [selfTestStats, setSelfTestStats] = useState<SelfTestStats | null>(null);
  const selfTestPollRef = useRef<NodeJS.Timeout | null>(null);

  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  const stopSelfTestPoll = useCallback(() => {
    if (selfTestPollRef.current) { clearInterval(selfTestPollRef.current); selfTestPollRef.current = null; }
  }, []);
  useEffect(() => () => { stopPolling(); stopSelfTestPoll(); }, [stopPolling, stopSelfTestPoll]);

  const pollSelfTestStats = useCallback(async () => {
    try {
      const res = await fetch("/api/stress-target/stats");
      if (res.ok) setSelfTestStats(await res.json());
    } catch {}
  }, []);

  const activateSelfTest = useCallback(async () => {
    // Reset the target counter first
    await fetch("/api/stress-target/reset", { method: "POST" });
    setSelfTestStats(null);
    const hostname = window.location.hostname;
    const p = window.location.port || (window.location.protocol === "https:" ? "443" : "80");
    setTarget(hostname);
    setPort(p);
    setPath("/api/stress-target/hit");
    setUseHttps(window.location.protocol === "https:");
    selfTestPollRef.current = setInterval(pollSelfTestStats, 500);
  }, [pollSelfTestStats]);

  const deactivateSelfTest = useCallback(() => {
    stopSelfTestPoll();
  }, [stopSelfTestPoll]);

  useEffect(() => {
    if (selfTestMode) activateSelfTest();
    else deactivateSelfTest();
  }, [selfTestMode, activateSelfTest, deactivateSelfTest]);

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
        title: data.resilienceReport ? "Resilience Test Complete" : "Stress Test Complete",
        description: data.resilienceReport
          ? `Max sustainable: ${data.resilienceReport.maxSustainableRps} req/s | Breaking point: ${data.resilienceReport.breakingPointRps} req/s`
          : `${m.requestsSent.toLocaleString()} requests — peak ${m.peakRps} req/s — ${m.requestsFailed} failures`,
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/offensive/stress/start", {
        target, port: parseInt(port) || (useHttps ? 443 : 80),
        path, technique, concurrency, duration, useHttps,
        rampMode, rampStartConcurrency: rampStartConc, rampStepPct, rampStepSecs,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null);
      toast({ title: rampMode ? "Ramp Mode Started" : "Stress Test Launched", description: `${technique} → ${useHttps ? "https" : "http"}://${target}:${port}${path}` });
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
    if (!selfTestMode) {
      if (v && port === "80") setPort("443");
      if (!v && port === "443") setPort("80");
    }
  };

  const lb = m?.latencyBucket;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Flame className="w-5 h-5 text-primary" />
          HTTP/HTTPS Resilience Stress Tester
        </h1>
        <p className="text-xs text-muted-foreground">10 real attack techniques — HTTP flood, Slowloris, TLS storm, connection exhaustion — live throughput + latency percentiles + ramp mode</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — This tool launches real protocol-level attacks. Use only on systems you own or have explicit written authorization to test.
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
                  <div className="text-[9px] text-muted-foreground mt-0.5 leading-snug">{t.desc}</div>
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center justify-between">
                <span>{selectedTech?.name ?? "Configuration"}</span>
                <div className="flex gap-2">
                  {/* Self-Test Toggle */}
                  <button onClick={() => !isRunning && setSelfTestMode(!selfTestMode)} disabled={isRunning}
                    data-testid="button-toggle-self-test"
                    className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[10px] font-semibold transition-all ${selfTestMode ? "border-emerald-500/60 bg-emerald-500/10 text-emerald-400" : "border-border/50 text-muted-foreground hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                    <Target className="w-3 h-3" />
                    {selfTestMode ? "Self-Test ON" : "Self-Test"}
                  </button>
                  {/* Ramp Mode Toggle */}
                  <button onClick={() => !isRunning && setRampMode(!rampMode)} disabled={isRunning}
                    data-testid="button-toggle-ramp"
                    className={`flex items-center gap-1.5 px-2 py-1 rounded border text-[10px] font-semibold transition-all ${rampMode ? "border-primary/60 bg-primary/10 text-primary" : "border-border/50 text-muted-foreground hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                    <ArrowUp className="w-3 h-3" />
                    {rampMode ? "Ramp ON" : "Ramp Mode"}
                  </button>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {selectedTech && <p className="text-xs text-muted-foreground border-l-2 border-primary/40 pl-2">{selectedTech.desc}</p>}

              {/* Self-Test Banner */}
              {selfTestMode && (
                <div className="p-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 space-y-1">
                  <div className="flex items-center gap-2">
                    <Target className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-xs font-semibold text-emerald-400">Self-Test Mode — Targeting This Server</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">Traffic is being fired at this platform's own stress endpoint. Measures how many req/s this server can sustain before it starts failing.</p>
                  {selfTestStats && (
                    <div className="grid grid-cols-3 gap-2 pt-1">
                      <div className="text-center">
                        <div className="text-sm font-bold font-mono text-emerald-400">{selfTestStats.currentRps}</div>
                        <div className="text-[9px] text-muted-foreground">Received/s</div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm font-bold font-mono">{selfTestStats.totalReceived.toLocaleString()}</div>
                        <div className="text-[9px] text-muted-foreground">Total Received</div>
                      </div>
                      <div className="text-center">
                        <div className="text-sm font-bold font-mono text-primary">{selfTestStats.peakRps}</div>
                        <div className="text-[9px] text-muted-foreground">Peak Received/s</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Ramp Mode Settings */}
              {rampMode && (
                <div className="p-3 rounded-md border border-primary/30 bg-primary/5 space-y-3">
                  <div className="flex items-center gap-2">
                    <ArrowUp className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-semibold">Ramp Mode — Auto-scales concurrency to find breaking point</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">Starts at low concurrency and ramps up every N seconds. Captures RPS + error rate at each step. Reports max sustainable RPS and the breaking point where errors exceed 20%.</p>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="space-y-1">
                      <Label className="text-[10px]">Start Concurrency: <span className="text-primary font-mono font-bold">{rampStartConc}</span></Label>
                      <Slider value={[rampStartConc]} onValueChange={([v]) => setRampStartConc(v)} min={1} max={16} step={1} disabled={isRunning} />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-[10px]">Step Size: <span className="text-primary font-mono font-bold">+{rampStepPct}%</span></Label>
                      <Slider value={[rampStepPct]} onValueChange={([v]) => setRampStepPct(v)} min={10} max={100} step={5} disabled={isRunning} />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-[10px]">Step Every: <span className="text-primary font-mono font-bold">{rampStepSecs}s</span></Label>
                      <Slider value={[rampStepSecs]} onValueChange={([v]) => setRampStepSecs(v)} min={5} max={30} step={5} disabled={isRunning} />
                    </div>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Target Host</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning || selfTestMode} data-testid="input-stress-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning || selfTestMode} data-testid="input-stress-port" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Path</Label>
                  <Input value={path} onChange={(e) => setPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning || selfTestMode} data-testid="input-stress-path" placeholder="/" />
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
                  <Label className="text-xs">
                    {rampMode ? "Max Concurrency" : "Concurrency"}: <span className="text-primary font-mono font-bold">{concurrency}</span> threads
                  </Label>
                  <Slider value={[concurrency]} onValueChange={([v]) => setConcurrency(v)} min={1} max={256} step={1} disabled={isRunning} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Duration: <span className="text-primary font-mono font-bold">{duration}s</span></Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={600} step={5} disabled={isRunning} />
                </div>
              </div>

              {/* Live Metrics */}
              {(isRunning || status) && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-severity-critical animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-bold">{isRunning ? `ATTACKING ${status?.config.target}` : "COMPLETE"}</span>
                      {status?.config.rampMode && (
                        <Badge variant="outline" className="text-[8px] border-primary/50 text-primary">
                          RAMP — {m?.currentConcurrency ?? 0} threads now
                        </Badge>
                      )}
                    </div>
                    <span className="text-xs font-mono text-muted-foreground">{status?.elapsed ?? 0}s / {status?.durationSecs ?? duration}s</span>
                  </div>
                  <Progress value={status?.progressPct ?? 0} className="h-1.5" />

                  {/* Primary metrics */}
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

                  {/* Latency Percentiles */}
                  {lb && (lb.p50 > 0 || lb.p95 > 0) && (
                    <div className="p-2 rounded-md border border-primary/20 bg-primary/5">
                      <div className="text-[9px] uppercase text-primary mb-1.5 font-semibold flex items-center gap-1">
                        <Clock className="w-2.5 h-2.5" /> Latency Percentiles
                      </div>
                      <div className="grid grid-cols-6 gap-1 text-[10px] font-mono text-center">
                        {[["Min", lb.min], ["P50", lb.p50], ["P75", lb.p75], ["P95", lb.p95], ["P99", lb.p99], ["Max", lb.max]].map(([label, val]) => (
                          <div key={label as string}>
                            <div className={`font-bold ${label === "P95" || label === "P99" || label === "Max" ? "text-severity-medium" : ""}`}>{val as number}ms</div>
                            <div className="text-[8px] text-muted-foreground">{label}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Ramp progress table */}
                  {status?.rampSnapshots && status.rampSnapshots.length > 0 && (
                    <div className="p-2 rounded-md border border-border/30 bg-muted/10">
                      <div className="text-[9px] uppercase text-muted-foreground mb-1.5 font-semibold flex items-center gap-1">
                        <ArrowUp className="w-2.5 h-2.5" /> Ramp Progress
                      </div>
                      <div className="space-y-0.5 max-h-28 overflow-y-auto">
                        {status.rampSnapshots.map((snap, i) => (
                          <div key={i} className="grid grid-cols-5 gap-1 text-[9px] font-mono py-0.5 border-b border-border/20">
                            <span className="text-muted-foreground">{snap.elapsedSecs}s</span>
                            <span>{snap.concurrency}t</span>
                            <span className="text-primary">{snap.rps} r/s</span>
                            <span>{snap.avgLatencyMs}ms</span>
                            <span className={snap.errorRatePct >= 20 ? "text-severity-critical font-bold" : snap.errorRatePct > 5 ? "text-severity-high" : "text-status-online"}>{snap.errorRatePct}% err</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Status codes */}
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

                  {/* Error breakdown */}
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
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Flame className="w-4 h-4 me-2" />{rampMode ? "Launch Ramp Test" : selfTestMode ? "Launch Self-Test" : "Launch Stress Test"}</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-stress">
                      <Square className="w-4 h-4 me-2" />Stop Test
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          {/* Resilience Report Card */}
          {status?.resilienceReport && (() => {
            const rr = status.resilienceReport;
            const hasBreaking = rr.breakingPointRps > 0;
            return (
              <Card className={`border-2 ${hasBreaking ? "border-severity-critical/40" : "border-emerald-500/40"}`}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-primary" />
                    Resilience Report
                    {hasBreaking
                      ? <Badge variant="outline" className="text-[9px] border-severity-critical/50 text-severity-critical">Breaking Point Found</Badge>
                      : <Badge variant="outline" className="text-[9px] border-emerald-500/50 text-emerald-400">No Breaking Point</Badge>
                    }
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    <div className="p-3 rounded-md border border-emerald-500/30 bg-emerald-500/5 text-center">
                      <CheckCircle className="w-4 h-4 text-emerald-400 mx-auto mb-1" />
                      <div className="text-lg font-bold font-mono text-emerald-400">{rr.maxSustainableRps}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Max Sustainable Req/s</div>
                    </div>
                    <div className={`p-3 rounded-md border text-center ${hasBreaking ? "border-severity-critical/30 bg-severity-critical/5" : "border-border/30 bg-muted/10"}`}>
                      <AlertCircle className={`w-4 h-4 mx-auto mb-1 ${hasBreaking ? "text-severity-critical" : "text-muted-foreground"}`} />
                      <div className={`text-lg font-bold font-mono ${hasBreaking ? "text-severity-critical" : "text-muted-foreground"}`}>{hasBreaking ? rr.breakingPointRps : "—"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Breaking Point Req/s</div>
                    </div>
                    <div className="p-3 rounded-md border border-border/30 bg-muted/10 text-center">
                      <div className="text-lg font-bold font-mono">{hasBreaking ? rr.breakingPointConcurrency : "—"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Threads at Break</div>
                    </div>
                    <div className="p-3 rounded-md border border-border/30 bg-muted/10 text-center">
                      <div className="text-lg font-bold font-mono">{hasBreaking ? `${rr.p95AtBreaking}ms` : "—"}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Avg Lat at Break</div>
                    </div>
                  </div>

                  <div className="p-2 rounded bg-muted/20 border border-border/30">
                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {hasBreaking
                        ? `This server sustained up to ${rr.maxSustainableRps} req/s cleanly. At ${rr.breakingPointRps} req/s (${rr.breakingPointConcurrency} concurrent connections), the error rate exceeded 20% (${rr.breakingPointErrorRate}%). To withstand higher load, add horizontal scaling, a CDN/load balancer, connection pooling, or increase worker thread count.`
                        : `No breaking point was reached within the test parameters. The server handled all ${rr.maxSustainableRps} req/s without exceeding 20% error rate. Try increasing max concurrency or duration to find the true ceiling.`
                      }
                    </p>
                  </div>
                </CardContent>
              </Card>
            );
          })()}

          {status && (
            <TrafficConsole trafficLog={status.trafficLog ?? []} active={isRunning} title="HTTP Stress Tester — Live Traffic" />
          )}
        </div>
      </div>
    </div>
  );
}
