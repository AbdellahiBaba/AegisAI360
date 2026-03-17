import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import {
  Zap, AlertTriangle, Activity, Shield, Waves, Square,
  ChevronRight, Network, BarChart3, Clock, Info, CheckCircle, AlertCircle,
} from "lucide-react";

type RealMode = "full" | "degraded" | "udp-only";

interface AttackVector {
  id: string;
  name: string;
  protocol: string;
  layer: string;
  amplification: number;
  description: string;
  severity: string;
  realMode: RealMode;
  realNote: string;
  fallbackTo?: string;
}

const ATTACK_VECTORS: AttackVector[] = [
  {
    id: "http-flood",
    name: "HTTP Flood",
    protocol: "HTTP", layer: "L7", amplification: 1, severity: "high",
    realMode: "full",
    realNote: "Fully real — opens concurrent HTTP/HTTPS connections using Node.js http/https module with randomized User-Agent, X-Forwarded-For, and paths. Will genuinely exhaust web server threads and file descriptors.",
    description: "Concurrent HTTP GET/POST flood with randomized browser User-Agent strings, spoofed X-Forwarded-For IPs, and rotating paths — exhausts web server worker threads and socket file descriptors.",
  },
  {
    id: "udp-flood",
    name: "UDP Flood",
    protocol: "UDP", layer: "L4", amplification: 1, severity: "high",
    realMode: "full",
    realNote: "Fully real — creates real dgram UDP sockets per thread and sends 1024-byte random payloads at configurable rate. Saturates NIC bandwidth and forces ICMP unreachable responses.",
    description: "Creates real UDP sockets per thread and fires 1024-byte random payloads at the target — saturates NIC bandwidth and forces ICMP unreachable processing overhead on every port hit.",
  },
  {
    id: "syn-flood",
    name: "SYN Flood",
    protocol: "TCP", layer: "L4", amplification: 1, severity: "critical",
    realMode: "degraded",
    realNote: "DEGRADED in sandbox — attempts to spawn a Python3 raw socket SYN script with spoofed source IPs, but falls back to TCP Connect Flood because raw sockets need CAP_NET_RAW/root which Replit does not grant. SYN flood with spoofing requires a dedicated VPS with root access.",
    fallbackTo: "TCP Connect Flood",
    description: "Attempts raw socket SYN packet construction with spoofed source IPs via Python3. Falls back to TCP Connect Flood (real TCP connections opened and destroyed rapidly) when raw socket permissions unavailable.",
  },
  {
    id: "slowloris",
    name: "Slowloris",
    protocol: "HTTP", layer: "L7", amplification: 1, severity: "medium",
    realMode: "full",
    realNote: "Fully real — opens real TCP sockets, sends partial HTTP headers, and drip-feeds X-a keep-alive headers every 15s indefinitely. Will genuinely exhaust Apache/nginx thread pools and max connection limits.",
    description: "Opens real TCP connections and sends partial HTTP headers indefinitely — each connection holds a thread or process open on the target server until the connection limit is exhausted and new connections are refused.",
  },
  {
    id: "icmp-flood",
    name: "ICMP Flood",
    protocol: "ICMP", layer: "L3", amplification: 1, severity: "medium",
    realMode: "full",
    realNote: "Fully real — spawns system ping -f (flood ping) process. If -f flag is unavailable, falls back to ping -i 0.001. Sends real ICMP echo requests at maximum system rate.",
    description: "Spawns system ping flood (-f flag) to send ICMP echo requests at maximum kernel rate — overwhelms target NIC interrupt processing and consumes CPU for packet handling.",
  },
  {
    id: "ack-flood",
    name: "ACK Flood",
    protocol: "TCP", layer: "L4", amplification: 1, severity: "medium",
    realMode: "full",
    realNote: "Fully real — opens rapid concurrent TCP connections. Bypasses simple ACK-allow stateless firewall rules and exhausts socket buffer resources on the target.",
    description: "Fires rapid TCP connection attempts to the target — bypasses stateless ACK-allow firewall rules, exhausts the target socket buffer pool, and forces continuous TCP state machine processing.",
  },
  {
    id: "dns-amp",
    name: "DNS Flood",
    protocol: "UDP/DNS", layer: "L4", amplification: 1, severity: "critical",
    realMode: "udp-only",
    realNote: "UDP FLOOD ONLY — sends real hand-crafted DNS query packets to port 53 on the target. NOT true DNS amplification (which requires spoofed source IPs pointing victim as source, then amplified response hits the victim). True reflective amplification requires raw socket IP spoofing which needs root access.",
    description: "Fires real binary-crafted DNS query packets to the target's port 53 — effective as a DNS service flood. The 54x amplification label applies to real-world reflective attacks requiring IP spoofing; this mode floods the target DNS port directly.",
  },
  {
    id: "ntp-amp",
    name: "NTP Flood (port 123)",
    protocol: "UDP/NTP", layer: "L4", amplification: 1, severity: "high",
    realMode: "udp-only",
    realNote: "UDP FLOOD ONLY to port 123 — sends real UDP packets to the target's NTP port. NOT reflective NTP amplification (556x) — that requires spoofed source IPs pointing at victim so NTP servers send amplified monlist responses back. Needs raw sockets with root access for true amplification.",
    description: "Sends real UDP packets directly to the target's NTP service on port 123 — saturates the NTP daemon and port 123 bandwidth. True 556x amplification requires reflective IP spoofing not available in sandboxed environments.",
  },
  {
    id: "ssdp-amp",
    name: "SSDP Flood (port 1900)",
    protocol: "UDP/SSDP", layer: "L4", amplification: 1, severity: "high",
    realMode: "udp-only",
    realNote: "UDP FLOOD ONLY to port 1900 — sends real UDP packets to the SSDP/UPnP port. NOT reflective amplification — true SSDP amp requires spoofed source IP so IoT/router SSDP M-SEARCH responses flood the victim. Requires raw socket root access for true reflection.",
    description: "Sends real UDP packets to the target's SSDP port 1900 — floods the UPnP service. True 30x SSDP amplification via consumer IoT device reflection requires IP spoofing capabilities not available here.",
  },
  {
    id: "memcached-amp",
    name: "Memcached Flood (port 11211)",
    protocol: "UDP/Memcached", layer: "L4", amplification: 1, severity: "critical",
    realMode: "udp-only",
    realNote: "UDP FLOOD ONLY to port 11211 — sends real UDP packets to the Memcached port. NOT the 51,000x amplification attack — that requires spoofed source IPs so exposed Memcached servers flood the victim with stats responses. The 51K multiplier is real-world accurate but needs raw socket root privileges.",
    description: "Sends real UDP packets to the target's Memcached service on port 11211 — saturates the Memcached daemon. The real-world 51,000x amplification attack via reflective IP spoofing requires root-level raw socket access unavailable in this environment.",
  },
];

const MODE_CONFIG: Record<RealMode, { label: string; cls: string; icon: typeof CheckCircle }> = {
  full:      { label: "FULLY REAL",   cls: "border-emerald-500/60 text-emerald-400 bg-emerald-500/8",  icon: CheckCircle },
  degraded:  { label: "DEGRADED",     cls: "border-amber-500/60 text-amber-400 bg-amber-500/8",        icon: AlertCircle },
  "udp-only":{ label: "UDP FLOOD ONLY", cls: "border-blue-500/60 text-blue-400 bg-blue-500/8",         icon: Info },
};

interface AttackMetrics {
  packetsSent: number;
  bytesWritten: number;
  errors: number;
  responses: number;
  currentPps: number;
  elapsedSeconds: number;
  progressPct: number;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  remaining: number;
  progressPct: number;
  metrics: AttackMetrics;
  config: { vector: string; target: string; port: number; duration: number };
}

function fmtBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(2)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
  return String(n);
}

export default function DdosSimulatorPage() {
  useDocumentTitle("DDoS Simulator");
  const { toast } = useToast();

  const [selectedVector, setSelectedVector] = useState<AttackVector>(ATTACK_VECTORS[0]);
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [rate, setRate] = useState(5000);
  const [duration, setDuration] = useState(30);
  const [threads, setThreads] = useState(8);
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [showNote, setShowNote] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/ddos/status/${id}`);
      if (res.status === 404) {
        stopPolling(); setJobId(null);
        setStatus((prev) => prev ? { ...prev, active: false, progressPct: 100 } : null);
        toast({ title: "Attack Complete", description: "Bombardment finished — review metrics above." });
        return;
      }
      const data: JobStatus = await res.json();
      setStatus(data);
      if (!data.active) {
        stopPolling(); setJobId(null);
        toast({ title: "Attack Finished", description: `${fmtNum(data.metrics.packetsSent)} packets sent — ${fmtBytes(data.metrics.bytesWritten)} transmitted` });
      }
    } catch {}
  }, [stopPolling, toast]);

  const launchAttack = async () => {
    if (!target.trim()) { toast({ title: "Target required", variant: "destructive" }); return; }
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/ddos/start", {
        vector: selectedVector.id, target: target.trim(),
        port: parseInt(port) || 80, ratePerSecond: rate, duration, threads,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to launch");
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Attack Launched", description: `${selectedVector.name} → ${target}:${port}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 800);
    } catch (err: any) {
      toast({ title: "Launch Failed", description: err.message, variant: "destructive" });
    } finally { setLaunching(false); }
  };

  const stopAttack = async () => {
    if (!jobId) return;
    setStopping(true);
    try {
      await fetch(`/api/ddos/stop/${jobId}`, { method: "DELETE" });
      stopPolling(); setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      toast({ title: "Attack Stopped" });
    } catch { toast({ title: "Stop failed", variant: "destructive" }); }
    finally { setStopping(false); }
  };

  const isRunning = !!jobId && status?.active;
  const modeConf = MODE_CONFIG[selectedVector.realMode];
  const ModeIcon = modeConf.icon;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2" data-testid="heading-ddos">
          <Zap className="w-5 h-5 text-primary" />
          DDoS Attack Simulator
        </h1>
        <p className="text-xs text-muted-foreground">
          Real-world multi-vector DDoS engine — live packet delivery with accurate capability reporting
        </p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-ddos-disclaimer">
          <span className="font-semibold">Authorized Use Only</span> — This tool sends real network traffic to the specified target. Use only on systems you own or have explicit written authorization to stress test. Unauthorized use is illegal under the CFAA and equivalent laws worldwide.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Attack Vector</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {ATTACK_VECTORS.map((v) => {
                const mc = MODE_CONFIG[v.realMode];
                return (
                  <button key={v.id} onClick={() => !isRunning && setSelectedVector(v)} disabled={isRunning}
                    data-testid={`button-vector-${v.id}`}
                    className={`w-full text-left p-2.5 rounded-md border transition-all text-xs ${selectedVector.id === v.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40 hover:bg-muted/30"} ${isRunning ? "opacity-50 cursor-not-allowed" : ""}`}>
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-semibold truncate">{v.name}</span>
                      <div className="flex items-center gap-1 shrink-0">
                        <Badge variant="outline" className="text-[8px] py-0">{v.protocol}</Badge>
                        <Badge variant="outline" className={`text-[8px] py-0 ${mc.cls}`}>{mc.label}</Badge>
                      </div>
                    </div>
                    {v.fallbackTo && (
                      <div className="text-[9px] text-amber-400 mt-0.5">Falls back to: {v.fallbackTo}</div>
                    )}
                  </button>
                );
              })}
            </CardContent>
          </Card>

          {/* Legend */}
          <Card className="bg-muted/10">
            <CardContent className="pt-3 space-y-1.5">
              <p className="text-[9px] uppercase tracking-wider text-muted-foreground font-semibold mb-2">Capability Legend</p>
              {(Object.entries(MODE_CONFIG) as [RealMode, typeof MODE_CONFIG[RealMode]][]).map(([key, mc]) => {
                const Icon = mc.icon;
                return (
                  <div key={key} className={`flex items-start gap-2 p-1.5 rounded border text-[10px] ${mc.cls}`}>
                    <Icon className="w-3 h-3 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold">{mc.label}</span>
                      {key === "full" && <span className="text-muted-foreground"> — sends real traffic, full effect</span>}
                      {key === "degraded" && <span className="text-muted-foreground"> — falls back (needs root/CAP)</span>}
                      {key === "udp-only" && <span className="text-muted-foreground"> — direct UDP flood, no spoofing</span>}
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Waves className="w-4 h-4 text-primary" />
                {selectedVector.name}
                <Badge variant="outline" className={`text-[9px] ${
                  selectedVector.severity === "critical" ? "border-severity-critical/50 text-severity-critical" :
                  selectedVector.severity === "high" ? "border-severity-high/50 text-severity-high" :
                  "border-severity-medium/50 text-severity-medium"
                }`}>{selectedVector.severity.toUpperCase()}</Badge>
                <Badge variant="outline" className={`text-[9px] ${modeConf.cls}`}>
                  <ModeIcon className="w-2.5 h-2.5 mr-1" />{modeConf.label}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground border-l-2 border-primary/40 pl-2">{selectedVector.description}</p>

              {/* Accurate capability note */}
              <button onClick={() => setShowNote(!showNote)} className="w-full text-left" data-testid="button-toggle-note">
                <div className={`p-2 rounded border text-[10px] flex items-start gap-2 ${modeConf.cls}`}>
                  <ModeIcon className="w-3 h-3 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold">Accurate Capability: </span>
                    <span>{showNote ? selectedVector.realNote : selectedVector.realNote.slice(0, 100) + "..."}</span>
                    <span className="text-primary ml-1 underline">{showNote ? "less" : "more"}</span>
                  </div>
                </div>
              </button>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Target IP / Hostname</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-ddos-target" placeholder="192.168.1.1" disabled={isRunning} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-ddos-port" placeholder="80" disabled={isRunning} />
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-xs">Packet Rate: <span className="text-primary font-mono">{rate.toLocaleString()} pps</span></Label>
                <Slider value={[rate]} onValueChange={([v]) => setRate(v)} min={100} max={500000} step={100} disabled={isRunning} data-testid="slider-ddos-rate" />
                <div className="flex justify-between text-[10px] text-muted-foreground"><span>100 pps</span><span>500K pps</span></div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-xs">Duration: <span className="text-primary font-mono">{duration}s</span></Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={600} step={5} disabled={isRunning} />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs">Threads: <span className="text-primary font-mono">{threads}</span></Label>
                  <Slider value={[threads]} onValueChange={([v]) => setThreads(v)} min={1} max={64} step={1} disabled={isRunning} />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Bandwidth</div>
                  <div className="text-sm font-bold font-mono text-primary" data-testid="text-est-bandwidth">
                    {(() => { const mbps = (rate * 1024 * 8) / 1_000_000; return mbps >= 1000 ? `${(mbps/1000).toFixed(1)} Gbps` : `${mbps.toFixed(1)} Mbps`; })()}
                  </div>
                  <div className="text-[9px] text-muted-foreground">direct only (no amp)</div>
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Packets</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-est-packets">{fmtNum(rate * duration)}</div>
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Data</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-est-data">{fmtBytes(rate * duration * 1024)}</div>
                </Card>
              </div>

              {(isRunning || status) && (
                <div className="space-y-3 p-3 border border-primary/20 rounded-md bg-primary/5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">
                        {isRunning ? `ATTACKING ${status?.config.target}:${status?.config.port}` : "ATTACK COMPLETE"}
                      </span>
                    </div>
                    <span className="text-xs font-mono text-primary">
                      {isRunning ? `${status?.remaining ?? duration}s remaining` : `${status?.elapsed ?? duration}s total`}
                    </span>
                  </div>
                  <Progress value={status?.progressPct ?? 0} className="h-2" />
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    <div className="p-2 rounded-md border bg-muted/20 text-center">
                      <div className={`text-sm font-bold font-mono ${isRunning ? "text-status-online" : ""}`}>{fmtNum(status?.metrics.currentPps ?? 0)}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Live PPS</div>
                    </div>
                    <div className="p-2 rounded-md border bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{fmtNum(status?.metrics.packetsSent ?? 0)}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Packets Sent</div>
                    </div>
                    <div className="p-2 rounded-md border bg-muted/20 text-center">
                      <div className="text-sm font-bold font-mono">{fmtBytes(status?.metrics.bytesWritten ?? 0)}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">Bytes Sent</div>
                    </div>
                    <div className="p-2 rounded-md border bg-muted/20 text-center">
                      <div className={`text-sm font-bold font-mono ${(status?.metrics.errors ?? 0) > 100 ? "text-severity-high" : ""}`}>{fmtNum(status?.metrics.errors ?? 0)}</div>
                      <div className="text-[9px] text-muted-foreground uppercase">{(status?.metrics.responses ?? 0)} responses</div>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launchAttack} disabled={launching || stopping} className="flex-1" data-testid="button-launch-attack">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><Zap className="w-4 h-4 me-2" />Launch Attack</>}
                    </Button>
                  : <Button onClick={stopAttack} disabled={stopping} variant="destructive" className="flex-1" data-testid="button-stop-attack">
                      {stopping ? <><Activity className="w-4 h-4 me-2 animate-spin" />Stopping...</> : <><Square className="w-4 h-4 me-2" />Stop Attack</>}
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-primary" />
                Defense Countermeasures
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                selectedVector.id === "syn-flood"    && "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1 — allocates no state until SYN+ACK is acknowledged",
                selectedVector.id === "udp-flood"    && "Rate-limit UDP inbound: iptables -A INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT; DROP remainder",
                selectedVector.id === "http-flood"   && "Deploy WAF with Cloudflare Turnstile / hCaptcha challenge — separates real browsers from flood traffic",
                selectedVector.id.includes("amp") || selectedVector.id.includes("ntp") || selectedVector.id.includes("ssdp") || selectedVector.id.includes("memcached")
                  && "Block spoofed source IPs (BCP38/uRPF). Disable open NTP monlist, open DNS resolvers, exposed Memcached UDP. Null-route amplifier IPs at BGP level",
                selectedVector.id === "slowloris"    && "Set minimum request rate: RequestReadTimeout header=10-20,MinRate=500 in Apache / client_header_timeout 10 in Nginx",
                selectedVector.id === "icmp-flood"   && "Limit ICMP: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT; DROP remainder",
                selectedVector.id === "ack-flood"    && "Stateful connection tracking — iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; DROP NEW from external",
                "Deploy Anycast + upstream scrubbing (Cloudflare Magic Transit, Akamai Prolexic, AWS Shield Advanced) for volumetric protection",
                "BGP Blackhole (RTBH): announce /32 host route with community 666 to null-route attack traffic at upstream router",
                "Per-IP connection limits: iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP",
              ].filter(Boolean).map((rec, i) => (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <ChevronRight className="w-3 h-3 text-primary mt-0.5 shrink-0" />
                  <span className="font-mono text-muted-foreground">{rec as string}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
