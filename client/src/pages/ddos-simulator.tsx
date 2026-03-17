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
import {
  Zap, Copy, Check, AlertTriangle, Activity, Shield,
  Waves, Square, Play, ChevronRight, Network, Server,
  BarChart3, Clock, Wifi,
} from "lucide-react";

interface AttackVector {
  id: string;
  name: string;
  protocol: string;
  layer: string;
  amplification: number;
  description: string;
  severity: string;
}

const ATTACK_VECTORS: AttackVector[] = [
  { id: "syn-flood",     name: "SYN Flood",             protocol: "TCP",         layer: "L4", amplification: 1,      description: "Exploits TCP 3-way handshake — floods target with SYN packets to exhaust connection table and crash the daemon", severity: "critical" },
  { id: "udp-flood",     name: "UDP Flood",             protocol: "UDP",         layer: "L4", amplification: 1,      description: "Floods random ports with high-rate UDP datagrams saturating NIC bandwidth and forcing ICMP unreachable responses", severity: "high" },
  { id: "http-flood",    name: "HTTP Flood",            protocol: "HTTP",        layer: "L7", amplification: 1,      description: "Exhausts web server threads with real concurrent HTTP GET/POST requests mimicking legitimate browser traffic", severity: "high" },
  { id: "dns-amp",       name: "DNS Amplification",     protocol: "UDP/DNS",     layer: "L4", amplification: 54,     description: "Floods target's DNS port with ANY-type queries — each 28-byte request generates ~1,500-byte response (54x amplification)", severity: "critical" },
  { id: "ntp-amp",       name: "NTP Amplification",     protocol: "UDP/NTP",     layer: "L4", amplification: 556,    description: "Sends NTP monlist queries over UDP/123 — highest real-world amplification vector at 556x request-to-response ratio", severity: "critical" },
  { id: "ssdp-amp",      name: "SSDP Amplification",    protocol: "UDP/SSDP",    layer: "L4", amplification: 30,     description: "Abuses UPnP SSDP M-SEARCH responses from consumer routers/IoT devices for 30x UDP amplification", severity: "high" },
  { id: "slowloris",     name: "Slowloris",             protocol: "HTTP",        layer: "L7", amplification: 1,      description: "Opens hundreds of real TCP connections to target web server and sends partial HTTP headers indefinitely — starves thread pool", severity: "medium" },
  { id: "icmp-flood",    name: "ICMP Flood",            protocol: "ICMP",        layer: "L3", amplification: 1,      description: "High-rate ICMP echo request flood overwhelming target network interface and consuming CPU for packet processing", severity: "medium" },
  { id: "memcached-amp", name: "Memcached Amplification",protocol: "UDP/Memcached",layer: "L4", amplification: 51000, description: "Highest known amplification factor (51,000x) — exploits exposed Memcached servers via UDP stats command", severity: "critical" },
  { id: "ack-flood",     name: "ACK Flood",             protocol: "TCP",         layer: "L4", amplification: 1,      description: "Floods target with real TCP connection attempts — bypasses stateless ACK-allow firewall rules and exhausts socket buffers", severity: "medium" },
];

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
  if (bytes >= 1_048_576)    return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1024)         return `${(bytes / 1024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function fmtNum(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1000)      return `${(n / 1000).toFixed(1)}K`;
  return String(n);
}

function MetricCard({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: string }) {
  return (
    <Card className={`p-3 ${accent || "bg-muted/30"}`}>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</div>
      <div className="text-base font-bold font-mono mt-0.5">{value}</div>
      {sub && <div className="text-[9px] text-muted-foreground">{sub}</div>}
    </Card>
  );
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

  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  const pollStatus = useCallback(async (id: string) => {
    try {
      const res = await fetch(`/api/ddos/status/${id}`);
      if (res.status === 404) {
        stopPolling();
        setJobId(null);
        setStatus((prev) => prev ? { ...prev, active: false, progressPct: 100 } : null);
        toast({ title: "Attack Complete", description: "Target bombardment finished." });
        return;
      }
      const data: JobStatus = await res.json();
      setStatus(data);
      if (!data.active) {
        stopPolling();
        setJobId(null);
        toast({ title: "Attack Finished", description: `${fmtNum(data.metrics.packetsSent)} packets sent — ${fmtBytes(data.metrics.bytesWritten)} transmitted` });
      }
    } catch {
      // keep polling
    }
  }, [stopPolling, toast]);

  useEffect(() => {
    return () => stopPolling();
  }, [stopPolling]);

  const launchAttack = async () => {
    if (!target.trim()) {
      toast({ title: "Target required", variant: "destructive" });
      return;
    }
    setLaunching(true);
    try {
      const res = await apiRequest("POST", "/api/ddos/start", {
        vector: selectedVector.id,
        target: target.trim(),
        port: parseInt(port) || 80,
        ratePerSecond: rate,
        duration,
        threads,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to launch");
      setJobId(data.jobId);
      setStatus(null);
      toast({ title: "Attack Launched", description: `${selectedVector.name} → ${target}:${port}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 800);
    } catch (err: any) {
      toast({ title: "Launch Failed", description: err.message, variant: "destructive" });
    } finally {
      setLaunching(false);
    }
  };

  const stopAttack = async () => {
    if (!jobId) return;
    setStopping(true);
    try {
      await fetch(`/api/ddos/stop/${jobId}`, { method: "DELETE" });
      stopPolling();
      setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      toast({ title: "Attack Stopped" });
    } catch {
      toast({ title: "Stop failed", variant: "destructive" });
    } finally {
      setStopping(false);
    }
  };

  const isRunning = !!jobId && status?.active;
  const bwBps = (status?.metrics.currentPps ?? rate) * 1024 * 8 * selectedVector.amplification;
  const estBwMbps = (rate * 1024 * 8 * selectedVector.amplification) / 1_000_000;

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2" data-testid="heading-ddos">
          <Zap className="w-5 h-5 text-primary" />
          DDoS Attack Simulator
        </h1>
        <p className="text-xs text-muted-foreground">
          Real-world multi-vector DDoS execution engine — live packet delivery with real-time metrics
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
              {ATTACK_VECTORS.map((v) => (
                <button
                  key={v.id}
                  onClick={() => !isRunning && setSelectedVector(v)}
                  disabled={isRunning}
                  data-testid={`button-vector-${v.id}`}
                  className={`w-full text-left p-2.5 rounded-md border transition-all text-xs ${
                    selectedVector.id === v.id
                      ? "border-primary bg-primary/10"
                      : "border-border/50 hover:border-primary/40 hover:bg-muted/30"
                  } ${isRunning ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <div className="flex items-center justify-between gap-1">
                    <span className="font-semibold truncate">{v.name}</span>
                    <div className="flex items-center gap-1 shrink-0">
                      <Badge variant="outline" className="text-[9px] py-0">{v.protocol}</Badge>
                      <Badge variant="outline" className="text-[9px] py-0">{v.layer}</Badge>
                    </div>
                  </div>
                  {v.amplification > 1 && (
                    <div className="text-[10px] font-bold mt-0.5 text-severity-critical">
                      {v.amplification.toLocaleString()}x Amplification
                    </div>
                  )}
                </button>
              ))}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Waves className="w-4 h-4 text-primary" />
                {selectedVector.name} — Target Configuration
                <Badge variant="outline" className={`text-[9px] ${
                  selectedVector.severity === "critical" ? "border-severity-critical/50 text-severity-critical" :
                  selectedVector.severity === "high" ? "border-severity-high/50 text-severity-high" :
                  "border-severity-medium/50 text-severity-medium"
                }`}>
                  {selectedVector.severity.toUpperCase()}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground">{selectedVector.description}</p>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Target IP / Hostname</Label>
                  <Input
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="h-8 text-xs font-mono"
                    data-testid="input-ddos-target"
                    placeholder="192.168.1.1"
                    disabled={isRunning}
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    className="h-8 text-xs font-mono"
                    data-testid="input-ddos-port"
                    placeholder="80"
                    disabled={isRunning}
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-xs">
                  Packet Rate:{" "}
                  <span className="text-primary font-mono">{rate.toLocaleString()} pps</span>
                </Label>
                <Slider
                  value={[rate]}
                  onValueChange={([v]) => setRate(v)}
                  min={100}
                  max={500000}
                  step={100}
                  disabled={isRunning}
                  data-testid="slider-ddos-rate"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>100 pps</span>
                  <span>500K pps</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-xs">
                    Duration:{" "}
                    <span className="text-primary font-mono">{duration}s</span>
                  </Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={600} step={5} disabled={isRunning} />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs">
                    Threads:{" "}
                    <span className="text-primary font-mono">{threads}</span>
                  </Label>
                  <Slider value={[threads]} onValueChange={([v]) => setThreads(v)} min={1} max={64} step={1} disabled={isRunning} />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Bandwidth</div>
                  <div className="text-sm font-bold font-mono text-primary" data-testid="text-est-bandwidth">
                    {estBwMbps >= 1000 ? `${(estBwMbps / 1000).toFixed(1)} Gbps` : `${estBwMbps.toFixed(1)} Mbps`}
                  </div>
                  {selectedVector.amplification > 1 && (
                    <div className="text-[9px] text-severity-critical">{selectedVector.amplification.toLocaleString()}x amplified</div>
                  )}
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Packets</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-est-packets">
                    {fmtNum(rate * duration)}
                  </div>
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase">Est. Data</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-est-data">
                    {fmtBytes(rate * duration * 1024 * selectedVector.amplification)}
                  </div>
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
                      {isRunning
                        ? `${status?.remaining ?? duration}s remaining`
                        : `${status?.elapsed ?? duration}s total`}
                    </span>
                  </div>

                  <Progress value={status?.progressPct ?? 0} className="h-2" />

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                    <MetricCard
                      label="Live PPS"
                      value={fmtNum(status?.metrics.currentPps ?? 0)}
                      sub="packets/sec"
                      accent={isRunning ? "border-status-online/30 bg-status-online/5" : ""}
                    />
                    <MetricCard
                      label="Packets Sent"
                      value={fmtNum(status?.metrics.packetsSent ?? 0)}
                      sub="total delivered"
                      accent={isRunning ? "border-primary/20 bg-primary/5" : ""}
                    />
                    <MetricCard
                      label="Bytes Sent"
                      value={fmtBytes(status?.metrics.bytesWritten ?? 0)}
                      sub="raw traffic"
                    />
                    <MetricCard
                      label="Errors"
                      value={fmtNum(status?.metrics.errors ?? 0)}
                      sub={`${status?.metrics.responses ?? 0} responses`}
                      accent={(status?.metrics.errors ?? 0) > 100 ? "border-severity-high/30 bg-severity-high/5" : ""}
                    />
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning ? (
                  <Button
                    onClick={launchAttack}
                    disabled={launching || stopping}
                    className="flex-1"
                    data-testid="button-launch-attack"
                  >
                    {launching
                      ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</>
                      : <><Zap className="w-4 h-4 me-2" />Launch Attack</>
                    }
                  </Button>
                ) : (
                  <Button
                    onClick={stopAttack}
                    disabled={stopping}
                    variant="destructive"
                    className="flex-1"
                    data-testid="button-stop-attack"
                  >
                    {stopping
                      ? <><Activity className="w-4 h-4 me-2 animate-spin" />Stopping...</>
                      : <><Square className="w-4 h-4 me-2" />Stop Attack</>
                    }
                  </Button>
                )}
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
                selectedVector.id === "syn-flood"    && "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1 — each SYN gets a cryptographic cookie instead of allocating state",
                selectedVector.id === "udp-flood"    && "Rate-limit UDP: iptables -A INPUT -p udp -m limit --limit 100/s --limit-burst 200 -j ACCEPT; -A INPUT -p udp -j DROP",
                selectedVector.id === "http-flood"   && "Deploy WAF with challenge-response (Cloudflare Turnstile / hCaptcha) — separate bot traffic from legitimate browsers",
                selectedVector.id.includes("amp")    && "Block outbound spoofed source IPs (BCP38/uRPF). Disable open resolvers/NTP monlist. Null-route amplifier IPs upstream",
                selectedVector.id === "slowloris"    && "Set Apache/Nginx min request rate: RequestReadTimeout header=10-20,MinRate=500 — drop slow connections immediately",
                selectedVector.id === "icmp-flood"   && "Limit ICMP rate: iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT; DROP remainder",
                selectedVector.id === "ack-flood"    && "Use stateful connection tracking — DROP packets not in ESTABLISHED,RELATED state from external interfaces",
                "Deploy Anycast routing + upstream scrubbing center (Cloudflare Magic Transit, Akamai Prolexic, AWS Shield Advanced) for volumetric vectors",
                "Enable BGP Blackhole (RTBH) — announce /32 host route with community 666 to null-route attack traffic at upstream router level",
                "Rate-limit new connections per source IP: iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above 20 --connlimit-mask 32 -j DROP",
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
