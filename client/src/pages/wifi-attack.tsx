import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Slider } from "@/components/ui/slider";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Wifi, Shield, Radio, Lock, Eye, AlertTriangle, Play, Square,
  Terminal, ChevronRight, Check, X, Loader2, RefreshCw, Copy, CheckCheck,
  Scan, Activity, WifiOff, Info,
} from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

// ─── Types ────────────────────────────────────────────────────────────────────

interface ToolStatus { name: string; available: boolean; path?: string; }

interface JobStatus {
  jobId: string; active: boolean; exitCode: number | null; signal: string | null;
  elapsed: number; output: string[]; totalLines: number;
  config: { technique: string; iface: string; bssid?: string; ssid?: string; channel?: string; duration?: number; };
}

// ─── Constants ────────────────────────────────────────────────────────────────

const ATTACK_MODES = [
  {
    id: "scan", name: "Network Scan", icon: Scan, severity: "info",
    desc: "Scan for nearby wireless networks using airodump-ng. Discovers BSSIDs, SSIDs, channels, encryption types, and connected clients.",
    tools: ["airmon-ng", "airodump-ng"],
    fields: ["iface", "channel", "duration"],
    notes: "Passive scan — no packets sent to target APs. Safe for recon.",
  },
  {
    id: "handshake", name: "WPA Handshake Capture", icon: Radio, severity: "high",
    desc: "Capture 4-way WPA/WPA2 handshakes by sending deauth frames to force client reconnection, then crack offline with aircrack-ng.",
    tools: ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"],
    fields: ["iface", "bssid", "ssid", "channel", "clientMac", "wordlist", "duration"],
    notes: "Requires at least one client connected to target AP. BSSID + channel required.",
  },
  {
    id: "deauth", name: "Deauthentication Attack", icon: Wifi, severity: "high",
    desc: "Force disconnect clients from target AP using forged 802.11 deauthentication frames. Use FF:FF:FF:FF:FF:FF as client MAC to broadcast-deauth all clients.",
    tools: ["airmon-ng", "aireplay-ng"],
    fields: ["iface", "bssid", "channel", "clientMac", "duration"],
    notes: "WPA3/802.11w protected APs resist deauth. Continuous until stopped or duration expires.",
  },
  {
    id: "evil-twin", name: "Evil Twin AP", icon: Eye, severity: "critical",
    desc: "Create a rogue AP mirroring the target SSID. Deploys a captive portal to capture credentials. Deauths clients from real AP to force them to connect to the clone.",
    tools: ["airmon-ng", "airbase-ng", "hostapd", "dnsmasq", "python3", "aireplay-ng"],
    fields: ["iface", "bssid", "ssid", "channel", "duration"],
    notes: "Requires two wireless interfaces or a secondary interface for the AP. Captured credentials printed in real time.",
  },
  {
    id: "pmkid", name: "PMKID Attack (Clientless)", icon: Lock, severity: "critical",
    desc: "Clientless WPA2 attack — capture PMKID directly from AP without needing any connected client. Convert to hashcat format and crack offline.",
    tools: ["airmon-ng", "hcxdumptool", "hcxpcapngtool", "hashcat"],
    fields: ["iface", "bssid", "wordlist", "duration"],
    notes: "Most modern WPA2 APs expose PMKID. Duration is capture time — longer = more capture attempts.",
  },
  {
    id: "wps-pin", name: "WPS PIN Brute Force", icon: Shield, severity: "high",
    desc: "Exploit WPS PIN vulnerability via Pixie Dust (instantly recovers PIN from WPS exchange in seconds) then falls back to brute force if Pixie Dust fails.",
    tools: ["airmon-ng", "reaver"],
    fields: ["iface", "bssid", "channel", "duration"],
    notes: "Pixie Dust works on weak WPS implementations. Many modern APs have WPS lockout — reaver handles backoff.",
  },
  {
    id: "karma", name: "KARMA Attack", icon: Radio, severity: "critical",
    desc: "Respond to all wireless probe requests to lure devices into connecting automatically. Captures EAP credentials via hostapd-wpe KARMA mode.",
    tools: ["airmon-ng", "airbase-ng", "hostapd-wpe"],
    fields: ["iface", "duration"],
    notes: "Effective against devices with saved open networks in their probe list. EAP/WPA-Enterprise credential capture.",
  },
];

const SEVERITY_STYLES: Record<string, string> = {
  info:     "border-sky-500/50 text-sky-400",
  high:     "border-severity-high/50 text-severity-high",
  critical: "border-severity-critical/50 text-severity-critical",
};

const DEFENSE_TIPS = [
  "Enable 802.11w (Management Frame Protection) — prevents deauth and disassociation attacks",
  "Use WPA3-SAE — immune to PMKID attacks and offline dictionary attacks against 4-way handshake",
  "Disable WPS on all APs — eliminates PIN brute force and Pixie Dust attack surface",
  "Deploy WIDS (Wireless Intrusion Detection) — detects rogue APs, deauth floods, and probe spoofing",
  "Use 802.1X/EAP enterprise authentication — prevents credential capture via evil twin portals",
  "Monitor for sudden client disconnection spikes — indicator of active deauth attack in progress",
  "Use certificate pinning in enterprise EAP configs — prevents KARMA/evil-twin MiTM on EAP-TLS",
];

// ─── CopyButton ───────────────────────────────────────────────────────────────

function CopyBtn({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" variant="ghost" className="h-7 w-7 p-0" onClick={() => {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }} data-testid="button-copy-output">
      {copied ? <CheckCheck className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </Button>
  );
}

// ─── Tool availability panel ──────────────────────────────────────────────────

function ToolPanel({ tools }: { tools: ToolStatus[] }) {
  const available = tools.filter(t => t.available).length;
  const total = tools.length;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">Required tools</span>
        <Badge variant="outline" className={`text-[9px] ${available === total ? "border-green-500/50 text-green-400" : available === 0 ? "border-red-500/50 text-red-400" : "border-amber-500/50 text-amber-400"}`}>
          {available}/{total} available
        </Badge>
      </div>
      <div className="flex flex-wrap gap-1.5">
        {tools.map(t => (
          <div key={t.name} className={`flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border ${t.available ? "border-green-500/30 text-green-400 bg-green-500/5" : "border-red-500/30 text-red-400 bg-red-500/5"}`} data-testid={`tool-status-${t.name}`}>
            {t.available ? <Check className="w-2.5 h-2.5" /> : <X className="w-2.5 h-2.5" />}
            {t.name}
          </div>
        ))}
      </div>
      {available < total && (
        <p className="text-[10px] text-muted-foreground">Missing tools — install on Kali Linux: <code className="text-amber-400">sudo apt-get install aircrack-ng hcxtools hashcat reaver hostapd-wpe</code></p>
      )}
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function WifiAttackPage() {
  useDocumentTitle("Wireless Attack Suite — AegisAI360");
  const { toast } = useToast();

  // Config
  const [iface, setIface] = useState("wlan0");
  const [bssid, setBssid] = useState("AA:BB:CC:DD:EE:FF");
  const [channel, setChannel] = useState("6");
  const [ssid, setSsid] = useState("TargetNetwork");
  const [clientMac, setClientMac] = useState("FF:FF:FF:FF:FF:FF");
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [duration, setDuration] = useState(60);

  const [selectedMode, setSelectedMode] = useState(ATTACK_MODES[0]);

  // Tool detection
  const [tools, setTools] = useState<ToolStatus[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);

  // Job state
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const [stopping, setStopping] = useState(false);
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const outputRef = useRef<string[]>([]);

  // Fetch tool availability when technique changes
  const fetchTools = useCallback(async (technique: string) => {
    setToolsLoading(true);
    try {
      const r = await fetch(`/api/offensive/wireless/tools/${technique}`, { credentials: "include" });
      if (r.ok) {
        const data = await r.json();
        setTools(data.tools ?? []);
      }
    } catch {}
    setToolsLoading(false);
  }, []);

  useEffect(() => { fetchTools(selectedMode.id); }, [selectedMode.id, fetchTools]);

  // Poll job status
  const pollJob = useCallback(async (id: string) => {
    try {
      const r = await fetch(`/api/offensive/wireless/status/${id}`, { credentials: "include" });
      if (!r.ok) { clearInterval(pollRef.current!); return; }
      const data: JobStatus = await r.json();
      setJobStatus(data);
      outputRef.current = data.output;
      if (!data.active) clearInterval(pollRef.current!);
    } catch {}
  }, []);

  const startPolling = useCallback((id: string) => {
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(() => pollJob(id), 800);
  }, [pollJob]);

  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const handleLaunch = async () => {
    setLaunching(true);
    try {
      const body: Record<string, any> = {
        technique: selectedMode.id,
        iface, duration,
      };
      if (selectedMode.fields.includes("bssid")) body.bssid = bssid;
      if (selectedMode.fields.includes("ssid")) body.ssid = ssid;
      if (selectedMode.fields.includes("channel")) body.channel = channel;
      if (selectedMode.fields.includes("clientMac")) body.clientMac = clientMac;
      if (selectedMode.fields.includes("wordlist")) body.wordlist = wordlist;

      const r = await fetch("/api/offensive/wireless/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(body),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Failed to start");

      setJobId(data.jobId);
      setJobStatus(null);
      outputRef.current = [];
      startPolling(data.jobId);
      toast({ title: "Attack Launched", description: `${selectedMode.name} started — job ${data.jobId.slice(0, 8)}` });
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    }
    setLaunching(false);
  };

  const handleStop = async () => {
    if (!jobId) return;
    setStopping(true);
    try {
      await fetch(`/api/offensive/wireless/stop/${jobId}`, { method: "DELETE", credentials: "include" });
      if (pollRef.current) clearInterval(pollRef.current);
      toast({ title: "Attack Stopped", description: "Process killed" });
      // Final poll
      await pollJob(jobId);
    } catch {}
    setStopping(false);
  };

  const handleSelectMode = (mode: typeof ATTACK_MODES[0]) => {
    if (jobStatus?.active) return;
    setSelectedMode(mode);
    setJobId(null);
    setJobStatus(null);
    outputRef.current = [];
  };

  const active = jobStatus?.active ?? false;
  const fields = selectedMode.fields;

  const exitBadge = () => {
    if (!jobStatus || active) return null;
    if (jobStatus.exitCode === 0) return <Badge variant="outline" className="border-green-500/50 text-green-400 text-[9px]">COMPLETED</Badge>;
    if (jobStatus.exitCode === 127) return <Badge variant="outline" className="border-red-500/50 text-red-400 text-[9px]">TOOL NOT FOUND</Badge>;
    if (jobStatus.signal) return <Badge variant="outline" className="border-amber-500/50 text-amber-400 text-[9px]">STOPPED</Badge>;
    return <Badge variant="outline" className="border-red-500/50 text-red-400 text-[9px]">EXIT {jobStatus.exitCode}</Badge>;
  };

  return (
    <div className="p-4 md:p-6 space-y-4">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Wifi className="w-5 h-5 text-primary" />
          Wireless Attack Suite
        </h1>
        <p className="text-xs text-muted-foreground">WPA/WPA2 cracking, deauthentication, evil twin, PMKID, WPS attacks, and KARMA for authorized wireless security assessments</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-wifi-disclaimer">
          <span className="font-semibold">Authorized Use Only</span> — Wireless attacks against networks without explicit written permission are federal crimes under the CFAA. These tools are for licensed penetration testers and authorized red team operations only. Requires a monitor-mode capable wireless adapter and Linux with aircrack-ng suite installed (Kali/Parrot recommended).
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        {/* Left panel — attack modules */}
        <div className="xl:col-span-1 space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Attack Modules</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {ATTACK_MODES.map((mode) => {
                const Icon = mode.icon;
                const isSelected = selectedMode.id === mode.id;
                return (
                  <button
                    key={mode.id}
                    onClick={() => handleSelectMode(mode)}
                    disabled={active}
                    data-testid={`button-wifi-mode-${mode.id}`}
                    className={`w-full text-left p-2.5 rounded-md border transition-all text-xs disabled:opacity-50 disabled:cursor-not-allowed
                      ${isSelected ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"}`}
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="w-3.5 h-3.5 text-primary shrink-0" />
                      <span className="font-medium">{mode.name}</span>
                    </div>
                    <Badge variant="outline" className={`text-[9px] mt-1 ${SEVERITY_STYLES[mode.severity]}`}>
                      {mode.severity.toUpperCase()}
                    </Badge>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          {/* Defense tips */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-3.5 h-3.5 text-primary" />
                Defense Tips
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {DEFENSE_TIPS.map((tip, i) => (
                <div key={i} className="flex items-start gap-1.5 text-[10px] text-muted-foreground">
                  <ChevronRight className="w-2.5 h-2.5 text-primary mt-0.5 shrink-0" />
                  <span>{tip}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right panel — config + terminal */}
        <div className="xl:col-span-3 space-y-4">
          {/* Attack config card */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <selectedMode.icon className="w-4 h-4 text-primary" />
                {selectedMode.name}
                <Badge variant="outline" className={`text-[9px] ${SEVERITY_STYLES[selectedMode.severity]}`}>
                  {selectedMode.severity.toUpperCase()}
                </Badge>
                {active && <Badge variant="outline" className="border-green-500/50 text-green-400 text-[9px] animate-pulse">RUNNING</Badge>}
                {exitBadge()}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground">{selectedMode.desc}</p>

              {/* Info note */}
              <div className="flex items-start gap-2 rounded-md border border-border/40 bg-muted/20 p-2.5">
                <Info className="w-3.5 h-3.5 text-sky-400 mt-0.5 shrink-0" />
                <p className="text-[10px] text-muted-foreground">{selectedMode.notes}</p>
              </div>

              {/* Tool availability */}
              {toolsLoading
                ? <div className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="w-3.5 h-3.5 animate-spin" />Checking tool availability...</div>
                : tools.length > 0 && <ToolPanel tools={tools} />
              }

              {/* Config fields */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Wireless Interface <span className="text-red-400">*</span></Label>
                  <Input value={iface} onChange={e => setIface(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="wlan0" data-testid="input-wifi-iface" />
                </div>

                {fields.includes("bssid") && (
                  <div className="space-y-1">
                    <Label className="text-xs">Target BSSID (MAC)</Label>
                    <Input value={bssid} onChange={e => setBssid(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="AA:BB:CC:DD:EE:FF" data-testid="input-wifi-bssid" />
                  </div>
                )}

                {fields.includes("ssid") && (
                  <div className="space-y-1">
                    <Label className="text-xs">Target SSID</Label>
                    <Input value={ssid} onChange={e => setSsid(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="NetworkName" data-testid="input-wifi-ssid" />
                  </div>
                )}

                {fields.includes("channel") && (
                  <div className="space-y-1">
                    <Label className="text-xs">Channel {selectedMode.id === "scan" ? "(blank = all)" : ""}</Label>
                    <Input value={channel} onChange={e => setChannel(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="1-14" data-testid="input-wifi-channel" />
                  </div>
                )}

                {fields.includes("clientMac") && (
                  <div className="space-y-1">
                    <Label className="text-xs">Client MAC <span className="text-muted-foreground">(FF:FF:... = broadcast)</span></Label>
                    <Input value={clientMac} onChange={e => setClientMac(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="FF:FF:FF:FF:FF:FF" data-testid="input-wifi-client" />
                  </div>
                )}

                {fields.includes("wordlist") && (
                  <div className={`space-y-1 ${fields.length > 4 ? "col-span-2 md:col-span-2" : ""}`}>
                    <Label className="text-xs">Wordlist Path</Label>
                    <Input value={wordlist} onChange={e => setWordlist(e.target.value)} disabled={active} className="h-8 text-xs font-mono" placeholder="/usr/share/wordlists/rockyou.txt" data-testid="input-wifi-wordlist" />
                  </div>
                )}
              </div>

              {/* Duration slider */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs">Duration</Label>
                  <span className="text-xs font-mono text-primary">{duration}s</span>
                </div>
                <Slider
                  value={[duration]} onValueChange={([v]) => setDuration(v)}
                  min={10} max={600} step={10} disabled={active}
                  data-testid="slider-wifi-duration"
                  className="w-full"
                />
                <div className="flex justify-between text-[10px] text-muted-foreground">
                  <span>10s</span><span>5 min</span><span>10 min</span>
                </div>
              </div>

              {/* Launch / Stop buttons */}
              <div className="flex items-center gap-3">
                {!active ? (
                  <Button
                    onClick={handleLaunch}
                    disabled={launching || !iface.trim()}
                    className="flex-1 h-9 bg-primary hover:bg-primary/90 text-primary-foreground"
                    data-testid="button-wifi-launch"
                  >
                    {launching
                      ? <><Loader2 className="w-4 h-4 me-2 animate-spin" />Launching...</>
                      : <><Play className="w-4 h-4 me-2" />Launch Attack</>
                    }
                  </Button>
                ) : (
                  <Button
                    onClick={handleStop}
                    disabled={stopping}
                    variant="destructive"
                    className="flex-1 h-9"
                    data-testid="button-wifi-stop"
                  >
                    {stopping
                      ? <><Loader2 className="w-4 h-4 me-2 animate-spin" />Stopping...</>
                      : <><Square className="w-4 h-4 me-2" />Stop Attack</>
                    }
                  </Button>
                )}
                {jobId && !active && (
                  <Button
                    variant="outline" size="sm"
                    onClick={() => { setJobId(null); setJobStatus(null); outputRef.current = []; }}
                    data-testid="button-wifi-reset"
                    className="h-9"
                  >
                    <RefreshCw className="w-3.5 h-3.5 me-1.5" />
                    Reset
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Live terminal output */}
          {jobId && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                  <Terminal className="w-3.5 h-3.5 text-primary" />
                  Live Terminal Output
                  {active && <Activity className="w-3 h-3 text-green-400 animate-pulse" />}
                  {jobStatus && (
                    <span className="text-muted-foreground font-normal ml-auto font-mono text-[10px]">
                      {jobStatus.elapsed}s elapsed | {jobStatus.totalLines} lines
                    </span>
                  )}
                  {jobStatus && (
                    <CopyBtn text={(jobStatus.output ?? []).join("\n")} />
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <TrafficConsole
                  trafficLog={jobStatus?.output ?? []}
                  active={active}
                  title={`${selectedMode.name} — Job ${jobId.slice(0, 8)}`}
                  className="rounded-t-none border-t-0"
                />
              </CardContent>
            </Card>
          )}

          {/* Environment note when no tools available */}
          {!toolsLoading && tools.length > 0 && tools.every(t => !t.available) && !jobId && (
            <Card className="border-amber-500/30 bg-amber-500/5">
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <WifiOff className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-amber-400">No wireless tools detected in this environment</p>
                    <p className="text-[10px] text-muted-foreground">
                      This platform is running in a cloud container without wireless hardware. The attack engine is fully functional — deploy to a Kali Linux / Parrot OS machine with a monitor-mode capable adapter (e.g. Alfa AWUS036ACH) and all attacks will execute in real time.
                    </p>
                    <div className="text-[10px] font-mono text-muted-foreground space-y-0.5 mt-2">
                      <p className="text-amber-400/80">Install on Kali/Parrot:</p>
                      <p>sudo apt-get install aircrack-ng hcxtools hcxdumptool hashcat reaver hostapd-wpe</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Launch anyway note — show if tools missing but user still wants to try */}
          {!toolsLoading && tools.length > 0 && tools.some(t => !t.available) && tools.some(t => t.available) && !jobId && (
            <div className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/5 p-2.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 shrink-0" />
              <p className="text-[10px] text-amber-400">Some required tools are missing. The attack will start but may fail at the missing tool step. Install missing tools and re-launch.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
