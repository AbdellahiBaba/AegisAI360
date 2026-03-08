import { useState, useEffect, useRef } from "react";

interface ThreatEntry {
  id: number;
  type: "BLOCKED" | "DETECTED" | "MITIGATED" | "QUARANTINED" | "ANALYZED";
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  timestamp: string;
}

const threatTypes = [
  { type: "BLOCKED" as const, severity: "critical" as const, templates: [
    "Brute Force SSH from {ip} → Port 22 ({count} attempts)",
    "RDP Exploit attempt from {ip} → Port 3389",
    "SQL Injection payload from {ip} → /api/auth",
    "Directory Traversal from {ip} → /etc/passwd",
    "Reverse Shell connection from {ip} → Port {port}",
    "Credential Stuffing from {ip} → /login ({count} attempts)",
  ]},
  { type: "DETECTED" as const, severity: "high" as const, templates: [
    "Malware C2 beacon to {ip}:{port} (Cobalt Strike)",
    "Suspicious PowerShell execution on {host}",
    "Encoded command detected on {host} (Base64)",
    "DLL Sideloading attempt on {host} — {dll}",
    "Mimikatz signature detected on {host}",
    "Registry persistence added on {host} — Run key",
  ]},
  { type: "MITIGATED" as const, severity: "medium" as const, templates: [
    "DDoS attempt {rate}Gbps from {ip} — Rate limited",
    "Port scan from {ip} — {count} ports probed, blocked",
    "ARP Spoofing detected from {mac} — Isolated",
    "DNS Tunneling to {domain} — Sinkholed",
    "Tor exit node {ip} — Geo-blocked",
  ]},
  { type: "QUARANTINED" as const, severity: "high" as const, templates: [
    "Ransomware payload quarantined on {host} — {malware}",
    "Trojan dropper isolated on {host} — SHA256:{hash}",
    "Phishing attachment quarantined — {file}",
  ]},
  { type: "ANALYZED" as const, severity: "low" as const, templates: [
    "IOC enriched: {ip} — ThreatScore {score}/100",
    "CVE-{year}-{cve} patch verified on {count} endpoints",
    "Threat intel feed updated — {count} new indicators",
    "Agent heartbeat received from {host} — All clear",
  ]},
];

function randomIP() {
  const ranges = [
    () => `${185 + Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    () => `45.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    () => `91.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    () => `103.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    () => `198.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
  ];
  return ranges[Math.floor(Math.random() * ranges.length)]();
}

function randomHost() {
  const prefixes = ["WORKSTATION", "SERVER", "ENDPOINT", "NODE", "DC"];
  return `${prefixes[Math.floor(Math.random() * prefixes.length)]}-${String(Math.floor(Math.random() * 99) + 1).padStart(2, "0")}`;
}

function generateThreat(id: number): ThreatEntry {
  const category = threatTypes[Math.floor(Math.random() * threatTypes.length)];
  const template = category.templates[Math.floor(Math.random() * category.templates.length)];
  const now = new Date();
  const timestamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;

  const message = template
    .replace("{ip}", randomIP())
    .replace("{port}", String(Math.floor(Math.random() * 65535)))
    .replace("{host}", randomHost())
    .replace("{count}", String(Math.floor(Math.random() * 5000) + 100))
    .replace("{rate}", (Math.random() * 10 + 0.5).toFixed(1))
    .replace("{mac}", `${Array.from({length: 6}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0")).join(":")}`)
    .replace("{domain}", ["evil-c2.xyz", "malware-drop.tk", "phish-kit.cc", "data-exfil.onion"][Math.floor(Math.random() * 4)])
    .replace("{malware}", ["WannaCry", "LockBit3.0", "BlackCat", "Conti", "REvil"][Math.floor(Math.random() * 5)])
    .replace("{hash}", Math.random().toString(36).substring(2, 10) + "...")
    .replace("{file}", ["invoice.pdf.exe", "report.docm", "update.scr", "readme.js"][Math.floor(Math.random() * 4)])
    .replace("{dll}", ["ntdll.dll", "kernel32.dll", "advapi32.dll"][Math.floor(Math.random() * 3)])
    .replace("{score}", String(Math.floor(Math.random() * 60) + 40))
    .replace("{year}", String(2024))
    .replace("{cve}", String(Math.floor(Math.random() * 50000) + 10000));

  return { id, type: category.type, message, severity: category.severity, timestamp };
}

const severityColors: Record<string, string> = {
  critical: "text-red-400",
  high: "text-amber-400",
  medium: "text-yellow-300",
  low: "text-emerald-400",
};

const typeColors: Record<string, string> = {
  BLOCKED: "text-red-500",
  DETECTED: "text-amber-500",
  MITIGATED: "text-yellow-400",
  QUARANTINED: "text-orange-500",
  ANALYZED: "text-emerald-500",
};

export function CyberThreatFeed() {
  const [threats, setThreats] = useState<ThreatEntry[]>(() =>
    Array.from({ length: 8 }, (_, i) => generateThreat(i))
  );
  const idRef = useRef(8);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const interval = setInterval(() => {
      idRef.current++;
      setThreats(prev => {
        const newThreat = generateThreat(idRef.current);
        return [newThreat, ...prev.slice(0, 11)];
      });
    }, 2200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full rounded-md border border-border/50 bg-black/80 backdrop-blur-sm overflow-hidden" data-testid="cyber-threat-feed">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-black/50">
        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase text-red-400">Live Threat Feed</span>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{threats.length} events</span>
      </div>
      <div ref={containerRef} className="max-h-[280px] overflow-hidden">
        {threats.map((threat, index) => (
          <div
            key={threat.id}
            className="flex items-start gap-2 px-4 py-1.5 border-b border-border/10 font-mono text-[11px] transition-all duration-500"
            style={{
              opacity: index === 0 ? 1 : Math.max(0.3, 1 - index * 0.08),
              animation: index === 0 ? "fadeSlideIn 0.4s ease-out" : undefined,
            }}
          >
            <span className="text-muted-foreground/60 shrink-0">[{threat.timestamp}]</span>
            <span className={`shrink-0 font-bold ${typeColors[threat.type]}`}>[{threat.type}]</span>
            <span className={`${severityColors[threat.severity]} truncate`}>{threat.message}</span>
          </div>
        ))}
      </div>
      <style>{`
        @keyframes fadeSlideIn {
          from { opacity: 0; transform: translateY(-12px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>
    </div>
  );
}
