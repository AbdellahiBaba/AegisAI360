import { useState, useEffect, useRef } from "react";

const logTemplates = [
  { level: "INFO", color: "text-emerald-400", messages: [
    "Agent heartbeat received from WORKSTATION-{num} — Status: HEALTHY",
    "Endpoint scan completed: {host} — 0 threats detected",
    "Policy sync completed — {count} endpoints updated",
    "Threat intelligence feed refreshed — {count} new IOCs ingested",
    "Auto-protect engaged on {host} — Defense mode ACTIVE",
    "Certificate renewed for *.aegisai360.com — Valid until 2025-12-01",
    "Backup completed successfully — {count}GB encrypted archive stored",
    "Network topology scan completed — {count} assets discovered",
    "SIEM correlation engine running — {count} rules active",
    "Compliance report generated — NIST CSF score: {score}%",
  ]},
  { level: "SCAN", color: "text-cyan-400", messages: [
    "Vulnerability scan initiated on {host} — Target: {target}",
    "Port scan completed: {ip} — {count} open ports identified",
    "OWASP Top 10 assessment running on {target}",
    "CVE-2024-{cve} check: PATCHED on {count}/{total} endpoints",
    "SSL/TLS audit: {target} — Grade A+ (TLS 1.3)",
    "Hash analysis: SHA256:{hash} — Classification: BENIGN",
    "Email header analysis: SPF=pass DKIM=pass DMARC=pass",
    "Password entropy check: Policy compliance at {score}%",
  ]},
  { level: "WARN", color: "text-amber-400", messages: [
    "Suspicious outbound connection blocked: {host} → {ip}:{port}",
    "Failed login attempt #{count} on {host} from {ip}",
    "Unusual process spawned on {host}: powershell.exe -enc ...",
    "High CPU usage detected on {host} — {score}% (threshold: 90%)",
    "Expired certificate detected: {target} — Expires in {count} days",
    "Anomalous DNS query volume from {host} — {count} queries/min",
    "Privilege escalation attempt detected on {host}",
    "Unpatched system identified: {host} — {count} critical updates pending",
  ]},
  { level: "ALERT", color: "text-red-400", messages: [
    "CRITICAL: Ransomware behavior detected on {host} — ISOLATED",
    "C2 communication intercepted: {host} → {ip} — BLOCKED",
    "Lateral movement detected: {host} → {host2} via SMB",
    "Data exfiltration attempt: {host} → {ip} — {count}MB blocked",
    "Zero-day exploit signature matched on {host} — CVE-2024-{cve}",
  ]},
  { level: "RESP", color: "text-blue-400", messages: [
    "Playbook executed: Isolate-Host — Target: {host}",
    "Firewall rule added: DENY {ip}/32 — Reason: Malicious activity",
    "File quarantined: {file} on {host} — SHA256:{hash}",
    "User account locked: admin@{host} — Brute force prevention",
    "Incident #INC-{cve} created — Severity: HIGH — Assigned: SOC-Team",
  ]},
];

function randomIP() {
  return `${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function randomHost() {
  const prefixes = ["WORKSTATION", "SERVER", "DC", "NODE", "ENDPOINT"];
  return `${prefixes[Math.floor(Math.random() * prefixes.length)]}-${String(Math.floor(Math.random() * 50) + 1).padStart(2, "0")}`;
}

function generateLog(): { level: string; color: string; text: string; timestamp: string } {
  const category = logTemplates[Math.floor(Math.random() * logTemplates.length)];
  const template = category.messages[Math.floor(Math.random() * category.messages.length)];
  const now = new Date();
  const timestamp = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")} ${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;

  const text = template
    .replace("{num}", String(Math.floor(Math.random() * 50) + 1).padStart(2, "0"))
    .replace("{host}", randomHost())
    .replace("{host2}", randomHost())
    .replace("{ip}", randomIP())
    .replace("{port}", String(Math.floor(Math.random() * 65535)))
    .replace("{count}", String(Math.floor(Math.random() * 500) + 1))
    .replace("{total}", String(Math.floor(Math.random() * 200) + 100))
    .replace("{score}", String(Math.floor(Math.random() * 30) + 70))
    .replace("{target}", ["api.example.com", "portal.corp.net", "mail.aegis.io", "cdn.assets.com"][Math.floor(Math.random() * 4)])
    .replace("{cve}", String(Math.floor(Math.random() * 50000) + 10000))
    .replace("{hash}", Math.random().toString(36).substring(2, 14))
    .replace("{file}", ["svchost.exe", "update.dll", "config.bat", "payload.ps1"][Math.floor(Math.random() * 4)]);

  return { level: category.level, color: category.color, text, timestamp };
}

export function CyberTerminal() {
  const [lines, setLines] = useState<Array<{ id: number; level: string; color: string; text: string; timestamp: string; typed: string }>>([]);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const initialLines = Array.from({ length: 6 }, () => {
      idRef.current++;
      const log = generateLog();
      return { ...log, id: idRef.current, typed: log.text };
    });
    setLines(initialLines);
  }, []);

  useEffect(() => {
    const addLine = () => {
      idRef.current++;
      const log = generateLog();
      const newLine = { ...log, id: idRef.current, typed: "" };

      setLines(prev => [...prev.slice(-18), newLine]);

      let charIndex = 0;
      const typeInterval = setInterval(() => {
        charIndex++;
        if (charIndex <= log.text.length) {
          setLines(prev =>
            prev.map(l => l.id === newLine.id ? { ...l, typed: log.text.substring(0, charIndex) } : l)
          );
        } else {
          clearInterval(typeInterval);
        }
      }, 15);
    };

    const interval = setInterval(addLine, 2800);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="w-full rounded-md border border-border/50 bg-[#0a0e1a] overflow-hidden font-mono" data-testid="cyber-terminal">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-[#0d1117]">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
        </div>
        <span className="text-[10px] tracking-[0.2em] uppercase text-muted-foreground ml-2">aegis@soc-console ~ /var/log/aegis</span>
        <span className="text-[10px] text-emerald-500 ml-auto animate-pulse">MONITORING</span>
      </div>
      <div ref={scrollRef} className="p-3 max-h-[300px] overflow-y-auto scrollbar-thin" style={{ scrollBehavior: "smooth" }}>
        {lines.map((line) => (
          <div key={line.id} className="flex gap-2 py-0.5 text-[11px] leading-relaxed">
            <span className="text-muted-foreground/50 shrink-0">[{line.timestamp}]</span>
            <span className={`shrink-0 font-bold ${line.color}`}>[{line.level.padEnd(5)}]</span>
            <span className="text-emerald-300/90">
              {line.typed}
              {line.typed.length < line.text.length && <span className="text-emerald-400 animate-pulse">_</span>}
            </span>
          </div>
        ))}
        <div className="flex items-center gap-1 py-0.5 text-[11px]">
          <span className="text-emerald-500">aegis@soc $</span>
          <span className="text-emerald-400 animate-pulse">_</span>
        </div>
      </div>
    </div>
  );
}
