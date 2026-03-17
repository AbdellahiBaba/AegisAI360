import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import { Network, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, Info } from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all", name: "Full Protocol Suite (12 protocols)", desc: "SSH, SMTP, SNMP, Redis, MongoDB, Telnet, RDP, MySQL, SMB, Memcached, LDAP, VNC — tests all simultaneously for maximum coverage" },
  { id: "ssh", name: "SSH (Port 22)", desc: "Banner grab + version detection, SSH-1.x deprecation check, weak implementation detection (Dropbear), protocol handshake test — flags known-vulnerable SSH versions" },
  { id: "smtp", name: "SMTP (Port 25)", desc: "Banner + EHLO, STARTTLS detection, VRFY user enumeration (9 common usernames), open relay test, SMTP header injection via MAIL FROM" },
  { id: "snmp", name: "SNMP (Port 161/UDP)", desc: "Brute-forces 14 community strings (public, private, community, admin, manager, cisco, secret) — sends real SNMP GET-REQUEST packets for sysDescr OID" },
  { id: "redis", name: "Redis (Port 6379)", desc: "PING test for unauthenticated access, then KEYS *, CONFIG GET *, CLIENT LIST, CONFIG SET dir/dbfilename — detects Redis RCE via file write if auth-free" },
  { id: "mongodb", name: "MongoDB (Port 27017)", desc: "Sends MongoDB wire protocol OP_MSG listDatabases — detects if the database is accessible without authentication" },
  { id: "telnet", name: "Telnet (Port 23)", desc: "Banner grab + unencrypted protocol alert, credential brute force with 6 default pairs — flags plaintext credential exposure" },
  { id: "rdp", name: "RDP (Port 3389)", desc: "Sends X.224 connection request — detects if NLA (Network Level Authentication) is enforced, flags BlueKeep/DejaBlue vulnerability window (CVE-2019-0708)" },
  { id: "mysql", name: "MySQL (Port 3306)", desc: "Banner grab + version detection, flags versions < 5.7 with known critical vulnerabilities, checks public exposure of auth handshake" },
  { id: "smb", name: "SMB (Port 445)", desc: "Sends SMB1 negotiate request — detects SMB version (SMB1 vs SMB2/3), flags EternalBlue vulnerability (MS17-010 / WannaCry / NotPetya)" },
  { id: "memcached", name: "Memcached (Port 11211)", desc: "Issues stats and get * commands — detects unauthenticated access, reports version, flags DRDoS amplification risk (x51,000 amplification factor)" },
  { id: "ldap", name: "LDAP (Port 389)", desc: "Sends anonymous bind request — detects if LDAP directory allows unauthenticated reads which could expose all users, groups, and OUs" },
  { id: "vnc", name: "VNC (Port 5900)", desc: "Banner grab + RFB version detection, tests for no-auth security type (security type 1 = None) — reports if remote desktop requires no password" },
];

const STATUS_COLORS: Record<string, string> = {
  vuln: "border-red-500/50 text-red-400 bg-red-500/5",
  info: "border-border/30 text-muted-foreground",
  failed: "border-yellow-500/30 text-yellow-500/70 bg-yellow-500/5",
  error: "border-border/30 text-muted-foreground/50",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  vuln: AlertTriangle,
  info: Info,
  failed: ShieldAlert,
  error: Info,
};

const PROTOCOL_PORT: Record<string, number> = {
  ssh: 22, smtp: 25, snmp: 161, redis: 6379, mongodb: 27017,
  telnet: 23, rdp: 3389, mysql: 3306, smb: 445, memcached: 11211,
  ldap: 389, vnc: 5900,
};

export default function ProtocolAttacker() {
  useDocumentTitle("Protocol Suite Attacker | AegisAI360");

  const [target, setTarget] = useState("");
  const [technique, setTechnique] = useState("all");
  const [customPorts, setCustomPorts] = useState<Record<string, string>>({});
  const [jobId, setJobId] = useState<string | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [active, setActive] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [trafficLog, setTrafficLog] = useState<string[]>([]);
  const pollRef = useRef<NodeJS.Timeout | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };

  const poll = useCallback(async (id: string) => {
    try {
      const data: any = await apiRequest("GET", `/api/offensive/protocol/status/${id}`);
      setResults(data.results ?? []);
      setSummary(data.summary ?? null);
      setActive(data.active ?? false);
      setElapsed(data.elapsed ?? 0);
      if (data.trafficLog) setTrafficLog(data.trafficLog);
      if (!data.active) {
        stopPolling();
        setJobId(null);
        toast({ title: "Protocol scan complete", description: `${data.summary?.tested ?? 0} tests, ${data.summary?.vulns ?? 0} vulnerabilities found` });
      }
    } catch {}
  }, [toast]);

  const startAttack = async () => {
    if (!target.trim()) { setError("Target hostname or IP required"); return; }
    setError(null);
    setResults([]);
    setSummary(null);
    setElapsed(0);
    const ports: Record<string, number> = {};
    Object.entries(customPorts).forEach(([k, v]) => { if (v) ports[k] = (parseInt(v) || PROTOCOL_PORT[k]) ?? 0; });
    try {
      const data: any = await apiRequest("POST", "/api/offensive/protocol/start", {
        target: target.trim(), technique, customPorts: Object.keys(ports).length > 0 ? ports : undefined,
      });
      setJobId(data.jobId);
      setActive(true);
      pollRef.current = setInterval(() => poll(data.jobId), 1200);
    } catch (e: any) {
      setError(e.message ?? "Failed to start");
    }
  };

  const stopAttack = async () => {
    if (!jobId) return;
    stopPolling();
    try { await apiRequest("DELETE", `/api/offensive/protocol/stop/${jobId}`); } catch {}
    setActive(false);
    setJobId(null);
  };

  useEffect(() => () => stopPolling(), []);
  useEffect(() => { if (bottomRef.current) bottomRef.current.scrollIntoView({ behavior: "smooth" }); }, [results.length]);

  const selectedTech = TECHNIQUES.find((t) => t.id === technique);
  const vulnCount = results.filter((r) => r.status === "vuln").length;
  const openPorts = results.filter((r) => r.status !== "failed" && r.status !== "error");
  const protocols = [...new Set(results.map((r) => r.protocol))];

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center gap-3">
        <Network className="w-7 h-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold text-foreground">Protocol Suite Attacker</h1>
          <p className="text-sm text-muted-foreground">12 protocols — SSH, SMTP, SNMP, Redis, MongoDB, Telnet, RDP, MySQL, SMB, Memcached, LDAP, VNC</p>
        </div>
        {active && <Badge className="ml-auto bg-red-500/10 text-red-400 border-red-500/30 animate-pulse">SCANNING</Badge>}
      </div>

      <Alert className="border-amber-500/30 bg-amber-500/5">
        <ShieldAlert className="w-4 h-4 text-amber-500" />
        <AlertDescription className="text-amber-600 dark:text-amber-400 text-xs">
          Authorized penetration testing only. Real TCP/UDP connections are made to target ports. Only test systems you own or have explicit written authorization to test.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Target Configuration</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">Target Host</Label>
              <Input data-testid="input-target" value={target} onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.1 or hostname" disabled={active} className="text-sm" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">Protocol / Technique</Label>
              <Select value={technique} onValueChange={setTechnique} disabled={active}>
                <SelectTrigger data-testid="select-technique" className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TECHNIQUES.map((t) => (
                    <SelectItem key={t.id} value={t.id} className="text-xs">{t.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {selectedTech && (
              <p className="text-xs text-muted-foreground leading-relaxed border-l-2 border-primary/30 pl-3">
                {selectedTech.desc}
              </p>
            )}
            {technique !== "all" && PROTOCOL_PORT[technique] && (
              <div>
                <Label className="text-xs text-muted-foreground mb-1.5 block">Custom Port (default: {PROTOCOL_PORT[technique]})</Label>
                <Input data-testid="input-custom-port" value={customPorts[technique] ?? ""} type="number"
                  onChange={(e) => setCustomPorts((p) => ({ ...p, [technique]: e.target.value }))}
                  placeholder={String(PROTOCOL_PORT[technique])} disabled={active} className="text-sm" />
              </div>
            )}
            {error && <p className="text-xs text-red-400">{error}</p>}
            {!active ? (
              <Button data-testid="button-start" onClick={startAttack} className="w-full bg-primary text-primary-foreground">
                <Network className="w-4 h-4 mr-2" /> Launch Protocol Scan
              </Button>
            ) : (
              <Button data-testid="button-stop" onClick={stopAttack} variant="destructive" className="w-full">
                <Square className="w-4 h-4 mr-2" /> Stop Scan
              </Button>
            )}
          </CardContent>
        </Card>

        <div className="lg:col-span-2 space-y-4">
          {summary && (
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Tests Run", value: summary.tested ?? 0, cls: "text-foreground" },
                { label: "Vulnerabilities", value: summary.vulns ?? 0, cls: summary.vulns > 0 ? "text-red-400" : "text-muted-foreground" },
                { label: "Open Ports", value: summary.open ?? 0, cls: "text-primary" },
                { label: "Elapsed", value: `${elapsed}s`, cls: "text-muted-foreground" },
              ].map(({ label, value, cls }) => (
                <Card key={label} className="text-center p-3">
                  <div className={`text-xl font-bold ${cls}`}>{value}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
                </Card>
              ))}
            </div>
          )}

          {protocols.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {protocols.map((p) => {
                const hasVuln = results.some((r) => r.protocol === p && r.status === "vuln");
                return (
                  <Badge key={p} data-testid={`badge-protocol-${p}`}
                    className={hasVuln ? "bg-red-500/10 text-red-400 border-red-500/30" : "bg-primary/10 text-primary border-primary/20"}>
                    {p}
                  </Badge>
                );
              })}
            </div>
          )}

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" />
                Live Scan Results
                {active && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse ml-1" />}
                {vulnCount > 0 && <Badge className="ml-auto bg-red-500/10 text-red-400 border-red-500/30 text-xs">{vulnCount} VULN{vulnCount > 1 ? "S" : ""}</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-[420px] overflow-y-auto space-y-1.5 pr-1">
                {results.length === 0 && !active && (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                    Configure a target and launch the scan
                  </div>
                )}
                {results.length === 0 && active && (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm animate-pulse">
                    Probing protocols...
                  </div>
                )}
                {results.map((r, i) => {
                  const Icon = STATUS_ICON[r.status] ?? Info;
                  return (
                    <div key={i} data-testid={`result-protocol-${i}`}
                      className={`text-xs rounded border p-2.5 font-mono ${STATUS_COLORS[r.status] ?? "border-border/30 text-muted-foreground"}`}>
                      <div className="flex items-start gap-2">
                        <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="font-semibold text-[10px] uppercase tracking-wide">{r.protocol}</span>
                            <span className="text-muted-foreground/50">port {r.port}</span>
                          </div>
                          <div className="break-words leading-relaxed">{r.detail}</div>
                        </div>
                        <Badge className={`ml-auto shrink-0 text-[9px] uppercase ${r.status === "vuln" ? "bg-red-500/10 text-red-400 border-red-500/30" : ""}`}>
                          {r.status}
                        </Badge>
                      </div>
                    </div>
                  );
                })}
                <div ref={bottomRef} />
              </div>
            </CardContent>
          </Card>

          {(results.length > 0 || active) && (
            <TrafficConsole
              trafficLog={trafficLog}
              active={active}
              title="Protocol Suite Attacker — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
