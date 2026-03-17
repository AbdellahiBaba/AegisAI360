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
import { HardDrive, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, Info, Wifi } from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all", name: "Full FTP Attack Suite", desc: "Runs all 10 FTP attack techniques — banner grab, anonymous login, default creds, path traversal, command injection, SITE commands, PASV flood, FTP bounce, directory listing, connection flood" },
  { id: "banner-grab", name: "Banner Grab + Version Fingerprint", desc: "Grabs the FTP server banner and detects software (vsftpd, ProFTPD, WU-FTPd, Pure-FTPd, FileZilla, IIS FTP) — flags known-vulnerable versions like vsftpd 2.3.4 (backdoor) and ProFTPD 1.3.3" },
  { id: "anonymous-login", name: "Anonymous Login Test", desc: "Tests USER anonymous / PASS anonymous@example.com — if code 230 is returned any unauthenticated attacker can read and write files" },
  { id: "default-creds", name: "Default Credential Brute Force (22 pairs)", desc: "Tests 22 well-known FTP credential pairs: anonymous, admin, ftp, root, guest, test, ftpuser, upload, backup — reports exact login that succeeded" },
  { id: "path-traversal", name: "Path Traversal (CWD + RETR)", desc: "Issues CWD /../../../etc/passwd and RETR commands across 9 traversal paths — detects if the server allows escaping the FTP root to read OS files" },
  { id: "command-injection", name: "USER/PASS Command Injection (6 payloads)", desc: "Injects shell metacharacters into USER field: ;ls, |id, $(id), backtick id, null-byte, SQL bypass — detects if OS commands execute" },
  { id: "site-commands", name: "SITE Command Abuse (9 commands)", desc: "Tests SITE EXEC id, SITE EXEC ls, SITE CHMOD 777, SITE CPFR/CPTO (ProFTPD RCE), SITE HELP, SITE WHOAMI — SITE CPFR is used in CVE-2015-3306" },
  { id: "bounce-attack", name: "FTP Bounce Attack (PORT command)", desc: "Sends PORT 192,168,100,1,0,21 — if server accepts (code 200) it can be used as a proxy to port-scan internal networks and third-party targets" },
  { id: "directory-listing", name: "Directory Listing (8 sensitive paths)", desc: "Tests CWD access to /, /etc, /var, /home, /root, /tmp, /var/www, /usr/local via anonymous login — reports which directories are reachable" },
  { id: "pasv-flood", name: "PASV Mode Connection Flood", desc: "Opens 50 simultaneous anonymous sessions each issuing PASV — tests if server enforces data-channel connection limits (resource exhaustion)" },
  { id: "connection-flood", name: "Control Channel Flood (100 connections)", desc: "Simultaneously opens 100 TCP connections to port 21 — measures how many are accepted before the server enforces connection limits" },
];

const STATUS_COLORS: Record<string, string> = {
  vuln: "border-red-500/50 text-red-400 bg-red-500/5",
  success: "border-green-500/50 text-green-400 bg-green-500/5",
  info: "border-border/30 text-muted-foreground",
  failed: "border-yellow-500/30 text-yellow-500/70 bg-yellow-500/5",
  error: "border-border/30 text-muted-foreground/50",
};

const STATUS_ICON: Record<string, React.ElementType> = {
  vuln: AlertTriangle,
  success: CheckCircle,
  info: Info,
  failed: ShieldAlert,
  error: Info,
};

export default function FtpAttacker() {
  useDocumentTitle("FTP Attack Suite | AegisAI360");

  const [target, setTarget] = useState("");
  const [port, setPort] = useState("21");
  const [technique, setTechnique] = useState("all");
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
      const data: any = await apiRequest("GET", `/api/offensive/ftp/status/${id}`);
      setResults(data.results ?? []);
      setSummary(data.summary ?? null);
      setActive(data.active ?? false);
      setElapsed(data.elapsed ?? 0);
      if (data.trafficLog) setTrafficLog(data.trafficLog);
      if (!data.active) {
        stopPolling();
        setJobId(null);
        toast({ title: "FTP attack complete", description: `${data.summary?.tested ?? 0} tests run, ${data.summary?.vulns ?? 0} vulnerabilities found` });
      }
    } catch {}
  }, [toast]);

  const startAttack = async () => {
    if (!target.trim()) { setError("Target hostname or IP required"); return; }
    setError(null);
    setResults([]);
    setSummary(null);
    setElapsed(0);
    try {
      const data: any = await apiRequest("POST", "/api/offensive/ftp/start", {
        target: target.trim(), port: parseInt(port) || 21, technique,
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
    try { await apiRequest("DELETE", `/api/offensive/ftp/stop/${jobId}`); } catch {}
    setActive(false);
    setJobId(null);
  };

  useEffect(() => () => stopPolling(), []);
  useEffect(() => { if (bottomRef.current) bottomRef.current.scrollIntoView({ behavior: "smooth" }); }, [results.length]);

  const selectedTech = TECHNIQUES.find((t) => t.id === technique);
  const vulnCount = results.filter((r) => r.status === "vuln").length;

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex items-center gap-3">
        <HardDrive className="w-7 h-7 text-primary" />
        <div>
          <h1 className="text-2xl font-bold text-foreground">FTP Attack Suite</h1>
          <p className="text-sm text-muted-foreground">Real FTP protocol attacks — banner grab, brute force, bounce, SITE commands, path traversal, flood</p>
        </div>
        {active && <Badge className="ml-auto bg-red-500/10 text-red-400 border-red-500/30 animate-pulse">ATTACKING</Badge>}
      </div>

      <Alert className="border-amber-500/30 bg-amber-500/5">
        <ShieldAlert className="w-4 h-4 text-amber-500" />
        <AlertDescription className="text-amber-600 dark:text-amber-400 text-xs">
          Authorized penetration testing only. Tests make real TCP connections to port 21. Only target systems you own or have explicit written authorization to test.
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
                placeholder="ftp.example.com or 192.168.1.1" disabled={active} className="text-sm" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">FTP Port</Label>
              <Input data-testid="input-port" value={port} onChange={(e) => setPort(e.target.value)}
                placeholder="21" type="number" disabled={active} className="text-sm" />
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-1.5 block">Attack Technique</Label>
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
            {error && <p className="text-xs text-red-400">{error}</p>}
            {!active ? (
              <Button data-testid="button-start" onClick={startAttack} className="w-full bg-primary text-primary-foreground">
                <HardDrive className="w-4 h-4 mr-2" /> Launch FTP Attack
              </Button>
            ) : (
              <Button data-testid="button-stop" onClick={stopAttack} variant="destructive" className="w-full">
                <Square className="w-4 h-4 mr-2" /> Stop Attack
              </Button>
            )}
          </CardContent>
        </Card>

        <div className="lg:col-span-2 space-y-4">
          {summary && (
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "Tests Run", value: summary.tested ?? 0, cls: "text-foreground" },
                { label: "Vulnerabilities", value: summary.vulns ?? 0, cls: summary.vulns > 0 ? "text-red-400" : "text-muted-foreground" },
                { label: "Elapsed", value: `${elapsed}s`, cls: "text-muted-foreground" },
              ].map(({ label, value, cls }) => (
                <Card key={label} className="text-center p-3">
                  <div className={`text-2xl font-bold ${cls}`}>{value}</div>
                  <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
                </Card>
              ))}
            </div>
          )}
          {summary?.serverBanner && (
            <Card className="border-primary/20 bg-primary/5">
              <CardContent className="p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Wifi className="w-4 h-4 text-primary" />
                  <span className="text-xs font-semibold text-primary">Server Identified: {summary.serverType ?? "Unknown"}</span>
                </div>
                <p className="text-xs text-muted-foreground font-mono">{summary.serverBanner}</p>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" />
                Live Results
                {active && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse ml-1" />}
                {vulnCount > 0 && <Badge className="ml-auto bg-red-500/10 text-red-400 border-red-500/30 text-xs">{vulnCount} VULN{vulnCount > 1 ? "S" : ""}</Badge>}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-[400px] overflow-y-auto space-y-1.5 pr-1">
                {results.length === 0 && !active && (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                    Configure a target and launch the attack
                  </div>
                )}
                {results.length === 0 && active && (
                  <div className="h-full flex items-center justify-center text-muted-foreground text-sm animate-pulse">
                    Connecting to FTP server...
                  </div>
                )}
                {results.map((r, i) => {
                  const Icon = STATUS_ICON[r.status] ?? Info;
                  return (
                    <div key={i} data-testid={`result-ftp-${i}`}
                      className={`text-xs rounded border p-2.5 font-mono ${STATUS_COLORS[r.status] ?? "border-border/30 text-muted-foreground"}`}>
                      <div className="flex items-start gap-2">
                        <Icon className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                        <div className="min-w-0">
                          <div className="font-semibold uppercase tracking-wide text-[10px] mb-0.5">{r.technique?.replace(/-/g, " ")}</div>
                          <div className="break-words leading-relaxed">{r.detail}</div>
                        </div>
                        <Badge className="ml-auto shrink-0 text-[9px] uppercase">{r.status}</Badge>
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
              title="FTP Attack Suite — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
