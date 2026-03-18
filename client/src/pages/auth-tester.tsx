import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { apiRequest } from "@/lib/queryClient";
import {
  KeyRound, AlertTriangle, Activity, Square, ShieldAlert,
  Info, Shield, Copy, ChevronDown, ChevronRight, Zap,
  Lock, Unlock, Eye, Database, Cpu, CheckCircle,
} from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  {
    id: "all",
    name: "Full Auth Audit",
    icon: Zap,
    severity: "critical",
    desc: "All 12 modules: default credentials, SQL/NoSQL/LDAP/XPath injection, lockout bypass, rate limit evasion, JWT attacks, session security, username enumeration, password spray, MFA bypass, content-type switching",
  },
  {
    id: "default-creds",
    name: "Default Credential Spray",
    icon: KeyRound,
    severity: "high",
    desc: "Tests 300+ default credential pairs — generic defaults, vendor defaults (Cisco, Juniper, Fortinet, VMware, F5, Ubiquiti), service defaults (Jenkins, GitLab, Grafana, Kibana, Tomcat, Nagios, Zabbix), top breach passwords, keyboard walks",
  },
  {
    id: "sqli-bypass",
    name: "SQL Injection Auth Bypass",
    icon: Database,
    severity: "critical",
    desc: "48 SQLi payloads: UNION-based, time-based SLEEP/WAITFOR, error-based EXTRACTVALUE, boolean-blind, stacked queries, encoded variants, Oracle/MSSQL/PostgreSQL/SQLite specific, HTTP parameter pollution",
  },
  {
    id: "nosql-inject",
    name: "NoSQL / LDAP / XPath Injection",
    icon: Database,
    severity: "critical",
    desc: "MongoDB operators ($ne, $gt, $regex, $where, $nin, $exists, $type), array injection; LDAP wildcard/OR/AND/null-byte; XPath OR/position attacks — all tested with JSON and form-encoded bodies",
  },
  {
    id: "lockout-bypass",
    name: "Account Lockout Bypass",
    icon: Lock,
    severity: "high",
    desc: "Triggers lockout with 12 attempts, then tests: IP rotation via 5 header types across 98 IPs (X-Forwarded-For, X-Real-IP, True-Client-IP, CF-Connecting-IP, X-Client-IP), username normalization (uppercase, trailing space, null byte, @domain), 15-thread parallel race condition flood",
  },
  {
    id: "rate-limit-check",
    name: "Rate Limit Evasion",
    icon: Activity,
    severity: "medium",
    desc: "40-request burst test with rotating IPs/User-Agents, slow-drip (1 req/2s × 20 rounds), CAPTCHA/bot-detection probe — reveals if endpoint protects against high-speed or slow enumeration attacks",
  },
  {
    id: "jwt-attack",
    name: "JWT Attack Suite",
    icon: Shield,
    severity: "critical",
    desc: "Captures live JWT from login responses, tests alg:none (unsigned token), HS256 weak-secret brute force (50 common secrets: secret, password, key, jwt, app_secret…), expired token reuse, algorithm confusion (RS256→HS256), forged admin claims (role, is_admin, isAdmin)",
  },
  {
    id: "session-security",
    name: "Session Security Audit",
    icon: Shield,
    severity: "medium",
    desc: "Inspects all Set-Cookie headers for HttpOnly, Secure, SameSite flags, token length and character entropy; probes session fixation (attacker-supplied token reuse); tests concurrent session token uniqueness",
  },
  {
    id: "user-enum",
    name: "Username Enumeration",
    icon: Eye,
    severity: "medium",
    desc: "Tests 5 likely-valid vs 3 definitely-invalid usernames: timing attack (100ms+ difference = vulnerable), response body length diff (50B+ = vulnerable), error message content analysis — three independent enumeration vectors",
  },
  {
    id: "password-spray",
    name: "Password Spray",
    icon: KeyRound,
    severity: "high",
    desc: "Slow-drip spray of 28 high-frequency breach passwords (Password1!, Welcome1!, Summer2024!, Company123!…) against top usernames — paced to avoid lockout, IPs rotated via X-Forwarded-For to simulate distributed attack",
  },
  {
    id: "mfa-bypass",
    name: "MFA / 2FA Bypass",
    icon: Cpu,
    severity: "critical",
    desc: "Step-skip: direct access to 7 protected paths without MFA; 14 common OTPs (000000, 111111, 123456, 654321, 999999…) tested on 5 common MFA endpoints (/mfa, /otp, /2fa, /verify, /api/2fa) with form and JSON bodies",
  },
  {
    id: "content-type-switch",
    name: "Content-Type Switching",
    icon: Cpu,
    severity: "high",
    desc: "10 variants: JSON body, JSON with NoSQL $ne bypass, JSON with SQLi payload, XML body, XML with XXE injection, HTTP parameter pollution, multipart/form-data, JSON array injection, JSON null password, JSON empty object",
  },
];

interface AuthResult {
  technique: string;
  username: string;
  password: string;
  status: "bypassed" | "found" | "failed" | "error" | "lockout_bypass" | "info"
    | "jwt_vuln" | "session_vuln" | "enum_found" | "spray_hit" | "mfa_bypass"
    | "nosql_bypass" | "timing_vuln";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  curlCommand?: string;
  timestamp: number;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  results: AuthResult[];
  totalResults: number;
  summary: {
    bypassed: number;
    found: number;
    tested: number;
    lockoutDetected: boolean;
    jwtVulns: number;
    sessionVulns: number;
    enumFound: boolean;
    riskScore: number;
  };
  config: { target: string; loginPath: string; technique: string };
  trafficLog?: string[];
}

const STATUS_CFG: Record<string, { label: string; cls: string; dot: string }> = {
  bypassed: { label: "BYPASSED", cls: "border-red-500/60 text-red-400", dot: "bg-red-500" },
  found: { label: "FOUND", cls: "border-red-500/60 text-red-400", dot: "bg-red-500" },
  nosql_bypass: { label: "NOSQL BYPASS", cls: "border-red-500/60 text-red-400", dot: "bg-red-500" },
  mfa_bypass: { label: "MFA BYPASSED", cls: "border-red-500/60 text-red-400", dot: "bg-red-500" },
  lockout_bypass: { label: "NO LOCKOUT", cls: "border-orange-400/60 text-orange-400", dot: "bg-orange-400" },
  spray_hit: { label: "SPRAY HIT", cls: "border-orange-400/60 text-orange-400", dot: "bg-orange-400" },
  jwt_vuln: { label: "JWT VULN", cls: "border-yellow-400/60 text-yellow-400", dot: "bg-yellow-400" },
  session_vuln: { label: "SESSION VULN", cls: "border-yellow-400/60 text-yellow-400", dot: "bg-yellow-400" },
  enum_found: { label: "ENUM FOUND", cls: "border-yellow-400/60 text-yellow-400", dot: "bg-yellow-400" },
  timing_vuln: { label: "TIMING VULN", cls: "border-yellow-400/60 text-yellow-400", dot: "bg-yellow-400" },
  info: { label: "INFO", cls: "border-primary/40 text-primary", dot: "bg-primary" },
  failed: { label: "FAILED", cls: "border-border/30 text-muted-foreground", dot: "bg-muted-foreground" },
  error: { label: "ERROR", cls: "border-border/20 text-muted-foreground opacity-50", dot: "bg-muted-foreground" },
};

const SEVERITY_STATUSES = new Set(["bypassed", "found", "nosql_bypass", "mfa_bypass", "lockout_bypass", "spray_hit", "jwt_vuln", "session_vuln", "enum_found", "timing_vuln"]);

function RiskBar({ score }: { score: number }) {
  const color = score >= 60 ? "bg-red-500" : score >= 30 ? "bg-orange-400" : score >= 10 ? "bg-yellow-400" : "bg-green-500";
  const label = score >= 60 ? "CRITICAL" : score >= 30 ? "HIGH" : score >= 10 ? "MEDIUM" : score > 0 ? "LOW" : "NONE";
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-[10px] font-mono">
        <span className="text-muted-foreground">RISK SCORE</span>
        <span className={`font-bold ${score >= 60 ? "text-red-400" : score >= 30 ? "text-orange-400" : score >= 10 ? "text-yellow-400" : "text-green-400"}`}>
          {score}/100 — {label}
        </span>
      </div>
      <div className="h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all duration-500`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

function CurlCopy({ cmd }: { cmd: string }) {
  const { toast } = useToast();
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(cmd); toast({ title: "Copied curl command" }); }}
      className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-primary/30 text-primary hover:bg-primary/10 flex items-center gap-1 shrink-0"
      data-testid="button-copy-curl"
    >
      <Copy className="w-2.5 h-2.5" />curl
    </button>
  );
}

export default function AuthTesterPage() {
  useDocumentTitle("Auth Security Tester");
  const { toast } = useToast();
  const [target, setTarget] = useState("192.168.1.1");
  const [port, setPort] = useState("80");
  const [loginPath, setLoginPath] = useState("/login");
  const [usernameField, setUsernameField] = useState("username");
  const [passwordField, setPasswordField] = useState("password");
  const [technique, setTechnique] = useState("all");
  const [customUsers, setCustomUsers] = useState("");
  const [customPasswords, setCustomPasswords] = useState("");
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<JobStatus | null>(null);
  const [launching, setLaunching] = useState(false);
  const [expandedModules, setExpandedModules] = useState<Set<string>>(new Set());
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
  }, []);
  useEffect(() => () => stopPolling(), [stopPolling]);

  const pollStatus = useCallback(async (id: string) => {
    const res = await fetch(`/api/offensive/auth/status/${id}`);
    if (res.status === 404) {
      stopPolling(); setJobId(null);
      setStatus((prev) => prev ? { ...prev, active: false } : null);
      return;
    }
    const data: JobStatus = await res.json();
    setStatus(data);
    if (!data.active) {
      stopPolling(); setJobId(null);
      const risk = data.summary.riskScore;
      toast({
        title: "Auth Test Complete",
        description: risk >= 60 ? `CRITICAL risk (${risk}/100) — authentication is severely compromised`
          : risk >= 30 ? `HIGH risk (${risk}/100) — serious auth vulnerabilities found`
          : risk >= 10 ? `MEDIUM risk (${risk}/100) — some auth weaknesses detected`
          : "Auth appears secure — no critical weaknesses found",
        variant: risk > 0 ? "destructive" : "default",
      });
    }
  }, [stopPolling, toast]);

  const launch = async () => {
    setLaunching(true);
    try {
      const body: any = { target, port: parseInt(port) || 80, loginPath, usernameField, passwordField, technique };
      if (customUsers.trim()) body.customUsers = customUsers.split("\n").map((s) => s.trim()).filter(Boolean);
      if (customPasswords.trim()) body.customPasswords = customPasswords.split("\n").map((s) => s.trim()).filter(Boolean);
      const res = await apiRequest("POST", "/api/offensive/auth/start", body);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error);
      setJobId(data.jobId); setStatus(null); setExpandedModules(new Set());
      toast({ title: "Auth Test Started", description: `Testing ${loginPath} on ${target}:${port}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 1200);
    } catch (e: any) {
      toast({ title: "Launch Failed", description: e.message, variant: "destructive" });
    } finally {
      setLaunching(false);
    }
  };

  const stop = async () => {
    if (!jobId) return;
    await fetch(`/api/offensive/auth/stop/${jobId}`, { method: "DELETE" });
    stopPolling(); setJobId(null);
    toast({ title: "Test Stopped" });
  };

  const isRunning = !!jobId && status?.active;
  const criticalFindings = status?.results.filter(r => SEVERITY_STATUSES.has(r.status)) ?? [];

  // Group results by technique module
  const resultsByModule: Record<string, AuthResult[]> = {};
  for (const r of (status?.results ?? [])) {
    if (!resultsByModule[r.technique]) resultsByModule[r.technique] = [];
    resultsByModule[r.technique].push(r);
  }

  const toggleModule = (mod: string) => {
    setExpandedModules(prev => {
      const next = new Set(prev);
      next.has(mod) ? next.delete(mod) : next.add(mod);
      return next;
    });
  };

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-primary" />
          Auth Security Tester
          <Badge variant="outline" className="text-[9px] border-primary/30 text-primary ml-1">v3.0</Badge>
        </h1>
        <p className="text-xs text-muted-foreground">
          12 real-world attack modules — default creds, SQLi/NoSQL/LDAP/XPath bypass, JWT attacks, session security, username enumeration, password spray, MFA bypass, content-type switching
        </p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — Sends real HTTP requests. Only use against your own systems or with explicit written authorization.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Left column: technique picker + wordlist */}
        <div className="xl:col-span-1 space-y-3">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Attack Module</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1 p-3 pt-0">
              {TECHNIQUES.map((t) => {
                const Icon = t.icon;
                const active = technique === t.id;
                const borderColor = active ? "border-primary bg-primary/10" : "border-border/40 hover:border-primary/40";
                return (
                  <button
                    key={t.id}
                    onClick={() => !isRunning && setTechnique(t.id)}
                    disabled={isRunning}
                    data-testid={`button-auth-tech-${t.id}`}
                    className={`w-full text-left p-2.5 rounded-md border text-xs transition-all ${borderColor} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}
                  >
                    <div className="flex items-center gap-1.5">
                      <Icon className={`w-3 h-3 shrink-0 ${active ? "text-primary" : "text-muted-foreground"}`} />
                      <span className="font-semibold">{t.name}</span>
                      {t.id === "all" && <Badge variant="outline" className="text-[8px] py-0 px-1 border-primary/30 text-primary ml-auto">ALL</Badge>}
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-0.5 leading-relaxed">{t.desc}</div>
                  </button>
                );
              })}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Custom Wordlist (Optional)</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 p-3 pt-0">
              <div className="space-y-1">
                <Label className="text-xs">Usernames (one per line)</Label>
                <Textarea
                  value={customUsers}
                  onChange={(e) => setCustomUsers(e.target.value)}
                  className="text-xs font-mono h-20 resize-none"
                  placeholder={"admin\nroot\ntest"}
                  disabled={isRunning}
                  data-testid="textarea-custom-users"
                />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Passwords (one per line)</Label>
                <Textarea
                  value={customPasswords}
                  onChange={(e) => setCustomPasswords(e.target.value)}
                  className="text-xs font-mono h-20 resize-none"
                  placeholder={"password\n123456\nadmin123"}
                  disabled={isRunning}
                  data-testid="textarea-custom-passwords"
                />
              </div>
              <p className="text-[10px] text-muted-foreground">Custom creds are combined with the built-in 300+ pair list</p>
            </CardContent>
          </Card>
        </div>

        {/* Right column: config + results */}
        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Login Endpoint Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 p-4 pt-0">
              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2 space-y-1">
                  <Label className="text-xs">Target Host</Label>
                  <Input value={target} onChange={(e) => setTarget(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-target" placeholder="192.168.1.1 or myapp.com" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Port</Label>
                  <Input value={port} onChange={(e) => setPort(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-port" />
                </div>
              </div>

              <div className="space-y-1">
                <Label className="text-xs">Login Path</Label>
                <Input value={loginPath} onChange={(e) => setLoginPath(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-path" placeholder="/login or /api/auth or /wp-login.php" />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Username Field</Label>
                  <Input value={usernameField} onChange={(e) => setUsernameField(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-ufield" placeholder="username, email, user…" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Password Field</Label>
                  <Input value={passwordField} onChange={(e) => setPasswordField(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-pfield" placeholder="password, pass, pwd…" />
                </div>
              </div>

              <p className="text-[10px] text-muted-foreground font-mono bg-muted/30 rounded p-2">
                POST {loginPath} → {usernameField}=PAYLOAD&amp;{passwordField}=PAYLOAD
              </p>

              {/* Live status dashboard */}
              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-green-400 animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">
                        {isRunning ? `TESTING ${status?.config.target}${status?.config.loginPath}` : "COMPLETE"}
                      </span>
                    </div>
                    {status && <span className="text-[10px] font-mono text-muted-foreground">{status.elapsed}s elapsed</span>}
                  </div>

                  {status?.summary && <RiskBar score={status.summary.riskScore} />}

                  <div className="grid grid-cols-6 gap-1.5 text-xs font-mono">
                    {[
                      { val: status?.summary.bypassed ?? 0, label: "BYPASS", crit: true },
                      { val: status?.summary.found ?? 0, label: "FOUND", crit: true },
                      { val: status?.summary.jwtVulns ?? 0, label: "JWT", crit: false },
                      { val: status?.summary.sessionVulns ?? 0, label: "SESSION", crit: false },
                      { val: status?.summary.tested ?? 0, label: "TESTED", crit: false },
                      { val: status?.summary.lockoutDetected ? "YES" : "NO", label: "LOCKOUT", crit: false },
                    ].map((item, i) => (
                      <div key={i} className="text-center p-1.5 rounded bg-muted/20">
                        <div className={`text-sm font-bold ${(typeof item.val === "number" ? item.val > 0 : item.val === "NO") && item.crit ? "text-red-400" : item.val === "YES" ? "text-green-400" : ""}`}>
                          {item.val}
                        </div>
                        <div className="text-[8px] text-muted-foreground">{item.label}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                {!isRunning
                  ? <Button onClick={launch} disabled={launching} className="flex-1" data-testid="button-launch-auth">
                      {launching ? <><Activity className="w-4 h-4 me-2 animate-spin" />Launching...</> : <><KeyRound className="w-4 h-4 me-2" />Start Auth Test</>}
                    </Button>
                  : <Button onClick={stop} variant="destructive" className="flex-1" data-testid="button-stop-auth">
                      <Square className="w-4 h-4 me-2" />Stop Test
                    </Button>
                }
              </div>
            </CardContent>
          </Card>

          {/* Critical findings */}
          {criticalFindings.length > 0 && (
            <Card className="border-red-500/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-red-400 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Critical Findings ({criticalFindings.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 p-4 pt-0">
                {criticalFindings.map((r, i) => {
                  const cfg = STATUS_CFG[r.status] || STATUS_CFG.info;
                  return (
                    <div key={i} className="p-3 border border-red-500/20 rounded-md bg-red-500/5 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <div className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                          <Badge variant="outline" className={`text-[9px] ${cfg.cls}`}>{cfg.label}</Badge>
                          <span className="text-[10px] font-mono text-muted-foreground">{r.technique}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {r.statusCode && <span className="text-[10px] font-mono text-muted-foreground">HTTP {r.statusCode}</span>}
                          {r.responseTime && <span className="text-[10px] font-mono text-muted-foreground">{r.responseTime}ms</span>}
                          {r.curlCommand && <CurlCopy cmd={r.curlCommand} />}
                        </div>
                      </div>
                      {(r.username || r.password) && !["lockout_bypass", "info", "session_vuln", "enum_found", "timing_vuln"].includes(r.status) && (
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                          <div className="bg-muted/30 rounded p-1.5">user: <span className="text-primary">{r.username.slice(0, 40)}</span></div>
                          <div className="bg-muted/30 rounded p-1.5">pass: <span className="text-primary">{r.password.slice(0, 40)}</span></div>
                        </div>
                      )}
                      {r.evidence && <div className="text-[10px] text-muted-foreground bg-muted/20 rounded p-1.5 leading-relaxed">{r.evidence}</div>}
                      {r.curlCommand && (
                        <div className="text-[10px] font-mono bg-black/30 text-green-400 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
                          {r.curlCommand}
                        </div>
                      )}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Results grouped by module */}
          {status && Object.keys(resultsByModule).length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider">Results by Module</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 p-4 pt-0">
                {Object.entries(resultsByModule).map(([mod, results]) => {
                  const sevCount = results.filter(r => SEVERITY_STATUSES.has(r.status)).length;
                  const expanded = expandedModules.has(mod);
                  return (
                    <div key={mod} className={`border rounded-md overflow-hidden ${sevCount > 0 ? "border-red-500/20" : "border-border/30"}`}>
                      <button
                        onClick={() => toggleModule(mod)}
                        className="w-full flex items-center justify-between p-2.5 text-left hover:bg-muted/20 transition-colors"
                        data-testid={`button-module-${mod}`}
                      >
                        <div className="flex items-center gap-2">
                          {expanded ? <ChevronDown className="w-3 h-3 text-muted-foreground" /> : <ChevronRight className="w-3 h-3 text-muted-foreground" />}
                          <span className="text-xs font-mono font-semibold">{mod}</span>
                          <span className="text-[10px] text-muted-foreground">({results.length} results)</span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          {sevCount > 0 && <Badge variant="outline" className="text-[8px] border-red-500/40 text-red-400">{sevCount} finding{sevCount > 1 ? "s" : ""}</Badge>}
                          {results.some(r => r.status === "info" && !SEVERITY_STATUSES.has(r.status)) && <Badge variant="outline" className="text-[8px] border-primary/30 text-primary">{results.filter(r => !SEVERITY_STATUSES.has(r.status) && r.status !== "failed").length} info</Badge>}
                        </div>
                      </button>
                      {expanded && (
                        <div className="border-t border-border/30 divide-y divide-border/20">
                          {results.map((r, i) => {
                            const cfg = STATUS_CFG[r.status] || STATUS_CFG.info;
                            const isSev = SEVERITY_STATUSES.has(r.status);
                            return (
                              <div key={i} className={`p-2 text-xs ${isSev ? "bg-red-500/5" : ""}`}>
                                <div className="flex items-center justify-between gap-2">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${cfg.dot}`} />
                                    <Badge variant="outline" className={`text-[8px] py-0 shrink-0 ${cfg.cls}`}>{cfg.label}</Badge>
                                    <span className="font-mono text-[10px] truncate text-muted-foreground">
                                      {r.username.slice(0, 30)}{r.username.length > 30 ? "…" : ""}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-1.5 shrink-0">
                                    {r.statusCode ? <span className="text-[10px] font-mono text-muted-foreground">HTTP {r.statusCode}</span> : null}
                                    {r.responseTime ? <span className="text-[10px] font-mono text-muted-foreground">{r.responseTime}ms</span> : null}
                                    {r.curlCommand && <CurlCopy cmd={r.curlCommand} />}
                                  </div>
                                </div>
                                {r.evidence && isSev && (
                                  <div className="mt-1 text-[10px] text-muted-foreground pl-5 leading-relaxed">{r.evidence}</div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {/* Completion state when nothing found */}
          {status && !isRunning && criticalFindings.length === 0 && status.results.length > 0 && (
            <Card className="border-green-500/30">
              <CardContent className="p-4">
                <div className="flex items-center gap-2 text-green-400">
                  <CheckCircle className="w-4 h-4" />
                  <span className="text-sm font-semibold">No Critical Findings</span>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {status.summary.tested} tests completed — no authentication bypasses, credential successes, JWT vulnerabilities, or session weaknesses detected.
                  {status.summary.lockoutDetected ? " Account lockout protection is active." : " Note: no lockout detected — consider adding one."}
                </p>
              </CardContent>
            </Card>
          )}

          {/* Traffic log */}
          {status && (
            <TrafficConsole
              trafficLog={status.trafficLog ?? []}
              active={isRunning}
              title="Auth Tester — Live Traffic"
            />
          )}
        </div>
      </div>
    </div>
  );
}
