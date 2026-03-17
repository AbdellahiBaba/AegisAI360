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
import { KeyRound, AlertTriangle, Activity, Square, ShieldAlert, CheckCircle, XCircle, Info, Shield } from "lucide-react";
import { TrafficConsole } from "@/components/traffic-console";

const TECHNIQUES = [
  { id: "all", name: "Full Auth Audit", desc: "All techniques: default credentials, SQLi bypass, lockout bypass, rate limit check" },
  { id: "default-creds", name: "Default Credential Spray", desc: "Tests 26 common default credential pairs (admin/admin, root/root, admin/password, etc.) against your login endpoint" },
  { id: "sqli-bypass", name: "SQLi Auth Bypass", desc: "Injects 11 SQL injection patterns into login fields — tests if authentication can be bypassed without valid credentials" },
  { id: "lockout-bypass", name: "Account Lockout Bypass", desc: "Fires 10 failed attempts and checks if lockout triggers. Then tests header spoofing (X-Forwarded-For) to bypass IP lockout" },
  { id: "rate-limit-check", name: "Rate Limit Check", desc: "Sends 20 rapid requests to detect if the endpoint enforces rate limiting (HTTP 429)" },
];

interface AuthResult {
  technique: string;
  username: string;
  password: string;
  status: "bypassed" | "found" | "failed" | "error" | "lockout_bypass" | "info";
  statusCode?: number;
  responseTime?: number;
  evidence?: string;
  timestamp: number;
}

interface JobStatus {
  jobId: string;
  active: boolean;
  elapsed: number;
  results: AuthResult[];
  totalResults: number;
  summary: { bypassed: number; found: number; tested: number; lockoutDetected: boolean };
  config: { target: string; loginPath: string; technique: string };
  trafficLog?: string[];
}

const STATUS_BADGE: Record<string, { label: string; cls: string }> = {
  bypassed: { label: "BYPASSED", cls: "border-severity-critical/50 text-severity-critical" },
  found: { label: "FOUND", cls: "border-severity-critical/50 text-severity-critical" },
  lockout_bypass: { label: "NO LOCKOUT", cls: "border-severity-high/50 text-severity-high" },
  info: { label: "INFO", cls: "border-primary/40 text-primary" },
  failed: { label: "FAILED", cls: "border-border/40 text-muted-foreground" },
  error: { label: "ERROR", cls: "border-border/30 text-muted-foreground opacity-60" },
};

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
      const issues = data.summary.bypassed + data.summary.found;
      toast({
        title: "Auth Test Complete",
        description: issues > 0
          ? `${issues} authentication vulnerability/vulnerabilities found!`
          : data.summary.lockoutDetected
          ? "Auth appears secure — lockout protection active"
          : "No credentials found, but check lockout bypass results",
        variant: issues > 0 ? "destructive" : "default",
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
      setJobId(data.jobId); setStatus(null);
      toast({ title: "Auth Test Started", description: `Testing ${loginPath} on ${target}:${port}` });
      pollRef.current = setInterval(() => pollStatus(data.jobId), 1000);
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
  const highPriorityResults = status?.results.filter((r) => r.status === "bypassed" || r.status === "found" || r.status === "lockout_bypass") ?? [];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <KeyRound className="w-5 h-5 text-primary" />
          Auth Security Tester
        </h1>
        <p className="text-xs text-muted-foreground">Tests your login endpoint for default credentials, SQL injection bypass, account lockout bypass, and rate limiting — all with real HTTP requests</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs">
          <span className="font-semibold">Authorized Testing Only</span> — Sends real authentication requests to the target. Only use against your own applications or with explicit written authorization.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-1 space-y-3">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Test Type</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {TECHNIQUES.map((t) => (
                <button key={t.id} onClick={() => !isRunning && setTechnique(t.id)} disabled={isRunning}
                  data-testid={`button-auth-tech-${t.id}`}
                  className={`w-full text-left p-2.5 rounded-md border text-xs transition-all ${technique === t.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"} ${isRunning ? "opacity-40 cursor-not-allowed" : ""}`}>
                  <div className="font-semibold">{t.name}</div>
                  <div className="text-[10px] text-muted-foreground mt-0.5">{t.desc}</div>
                </button>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Custom Wordlist (Optional)</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1">
                <Label className="text-xs">Usernames (one per line)</Label>
                <Textarea value={customUsers} onChange={(e) => setCustomUsers(e.target.value)} className="text-xs font-mono h-20 resize-none" placeholder={"admin\nroot\ntest"} disabled={isRunning} data-testid="textarea-custom-users" />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Passwords (one per line)</Label>
                <Textarea value={customPasswords} onChange={(e) => setCustomPasswords(e.target.value)} className="text-xs font-mono h-20 resize-none" placeholder={"password\n123456\nadmin123"} disabled={isRunning} data-testid="textarea-custom-passwords" />
              </div>
              <p className="text-[10px] text-muted-foreground">Leave blank to use the built-in default credentials list (26 pairs)</p>
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">Login Endpoint Configuration</CardTitle></CardHeader>
            <CardContent className="space-y-4">
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
                  <Label className="text-xs">Username Field Name</Label>
                  <Input value={usernameField} onChange={(e) => setUsernameField(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-ufield" placeholder="username, email, user..." />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Password Field Name</Label>
                  <Input value={passwordField} onChange={(e) => setPasswordField(e.target.value)} className="h-8 text-xs font-mono" disabled={isRunning} data-testid="input-auth-pfield" placeholder="password, pass, pwd..." />
                </div>
              </div>

              <p className="text-[10px] text-muted-foreground font-mono bg-muted/30 rounded p-2">
                POST {loginPath} → {usernameField}=PAYLOAD&{passwordField}=PAYLOAD
              </p>

              {(isRunning || status) && (
                <div className="p-3 border border-primary/20 rounded-md bg-primary/5 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${isRunning ? "bg-status-online animate-pulse" : "bg-muted-foreground"}`} />
                      <span className="text-xs font-mono font-semibold">{isRunning ? `TESTING ${status?.config.target}${status?.config.loginPath}` : "COMPLETE"}</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-xs font-mono">
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.bypassed ?? 0) > 0 ? "text-severity-critical" : "text-foreground"}`}>{status?.summary.bypassed ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">BYPASSED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${(status?.summary.found ?? 0) > 0 ? "text-severity-critical" : "text-foreground"}`}>{status?.summary.found ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">FOUND</div>
                    </div>
                    <div className="text-center">
                      <div className="text-base font-bold">{status?.summary.tested ?? 0}</div>
                      <div className="text-[9px] text-muted-foreground">TESTED</div>
                    </div>
                    <div className="text-center">
                      <div className={`text-base font-bold ${status?.summary.lockoutDetected ? "text-status-online" : "text-severity-high"}`}>{status?.summary.lockoutDetected ? "YES" : "NO"}</div>
                      <div className="text-[9px] text-muted-foreground">LOCKOUT</div>
                    </div>
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

          {highPriorityResults.length > 0 && (
            <Card className="border-severity-critical/30">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs uppercase tracking-wider text-severity-critical flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4" />
                  Critical Findings ({highPriorityResults.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {highPriorityResults.map((r, i) => {
                  const b = STATUS_BADGE[r.status];
                  return (
                    <div key={i} className="p-3 border border-severity-critical/20 rounded-md bg-severity-critical/5 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <Badge variant="outline" className={`text-[9px] ${b.cls}`}>{b.label}</Badge>
                        <span className="text-[10px] font-mono text-muted-foreground">{r.technique}</span>
                      </div>
                      {r.status !== "lockout_bypass" && r.status !== "info" && (
                        <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
                          <div className="bg-muted/30 rounded p-1.5">user: <span className="text-primary">{r.username}</span></div>
                          <div className="bg-muted/30 rounded p-1.5">pass: <span className="text-primary">{r.password}</span></div>
                        </div>
                      )}
                      {r.evidence && <div className="text-[10px] text-muted-foreground bg-muted/20 rounded p-1.5">{r.evidence}</div>}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}

          {status && status.results.length > 0 && (
            <Card>
              <CardHeader className="pb-2"><CardTitle className="text-xs uppercase tracking-wider">All Test Results</CardTitle></CardHeader>
              <CardContent>
                <div className="space-y-1 max-h-64 overflow-y-auto">
                  {[...status.results].reverse().map((r, i) => {
                    const b = STATUS_BADGE[r.status];
                    return (
                      <div key={i} className={`p-2 rounded-md border text-xs flex items-center justify-between gap-2 ${r.status === "bypassed" || r.status === "found" ? "border-severity-critical/30 bg-severity-critical/5" : "border-border/30"}`}>
                        <div className="flex items-center gap-2 min-w-0">
                          <Badge variant="outline" className={`text-[8px] py-0 shrink-0 ${b.cls}`}>{b.label}</Badge>
                          <span className="font-mono text-[10px] truncate">{r.username} / {r.password.slice(0, 20)}</span>
                        </div>
                        <div className="text-[10px] font-mono text-muted-foreground shrink-0">
                          {r.statusCode ? `HTTP ${r.statusCode}` : ""} {r.responseTime ? `· ${r.responseTime}ms` : ""}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

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
