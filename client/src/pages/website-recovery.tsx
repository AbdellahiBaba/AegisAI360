import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  RotateCcw, Globe, Shield, Search, AlertTriangle, CheckCircle2,
  XCircle, Loader2, Terminal, Download, Clock, ArrowRight,
  Server, Lock, FileWarning, Eye, Zap, Bug, ShieldAlert,
  ChevronRight, ExternalLink, Copy, FileText,
} from "lucide-react";

interface RecoveryFinding {
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
  timestamp: number;
}

interface RecoveryPhase {
  name: string;
  status: "pending" | "running" | "complete" | "error";
  progress: number;
  findings: RecoveryFinding[];
}

interface RecoverySummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  adminPanelsFound: string[];
  techStack: string[];
  openPorts: number[];
  exposedFiles: string[];
  vulnerabilities: string[];
  recommendations: string[];
}

interface RecoveryOperation {
  id: string;
  targetUrl: string;
  status: "running" | "complete" | "error";
  startedAt: number;
  completedAt?: number;
  phases: RecoveryPhase[];
  logs: string[];
  summary?: RecoverySummary;
}

interface HistoryItem {
  id: string;
  targetUrl: string;
  status: string;
  startedAt: number;
  completedAt?: number;
  totalFindings: number;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string; icon: typeof AlertTriangle }> = {
  critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", icon: XCircle },
  high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertTriangle },
  medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: ShieldAlert },
  low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", icon: Eye },
  info: { color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/30", icon: FileText },
};

const PHASE_ICONS = [Search, Globe, Bug, Zap, FileText];

export default function WebsiteRecoveryPage() {
  const { toast } = useToast();
  const [targetUrl, setTargetUrl] = useState("");
  const [currentOp, setCurrentOp] = useState<RecoveryOperation | null>(null);
  const [isStarting, setIsStarting] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState("scan");
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const logContainerRef = useRef<HTMLDivElement>(null);

  const fetchHistory = useCallback(async () => {
    try {
      const resp = await fetch("/api/website-recovery/history", { credentials: "include" });
      if (resp.ok) {
        const data = await resp.json();
        setHistory(data);
      }
    } catch {}
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [currentOp?.logs]);

  const pollStatus = useCallback((operationId: string) => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    pollingRef.current = setInterval(async () => {
      try {
        const resp = await fetch(`/api/website-recovery/status/${operationId}`, { credentials: "include" });
        if (resp.ok) {
          const data: RecoveryOperation = await resp.json();
          setCurrentOp(data);
          if (data.status === "complete" || data.status === "error") {
            if (pollingRef.current) clearInterval(pollingRef.current);
            pollingRef.current = null;
            fetchHistory();
            if (data.status === "complete") {
              toast({ title: "Recovery Complete", description: `Found ${data.summary?.totalFindings || 0} findings for ${data.targetUrl}` });
            }
          }
        }
      } catch {}
    }, 1500);
  }, [fetchHistory, toast]);

  useEffect(() => {
    return () => { if (pollingRef.current) clearInterval(pollingRef.current); };
  }, []);

  const startRecovery = async () => {
    if (!targetUrl.trim()) return;
    let url = targetUrl.trim();
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
      setTargetUrl(url);
    }

    setIsStarting(true);
    try {
      const resp = await apiRequest("POST", "/api/website-recovery/start", { url });
      const data = await resp.json();
      setCurrentOp(null);
      pollStatus(data.operationId);
      setActiveTab("scan");
      toast({ title: "Recovery Started", description: `Scanning ${url}...` });
    } catch (err: any) {
      toast({ title: "Error", description: err.message || "Failed to start recovery", variant: "destructive" });
    } finally {
      setIsStarting(false);
    }
  };

  const loadOperation = async (id: string) => {
    try {
      const resp = await fetch(`/api/website-recovery/status/${id}`, { credentials: "include" });
      if (resp.ok) {
        const data: RecoveryOperation = await resp.json();
        setCurrentOp(data);
        setActiveTab("scan");
        if (data.status === "running") {
          pollStatus(id);
        }
      }
    } catch {}
  };

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      toast({ title: "Copied", description: "Copied to clipboard" });
    });
  };

  const overallProgress = currentOp
    ? Math.floor(currentOp.phases.reduce((acc, p) => acc + p.progress, 0) / currentOp.phases.length)
    : 0;

  const allFindings = currentOp ? currentOp.phases.flatMap(p => p.findings) : [];

  return (
    <div className="min-h-screen bg-background p-4 md:p-6 space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2" data-testid="text-page-title">
            <RotateCcw className="w-6 h-6 text-amber-400" />
            Emergency Website Recovery
          </h1>
          <p className="text-sm text-muted-foreground mt-1" data-testid="text-page-description">
            Regain control of your compromised website with automated reconnaissance, vulnerability assessment, and recovery
          </p>
        </div>
        {currentOp?.status === "running" && (
          <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 animate-pulse" data-testid="badge-operation-running">
            <Loader2 className="w-3 h-3 mr-1 animate-spin" />
            Recovery in progress... {overallProgress}%
          </Badge>
        )}
      </div>

      <Card className="border-amber-500/20 bg-gradient-to-r from-amber-500/5 to-transparent">
        <CardContent className="pt-6">
          <div className="flex flex-col md:flex-row gap-3">
            <div className="flex-1 relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Enter compromised website URL (e.g., https://example.com)"
                className="pl-10 h-11 bg-background"
                onKeyDown={(e) => e.key === "Enter" && startRecovery()}
                disabled={isStarting || currentOp?.status === "running"}
                data-testid="input-target-url"
              />
            </div>
            <Button
              onClick={startRecovery}
              disabled={!targetUrl.trim() || isStarting || currentOp?.status === "running"}
              className="h-11 px-6 bg-amber-600 hover:bg-amber-700 text-white"
              data-testid="button-start-recovery"
            >
              {isStarting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Shield className="w-4 h-4 mr-2" />}
              {isStarting ? "Initializing..." : "Start Recovery"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30" data-testid="tabs-main">
          <TabsTrigger value="scan" className="text-xs" data-testid="tab-scan">
            <Search className="w-3 h-3 mr-1" />Scan
          </TabsTrigger>
          <TabsTrigger value="findings" className="text-xs" data-testid="tab-findings">
            <AlertTriangle className="w-3 h-3 mr-1" />Findings ({allFindings.length})
          </TabsTrigger>
          <TabsTrigger value="logs" className="text-xs" data-testid="tab-logs">
            <Terminal className="w-3 h-3 mr-1" />Logs
          </TabsTrigger>
          <TabsTrigger value="report" className="text-xs" data-testid="tab-report">
            <FileText className="w-3 h-3 mr-1" />Report
          </TabsTrigger>
          <TabsTrigger value="history" className="text-xs" data-testid="tab-history">
            <Clock className="w-3 h-3 mr-1" />History
          </TabsTrigger>
        </TabsList>

        <TabsContent value="scan" className="space-y-4 mt-4">
          {!currentOp ? (
            <Card>
              <CardContent className="py-16 text-center">
                <Shield className="w-16 h-16 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-muted-foreground" data-testid="text-empty-state">Enter a URL above to start recovery</h3>
                <p className="text-sm text-muted-foreground/70 mt-2">AegisAI360 will perform automated reconnaissance, vulnerability assessment, and recovery attempts</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <div className="grid gap-3">
                {currentOp.phases.map((phase, i) => {
                  const PhaseIcon = PHASE_ICONS[i] || Search;
                  return (
                    <Card key={i} className={`transition-all ${phase.status === "running" ? "border-amber-500/40 shadow-amber-500/10 shadow-lg" : ""}`}>
                      <CardContent className="py-4">
                        <div className="flex items-center gap-3">
                          <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                            phase.status === "complete" ? "bg-green-500/10 text-green-400" :
                            phase.status === "running" ? "bg-amber-500/10 text-amber-400" :
                            phase.status === "error" ? "bg-red-500/10 text-red-400" :
                            "bg-muted/50 text-muted-foreground"
                          }`}>
                            {phase.status === "running" ? <Loader2 className="w-5 h-5 animate-spin" /> :
                             phase.status === "complete" ? <CheckCircle2 className="w-5 h-5" /> :
                             phase.status === "error" ? <XCircle className="w-5 h-5" /> :
                             <PhaseIcon className="w-5 h-5" />}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between">
                              <h4 className="text-sm font-medium" data-testid={`text-phase-name-${i}`}>{phase.name}</h4>
                              <div className="flex items-center gap-2">
                                {phase.findings.length > 0 && (
                                  <Badge variant="secondary" className="text-[10px]" data-testid={`badge-phase-findings-${i}`}>
                                    {phase.findings.length} findings
                                  </Badge>
                                )}
                                <span className="text-xs text-muted-foreground" data-testid={`text-phase-progress-${i}`}>
                                  {phase.progress}%
                                </span>
                              </div>
                            </div>
                            <div className="mt-2 h-1.5 bg-muted rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full transition-all duration-500 ${
                                  phase.status === "complete" ? "bg-green-500" :
                                  phase.status === "running" ? "bg-amber-500" :
                                  phase.status === "error" ? "bg-red-500" :
                                  "bg-muted-foreground/20"
                                }`}
                                style={{ width: `${phase.progress}%` }}
                              />
                            </div>
                            {phase.status === "running" && phase.findings.length > 0 && (
                              <p className="text-xs text-muted-foreground mt-2 truncate">
                                Latest: {phase.findings[phase.findings.length - 1]?.title}
                              </p>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              {currentOp.status !== "running" && allFindings.length > 0 && (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  {(["critical", "high", "medium", "low", "info"] as const).map((sev) => {
                    const count = allFindings.filter(f => f.severity === sev).length;
                    const cfg = SEVERITY_CONFIG[sev];
                    return (
                      <Card key={sev} className={`${cfg.bg} border ${cfg.border}`}>
                        <CardContent className="py-3 text-center">
                          <p className={`text-2xl font-bold ${cfg.color}`} data-testid={`text-count-${sev}`}>{count}</p>
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{sev}</p>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </TabsContent>

        <TabsContent value="findings" className="space-y-3 mt-4">
          {allFindings.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Search className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No findings yet. Start a recovery operation to see results.</p>
              </CardContent>
            </Card>
          ) : (
            allFindings.sort((a, b) => {
              const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
              return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
            }).map((finding, i) => {
              const cfg = SEVERITY_CONFIG[finding.severity];
              const Icon = cfg.icon;
              return (
                <Card key={i} className={`${cfg.bg} border ${cfg.border}`} data-testid={`card-finding-${i}`}>
                  <CardContent className="py-3">
                    <div className="flex items-start gap-3">
                      <Icon className={`w-4 h-4 mt-0.5 ${cfg.color} shrink-0`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium" data-testid={`text-finding-title-${i}`}>{finding.title}</span>
                          <Badge variant="outline" className={`text-[9px] ${cfg.color} ${cfg.border}`}>{finding.severity}</Badge>
                          <Badge variant="secondary" className="text-[9px]">{finding.category}</Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1" data-testid={`text-finding-detail-${i}`}>{finding.detail}</p>
                      </div>
                      <Button size="sm" variant="ghost" className="h-6 w-6 p-0 shrink-0" onClick={() => copyText(finding.detail)} data-testid={`button-copy-finding-${i}`}>
                        <Copy className="w-3 h-3" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })
          )}
        </TabsContent>

        <TabsContent value="logs" className="mt-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Terminal className="w-4 h-4 text-green-400" />
                Operation Log
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div
                ref={logContainerRef}
                className="bg-black/90 rounded-lg p-4 font-mono text-xs space-y-0.5 max-h-[500px] overflow-y-auto"
                data-testid="container-logs"
              >
                {currentOp?.logs.length ? (
                  currentOp.logs.map((log, i) => (
                    <div key={i} className={`${
                      log.includes("CRITICAL") ? "text-red-400" :
                      log.includes("Found") ? "text-green-400" :
                      log.includes("complete") ? "text-blue-400" :
                      log.includes("Starting") ? "text-amber-400" :
                      "text-gray-400"
                    }`} data-testid={`text-log-${i}`}>
                      {log}
                    </div>
                  ))
                ) : (
                  <div className="text-gray-600">Waiting for operation logs...</div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="report" className="mt-4 space-y-4">
          {!currentOp?.summary ? (
            <Card>
              <CardContent className="py-12 text-center">
                <FileText className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">Report will be available after the scan completes.</p>
              </CardContent>
            </Card>
          ) : (
            <>
              <Card className="border-amber-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield className="w-4 h-4 text-amber-400" />
                    Recovery Report — {currentOp.targetUrl}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                    <div className="p-3 bg-muted/30 rounded-lg">
                      <p className="text-[10px] text-muted-foreground uppercase">Total Findings</p>
                      <p className="text-xl font-bold" data-testid="text-report-total">{currentOp.summary.totalFindings}</p>
                    </div>
                    <div className="p-3 bg-red-500/10 rounded-lg border border-red-500/20">
                      <p className="text-[10px] text-red-400 uppercase">Critical</p>
                      <p className="text-xl font-bold text-red-400" data-testid="text-report-critical">{currentOp.summary.criticalCount}</p>
                    </div>
                    <div className="p-3 bg-orange-500/10 rounded-lg border border-orange-500/20">
                      <p className="text-[10px] text-orange-400 uppercase">High</p>
                      <p className="text-xl font-bold text-orange-400" data-testid="text-report-high">{currentOp.summary.highCount}</p>
                    </div>
                  </div>

                  {currentOp.summary.techStack.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><Server className="w-3.5 h-3.5 text-blue-400" />Technology Stack</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {currentOp.summary.techStack.map((t, i) => (
                          <Badge key={i} variant="secondary" className="text-[10px]" data-testid={`badge-tech-${i}`}>{t}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {currentOp.summary.openPorts.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-green-400" />Open Ports</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {currentOp.summary.openPorts.map((p, i) => (
                          <Badge key={i} variant="outline" className={`text-[10px] ${[21, 22, 3306, 5432].includes(p) ? "border-red-500/30 text-red-400" : ""}`} data-testid={`badge-port-${i}`}>
                            :{p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {currentOp.summary.adminPanelsFound.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><Lock className="w-3.5 h-3.5 text-amber-400" />Admin Panels Discovered</h4>
                      <div className="space-y-1">
                        {currentOp.summary.adminPanelsFound.map((p, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs bg-muted/30 rounded px-3 py-1.5" data-testid={`text-admin-panel-${i}`}>
                            <ChevronRight className="w-3 h-3 text-amber-400" />
                            <span className="font-mono">{p}</span>
                            <a href={`${currentOp.targetUrl}${p}`} target="_blank" rel="noopener noreferrer" className="ml-auto text-muted-foreground hover:text-foreground">
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {currentOp.summary.exposedFiles.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><FileWarning className="w-3.5 h-3.5 text-red-400" />Exposed Files</h4>
                      <div className="space-y-1">
                        {currentOp.summary.exposedFiles.map((f, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs bg-red-500/5 border border-red-500/10 rounded px-3 py-1.5" data-testid={`text-exposed-file-${i}`}>
                            <FileWarning className="w-3 h-3 text-red-400" />
                            <span className="font-mono">{f}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {currentOp.summary.vulnerabilities.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><Bug className="w-3.5 h-3.5 text-red-400" />Vulnerabilities</h4>
                      <div className="space-y-1">
                        {currentOp.summary.vulnerabilities.map((v, i) => (
                          <div key={i} className="flex items-center gap-2 text-xs bg-muted/30 rounded px-3 py-1.5" data-testid={`text-vulnerability-${i}`}>
                            <AlertTriangle className="w-3 h-3 text-orange-400" />
                            <span>{v}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {currentOp.summary.recommendations.length > 0 && (
                    <div>
                      <h4 className="text-xs font-medium mb-2 flex items-center gap-1.5"><Shield className="w-3.5 h-3.5 text-green-400" />Recovery Recommendations</h4>
                      <div className="space-y-1.5">
                        {currentOp.summary.recommendations.map((r, i) => (
                          <div key={i} className="flex items-start gap-2 text-xs" data-testid={`text-recommendation-${i}`}>
                            <ArrowRight className={`w-3 h-3 mt-0.5 shrink-0 ${r.startsWith("URGENT") ? "text-red-400" : "text-green-400"}`} />
                            <span className={r.startsWith("URGENT") ? "text-red-400 font-medium" : ""}>{r}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          {history.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Clock className="w-12 h-12 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No previous recovery operations.</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {history.map((item) => (
                <Card
                  key={item.id}
                  className="cursor-pointer hover:border-amber-500/30 transition-colors"
                  onClick={() => loadOperation(item.id)}
                  data-testid={`card-history-${item.id}`}
                >
                  <CardContent className="py-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                          item.status === "complete" ? "bg-green-500/10 text-green-400" :
                          item.status === "running" ? "bg-amber-500/10 text-amber-400" :
                          "bg-red-500/10 text-red-400"
                        }`}>
                          {item.status === "complete" ? <CheckCircle2 className="w-4 h-4" /> :
                           item.status === "running" ? <Loader2 className="w-4 h-4 animate-spin" /> :
                           <XCircle className="w-4 h-4" />}
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-medium truncate" data-testid={`text-history-url-${item.id}`}>{item.targetUrl}</p>
                          <p className="text-[10px] text-muted-foreground">
                            {new Date(item.startedAt).toLocaleString()} | {item.totalFindings} findings
                          </p>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
