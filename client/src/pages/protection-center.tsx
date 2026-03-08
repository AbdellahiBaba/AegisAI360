import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldOff,
  Flame, Bell, Radar, AlertTriangle, CheckCircle2,
  Loader2, Monitor, Send,
} from "lucide-react";

interface AgentDeployment {
  agentId: number;
  hostname: string;
  status: string;
  lastCommand: string;
  commandStatus: string;
  commandTime: string;
}

interface ProtectionStatus {
  score: number;
  level: "protected" | "issues" | "at_risk";
  defenseMode: string;
  activeFirewallRules: number;
  totalFirewallRules: number;
  activeAlertRules: number;
  totalAlertRules: number;
  activePolicies: number;
  totalPolicies: number;
  unresolvedAlerts: number;
  lastScanDate: string | null;
  openThreats: number;
  totalAgents: number;
  onlineAgents: number;
  monitoringAgents: number;
  agentDeployments: AgentDeployment[];
}

interface ActivateResult {
  defenseModeSet: boolean;
  policiesActivated: number;
  alertRulesActivated: number;
  scansStarted: number;
  agentsDeployed: number;
  agentCommandsSent: number;
}

const PROGRESS_STEPS = [
  "protectionCenter.stepDefense",
  "protectionCenter.stepPolicies",
  "protectionCenter.stepAlertRules",
  "protectionCenter.stepAgents",
  "protectionCenter.stepScanning",
  "protectionCenter.stepComplete",
];

function ShieldIcon({ level }: { level: string }) {
  const sizeClass = "w-24 h-24";
  if (level === "protected") {
    return (
      <div className="relative flex items-center justify-center" data-testid="shield-icon-protected">
        <div className="absolute inset-0 rounded-full bg-status-online/10 animate-pulse-glow" style={{ width: 120, height: 120, margin: "auto" }} />
        <ShieldCheck className={`${sizeClass} text-status-online`} />
      </div>
    );
  }
  if (level === "issues") {
    return (
      <div className="relative flex items-center justify-center" data-testid="shield-icon-issues">
        <ShieldAlert className={`${sizeClass} text-severity-medium`} />
      </div>
    );
  }
  return (
    <div className="relative flex items-center justify-center" data-testid="shield-icon-at-risk">
      <ShieldOff className={`${sizeClass} text-severity-critical`} />
    </div>
  );
}

function getScoreColor(score: number) {
  if (score >= 80) return "text-status-online";
  if (score >= 50) return "text-severity-medium";
  return "text-severity-critical";
}

function getProgressColor(score: number) {
  if (score >= 80) return "bg-status-online";
  if (score >= 50) return "bg-severity-medium";
  return "bg-severity-critical";
}

function getCommandStatusBadge(status: string, t: (key: string) => string) {
  if (status === "executed" || status === "completed") {
    return <Badge variant="secondary" className="font-mono text-xs">{t("protectionCenter.commandExecuted")}</Badge>;
  }
  if (status === "failed") {
    return <Badge variant="destructive" className="font-mono text-xs">{t("protectionCenter.commandFailed")}</Badge>;
  }
  return <Badge variant="outline" className="font-mono text-xs">{t("protectionCenter.commandPending")}</Badge>;
}

export default function ProtectionCenter() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [activateStep, setActivateStep] = useState(-1);

  const { data: status, isLoading } = useQuery<ProtectionStatus>({
    queryKey: ["/api/protection/status"],
    refetchInterval: 15000,
  });

  const activateMutation = useMutation({
    mutationFn: async () => {
      setActivateStep(0);
      const res = await apiRequest("POST", "/api/protection/activate");
      return res.json() as Promise<ActivateResult>;
    },
    onSuccess: () => {
      let step = 1;
      const interval = setInterval(() => {
        step++;
        setActivateStep(step);
        if (step >= PROGRESS_STEPS.length - 1) {
          clearInterval(interval);
          setTimeout(() => {
            setActivateStep(-1);
            queryClient.invalidateQueries({ queryKey: ["/api/protection/status"] });
            queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
            toast({
              title: t("protectionCenter.activated"),
              description: t("protectionCenter.activatedDesc"),
            });
          }, 1000);
        }
      }, 800);
    },
    onError: (error: Error) => {
      setActivateStep(-1);
      toast({
        title: t("protectionCenter.activateFailed"),
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const toggleDefenseModeMutation = useMutation({
    mutationFn: async (mode: string) => {
      const res = await apiRequest("PATCH", "/api/settings/defense-mode", { defenseMode: mode });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/protection/status"] });
      toast({ title: t("settings.defenseModeUpdated") });
    },
  });

  const resolveAllMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/protection/resolve-all");
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/protection/status"] });
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      toast({
        title: t("protectionCenter.threatsResolved"),
        description: t("protectionCenter.threatsResolvedDesc", { count: data.resolved }),
      });
    },
    onError: (error: Error) => {
      toast({ title: t("protectionCenter.resolveFailed"), description: error.message, variant: "destructive" });
    },
  });

  const deployAgentsMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/protection/deploy-agents");
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/protection/status"] });
      if (data.agentsDeployed > 0) {
        toast({
          title: t("protectionCenter.deploySuccess"),
          description: t("protectionCenter.deploySuccessDesc", { count: data.agentsDeployed }),
        });
      } else {
        toast({
          title: t("protectionCenter.noOnlineAgents"),
          variant: "destructive",
        });
      }
    },
    onError: (error: Error) => {
      toast({ title: t("protectionCenter.deployFailed"), description: error.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6">
        <div className="flex flex-col items-center gap-4 py-12">
          <Skeleton className="w-24 h-24 rounded-full" />
          <Skeleton className="w-48 h-8" />
          <Skeleton className="w-64 h-4" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map(i => (
            <Card key={i}><CardContent className="p-4"><Skeleton className="h-16 w-full" /></CardContent></Card>
          ))}
        </div>
      </div>
    );
  }

  const protectionStatus = status || {
    score: 0, level: "at_risk" as const, defenseMode: "manual",
    activeFirewallRules: 0, totalFirewallRules: 0,
    activeAlertRules: 0, totalAlertRules: 0,
    activePolicies: 0, totalPolicies: 0,
    unresolvedAlerts: 0, lastScanDate: null, openThreats: 0,
    totalAgents: 0, onlineAgents: 0, monitoringAgents: 0,
    agentDeployments: [],
  };

  const isActivating = activateStep >= 0;
  const levelLabel = t(`protectionCenter.level_${protectionStatus.level}`);

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div className="flex flex-col items-center gap-4 py-8">
        <ShieldIcon level={protectionStatus.level} />

        <div className="text-center space-y-2">
          <h1 className="text-2xl font-bold font-mono tracking-wider uppercase" data-testid="text-protection-status">
            {levelLabel}
          </h1>
          <div className="flex items-center justify-center gap-3">
            <span className={`text-4xl font-bold font-mono ${getScoreColor(protectionStatus.score)}`} data-testid="text-protection-score">
              {protectionStatus.score}
            </span>
            <span className="text-sm text-muted-foreground font-mono">/100</span>
          </div>
          <div className="w-64 mx-auto">
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-1000 ${getProgressColor(protectionStatus.score)}`}
                style={{ width: `${protectionStatus.score}%` }}
              />
            </div>
          </div>
        </div>

        {isActivating ? (
          <Card className="w-full max-w-md">
            <CardContent className="p-6 space-y-4">
              <div className="flex items-center gap-3">
                <Loader2 className="w-5 h-5 animate-spin text-primary" />
                <span className="text-sm font-mono" data-testid="text-activate-step">
                  {t(PROGRESS_STEPS[Math.min(activateStep, PROGRESS_STEPS.length - 1)])}
                </span>
              </div>
              <Progress value={((activateStep + 1) / PROGRESS_STEPS.length) * 100} />
            </CardContent>
          </Card>
        ) : (
          <Button
            size="lg"
            className="font-mono uppercase tracking-wider text-sm"
            onClick={() => activateMutation.mutate()}
            disabled={activateMutation.isPending || protectionStatus.score >= 100}
            data-testid="button-protect-me"
          >
            <Shield className="w-5 h-5 me-2" />
            {protectionStatus.score >= 100
              ? t("protectionCenter.fullyProtected")
              : t("protectionCenter.protectMe")}
          </Button>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl mx-auto">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-muted">
                  <Shield className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-defense-label">
                    {t("protectionCenter.autoDefense")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {protectionStatus.defenseMode === "auto"
                      ? t("protectionCenter.autoDefenseOn")
                      : t("protectionCenter.autoDefenseOff")}
                  </p>
                </div>
              </div>
              <Switch
                checked={protectionStatus.defenseMode === "auto"}
                onCheckedChange={(checked) => {
                  toggleDefenseModeMutation.mutate(checked ? "auto" : "manual");
                }}
                data-testid="switch-defense-mode"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-muted">
                  <Flame className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-firewall-label">
                    {t("protectionCenter.firewall")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {t("protectionCenter.firewallStatus", {
                      active: protectionStatus.activeFirewallRules,
                      total: protectionStatus.totalFirewallRules,
                    })}
                  </p>
                </div>
              </div>
              <Badge variant="secondary" className="font-mono text-xs" data-testid="badge-firewall-count">
                {protectionStatus.activeFirewallRules}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-muted">
                  <Bell className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-alert-rules-label">
                    {t("protectionCenter.alertRules")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {t("protectionCenter.alertRulesStatus", {
                      active: protectionStatus.activeAlertRules,
                      total: protectionStatus.totalAlertRules,
                    })}
                  </p>
                </div>
              </div>
              <Badge variant="secondary" className="font-mono text-xs" data-testid="badge-alert-rules-count">
                {protectionStatus.activeAlertRules}
              </Badge>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-muted">
                  <Radar className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-last-scan-label">
                    {t("protectionCenter.lastScan")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {protectionStatus.lastScanDate
                      ? new Date(protectionStatus.lastScanDate).toLocaleDateString()
                      : t("common.never")}
                  </p>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => activateMutation.mutate()}
                disabled={activateMutation.isPending}
                data-testid="button-scan-now"
              >
                {t("protectionCenter.scanNow")}
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-md ${protectionStatus.onlineAgents > 0 ? "bg-status-online/10" : "bg-muted"}`}>
                  <Monitor className={`w-5 h-5 ${protectionStatus.onlineAgents > 0 ? "text-status-online" : "text-muted-foreground"}`} />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-agent-monitoring-label">
                    {t("protectionCenter.agentMonitoring")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {protectionStatus.totalAgents > 0
                      ? t("protectionCenter.agentMonitoringStatus", {
                          monitoring: protectionStatus.monitoringAgents,
                          online: protectionStatus.onlineAgents,
                        })
                      : t("protectionCenter.noAgents")}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="font-mono text-xs" data-testid="badge-agent-count">
                  {protectionStatus.onlineAgents}/{protectionStatus.totalAgents}
                </Badge>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => deployAgentsMutation.mutate()}
                  disabled={deployAgentsMutation.isPending || protectionStatus.totalAgents === 0}
                  data-testid="button-deploy-all-agents"
                >
                  {deployAgentsMutation.isPending ? (
                    <Loader2 className="w-4 h-4 animate-spin me-1" />
                  ) : (
                    <Send className="w-4 h-4 me-1" />
                  )}
                  {t("protectionCenter.deployToAll")}
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-md ${protectionStatus.openThreats > 0 ? "bg-severity-critical/10" : "bg-muted"}`}>
                  <AlertTriangle className={`w-5 h-5 ${protectionStatus.openThreats > 0 ? "text-severity-critical" : "text-muted-foreground"}`} />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-threats-label">
                    {t("protectionCenter.openThreats")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {protectionStatus.openThreats > 0
                      ? t("protectionCenter.openThreatsDesc", { count: protectionStatus.openThreats })
                      : t("protectionCenter.noOpenThreats")}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge
                  variant={protectionStatus.openThreats > 0 ? "destructive" : "secondary"}
                  className="font-mono text-xs"
                  data-testid="badge-threats-count"
                >
                  {protectionStatus.openThreats}
                </Badge>
                {protectionStatus.openThreats > 0 && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => resolveAllMutation.mutate()}
                    disabled={resolveAllMutation.isPending}
                    data-testid="button-resolve-all"
                  >
                    {resolveAllMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin me-1" />
                    ) : (
                      <CheckCircle2 className="w-4 h-4 me-1" />
                    )}
                    {t("protectionCenter.resolveAll")}
                  </Button>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardContent className="p-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-md bg-muted">
                  <ShieldCheck className="w-5 h-5 text-muted-foreground" />
                </div>
                <div>
                  <p className="text-sm font-medium" data-testid="text-policies-label">
                    {t("protectionCenter.policies")}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {t("protectionCenter.policiesStatus", {
                      active: protectionStatus.activePolicies,
                      total: protectionStatus.totalPolicies,
                    })}
                  </p>
                </div>
              </div>
              <Badge variant="secondary" className="font-mono text-xs" data-testid="badge-policies-count">
                {protectionStatus.activePolicies}
              </Badge>
            </div>
          </CardContent>
        </Card>

        {protectionStatus.agentDeployments && protectionStatus.agentDeployments.length > 0 && (
          <Card className="md:col-span-2">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono" data-testid="text-agent-deployments-title">
                {t("protectionCenter.agentDeployments")}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 pt-0">
              <div className="space-y-2">
                {protectionStatus.agentDeployments.map((dep) => (
                  <div
                    key={dep.agentId}
                    className="flex items-center justify-between gap-3 flex-wrap py-2 border-b border-border last:border-0"
                    data-testid={`row-agent-deployment-${dep.agentId}`}
                  >
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${dep.status === "online" ? "bg-status-online" : "bg-muted-foreground"}`} />
                      <span className="text-sm font-mono" data-testid={`text-agent-hostname-${dep.agentId}`}>
                        {dep.hostname}
                      </span>
                      <span className="text-xs text-muted-foreground">
                        {dep.lastCommand}
                      </span>
                    </div>
                    <div data-testid={`badge-agent-cmd-status-${dep.agentId}`}>
                      {getCommandStatusBadge(dep.commandStatus, t)}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
