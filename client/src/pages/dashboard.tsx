import { useQuery, useMutation } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
import { usePlan } from "@/hooks/use-plan";
import {
  ShieldAlert, AlertTriangle, Bug, Activity, ArrowUpRight, ArrowDownRight,
  Clock, Monitor, Lock, Radio, ShieldOff, Flame, Crosshair, Zap, CreditCard,
  Shield, ScanLine, Ban, Eye, Info, Server, FileDown, ChevronDown, ChevronUp,
  BarChart3, Waves, LayoutDashboard, Settings2,
} from "lucide-react";
import { generateExecutiveSummaryPDF } from "@/lib/reportGenerator";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";
import type { SecurityEvent, ResponseAction } from "@shared/schema";
import { ThreatMap } from "@/components/threat-map";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

type WidgetId = "threat_level" | "stat_cards" | "quick_actions" | "event_trend" | "severity_breakdown" | "threat_map" | "recent_alerts" | "activity_feed" | "response_actions";

interface DashboardLayout {
  [key: string]: boolean;
}

const WIDGET_DEFINITIONS: { id: WidgetId; labelKey: string; defaultLabel: string }[] = [
  { id: "threat_level", labelKey: "dashboard.widgetThreatLevel", defaultLabel: "Threat Level" },
  { id: "stat_cards", labelKey: "dashboard.widgetStatCards", defaultLabel: "Stat Cards" },
  { id: "quick_actions", labelKey: "dashboard.widgetQuickActions", defaultLabel: "Quick Actions" },
  { id: "event_trend", labelKey: "dashboard.widgetEventTrend", defaultLabel: "Event Trend Chart" },
  { id: "severity_breakdown", labelKey: "dashboard.widgetSeverityBreakdown", defaultLabel: "Severity Breakdown" },
  { id: "threat_map", labelKey: "dashboard.widgetThreatMap", defaultLabel: "Threat Map" },
  { id: "recent_alerts", labelKey: "dashboard.widgetRecentAlerts", defaultLabel: "Recent Alerts" },
  { id: "activity_feed", labelKey: "dashboard.widgetActivityFeed", defaultLabel: "Activity Feed" },
  { id: "response_actions", labelKey: "dashboard.widgetResponseActions", defaultLabel: "Response Actions" },
];

function isWidgetVisible(layout: DashboardLayout | null | undefined, widgetId: WidgetId): boolean {
  if (!layout) return true;
  return layout[widgetId] !== false;
}

function CustomizeDashboardDialog({ layout, onSave, isPending }: { layout: DashboardLayout | null | undefined; onSave: (layout: DashboardLayout) => void; isPending: boolean }) {
  const { t } = useTranslation();
  const [localLayout, setLocalLayout] = useState<DashboardLayout>({});
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (open) {
      const initial: DashboardLayout = {};
      for (const w of WIDGET_DEFINITIONS) {
        initial[w.id] = isWidgetVisible(layout, w.id);
      }
      setLocalLayout(initial);
    }
  }, [open, layout]);

  const handleToggle = (widgetId: WidgetId, checked: boolean) => {
    setLocalLayout((prev) => ({ ...prev, [widgetId]: checked }));
  };

  const handleSave = () => {
    onSave(localLayout);
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" data-testid="button-customize-dashboard">
          <Settings2 className="w-4 h-4 me-1" />
          {t("dashboard.customize", "Customize")}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t("dashboard.customizeTitle", "Customize Dashboard")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-3 py-2">
          {WIDGET_DEFINITIONS.map((w) => (
            <div key={w.id} className="flex items-center justify-between gap-4" data-testid={`toggle-widget-${w.id}`}>
              <Label htmlFor={`widget-${w.id}`} className="text-sm">
                {t(w.labelKey, w.defaultLabel)}
              </Label>
              <Switch
                id={`widget-${w.id}`}
                checked={localLayout[w.id] !== false}
                onCheckedChange={(checked) => handleToggle(w.id, checked)}
                data-testid={`switch-widget-${w.id}`}
              />
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={() => setOpen(false)} data-testid="button-cancel-customize">
            {t("common.cancel", "Cancel")}
          </Button>
          <Button onClick={handleSave} disabled={isPending} data-testid="button-save-customize">
            {isPending ? t("common.saving", "Saving...") : t("common.save", "Save")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
import { OnboardingWizard } from "@/components/onboarding-wizard";

interface DashboardStats {
  totalEvents: number;
  criticalAlerts: number;
  activeIncidents: number;
  threatScore: number;
  eventTrend: number;
  incidentTrend: number;
  assetCount: number;
  quarantineCount: number;
  honeypotActivity: number;
  blockedIps: number;
  activeRules: number;
}

const severityColors: Record<string, string> = {
  critical: "rgb(239 68 68)",
  high: "rgb(249 115 22)",
  medium: "rgb(234 179 8)",
  low: "rgb(59 130 246)",
  info: "rgb(148 163 184)",
};

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={`${severityClasses[severity] || severityClasses.info} text-[10px] uppercase tracking-wider`}>
      {severity}
    </Badge>
  );
}

function SectionHeading({ icon: Icon, title, subtitle }: { icon: React.ElementType; title: string; subtitle?: string }) {
  return (
    <div className="flex items-center gap-3 pt-2" data-testid={`section-${title.toLowerCase().replace(/\s+/g, '-')}`}>
      <div className="p-1.5 rounded-md bg-muted">
        <Icon className="w-4 h-4 text-muted-foreground" />
      </div>
      <div className="flex items-baseline gap-2 flex-wrap">
        <h2 className="text-sm font-semibold tracking-wider uppercase font-mono">{title}</h2>
        {subtitle && <span className="text-[10px] text-muted-foreground font-mono">{subtitle}</span>}
      </div>
      <Separator className="flex-1" />
    </div>
  );
}

function getThreatLevel(stats: DashboardStats): number {
  if (stats.criticalAlerts >= 5 || stats.activeIncidents >= 3) return 1;
  if (stats.criticalAlerts >= 3) return 2;
  if (stats.criticalAlerts >= 1 || stats.activeIncidents >= 1) return 3;
  if (stats.totalEvents > 0) return 4;
  return 5;
}

function ThreatLevelIndicator({ stats }: { stats: DashboardStats }) {
  const { t } = useTranslation();
  const level = getThreatLevel(stats);
  const levelDescriptions: Record<number, string> = {
    1: t("dashboard.defcon1"),
    2: t("dashboard.defcon2"),
    3: t("dashboard.defcon3"),
    4: t("dashboard.defcon4"),
    5: t("dashboard.defcon5"),
  };
  return (
    <div className={`threat-level-${level} rounded-md p-4 flex items-center justify-between gap-4 flex-wrap flex-1`} data-testid="threat-level-indicator">
      <div className="flex items-center gap-3">
        <Crosshair className="w-6 h-6" />
        <div>
          <div className="text-lg font-bold font-mono tracking-widest uppercase" data-testid="threat-level">
            {t("dashboard.defcon")} {level}
          </div>
          <div className="text-xs font-mono tracking-wider opacity-90" data-testid="threat-level-description">
            {levelDescriptions[level]}
          </div>
        </div>
      </div>
      <div className="font-mono text-xs tracking-wider opacity-75">
        {t("dashboard.threatScore")}: {stats.threatScore}/100
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, trend, trendLabel, accent }: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  trend?: number;
  trendLabel?: string;
  accent?: string;
}) {
  const isPositiveTrend = trend !== undefined && trend > 0;
  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="flex flex-col gap-1">
            <span className="text-xs text-muted-foreground uppercase tracking-wider font-mono">{title}</span>
            <span className={`text-2xl font-bold font-mono ${accent || ""}`} data-testid={`stat-${title.toLowerCase().replace(/\s+/g, '-')}`}>
              {value}
            </span>
            {trend !== undefined && (
              <div className="flex items-center gap-1 flex-wrap">
                {isPositiveTrend ? (
                  <ArrowUpRight className="w-3 h-3 text-severity-critical" />
                ) : (
                  <ArrowDownRight className="w-3 h-3 text-status-online" />
                )}
                <span className={`text-[10px] font-mono ${isPositiveTrend ? "text-severity-critical" : "text-status-online"}`}>
                  {isPositiveTrend ? "+" : ""}{trend}%
                </span>
                {trendLabel && <span className="text-[10px] text-muted-foreground">{trendLabel}</span>}
              </div>
            )}
          </div>
          <div className={`p-2 rounded-md ${accent ? "bg-primary/10" : "bg-muted"}`}>
            <Icon className={`w-5 h-5 ${accent || "text-muted-foreground"}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function EventTrendChart({ data }: { data: { time: string; events: number }[] }) {
  const { t } = useTranslation();
  return (
    <Card className="lg:col-span-3">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.eventTrend")}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[260px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(185 85% 48%)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(185 85% 48%)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(222 20% 14%)" />
              <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(195 12% 55%)" }} />
              <YAxis tick={{ fontSize: 10, fill: "hsl(195 12% 55%)" }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222 28% 8%)",
                  border: "1px solid hsl(222 20% 14%)",
                  borderRadius: "6px",
                  fontSize: "12px",
                  color: "hsl(195 20% 90%)",
                }}
              />
              <Area
                type="monotone"
                dataKey="events"
                stroke="hsl(185 85% 48%)"
                strokeWidth={2}
                fill="url(#eventGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

function SeverityBreakdown({ data }: { data: { name: string; value: number }[] }) {
  const { t } = useTranslation();
  return (
    <Card className="lg:col-span-2">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.severityBreakdown")}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[260px] flex items-center justify-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={90}
                paddingAngle={3}
                dataKey="value"
              >
                {data.map((entry) => (
                  <Cell key={entry.name} fill={severityColors[entry.name] || severityColors.info} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(222 28% 8%)",
                  border: "1px solid hsl(222 20% 14%)",
                  borderRadius: "6px",
                  fontSize: "12px",
                  color: "hsl(195 20% 90%)",
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="flex flex-wrap gap-3 mt-2 justify-center">
          {data.map((entry) => (
            <div key={entry.name} className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: severityColors[entry.name] }} />
              <span className="text-[11px] text-muted-foreground capitalize font-mono">{entry.name}</span>
              <span className="text-[11px] font-mono font-bold">{entry.value}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function formatTimeAgo(dateStr: string) {
  const date = new Date(dateStr);
  const now = new Date();
  const diff = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function simplifyThreatDescription(description: string, eventType: string): string {
  const patterns: [RegExp, string][] = [
    [/sql injection/i, "Someone tried to hack your database"],
    [/xss|cross.?site scripting/i, "Someone tried to inject malicious code into your website"],
    [/brute.?force|multiple.*login.*attempt/i, "Someone is trying to guess passwords on your system"],
    [/port scan/i, "Someone is probing your system for weaknesses"],
    [/ransomware/i, "Ransomware activity detected on your system"],
    [/phishing/i, "A phishing attack was detected targeting your users"],
    [/malware/i, "Malicious software was detected"],
    [/data exfiltration|data.*transfer.*unusual/i, "Unusual data transfer detected - possible data theft"],
    [/c2|command.*control|beacon/i, "A device may be communicating with an attacker's server"],
    [/unauthorized.*access/i, "Someone tried to access your system without permission"],
    [/unauthorized.*device/i, "An unknown device was found on your network"],
    [/lateral.*movement/i, "An attacker may be moving through your network"],
    [/privilege.*escalation/i, "Someone tried to gain higher access on your system"],
    [/dns.*tunnel/i, "Someone may be hiding data transfers in DNS traffic"],
    [/vulnerability/i, "A security weakness was found in your system"],
    [/expired.*ssl|ssl.*expir/i, "Your security certificate has expired or is expiring"],
  ];

  for (const [pattern, simple] of patterns) {
    if (pattern.test(description) || pattern.test(eventType)) {
      const ipMatch = description.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      return ipMatch ? `${simple} (from ${ipMatch[1]})` : simple;
    }
  }
  return description;
}

function QuickActions() {
  const { toast } = useToast();
  const { t } = useTranslation();
  const [, navigate] = useLocation();
  const [isOpen, setIsOpen] = useState(true);

  const lockdownMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/response/emergency-lockdown");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("dashboard.lockdownActivated"), description: t("dashboard.lockdownDescription") });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/response/actions"] });
    },
    onError: (error: Error) => {
      toast({ title: t("dashboard.lockdownFailed"), description: error.message, variant: "destructive" });
    },
  });

  const protectMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/protection/activate");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("dashboard.protectionActivated") });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/protection/status"] });
    },
    onError: () => {
      toast({ title: t("dashboard.protectionFailed"), variant: "destructive" });
    },
  });

  const blockAllMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/response/emergency-lockdown");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("dashboard.threatsBlocked") });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
    },
    onError: () => {
      toast({ title: t("dashboard.blockFailed"), variant: "destructive" });
    },
  });

  return (
    <Collapsible open={isOpen} onOpenChange={setIsOpen}>
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.quickActions")}</CardTitle>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="icon" data-testid="button-toggle-quick-actions">
                {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </Button>
            </CollapsibleTrigger>
          </div>
        </CardHeader>
        <CollapsibleContent>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
              <Button
                className="h-auto py-3 flex flex-col items-center gap-1.5"
                onClick={() => protectMutation.mutate()}
                disabled={protectMutation.isPending}
                data-testid="button-activate-protection"
              >
                <Shield className="w-5 h-5" />
                <span className="text-[10px] font-mono uppercase tracking-wider">
                  {protectMutation.isPending ? t("common.activating") : t("dashboard.activateProtection")}
                </span>
              </Button>
              <Button
                variant="secondary"
                className="h-auto py-3 flex flex-col items-center gap-1.5"
                onClick={() => navigate("/network-monitor")}
                data-testid="button-scan-systems"
              >
                <ScanLine className="w-5 h-5" />
                <span className="text-[10px] font-mono uppercase tracking-wider">{t("dashboard.scanSystems")}</span>
              </Button>
              <Button
                variant="secondary"
                className="h-auto py-3 flex flex-col items-center gap-1.5"
                onClick={() => { if (window.confirm(t("dashboard.blockAllConfirm"))) blockAllMutation.mutate(); }}
                disabled={blockAllMutation.isPending}
                data-testid="button-block-all-threats"
              >
                <Ban className="w-5 h-5" />
                <span className="text-[10px] font-mono uppercase tracking-wider">
                  {blockAllMutation.isPending ? t("common.blocking") : t("dashboard.blockAllThreats")}
                </span>
              </Button>
              <Button
                variant="destructive"
                className="h-auto py-3 flex flex-col items-center gap-1.5"
                onClick={() => { if (window.confirm(t("dashboard.lockdownConfirm"))) lockdownMutation.mutate(); }}
                disabled={lockdownMutation.isPending}
                data-testid="button-emergency-lockdown"
              >
                <Flame className="w-5 h-5" />
                <span className="text-[10px] font-mono uppercase tracking-wider">
                  {lockdownMutation.isPending ? t("common.initiating") : t("dashboard.emergencyLockdown")}
                </span>
              </Button>
            </div>
            <div className="mt-2 flex justify-center">
              <Button
                variant="ghost"
                size="sm"
                className="text-[10px] text-muted-foreground"
                onClick={() => navigate("/protection-center")}
                data-testid="button-view-protection"
              >
                <Eye className="w-3 h-3 me-1" />
                {t("dashboard.viewProtectionStatus")}
              </Button>
            </div>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}

function RecentAlerts({ events }: { events: SecurityEvent[] }) {
  const { t } = useTranslation();
  return (
    <Card className="lg:col-span-3">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.recentAlerts")}</CardTitle>
          <Badge variant="secondary" className="text-[10px] font-mono">{events.length} {t("common.events")}</Badge>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[300px]">
          <div className="px-4 pb-4">
            {events.length === 0 ? (
              <div className="text-center text-sm text-muted-foreground py-8 font-mono">{t("dashboard.noRecentAlerts")}</div>
            ) : (
              <div className="space-y-1">
                {events.map((event) => (
                  <div
                    key={event.id}
                    className="flex items-center gap-3 py-2 px-2 rounded-md animate-fade-in"
                    data-testid={`alert-row-${event.id}`}
                  >
                    <div className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: severityColors[event.severity] }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs truncate">{simplifyThreatDescription(event.description, event.eventType)}</p>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        <span className="text-[10px] text-muted-foreground font-mono">{event.sourceIp || t("common.noData")}</span>
                        <span className="text-[10px] text-muted-foreground">{event.source}</span>
                      </div>
                    </div>
                    <SeverityBadge severity={event.severity} />
                    <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatTimeAgo(event.createdAt as unknown as string)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function ActivityFeed({ events }: { events: SecurityEvent[] }) {
  const { t } = useTranslation();
  return (
    <Card className="lg:col-span-2">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.liveFeed")}</CardTitle>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-status-online animate-pulse-glow" />
            <span className="text-[10px] text-muted-foreground font-mono">{t("common.live")}</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[300px]">
          <div className="px-4 pb-4 space-y-2">
            {events.map((event) => (
              <div key={event.id} className="flex gap-2 animate-slide-in" data-testid={`feed-item-${event.id}`}>
                <div className="flex flex-col items-center">
                  <div className="w-1.5 h-1.5 rounded-full mt-1.5 flex-shrink-0" style={{ backgroundColor: severityColors[event.severity] }} />
                  <div className="w-px flex-1 bg-border mt-1" />
                </div>
                <div className="flex-1 pb-2">
                  <p className="text-[11px] leading-snug">{event.description}</p>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {formatTimeAgo(event.createdAt as unknown as string)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function ResponseActionsFeed({ actions }: { actions: ResponseAction[] }) {
  const { t } = useTranslation();
  const actionStatusClasses: Record<string, string> = {
    completed: "bg-status-online/20 text-status-online",
    pending: "bg-severity-medium/20 text-severity-medium",
    failed: "bg-severity-critical/20 text-severity-critical",
    executing: "bg-severity-high/20 text-severity-high",
  };

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono">{t("dashboard.responseActions")}</CardTitle>
          <Zap className="w-4 h-4 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[300px]">
          <div className="px-4 pb-4">
            {actions.length === 0 ? (
              <div className="text-center text-sm text-muted-foreground py-8 font-mono">{t("dashboard.noRecentActions")}</div>
            ) : (
              <div className="space-y-2">
                {actions.map((action) => (
                  <div
                    key={action.id}
                    className="flex items-center gap-3 py-2 px-2 rounded-md"
                    data-testid={`response-action-${action.id}`}
                  >
                    <ShieldOff className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono uppercase truncate">{action.actionType}</p>
                      <span className="text-[10px] text-muted-foreground font-mono">{action.target}</span>
                    </div>
                    <Badge className={`text-[10px] font-mono ${actionStatusClasses[action.status] || actionStatusClasses.pending}`}>
                      {action.status}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground font-mono flex-shrink-0">
                      {formatTimeAgo(action.createdAt as unknown as string)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

interface BillingStatus {
  plan: string;
  stripeSubscriptionId: string | null;
  subscriptionStatus: string;
  subscriptionExpiresAt: string | null;
  trialUsed: boolean;
  trialStartedAt: string | null;
}

export default function Dashboard() {
  useDocumentTitle("Dashboard");
  const { t } = useTranslation();
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const { hasFeature } = usePlan();
  const dashLayout = user?.dashboardLayout as DashboardLayout | null | undefined;
  const show = (id: WidgetId) => isWidgetVisible(dashLayout, id);

  const layoutMutation = useMutation({
    mutationFn: async (layout: DashboardLayout) => {
      await apiRequest("PATCH", "/api/user/dashboard-layout", { layout });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      toast({ title: t("dashboard.layoutSaved", "Dashboard layout saved") });
    },
    onError: () => {
      toast({ title: t("dashboard.layoutSaveFailed", "Failed to save layout"), variant: "destructive" });
    },
  });

  const [showOnboarding, setShowOnboarding] = useState(false);

  useEffect(() => {
    if (user && user.onboardingCompleted === false) {
      setShowOnboarding(true);
    }
  }, [user]);

  const { data: billingStatus } = useQuery<BillingStatus>({
    queryKey: ["/api/billing/status"],
    enabled: user?.role === "admin",
  });

  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ["/api/dashboard/stats"],
    refetchInterval: 10000,
  });

  const { data: events, isLoading: eventsLoading } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/security-events"],
    refetchInterval: 10000,
  });

  const { data: trendData } = useQuery<{ time: string; events: number }[]>({
    queryKey: ["/api/dashboard/trend"],
    refetchInterval: 30000,
  });

  const { data: responseActions } = useQuery<ResponseAction[]>({
    queryKey: ["/api/response/actions"],
    refetchInterval: 15000,
  });

  const wsReady = !!stats;
  useEffect(() => {
    if (!wsReady) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);
    socket.onmessage = () => {
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/trend"] });
      queryClient.invalidateQueries({ queryKey: ["/api/response/actions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/threat-map"] });
    };
    return () => {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
    };
  }, [wsReady]);

  const isTrialing = billingStatus?.subscriptionStatus === "trialing";

  const [trialRemaining, setTrialRemaining] = useState<number>(0);
  useEffect(() => {
    if (!billingStatus?.subscriptionExpiresAt || !isTrialing) return;
    const tick = () => setTrialRemaining(Math.max(0, new Date(billingStatus.subscriptionExpiresAt!).getTime() - Date.now()));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [billingStatus?.subscriptionExpiresAt, isTrialing]);

  const recentEvents = events?.slice(0, 15) || [];
  const feedEvents = events?.slice(0, 10) || [];
  const recentActions = responseActions?.slice(0, 10) || [];

  const severityData = events
    ? [
        { name: "critical", value: events.filter((e) => e.severity === "critical").length },
        { name: "high", value: events.filter((e) => e.severity === "high").length },
        { name: "medium", value: events.filter((e) => e.severity === "medium").length },
        { name: "low", value: events.filter((e) => e.severity === "low").length },
        { name: "info", value: events.filter((e) => e.severity === "info").length },
      ].filter((d) => d.value > 0)
    : [];

  if (statsLoading || eventsLoading) {
    return (
      <div className="p-4 md:p-6 space-y-6">
        <Skeleton className="h-16 w-full rounded-md" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}><CardContent className="p-4"><Skeleton className="h-20 w-full" /></CardContent></Card>
          ))}
        </div>
        <Skeleton className="h-8 w-48 rounded-md" />
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
          <Card className="lg:col-span-3"><CardContent className="p-4"><Skeleton className="h-[260px] w-full" /></CardContent></Card>
          <Card className="lg:col-span-2"><CardContent className="p-4"><Skeleton className="h-[260px] w-full" /></CardContent></Card>
        </div>
        <Skeleton className="h-[280px] w-full rounded-md" />
      </div>
    );
  }

  const showUpgradeBanner = user?.role === "admin" && !user?.isSuperAdmin && billingStatus && !billingStatus.stripeSubscriptionId && billingStatus.subscriptionStatus !== "trialing";
  const trialExpiredOnDash = billingStatus?.trialUsed && !isTrialing && billingStatus?.subscriptionStatus !== "active" && billingStatus?.subscriptionStatus !== "inactive";
  const trialHours = Math.floor(trialRemaining / 3600000);
  const trialMins = Math.floor((trialRemaining % 3600000) / 60000);
  const trialSecs = Math.floor((trialRemaining % 60000) / 1000);

  return (
    <div className="p-4 md:p-6 space-y-5 grid-pattern">
      <OnboardingWizard open={showOnboarding} onComplete={() => setShowOnboarding(false)} />

      {/* Trial countdown banner */}
      {isTrialing && billingStatus?.subscriptionExpiresAt && (
        <div className="flex items-center justify-between gap-3 p-3 rounded-lg border border-amber-500/50 bg-amber-500/8 flex-wrap" data-testid="banner-trial-active">
          <div className="flex items-center gap-3">
            <Clock className="w-5 h-5 text-amber-400 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-300">Free trial active</p>
              <p className="text-xs text-muted-foreground">
                Time remaining:{" "}
                <span className="font-mono text-amber-300" data-testid="text-trial-remaining">
                  {String(trialHours).padStart(2, "0")}:{String(trialMins).padStart(2, "0")}:{String(trialSecs).padStart(2, "0")}
                </span>
              </p>
            </div>
          </div>
          <Button size="sm" onClick={() => navigate("/billing")} className="bg-amber-500 hover:bg-amber-600 text-black text-xs" data-testid="button-upgrade-from-trial-banner">
            Subscribe before trial ends
          </Button>
        </div>
      )}

      {/* Trial expired banner */}
      {trialExpiredOnDash && (
        <div className="flex items-center justify-between gap-3 p-3 rounded-lg border border-red-500/50 bg-red-500/8 flex-wrap" data-testid="banner-trial-expired-dashboard">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-red-400">Trial ended — agents disconnected</p>
              <p className="text-xs text-muted-foreground">Subscribe to a plan to reconnect all agents and restore access.</p>
            </div>
          </div>
          <Button size="sm" onClick={() => navigate("/billing")} data-testid="button-subscribe-after-trial">
            Subscribe now
          </Button>
        </div>
      )}

      {showUpgradeBanner && (
        <Card className="border-primary/30 bg-primary/5" data-testid="upgrade-banner">
          <CardContent className="p-4 flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <CreditCard className="w-5 h-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-bold">{t("billing.welcomeTitle", "Choose Your Plan")}</p>
                <p className="text-xs text-muted-foreground">{t("billing.welcomeSubtitle", "Select a subscription plan to unlock the full platform capabilities")}</p>
              </div>
            </div>
            <Button
              size="sm"
              onClick={() => navigate("/billing")}
              className="tracking-wider uppercase text-xs"
              data-testid="button-upgrade-plan"
            >
              {t("billing.viewPlans", "View Plans")}
            </Button>
          </CardContent>
        </Card>
      )}

      <SectionHeading icon={LayoutDashboard} title={t("dashboard.overview", "Overview")} subtitle={t("dashboard.overviewSubtitle", "System status at a glance")} />

      <div className="flex items-center justify-between gap-3 flex-wrap">
        {show("threat_level") && stats ? <ThreatLevelIndicator stats={stats} /> : <div className="flex-1" />}
        <div className="flex items-center gap-2 flex-wrap">
          <CustomizeDashboardDialog layout={dashLayout} onSave={(l) => layoutMutation.mutate(l)} isPending={layoutMutation.isPending} />
          <Button
            variant="outline"
            size="sm"
            onClick={() => stats && generateExecutiveSummaryPDF(stats, events || [], severityData)}
            data-testid="button-generate-pdf-report"
          >
            <FileDown className="w-4 h-4 me-1" />
            {t("dashboard.generateReport", "Generate PDF Report")}
          </Button>
        </div>
      </div>

      {show("stat_cards") && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard
              title={t("dashboard.events24h")}
              value={stats?.totalEvents ?? 0}
              icon={ShieldAlert}
              trend={stats?.eventTrend ?? 0}
              trendLabel={t("dashboard.vsYesterday")}
            />
            <StatCard
              title={t("dashboard.critical")}
              value={stats?.criticalAlerts ?? 0}
              icon={AlertTriangle}
              accent={(stats?.criticalAlerts ?? 0) > 0 ? "text-severity-critical" : undefined}
            />
            <StatCard
              title={t("dashboard.incidents")}
              value={stats?.activeIncidents ?? 0}
              icon={Bug}
              trend={stats?.incidentTrend ?? 0}
              trendLabel={t("dashboard.thisWeek")}
            />
            <StatCard
              title={t("dashboard.blockedIps")}
              value={stats?.blockedIps ?? 0}
              icon={ShieldOff}
              accent={(stats?.blockedIps ?? 0) > 0 ? "text-severity-high" : undefined}
            />
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <StatCard
              title={t("dashboard.assets")}
              value={stats?.assetCount ?? 0}
              icon={Monitor}
            />
            <StatCard
              title={t("dashboard.quarantined")}
              value={stats?.quarantineCount ?? 0}
              icon={Lock}
              accent={(stats?.quarantineCount ?? 0) > 0 ? "text-severity-high" : undefined}
            />
            <StatCard
              title={t("dashboard.activeRules")}
              value={stats?.activeRules ?? 0}
              icon={Activity}
            />
          </div>
        </>
      )}

      {show("quick_actions") && hasFeature("allowNetworkIsolation") && <QuickActions />}

      {hasFeature("allowThreatIntel") ? (
        <>
          {(show("event_trend") || show("severity_breakdown")) && (
            <>
              <SectionHeading icon={BarChart3} title={t("dashboard.analytics", "Analytics")} subtitle={t("dashboard.analyticsSubtitle", "Trends & severity distribution")} />
              <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
                {show("event_trend") && <EventTrendChart data={trendData || []} />}
                {show("severity_breakdown") && <SeverityBreakdown data={severityData} />}
              </div>
            </>
          )}

          {show("threat_map") && <ThreatMap />}
        </>
      ) : (
        <Card className="border-dashed border-primary/30 bg-primary/5" data-testid="card-upgrade-analytics">
          <CardContent className="flex flex-col items-center justify-center py-8 gap-3">
            <BarChart3 className="w-8 h-8 text-primary/50" />
            <p className="text-sm font-medium text-muted-foreground text-center">Analytics, Threat Map, and Advanced Widgets are available on Professional and Enterprise plans</p>
            <Button variant="outline" size="sm" onClick={() => navigate("/billing")} data-testid="button-upgrade-analytics">
              <CreditCard className="w-4 h-4 mr-1" />
              Upgrade Plan
            </Button>
          </CardContent>
        </Card>
      )}

      {(show("recent_alerts") || show("activity_feed")) && (
        <>
          <SectionHeading icon={Waves} title={t("dashboard.activity", "Activity")} subtitle={t("dashboard.activitySubtitle", "Recent alerts & live event feed")} />
          <div className="grid grid-cols-1 lg:grid-cols-5 gap-3">
            {show("recent_alerts") && <RecentAlerts events={recentEvents} />}
            {show("activity_feed") && <ActivityFeed events={feedEvents} />}
          </div>
        </>
      )}

      {show("response_actions") && hasFeature("allowThreatIntel") && (
        <>
          <SectionHeading icon={Zap} title={t("dashboard.response", "Response")} subtitle={t("dashboard.responseSubtitle", "Automated response actions")} />
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            <ResponseActionsFeed actions={recentActions} />
          </div>
        </>
      )}
    </div>
  );
}
