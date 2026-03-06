import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { queryClient } from "@/lib/queryClient";
import { ShieldAlert, AlertTriangle, Bug, Activity, ArrowUpRight, ArrowDownRight, Clock, Monitor, Lock, Radio } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import type { SecurityEvent } from "@shared/schema";

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
            <span className="text-xs text-muted-foreground uppercase tracking-wider">{title}</span>
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
  return (
    <Card className="col-span-2">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium tracking-wider uppercase">Event Trend (24h)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[220px]">
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
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium tracking-wider uppercase">Severity Breakdown</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[220px] flex items-center justify-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={50}
                outerRadius={80}
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
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: severityColors[entry.name] }} />
              <span className="text-[10px] text-muted-foreground capitalize">{entry.name}</span>
              <span className="text-[10px] font-mono font-bold">{entry.value}</span>
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

function RecentAlerts({ events }: { events: SecurityEvent[] }) {
  return (
    <Card className="col-span-2">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase">Recent Alerts</CardTitle>
          <Badge variant="secondary" className="text-[10px]">{events.length} events</Badge>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[260px]">
          <div className="px-4 pb-4">
            {events.length === 0 ? (
              <div className="text-center text-sm text-muted-foreground py-8">No recent alerts</div>
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
                      <p className="text-xs truncate">{event.description}</p>
                      <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                        <span className="text-[10px] text-muted-foreground font-mono">{event.sourceIp || "N/A"}</span>
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
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase">Live Feed</CardTitle>
          <div className="flex items-center gap-1.5">
            <div className="w-1.5 h-1.5 rounded-full bg-status-online animate-pulse-glow" />
            <span className="text-[10px] text-muted-foreground">Live</span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[260px]">
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

export default function Dashboard() {
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

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    const socket = new WebSocket(wsUrl);
    socket.onmessage = () => {
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/trend"] });
    };
    return () => socket.close();
  }, []);

  const recentEvents = events?.slice(0, 15) || [];
  const feedEvents = events?.slice(0, 10) || [];

  const severityData = events
    ? [
        { name: "critical", value: events.filter((e) => e.severity === "critical").length },
        { name: "high", value: events.filter((e) => e.severity === "high").length },
        { name: "medium", value: events.filter((e) => e.severity === "medium").length },
        { name: "low", value: events.filter((e) => e.severity === "low").length },
        { name: "info", value: events.filter((e) => e.severity === "info").length },
      ].filter((d) => d.value > 0)
    : [];

  const getThreatScoreColor = (score: number) => {
    if (score >= 75) return "text-severity-critical";
    if (score >= 50) return "text-severity-high";
    if (score >= 25) return "text-severity-medium";
    return "text-status-online";
  };

  if (statsLoading || eventsLoading) {
    return (
      <div className="p-6 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}><CardContent className="p-4"><Skeleton className="h-20 w-full" /></CardContent></Card>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <Card className="col-span-2"><CardContent className="p-4"><Skeleton className="h-[260px] w-full" /></CardContent></Card>
          <Card><CardContent className="p-4"><Skeleton className="h-[260px] w-full" /></CardContent></Card>
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
        <StatCard
          title="Events (24h)"
          value={stats?.totalEvents ?? 0}
          icon={ShieldAlert}
          trend={stats?.eventTrend ?? 0}
          trendLabel="vs yesterday"
        />
        <StatCard
          title="Critical"
          value={stats?.criticalAlerts ?? 0}
          icon={AlertTriangle}
          accent={(stats?.criticalAlerts ?? 0) > 0 ? "text-severity-critical" : undefined}
        />
        <StatCard
          title="Incidents"
          value={stats?.activeIncidents ?? 0}
          icon={Bug}
          trend={stats?.incidentTrend ?? 0}
          trendLabel="this week"
        />
        <StatCard
          title="Threat Score"
          value={`${stats?.threatScore ?? 0}/100`}
          icon={Activity}
          accent={getThreatScoreColor(stats?.threatScore ?? 0)}
        />
        <StatCard
          title="Assets"
          value={stats?.assetCount ?? 0}
          icon={Monitor}
        />
        <StatCard
          title="Quarantined"
          value={stats?.quarantineCount ?? 0}
          icon={Lock}
          accent={(stats?.quarantineCount ?? 0) > 0 ? "text-severity-high" : undefined}
        />
        <StatCard
          title="Honeypot"
          value={stats?.honeypotActivity ?? 0}
          icon={Radio}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <EventTrendChart data={trendData || []} />
        <SeverityBreakdown data={severityData} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <RecentAlerts events={recentEvents} />
        <ActivityFeed events={feedEvents} />
      </div>
    </div>
  );
}
