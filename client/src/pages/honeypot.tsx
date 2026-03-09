import { useQuery, useMutation } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Bug, Globe, Terminal, Radio, MapPin, Wifi, ShieldBan, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { HoneypotEvent } from "@shared/schema";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const countryCodes: Record<string, string> = {
  CN: "CN", RU: "RU", US: "US", KR: "KR", BR: "BR",
  IN: "IN", DE: "DE", NL: "NL", UA: "UA", IR: "IR",
  VN: "VN", RO: "RO",
};

const serviceColors: Record<string, string> = {
  SSH: "bg-severity-critical",
  HTTP: "bg-severity-high",
  SMB: "bg-severity-medium",
  RDP: "bg-primary",
  FTP: "bg-severity-low",
};

function formatTime(dateStr: string) {
  const d = new Date(dateStr);
  return d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function formatTimeAgo(dateStr: string) {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Honeypot() {
  useDocumentTitle("Honeypot");
  const { t } = useTranslation();
  const { toast } = useToast();

  const { data: events, isLoading } = useQuery<HoneypotEvent[]>({
    queryKey: ["/api/honeypot"],
    refetchInterval: 10000,
  });

  const blockIp = useMutation({
    mutationFn: async ({ ip, reason }: { ip: string; reason: string }) => {
      const res = await apiRequest("POST", "/api/response/block-ip", { ip, reason });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: t("honeypot.attackerBlocked") });
    },
    onError: (err: Error) => {
      toast({ title: t("honeypot.blockFailed"), description: err.message, variant: "destructive" });
    },
  });

  const isReady = !!events;
  useEffect(() => {
    if (!isReady) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${window.location.host}/ws`);
    socket.onmessage = (msg) => {
      const data = JSON.parse(msg.data);
      if (data.type === "new_honeypot_event") {
        queryClient.invalidateQueries({ queryKey: ["/api/honeypot"] });
      }
    };
    return () => {
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close();
      }
    };
  }, [isReady]);

  const stats = useMemo(() => {
    if (!events) return { total: 0, uniqueIps: 0, services: {}, countries: {}, topAttacker: null };
    const uniqueIps = new Set(events.map((e) => e.attackerIp));
    const services: Record<string, number> = {};
    const countries: Record<string, number> = {};
    for (const e of events) {
      services[e.service] = (services[e.service] || 0) + 1;
      if (e.country) countries[e.country] = (countries[e.country] || 0) + 1;
    }
    const ipCounts: Record<string, number> = {};
    for (const e of events) ipCounts[e.attackerIp] = (ipCounts[e.attackerIp] || 0) + 1;
    const topAttacker = Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0];
    return { total: events.length, uniqueIps: uniqueIps.size, services, countries, topAttacker };
  }, [events]);

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-3"><Skeleton className="h-[400px] w-full" /></div>
      </div>
    );
  }

  if (!events || events.length === 0) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold tracking-wider uppercase">{t("honeypot.title")}</h1>
            <p className="text-xs text-muted-foreground">{t("honeypot.subtitle")}</p>
          </div>
        </div>
        <Card>
          <CardContent className="py-16 text-center">
            <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-40" />
            <h2 className="text-base font-semibold mb-2" data-testid="text-honeypot-empty-title">No honeypot events yet</h2>
            <p className="text-sm text-muted-foreground max-w-md mx-auto" data-testid="text-honeypot-empty-description">
              Deploy an agent and start monitoring. Honeypot events will appear here as attackers interact with your decoy services.
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">{t("honeypot.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("honeypot.subtitle")}</p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-status-online animate-pulse-glow" />
          <span className="text-xs text-muted-foreground">{t("honeypot.liveMonitoring")}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("honeypot.totalInteractions")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-interactions">{stats.total}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("honeypot.uniqueAttackers")}</span>
          <p className="text-2xl font-bold font-mono text-severity-critical mt-1" data-testid="stat-unique-attackers">{stats.uniqueIps}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("honeypot.servicesTargeted")}</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-services">{Object.keys(stats.services).length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("honeypot.topAttacker")}</span>
          <p className="text-sm font-bold font-mono text-severity-high mt-1" data-testid="stat-top-attacker">
            {stats.topAttacker ? `${stats.topAttacker[0]} (${stats.topAttacker[1]})` : t("common.noData")}
          </p>
        </CardContent></Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Wifi className="w-4 h-4 text-primary" />{t("honeypot.serviceBreakdown")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(stats.services).sort((a, b) => b[1] - a[1]).map(([service, count]) => (
                <div key={service} className="flex items-center gap-2">
                  <Badge className={`text-[10px] ${serviceColors[service] || "bg-muted"} text-white`}>{service}</Badge>
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className={`h-full rounded-full ${serviceColors[service] || "bg-primary"}`}
                      style={{ width: `${(count / stats.total) * 100}%` }}
                    />
                  </div>
                  <span className="text-xs font-mono text-muted-foreground w-8 text-right">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <MapPin className="w-4 h-4 text-primary" />{t("honeypot.attackOrigins")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {Object.entries(stats.countries).sort((a, b) => b[1] - a[1]).map(([country, count]) => (
                <div key={country} className="flex items-center gap-2" data-testid={`country-row-${country}`}>
                  <span className="text-[10px] font-mono font-bold text-muted-foreground">{countryCodes[country] || country}</span>
                  <span className="text-xs font-mono flex-1">{country}</span>
                  <span className="text-xs font-mono text-muted-foreground">{count}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Bug className="w-4 h-4 text-primary" />{t("honeypot.activeHoneypots")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {[...new Set(events?.map((e) => e.honeypotName) || [])].map((name) => {
                const count = events?.filter((e) => e.honeypotName === name).length || 0;
                return (
                  <div key={name} className="flex items-center justify-between p-2 rounded bg-muted/50">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full bg-status-online animate-pulse-glow" />
                      <span className="text-xs font-mono">{name}</span>
                    </div>
                    <Badge variant="secondary" className="text-[10px]">{count} {t("common.hits")}</Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Radio className="w-4 h-4 text-severity-critical animate-pulse-glow" />{t("honeypot.liveAttackFeed")}
            </CardTitle>
            <Badge variant="secondary" className="text-[10px]">{events?.length || 0} {t("common.events")}</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="h-[400px]">
            <div className="px-4 pb-4">
              <div className="space-y-1">
                {events?.map((event) => (
                  <div key={event.id} className="flex items-center gap-3 py-2 px-2 rounded-md animate-fade-in" data-testid={`honeypot-row-${event.id}`}>
                    <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${serviceColors[event.service] || "bg-muted"}`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs font-mono font-bold text-severity-critical">{event.attackerIp}</span>
                        <Badge className={`text-[10px] ${serviceColors[event.service] || "bg-muted"} text-white`}>{event.service}</Badge>
                        <span className="text-[10px] text-muted-foreground">{event.honeypotName}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-0.5">
                        <Terminal className="w-3 h-3 text-muted-foreground" />
                        <span className="text-[11px] font-mono text-muted-foreground truncate">{event.payload}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0">
                      {event.country && (
                        <span className="text-[10px] font-mono font-bold text-muted-foreground">{event.country ? (countryCodes[event.country] || event.country) : "--"}</span>
                      )}
                      <Badge variant="secondary" className="text-[10px]">{event.action.replace(/_/g, " ")}</Badge>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {formatTimeAgo(event.createdAt as unknown as string)}
                      </span>
                      <Button
                        size="sm"
                        variant="destructive"
                        className="text-[9px]"
                        onClick={(e) => {
                          e.stopPropagation();
                          if (window.confirm(t("honeypot.blockAttackerConfirm", { ip: event.attackerIp }))) {
                            blockIp.mutate({ ip: event.attackerIp, reason: `Honeypot attacker: ${event.service} ${event.action}` });
                          }
                        }}
                        disabled={blockIp.isPending}
                        data-testid={`button-block-attacker-${event.id}`}
                      >
                        <ShieldBan className="w-3 h-3 me-0.5" />
                        {t("common.block")}
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
