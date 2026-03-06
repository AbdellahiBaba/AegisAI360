import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useTranslation } from "react-i18next";
import { Clock, Download, Filter, User, Shield, FileText, AlertTriangle, Settings } from "lucide-react";
import type { AuditLog } from "@shared/schema";
import { useState, useMemo } from "react";

const actionIcons: Record<string, React.ElementType> = {
  create_incident: AlertTriangle,
  update_incident: AlertTriangle,
  create_policy: Shield,
  toggle_policy: Shield,
  create_invite: User,
  change_role: User,
  quarantine_file: FileText,
  quarantine_restored: FileText,
  quarantine_deleted: FileText,
};

const actionColors: Record<string, string> = {
  create_incident: "bg-severity-high",
  update_incident: "bg-severity-medium",
  create_policy: "bg-primary",
  toggle_policy: "bg-primary",
  create_invite: "bg-status-online",
  change_role: "bg-severity-medium",
  quarantine_file: "bg-severity-critical",
  quarantine_restored: "bg-status-online",
  quarantine_deleted: "bg-severity-high",
};

function formatTime(dateStr: string) {
  const d = new Date(dateStr);
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
}

function formatTimeAgo(dateStr: string) {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Forensics() {
  const { t } = useTranslation();
  const [actionFilter, setActionFilter] = useState("all");
  const [search, setSearch] = useState("");

  const { data: logs, isLoading } = useQuery<AuditLog[]>({
    queryKey: ["/api/audit-logs"],
    refetchInterval: 10000,
  });

  const filteredLogs = useMemo(() => {
    if (!logs) return [];
    return logs.filter((log) => {
      if (actionFilter !== "all" && log.action !== actionFilter) return false;
      if (search && !log.details?.toLowerCase().includes(search.toLowerCase()) && !log.action.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [logs, actionFilter, search]);

  const uniqueActions = useMemo(() => {
    if (!logs) return [];
    return [...new Set(logs.map((l) => l.action))];
  }, [logs]);

  const exportCsv = () => {
    const headers = ["Timestamp", "Action", "Target Type", "Target ID", "User ID", "Details", "IP Address"];
    const rows = filteredLogs.map((l) => [
      l.createdAt, l.action, l.targetType || "", l.targetId || "", l.userId || "", l.details || "", l.ipAddress || "",
    ]);
    const csv = [headers.join(","), ...rows.map((r) => r.map((c) => `"${c}"`).join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-log-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[500px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">{t("forensics.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("forensics.subtitle")}</p>
        </div>
        <Button size="sm" variant="secondary" onClick={exportCsv} data-testid="button-export-csv">
          <Download className="w-4 h-4 me-1" />{t("forensics.exportCsv")}
        </Button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("forensics.totalEvents")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-logs">{logs?.length || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("forensics.filtered")}</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-filtered">{filteredLogs.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("forensics.actionTypes")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-action-types">{uniqueActions.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("forensics.latest")}</span>
          <p className="text-sm font-bold font-mono mt-1 text-muted-foreground" data-testid="stat-latest">
            {logs?.[0] ? formatTimeAgo(logs[0].createdAt as unknown as string) : t("common.noData")}
          </p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Filter className="w-4 h-4" />{t("forensics.filters")}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Input
                placeholder={t("forensics.searchDetails")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-48 h-8 text-xs"
                data-testid="input-search-logs"
              />
              <Select value={actionFilter} onValueChange={setActionFilter}>
                <SelectTrigger className="w-40 h-8 text-xs" data-testid="select-action-filter">
                  <SelectValue placeholder={t("forensics.allActions")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t("forensics.allActions")}</SelectItem>
                  {uniqueActions.map((a) => (
                    <SelectItem key={a} value={a}>{a.replace(/_/g, " ")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <Clock className="w-4 h-4 text-primary" />{t("forensics.timeline")}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="h-[500px]">
            <div className="px-4 pb-4">
              {filteredLogs.length === 0 ? (
                <div className="text-center text-sm text-muted-foreground py-12">{t("forensics.noAuditEvents")}</div>
              ) : (
                <div className="relative">
                  <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />
                  <div className="space-y-1">
                    {filteredLogs.map((log) => {
                      const Icon = actionIcons[log.action] || Settings;
                      const color = actionColors[log.action] || "bg-muted";
                      return (
                        <div key={log.id} className="flex gap-3 ps-1 py-2 animate-fade-in" data-testid={`audit-row-${log.id}`}>
                          <div className="flex flex-col items-center flex-shrink-0">
                            <div className={`w-7 h-7 rounded-full ${color} flex items-center justify-center z-10`}>
                              <Icon className="w-3.5 h-3.5 text-white" />
                            </div>
                          </div>
                          <div className="flex-1 min-w-0 pb-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <Badge variant="secondary" className="text-[10px] font-mono">{log.action.replace(/_/g, " ")}</Badge>
                              {log.targetType && (
                                <span className="text-[10px] text-muted-foreground">
                                  {log.targetType} #{log.targetId}
                                </span>
                              )}
                            </div>
                            {log.details && (
                              <p className="text-xs mt-0.5 text-foreground">{log.details}</p>
                            )}
                            <div className="flex items-center gap-3 mt-1 flex-wrap">
                              <span className="text-[10px] text-muted-foreground font-mono flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {formatTime(log.createdAt as unknown as string)}
                              </span>
                              {log.userId && (
                                <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                                  <User className="w-3 h-3" />
                                  {log.userId.slice(0, 8)}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
