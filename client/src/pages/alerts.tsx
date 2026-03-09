import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Search, Filter, Clock, Globe, Server, ArrowRight, ShieldBan, AlertTriangle, Loader2, Download, Trash2, CheckCircle, Eye, XCircle, Brain, ChevronDown, ChevronUp, Sparkles } from "lucide-react";
import { exportToCsv } from "@/lib/csvExport";
import { useToast } from "@/hooks/use-toast";
import type { SecurityEvent } from "@shared/schema";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

const statusClasses: Record<string, string> = {
  new: "bg-severity-critical/20 text-severity-critical",
  investigating: "bg-severity-medium/20 text-severity-medium",
  resolved: "bg-status-online/20 text-status-online",
  dismissed: "bg-muted text-muted-foreground",
};

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function getAiScoreColor(score: number): string {
  if (score >= 80) return "bg-severity-critical text-white";
  if (score >= 60) return "bg-severity-high text-white";
  if (score >= 40) return "bg-severity-medium text-black";
  if (score >= 20) return "bg-severity-low text-white";
  return "bg-severity-info text-white";
}

function getAiScoreLabel(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Info";
}

function getRecommendationBadgeClass(rec: string): string {
  const lower = rec.toLowerCase();
  if (lower.startsWith("escalate")) return "bg-severity-critical/20 text-severity-critical";
  if (lower.startsWith("monitor")) return "bg-severity-medium/20 text-severity-medium";
  if (lower.startsWith("dismiss")) return "bg-status-online/20 text-status-online";
  return "bg-muted text-muted-foreground";
}

export default function Alerts() {
  useDocumentTitle("Security Alerts");
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [aiInsightsOpen, setAiInsightsOpen] = useState(true);
  const { toast } = useToast();
  const { t } = useTranslation();

  const { data: events, isLoading } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/security-events"],
    refetchInterval: 15000,
  });

  const updateStatus = useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      await apiRequest("PATCH", `/api/security-events/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      toast({ title: t("alerts.statusUpdated") });
    },
  });

  const bulkUpdateStatus = useMutation({
    mutationFn: async ({ ids, status }: { ids: number[]; status: string }) => {
      const res = await apiRequest("PATCH", "/api/security-events/bulk", { ids, status });
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      setSelectedIds(new Set());
      toast({ title: t("alerts.statusUpdated"), description: `${data.updated} events updated` });
    },
    onError: (err: Error) => {
      toast({ title: t("alerts.failed"), description: err.message, variant: "destructive" });
    },
  });

  const bulkDelete = useMutation({
    mutationFn: async ({ ids }: { ids: number[] }) => {
      const res = await apiRequest("DELETE", "/api/security-events/bulk", { ids });
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      setSelectedIds(new Set());
      toast({ title: "Events deleted", description: `${data.deleted} events removed` });
    },
    onError: (err: Error) => {
      toast({ title: t("alerts.failed"), description: err.message, variant: "destructive" });
    },
  });

  const blockIp = useMutation({
    mutationFn: async ({ ip, reason }: { ip: string; reason: string }) => {
      const res = await apiRequest("POST", "/api/response/block-ip", { ip, reason });
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: t("alerts.ipBlocked"), description: t("alerts.eventsMitigated", { count: data.mitigatedCount || 0 }) });
    },
    onError: (err: Error) => {
      toast({ title: t("alerts.blockFailed"), description: err.message, variant: "destructive" });
    },
  });

  const createIncidentFromEvent = useMutation({
    mutationFn: async ({ eventId }: { eventId: number }) => {
      const res = await apiRequest("POST", "/api/response/create-incident-from-event", { eventId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: t("alerts.incidentCreated") });
    },
    onError: (err: Error) => {
      toast({ title: t("alerts.failed"), description: err.message, variant: "destructive" });
    },
  });

  const retriage = useMutation({
    mutationFn: async ({ eventId }: { eventId: number }) => {
      const res = await apiRequest("POST", `/api/security-events/${eventId}/retriage`);
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      if (selectedEvent && data.event) {
        setSelectedEvent(data.event);
      }
      toast({ title: "AI Triage Complete", description: `Threat score: ${data.event?.aiThreatScore ?? "N/A"}` });
    },
    onError: (err: Error) => {
      toast({ title: "AI Triage Failed", description: err.message, variant: "destructive" });
    },
  });

  const filtered = (events || []).filter((event) => {
    const matchesSearch =
      search === "" ||
      event.description.toLowerCase().includes(search.toLowerCase()) ||
      event.sourceIp?.toLowerCase().includes(search.toLowerCase()) ||
      event.eventType.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || event.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || event.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const allFilteredSelected = filtered.length > 0 && filtered.every((e) => selectedIds.has(e.id));
  const someFilteredSelected = filtered.some((e) => selectedIds.has(e.id));
  const isBulkPending = bulkUpdateStatus.isPending || bulkDelete.isPending;

  function toggleSelectAll() {
    if (allFilteredSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((e) => e.id)));
    }
  }

  function toggleSelect(id: number) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-[600px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-lg font-semibold tracking-wide">{t("alerts.title")}</h1>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              exportToCsv(
                "security-alerts",
                ["ID", "Description", "Type", "Source", "Source IP", "Destination IP", "Port", "Protocol", "Severity", "Status", "AI Score", "AI Classification", "Created At"],
                filtered.map((e) => [
                  e.id,
                  e.description,
                  e.eventType,
                  e.source,
                  e.sourceIp || "",
                  e.destinationIp || "",
                  e.port || "",
                  e.protocol || "",
                  e.severity,
                  e.status,
                  e.aiThreatScore ?? "",
                  e.aiClassification || "",
                  e.createdAt ? new Date(e.createdAt as unknown as string).toISOString() : "",
                ])
              );
            }}
            disabled={filtered.length === 0}
            data-testid="button-export-csv"
          >
            <Download className="w-4 h-4 me-1" />
            {t("common.exportCsv", "Export CSV")}
          </Button>
          <Badge variant="secondary" className="font-mono text-xs">{filtered.length} {t("common.events")}</Badge>
        </div>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder={t("alerts.searchEvents")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-events"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-full sm:w-[140px]" data-testid="select-severity-filter">
            <Filter className="w-3 h-3 me-1" />
            <SelectValue placeholder={t("common.severity")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("alerts.allSeverity")}</SelectItem>
            <SelectItem value="critical">{t("common.critical")}</SelectItem>
            <SelectItem value="high">{t("common.high")}</SelectItem>
            <SelectItem value="medium">{t("common.medium")}</SelectItem>
            <SelectItem value="low">{t("common.low")}</SelectItem>
            <SelectItem value="info">{t("common.info")}</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[140px]" data-testid="select-status-filter">
            <SelectValue placeholder={t("common.status")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("alerts.allStatus")}</SelectItem>
            <SelectItem value="new">{t("alerts.new")}</SelectItem>
            <SelectItem value="investigating">{t("alerts.investigating")}</SelectItem>
            <SelectItem value="resolved">{t("alerts.resolved")}</SelectItem>
            <SelectItem value="dismissed">{t("alerts.dismissed")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {selectedIds.size > 0 && (
        <Card data-testid="bulk-action-bar">
          <CardContent className="p-3 flex items-center gap-3 flex-wrap">
            <Badge variant="secondary" className="font-mono text-xs" data-testid="text-selected-count">
              {selectedIds.size} selected
            </Badge>
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                size="sm"
                variant="outline"
                disabled={isBulkPending}
                onClick={() => bulkUpdateStatus.mutate({ ids: Array.from(selectedIds), status: "investigating" })}
                data-testid="button-bulk-investigating"
              >
                {bulkUpdateStatus.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <Eye className="w-3 h-3 me-1" />}
                Mark Investigating
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={isBulkPending}
                onClick={() => bulkUpdateStatus.mutate({ ids: Array.from(selectedIds), status: "resolved" })}
                data-testid="button-bulk-resolved"
              >
                {bulkUpdateStatus.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <CheckCircle className="w-3 h-3 me-1" />}
                Mark Resolved
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={isBulkPending}
                onClick={() => bulkUpdateStatus.mutate({ ids: Array.from(selectedIds), status: "dismissed" })}
                data-testid="button-bulk-dismissed"
              >
                {bulkUpdateStatus.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <XCircle className="w-3 h-3 me-1" />}
                Dismiss
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={isBulkPending}
                onClick={() => {
                  if (!window.confirm(`Delete ${selectedIds.size} selected events? This cannot be undone.`)) return;
                  bulkDelete.mutate({ ids: Array.from(selectedIds) });
                }}
                data-testid="button-bulk-delete"
              >
                {bulkDelete.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <Trash2 className="w-3 h-3 me-1" />}
                Delete
              </Button>
            </div>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setSelectedIds(new Set())}
              data-testid="button-clear-selection"
            >
              Clear selection
            </Button>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[32px_1fr_100px_120px_100px_60px_80px_80px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span className="flex items-center justify-center">
                  <Checkbox
                    checked={allFilteredSelected}
                    onCheckedChange={toggleSelectAll}
                    aria-label="Select all"
                    data-testid="checkbox-select-all"
                    className={someFilteredSelected && !allFilteredSelected ? "opacity-60" : ""}
                  />
                </span>
                <span>{t("alerts.columnDescription")}</span>
                <span>{t("alerts.columnType")}</span>
                <span>{t("alerts.columnSource")}</span>
                <span>{t("alerts.columnSeverity")}</span>
                <span>AI</span>
                <span>{t("alerts.columnStatus")}</span>
                <span>{t("alerts.columnTime")}</span>
              </div>
              {filtered.length === 0 ? (
                <div className="text-center text-sm text-muted-foreground py-12">{t("alerts.noEventsFound")}</div>
              ) : (
                filtered.map((event) => (
                  <div
                    key={event.id}
                    className={`grid grid-cols-[32px_1fr_100px_120px_100px_60px_80px_80px] gap-2 px-4 py-2.5 border-b last:border-0 hover-elevate cursor-pointer items-center ${selectedIds.has(event.id) ? "bg-accent/30" : ""}`}
                    onClick={() => setSelectedEvent(event)}
                    data-testid={`event-row-${event.id}`}
                  >
                    <span className="flex items-center justify-center" onClick={(e) => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedIds.has(event.id)}
                        onCheckedChange={() => toggleSelect(event.id)}
                        aria-label={`Select event ${event.id}`}
                        data-testid={`checkbox-event-${event.id}`}
                      />
                    </span>
                    <div className="min-w-0">
                      <p className="text-xs truncate">{event.description}</p>
                      <p className="text-[10px] text-muted-foreground font-mono mt-0.5">
                        {event.sourceIp || t("common.noData")} {event.destinationIp ? `\u2192 ${event.destinationIp}` : ""}
                      </p>
                    </div>
                    <span className="text-[10px] text-muted-foreground capitalize font-mono">{event.eventType.replace(/_/g, " ")}</span>
                    <span className="text-[10px] text-muted-foreground">{event.source}</span>
                    <Badge className={`${severityClasses[event.severity]} text-[9px] uppercase w-fit`}>
                      {event.severity}
                    </Badge>
                    <span className="flex items-center justify-center">
                      {event.aiThreatScore != null ? (
                        <Badge
                          className={`${getAiScoreColor(event.aiThreatScore)} text-[9px] font-mono w-fit`}
                          data-testid={`badge-ai-score-${event.id}`}
                        >
                          {event.aiThreatScore}
                        </Badge>
                      ) : (
                        <span className="text-[9px] text-muted-foreground">--</span>
                      )}
                    </span>
                    <Badge className={`${statusClasses[event.status]} text-[9px] uppercase w-fit`}>
                      {event.status}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      {formatDate(event.createdAt as unknown as string)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Sheet open={!!selectedEvent} onOpenChange={() => setSelectedEvent(null)}>
        <SheetContent className="w-[400px] sm:w-[500px]">
          {selectedEvent && (
            <>
              <SheetHeader>
                <SheetTitle className="text-sm tracking-wider uppercase">{t("alerts.eventDetails")}</SheetTitle>
              </SheetHeader>
              <ScrollArea className="h-[calc(100vh-80px)] pr-2">
                <div className="space-y-4 mt-4">
                  <div className="flex gap-2 flex-wrap">
                    <Badge className={`${severityClasses[selectedEvent.severity]} text-[10px] uppercase`}>
                      {selectedEvent.severity}
                    </Badge>
                    <Badge className={`${statusClasses[selectedEvent.status]} text-[10px] uppercase`}>
                      {selectedEvent.status}
                    </Badge>
                    {selectedEvent.aiThreatScore != null && (
                      <Badge
                        className={`${getAiScoreColor(selectedEvent.aiThreatScore)} text-[10px]`}
                        data-testid="badge-ai-score-detail"
                      >
                        <Brain className="w-3 h-3 me-1" />
                        AI: {selectedEvent.aiThreatScore} ({getAiScoreLabel(selectedEvent.aiThreatScore)})
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm">{selectedEvent.description}</p>
                  <div className="space-y-3">
                    <DetailRow icon={Server} label={t("alerts.eventType")} value={selectedEvent.eventType.replace(/_/g, " ")} />
                    <DetailRow icon={Globe} label={t("alerts.sourceIp")} value={selectedEvent.sourceIp || t("common.noData")} />
                    <DetailRow icon={ArrowRight} label={t("alerts.destIp")} value={selectedEvent.destinationIp || t("common.noData")} />
                    <DetailRow icon={Server} label={t("alerts.port")} value={selectedEvent.port?.toString() || t("common.noData")} />
                    <DetailRow icon={Server} label={t("alerts.protocol")} value={selectedEvent.protocol || t("common.noData")} />
                    <DetailRow icon={Server} label={t("common.source")} value={selectedEvent.source} />
                    <DetailRow icon={Clock} label={t("common.time")} value={formatDate(selectedEvent.createdAt as unknown as string)} />
                  </div>

                  {(selectedEvent.aiThreatScore != null || selectedEvent.aiClassification || selectedEvent.aiRecommendation) && (
                    <Collapsible open={aiInsightsOpen} onOpenChange={setAiInsightsOpen}>
                      <CollapsibleTrigger asChild>
                        <div className="flex items-center justify-between border-t pt-4 cursor-pointer" data-testid="toggle-ai-insights">
                          <div className="flex items-center gap-2">
                            <Sparkles className="w-4 h-4 text-amber-500" />
                            <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">AI Insights</p>
                          </div>
                          {aiInsightsOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                        </div>
                      </CollapsibleTrigger>
                      <CollapsibleContent>
                        <div className="space-y-3 mt-3 pl-1 border-l-2 border-amber-500/30 ml-2">
                          <div className="pl-3 space-y-3">
                            {selectedEvent.aiThreatScore != null && (
                              <div className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground w-24 flex-shrink-0">Threat Score</span>
                                <div className="flex items-center gap-2">
                                  <div className="w-24 h-2 rounded-full bg-muted">
                                    <div
                                      className={`h-2 rounded-full ${selectedEvent.aiThreatScore >= 80 ? "bg-severity-critical" : selectedEvent.aiThreatScore >= 60 ? "bg-severity-high" : selectedEvent.aiThreatScore >= 40 ? "bg-severity-medium" : selectedEvent.aiThreatScore >= 20 ? "bg-severity-low" : "bg-severity-info"}`}
                                      style={{ width: `${selectedEvent.aiThreatScore}%` }}
                                    />
                                  </div>
                                  <span className="text-xs font-mono font-semibold" data-testid="text-ai-score-value">{selectedEvent.aiThreatScore}/100</span>
                                </div>
                              </div>
                            )}
                            {selectedEvent.aiClassification && (
                              <div className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground w-24 flex-shrink-0">Classification</span>
                                <Badge variant="outline" className="text-[10px] capitalize" data-testid="badge-ai-classification">
                                  {selectedEvent.aiClassification.replace(/_/g, " ")}
                                </Badge>
                              </div>
                            )}
                            {selectedEvent.aiRecommendation && (
                              <div className="space-y-1.5">
                                <div className="flex items-center gap-3">
                                  <span className="text-xs text-muted-foreground w-24 flex-shrink-0">Action</span>
                                  <Badge className={`${getRecommendationBadgeClass(selectedEvent.aiRecommendation)} text-[10px] capitalize`} data-testid="badge-ai-recommendation">
                                    {selectedEvent.aiRecommendation.split("|")[0].trim()}
                                  </Badge>
                                </div>
                                {selectedEvent.aiRecommendation.includes("|") && (
                                  <p className="text-[11px] text-muted-foreground italic pl-[calc(6rem+12px)]" data-testid="text-ai-reasoning">
                                    {selectedEvent.aiRecommendation.split("|").slice(1).join("|").trim()}
                                  </p>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </CollapsibleContent>
                    </Collapsible>
                  )}

                  {!selectedEvent.aiThreatScore && (
                    <div className="border-t pt-4">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => retriage.mutate({ eventId: selectedEvent.id })}
                        disabled={retriage.isPending}
                        data-testid="button-ai-triage"
                      >
                        {retriage.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <Brain className="w-3 h-3 me-1" />}
                        Run AI Triage
                      </Button>
                    </div>
                  )}

                  <div className="flex gap-2 mt-6 flex-wrap">
                    {selectedEvent.status === "new" && (
                      <Button
                        size="sm"
                        onClick={() => {
                          updateStatus.mutate({ id: selectedEvent.id, status: "investigating" });
                          setSelectedEvent({ ...selectedEvent, status: "investigating" });
                        }}
                        data-testid="button-investigate-event"
                      >
                        {t("alerts.investigate")}
                      </Button>
                    )}
                    {selectedEvent.status !== "resolved" && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => {
                          updateStatus.mutate({ id: selectedEvent.id, status: "resolved" });
                          setSelectedEvent({ ...selectedEvent, status: "resolved" });
                        }}
                        data-testid="button-resolve-event"
                      >
                        {t("alerts.resolve")}
                      </Button>
                    )}
                    {selectedEvent.status !== "dismissed" && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => {
                          updateStatus.mutate({ id: selectedEvent.id, status: "dismissed" });
                          setSelectedEvent({ ...selectedEvent, status: "dismissed" });
                        }}
                        data-testid="button-dismiss-event"
                      >
                        {t("alerts.dismiss")}
                      </Button>
                    )}
                  </div>
                  <div className="border-t pt-4 mt-4 space-y-2">
                    <p className="text-[10px] uppercase tracking-wider text-muted-foreground font-semibold">{t("alerts.responseActions")}</p>
                    <div className="flex gap-2 flex-wrap">
                      {selectedEvent.sourceIp && (
                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => {
                            if (!window.confirm(t("alerts.blockIpConfirm", { ip: selectedEvent.sourceIp }))) return;
                            blockIp.mutate({ ip: selectedEvent.sourceIp!, reason: `Blocked from event: ${selectedEvent.description.slice(0, 80)}` });
                          }}
                          disabled={blockIp.isPending}
                          data-testid="button-block-ip"
                        >
                          {blockIp.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <ShieldBan className="w-3 h-3 me-1" />}
                          {t("alerts.blockSourceIp")}
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => {
                          if (!window.confirm(t("alerts.createIncidentConfirm"))) return;
                          createIncidentFromEvent.mutate({ eventId: selectedEvent.id });
                        }}
                        disabled={createIncidentFromEvent.isPending}
                        data-testid="button-create-incident-from-event"
                      >
                        {createIncidentFromEvent.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <AlertTriangle className="w-3 h-3 me-1" />}
                        {t("alerts.createIncident")}
                      </Button>
                    </div>
                  </div>
                </div>
              </ScrollArea>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function DetailRow({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
      <span className="text-xs text-muted-foreground w-20 flex-shrink-0">{label}</span>
      <span className="text-xs font-mono">{value}</span>
    </div>
  );
}
