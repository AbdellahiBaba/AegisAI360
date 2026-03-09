import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import type { SecurityEvent, ThreatHuntingQuery } from "@shared/schema";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Search, Save, Trash2, Play, Clock, Crosshair,
  ChevronDown, ChevronRight, Sparkles, Loader2, BookOpen,
  X, Filter, BarChart3,
} from "lucide-react";

interface HuntFilters {
  timeRange?: string;
  eventTypes?: string[];
  severities?: string[];
  sourceIps?: string[];
  destIps?: string[];
  keywords?: string;
  tactics?: string[];
  techniques?: string[];
}

interface SearchResult {
  events: SecurityEvent[];
  timeline: { time: string; count: number }[];
  total: number;
}

const EVENT_TYPES = [
  "brute_force", "malware", "intrusion", "port_scan", "ddos",
  "data_exfiltration", "privilege_escalation", "lateral_movement",
  "phishing", "ransomware", "network_vulnerability", "credential_stuffing",
  "unauthorized_access", "policy_violation",
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const TACTICS = [
  "initial-access", "execution", "persistence", "privilege-escalation",
  "defense-evasion", "credential-access", "discovery", "lateral-movement",
  "collection", "exfiltration", "command-and-control", "impact",
];

const TIME_RANGES = [
  { value: "1h", label: "Last 1 Hour" },
  { value: "6h", label: "Last 6 Hours" },
  { value: "24h", label: "Last 24 Hours" },
  { value: "7d", label: "Last 7 Days" },
  { value: "30d", label: "Last 30 Days" },
];

function severityColor(severity: string) {
  switch (severity) {
    case "critical": return "bg-red-500/10 text-red-500 border-red-500/30";
    case "high": return "bg-orange-500/10 text-orange-500 border-orange-500/30";
    case "medium": return "bg-yellow-500/10 text-yellow-500 border-yellow-500/30";
    case "low": return "bg-blue-500/10 text-blue-500 border-blue-500/30";
    default: return "bg-muted text-muted-foreground";
  }
}

function MultiSelect({ options, selected, onChange, placeholder }: {
  options: string[];
  selected: string[];
  onChange: (val: string[]) => void;
  placeholder: string;
}) {
  const [open, setOpen] = useState(false);

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="sm"
        className="w-full justify-between text-xs"
        onClick={() => setOpen(!open)}
        data-testid={`button-multiselect-${placeholder.toLowerCase().replace(/\s+/g, '-')}`}
      >
        <span className="truncate">
          {selected.length > 0 ? `${selected.length} selected` : placeholder}
        </span>
        <ChevronDown className="w-3 h-3 ml-1 flex-shrink-0" />
      </Button>
      {open && (
        <div className="absolute z-50 mt-1 w-full max-h-48 overflow-auto rounded-md border bg-popover p-1 shadow-md">
          {options.map((opt) => (
            <button
              key={opt}
              className={`flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover-elevate cursor-pointer ${selected.includes(opt) ? "bg-primary/10 text-primary font-medium" : ""}`}
              onClick={() => {
                onChange(
                  selected.includes(opt)
                    ? selected.filter((s) => s !== opt)
                    : [...selected, opt]
                );
              }}
              data-testid={`option-${opt}`}
            >
              <div className={`w-3 h-3 border rounded-sm flex items-center justify-center ${selected.includes(opt) ? "bg-primary border-primary" : "border-muted-foreground/40"}`}>
                {selected.includes(opt) && <span className="text-primary-foreground text-[8px]">&#10003;</span>}
              </div>
              <span className="capitalize">{opt.replace(/_/g, " ").replace(/-/g, " ")}</span>
            </button>
          ))}
          {selected.length > 0 && (
            <button
              className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-muted-foreground hover-elevate mt-1 border-t cursor-pointer"
              onClick={() => onChange([])}
              data-testid="button-clear-selection"
            >
              <X className="w-3 h-3" />
              Clear all
            </button>
          )}
        </div>
      )}
    </div>
  );
}

export default function ThreatHuntingPage() {
  useDocumentTitle("Threat Hunting - AegisAI360");

  const { toast } = useToast();
  const [filters, setFilters] = useState<HuntFilters>({});
  const [nlQuery, setNlQuery] = useState("");
  const [results, setResults] = useState<SearchResult | null>(null);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [saveDialogOpen, setSaveDialogOpen] = useState(false);
  const [savedQueriesPanelOpen, setSavedQueriesPanelOpen] = useState(false);
  const [saveName, setSaveName] = useState("");
  const [saveDescription, setSaveDescription] = useState("");
  const [sourceIpInput, setSourceIpInput] = useState("");
  const [destIpInput, setDestIpInput] = useState("");

  const { data: savedQueries, isLoading: queriesLoading } = useQuery<ThreatHuntingQuery[]>({
    queryKey: ["/api/threat-hunting/queries"],
  });

  const searchMutation = useMutation({
    mutationFn: async (searchFilters: HuntFilters) => {
      const res = await apiRequest("POST", "/api/threat-hunting/search", searchFilters);
      return res.json() as Promise<SearchResult>;
    },
    onSuccess: (data) => {
      setResults(data);
      toast({ title: "Search Complete", description: `Found ${data.total} matching events` });
    },
    onError: () => {
      toast({ title: "Search Failed", description: "Failed to execute search query", variant: "destructive" });
    },
  });

  const nlSearchMutation = useMutation({
    mutationFn: async (query: string) => {
      const res = await apiRequest("POST", "/api/threat-hunting/nl-search", { query });
      return res.json() as Promise<{ filters: HuntFilters }>;
    },
    onSuccess: (data) => {
      setFilters(data.filters);
      searchMutation.mutate(data.filters);
      toast({ title: "Query Parsed", description: "Natural language query converted to filters" });
    },
    onError: () => {
      toast({ title: "Parse Failed", description: "Failed to parse natural language query", variant: "destructive" });
    },
  });

  const saveQueryMutation = useMutation({
    mutationFn: async (data: { name: string; description: string; query: HuntFilters }) => {
      const res = await apiRequest("POST", "/api/threat-hunting/queries", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-hunting/queries"] });
      setSaveDialogOpen(false);
      setSaveName("");
      setSaveDescription("");
      toast({ title: "Query Saved", description: "Threat hunting query saved successfully" });
    },
  });

  const deleteQueryMutation = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/threat-hunting/queries/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-hunting/queries"] });
      toast({ title: "Query Deleted" });
    },
  });

  const handleSearch = useCallback(() => {
    searchMutation.mutate(filters);
  }, [filters]);

  const handleNlSearch = useCallback(() => {
    if (nlQuery.trim()) {
      nlSearchMutation.mutate(nlQuery.trim());
    }
  }, [nlQuery]);

  const loadSavedQuery = useCallback((q: ThreatHuntingQuery) => {
    const queryData = q.query as HuntFilters;
    setFilters(queryData);
    setSavedQueriesPanelOpen(false);
    searchMutation.mutate(queryData);
  }, []);

  const addSourceIp = useCallback(() => {
    const ip = sourceIpInput.trim();
    if (ip && !(filters.sourceIps || []).includes(ip)) {
      setFilters(prev => ({ ...prev, sourceIps: [...(prev.sourceIps || []), ip] }));
      setSourceIpInput("");
    }
  }, [sourceIpInput, filters.sourceIps]);

  const addDestIp = useCallback(() => {
    const ip = destIpInput.trim();
    if (ip && !(filters.destIps || []).includes(ip)) {
      setFilters(prev => ({ ...prev, destIps: [...(prev.destIps || []), ip] }));
      setDestIpInput("");
    }
  }, [destIpInput, filters.destIps]);

  const clearFilters = useCallback(() => {
    setFilters({});
    setResults(null);
  }, []);

  const hasActiveFilters = Object.values(filters).some(v =>
    v !== undefined && v !== "" && (!Array.isArray(v) || v.length > 0)
  );

  const maxTimelineCount = results ? Math.max(...results.timeline.map(t => t.count), 1) : 1;

  return (
    <div className="flex flex-col h-full">
      <div className="p-4 border-b space-y-3">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-primary" />
            <h1 className="text-lg font-semibold" data-testid="text-page-title">Threat Hunting</h1>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSavedQueriesPanelOpen(true)}
              data-testid="button-saved-queries"
            >
              <BookOpen className="w-3.5 h-3.5 mr-1.5" />
              Saved Queries
              {savedQueries && savedQueries.length > 0 && (
                <Badge variant="secondary" className="ml-1.5 text-[9px]">{savedQueries.length}</Badge>
              )}
            </Button>
            {hasActiveFilters && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSaveDialogOpen(true)}
                data-testid="button-save-query"
              >
                <Save className="w-3.5 h-3.5 mr-1.5" />
                Save Query
              </Button>
            )}
            {hasActiveFilters && (
              <Button
                variant="ghost"
                size="sm"
                onClick={clearFilters}
                data-testid="button-clear-filters"
              >
                <X className="w-3.5 h-3.5 mr-1.5" />
                Clear
              </Button>
            )}
          </div>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <Sparkles className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              placeholder='Natural language search (e.g., "brute force attacks in the last 24 hours")'
              value={nlQuery}
              onChange={(e) => setNlQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleNlSearch()}
              className="pl-8 text-xs"
              data-testid="input-nl-search"
            />
          </div>
          <Button
            size="sm"
            onClick={handleNlSearch}
            disabled={!nlQuery.trim() || nlSearchMutation.isPending}
            data-testid="button-nl-search"
          >
            {nlSearchMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
          </Button>
        </div>
      </div>

      <div className="flex flex-1 min-h-0">
        <div className="w-64 border-r p-3 overflow-auto space-y-4 flex-shrink-0">
          <div className="flex items-center gap-1.5 text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            <Filter className="w-3.5 h-3.5" />
            Filters
          </div>

          <div className="space-y-3">
            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Time Range</Label>
              <Select
                value={filters.timeRange || ""}
                onValueChange={(v) => setFilters(prev => ({ ...prev, timeRange: v || undefined }))}
              >
                <SelectTrigger className="text-xs" data-testid="select-time-range">
                  <SelectValue placeholder="All time" />
                </SelectTrigger>
                <SelectContent>
                  {TIME_RANGES.map(tr => (
                    <SelectItem key={tr.value} value={tr.value}>{tr.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Event Types</Label>
              <MultiSelect
                options={EVENT_TYPES}
                selected={filters.eventTypes || []}
                onChange={(v) => setFilters(prev => ({ ...prev, eventTypes: v.length > 0 ? v : undefined }))}
                placeholder="All types"
              />
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Severities</Label>
              <MultiSelect
                options={SEVERITIES}
                selected={filters.severities || []}
                onChange={(v) => setFilters(prev => ({ ...prev, severities: v.length > 0 ? v : undefined }))}
                placeholder="All severities"
              />
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">MITRE Tactics</Label>
              <MultiSelect
                options={TACTICS}
                selected={filters.tactics || []}
                onChange={(v) => setFilters(prev => ({ ...prev, tactics: v.length > 0 ? v : undefined }))}
                placeholder="All tactics"
              />
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Source IPs</Label>
              <div className="flex gap-1">
                <Input
                  placeholder="Add IP..."
                  value={sourceIpInput}
                  onChange={(e) => setSourceIpInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addSourceIp()}
                  className="text-xs"
                  data-testid="input-source-ip"
                />
                <Button size="icon" variant="ghost" onClick={addSourceIp} data-testid="button-add-source-ip">
                  <span className="text-lg leading-none">+</span>
                </Button>
              </div>
              {(filters.sourceIps || []).map(ip => (
                <Badge key={ip} variant="secondary" className="mt-1 mr-1 text-[10px]">
                  {ip}
                  <button className="ml-1 cursor-pointer" onClick={() => setFilters(prev => ({ ...prev, sourceIps: prev.sourceIps?.filter(i => i !== ip) }))}>
                    <X className="w-2.5 h-2.5" />
                  </button>
                </Badge>
              ))}
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Dest IPs</Label>
              <div className="flex gap-1">
                <Input
                  placeholder="Add IP..."
                  value={destIpInput}
                  onChange={(e) => setDestIpInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addDestIp()}
                  className="text-xs"
                  data-testid="input-dest-ip"
                />
                <Button size="icon" variant="ghost" onClick={addDestIp} data-testid="button-add-dest-ip">
                  <span className="text-lg leading-none">+</span>
                </Button>
              </div>
              {(filters.destIps || []).map(ip => (
                <Badge key={ip} variant="secondary" className="mt-1 mr-1 text-[10px]">
                  {ip}
                  <button className="ml-1 cursor-pointer" onClick={() => setFilters(prev => ({ ...prev, destIps: prev.destIps?.filter(i => i !== ip) }))}>
                    <X className="w-2.5 h-2.5" />
                  </button>
                </Badge>
              ))}
            </div>

            <div>
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Keywords</Label>
              <Input
                placeholder="Search terms..."
                value={filters.keywords || ""}
                onChange={(e) => setFilters(prev => ({ ...prev, keywords: e.target.value || undefined }))}
                className="text-xs"
                data-testid="input-keywords"
              />
            </div>

            <Button
              className="w-full"
              size="sm"
              onClick={handleSearch}
              disabled={searchMutation.isPending}
              data-testid="button-search"
            >
              {searchMutation.isPending ? (
                <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" />
              ) : (
                <Search className="w-3.5 h-3.5 mr-1.5" />
              )}
              Hunt
            </Button>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-4">
          {!results && !searchMutation.isPending && (
            <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
              <Crosshair className="w-12 h-12 mb-3 opacity-20" />
              <p className="text-sm font-medium" data-testid="text-empty-state">Build your query and start hunting</p>
              <p className="text-xs mt-1">Use the filter panel or natural language search to find threats</p>
            </div>
          )}

          {searchMutation.isPending && (
            <div className="space-y-3">
              <Skeleton className="h-32 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          )}

          {results && (
            <>
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-primary" />
                  <span className="text-sm font-semibold" data-testid="text-result-count">
                    {results.total} Events Found
                  </span>
                </div>
                {results.timeline.length > 0 && (
                  <span className="text-[10px] text-muted-foreground">
                    {results.timeline[0]?.time?.slice(0, 16)} — {results.timeline[results.timeline.length - 1]?.time?.slice(0, 16)}
                  </span>
                )}
              </div>

              {results.timeline.length > 0 && (
                <Card className="p-3">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Timeline</div>
                  <div className="flex items-end gap-px h-16" data-testid="chart-timeline">
                    {results.timeline.map((bucket, i) => (
                      <div
                        key={i}
                        className="flex-1 bg-primary/60 rounded-t-sm min-w-[2px] hover-elevate transition-colors"
                        style={{ height: `${(bucket.count / maxTimelineCount) * 100}%` }}
                        title={`${bucket.time}: ${bucket.count} events`}
                      />
                    ))}
                  </div>
                </Card>
              )}

              <Card>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8"></TableHead>
                      <TableHead className="text-xs">Time</TableHead>
                      <TableHead className="text-xs">Type</TableHead>
                      <TableHead className="text-xs">Severity</TableHead>
                      <TableHead className="text-xs">Source IP</TableHead>
                      <TableHead className="text-xs">Description</TableHead>
                      <TableHead className="text-xs">Tactic</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.events.map((event) => (
                      <>
                        <TableRow
                          key={event.id}
                          className="cursor-pointer hover-elevate"
                          onClick={() => setExpandedRow(expandedRow === event.id ? null : event.id)}
                          data-testid={`row-event-${event.id}`}
                        >
                          <TableCell className="w-8">
                            {expandedRow === event.id ? (
                              <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
                            ) : (
                              <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                            )}
                          </TableCell>
                          <TableCell className="text-[11px] font-mono text-muted-foreground whitespace-nowrap">
                            {new Date(event.createdAt).toLocaleString()}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-[10px]">
                              {event.eventType?.replace(/_/g, " ")}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge className={`text-[10px] border ${severityColor(event.severity)}`}>
                              {event.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-[11px] font-mono">{event.sourceIp || "—"}</TableCell>
                          <TableCell className="text-[11px] max-w-[200px] truncate">{event.description}</TableCell>
                          <TableCell className="text-[11px]">{event.tactic || "—"}</TableCell>
                        </TableRow>
                        {expandedRow === event.id && (
                          <TableRow key={`${event.id}-detail`}>
                            <TableCell colSpan={7}>
                              <div className="p-3 bg-muted/30 rounded-md space-y-2 text-xs">
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                  <div>
                                    <span className="text-muted-foreground">Source:</span>{" "}
                                    <span className="font-mono">{event.source}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Dest IP:</span>{" "}
                                    <span className="font-mono">{event.destinationIp || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Port:</span>{" "}
                                    <span className="font-mono">{event.port || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Protocol:</span>{" "}
                                    <span className="font-mono">{event.protocol || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Technique:</span>{" "}
                                    <span className="font-mono">{event.techniqueId || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="text-muted-foreground">Status:</span>{" "}
                                    <span className="font-mono">{event.status}</span>
                                  </div>
                                  {event.aiThreatScore != null && (
                                    <div>
                                      <span className="text-muted-foreground">AI Score:</span>{" "}
                                      <span className="font-mono">{event.aiThreatScore}/100</span>
                                    </div>
                                  )}
                                  {event.aiClassification && (
                                    <div>
                                      <span className="text-muted-foreground">AI Class:</span>{" "}
                                      <span className="font-mono">{event.aiClassification}</span>
                                    </div>
                                  )}
                                </div>
                                {event.description && (
                                  <div>
                                    <span className="text-muted-foreground">Full Description:</span>
                                    <p className="mt-1">{event.description}</p>
                                  </div>
                                )}
                                {event.rawData && (
                                  <div>
                                    <span className="text-muted-foreground">Raw Data:</span>
                                    <pre className="mt-1 p-2 bg-muted rounded text-[10px] font-mono overflow-x-auto max-h-32">{event.rawData}</pre>
                                  </div>
                                )}
                              </div>
                            </TableCell>
                          </TableRow>
                        )}
                      </>
                    ))}
                    {results.events.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                          No events match the current filters
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </Card>
            </>
          )}
        </div>
      </div>

      <Dialog open={saveDialogOpen} onOpenChange={setSaveDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-sm">Save Hunting Query</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label className="text-xs">Name</Label>
              <Input
                placeholder="Query name..."
                value={saveName}
                onChange={(e) => setSaveName(e.target.value)}
                data-testid="input-save-name"
              />
            </div>
            <div>
              <Label className="text-xs">Description (optional)</Label>
              <Input
                placeholder="Describe this query..."
                value={saveDescription}
                onChange={(e) => setSaveDescription(e.target.value)}
                data-testid="input-save-description"
              />
            </div>
            <div className="text-[10px] text-muted-foreground">
              Active filters: {Object.entries(filters).filter(([, v]) => v !== undefined && v !== "" && (!Array.isArray(v) || v.length > 0)).map(([k]) => k).join(", ") || "None"}
            </div>
            <Button
              className="w-full"
              size="sm"
              disabled={!saveName.trim() || saveQueryMutation.isPending}
              onClick={() => saveQueryMutation.mutate({ name: saveName, description: saveDescription, query: filters })}
              data-testid="button-confirm-save"
            >
              {saveQueryMutation.isPending ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Save className="w-3.5 h-3.5 mr-1.5" />}
              Save Query
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <Sheet open={savedQueriesPanelOpen} onOpenChange={setSavedQueriesPanelOpen}>
        <SheetContent className="w-80">
          <SheetHeader>
            <SheetTitle className="text-sm flex items-center gap-2">
              <BookOpen className="w-4 h-4" />
              Saved Queries
            </SheetTitle>
          </SheetHeader>
          <div className="mt-4 space-y-2">
            {queriesLoading && (
              <div className="space-y-2">
                <Skeleton className="h-16 w-full" />
                <Skeleton className="h-16 w-full" />
              </div>
            )}
            {savedQueries && savedQueries.length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-8" data-testid="text-no-saved-queries">
                No saved queries yet
              </p>
            )}
            {savedQueries?.map((q) => (
              <Card
                key={q.id}
                className="p-3 hover-elevate cursor-pointer"
                data-testid={`card-saved-query-${q.id}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0" onClick={() => loadSavedQuery(q)}>
                    <p className="text-xs font-medium truncate">{q.name}</p>
                    {q.description && (
                      <p className="text-[10px] text-muted-foreground mt-0.5 truncate">{q.description}</p>
                    )}
                    <div className="flex items-center gap-2 mt-1.5">
                      {q.resultCount != null && (
                        <Badge variant="secondary" className="text-[9px]">{q.resultCount} results</Badge>
                      )}
                      <span className="text-[9px] text-muted-foreground">
                        {new Date(q.createdAt).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => loadSavedQuery(q)}
                      data-testid={`button-load-query-${q.id}`}
                    >
                      <Play className="w-3 h-3" />
                    </Button>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => deleteQueryMutation.mutate(q.id)}
                      data-testid={`button-delete-query-${q.id}`}
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              </Card>
            ))}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
