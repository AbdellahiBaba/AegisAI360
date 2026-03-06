import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Label } from "@/components/ui/label";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Plus, Search, Globe, Hash, Link, Mail, Server } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { ThreatIntel } from "@shared/schema";

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
};

const typeIcons: Record<string, React.ElementType> = {
  ip: Globe,
  domain: Server,
  hash: Hash,
  url: Link,
  email: Mail,
};

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

export default function ThreatIntelPage() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [value, setValue] = useState("");
  const [indicatorType, setIndicatorType] = useState("ip");
  const [threatType, setThreatType] = useState("malware");
  const [severity, setSeverity] = useState("medium");
  const [source, setSource] = useState("");
  const [description, setDescription] = useState("");
  const { toast } = useToast();

  const { data: indicators, isLoading } = useQuery<ThreatIntel[]>({
    queryKey: ["/api/threat-intel"],
  });

  const createIndicator = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/threat-intel", {
        indicatorType, value, threatType, severity, source, description: description || undefined,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel"] });
      toast({ title: "Indicator added" });
      setDialogOpen(false);
      setValue("");
      setSource("");
      setDescription("");
    },
  });

  const toggleActive = useMutation({
    mutationFn: async ({ id, active }: { id: number; active: boolean }) => {
      await apiRequest("PATCH", `/api/threat-intel/${id}`, { active });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel"] });
    },
  });

  const filtered = (indicators || []).filter((ind) => {
    const matchesSearch =
      search === "" ||
      ind.value.toLowerCase().includes(search.toLowerCase()) ||
      ind.description?.toLowerCase().includes(search.toLowerCase());
    const matchesType = typeFilter === "all" || ind.indicatorType === typeFilter;
    return matchesSearch && matchesType;
  });

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
        <h1 className="text-lg font-semibold tracking-wide">Threat Intelligence</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-indicator">
              <Plus className="w-4 h-4 mr-1" />
              Add IOC
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Indicator of Compromise</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select value={indicatorType} onValueChange={setIndicatorType}>
                    <SelectTrigger data-testid="select-indicator-type"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip">IP Address</SelectItem>
                      <SelectItem value="domain">Domain</SelectItem>
                      <SelectItem value="hash">File Hash</SelectItem>
                      <SelectItem value="url">URL</SelectItem>
                      <SelectItem value="email">Email</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Threat Type</Label>
                  <Select value={threatType} onValueChange={setThreatType}>
                    <SelectTrigger data-testid="select-threat-type"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="malware">Malware</SelectItem>
                      <SelectItem value="phishing">Phishing</SelectItem>
                      <SelectItem value="c2">C2 Server</SelectItem>
                      <SelectItem value="botnet">Botnet</SelectItem>
                      <SelectItem value="apt">APT</SelectItem>
                      <SelectItem value="ransomware">Ransomware</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Value</Label>
                <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. 192.168.1.1 or evil.com" data-testid="input-indicator-value" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>Severity</Label>
                  <Select value={severity} onValueChange={setSeverity}>
                    <SelectTrigger data-testid="select-indicator-severity"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Source</Label>
                  <Input value={source} onChange={(e) => setSource(e.target.value)} placeholder="e.g. VirusTotal" data-testid="input-indicator-source" />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Additional context..." data-testid="input-indicator-description" />
              </div>
              <Button
                onClick={() => createIndicator.mutate()}
                disabled={!value || !source || createIndicator.isPending}
                className="w-full"
                data-testid="button-submit-indicator"
              >
                {createIndicator.isPending ? "Adding..." : "Add Indicator"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder="Search indicators..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-9" data-testid="input-search-intel" />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[140px]" data-testid="select-type-filter">
            <SelectValue placeholder="Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="ip">IP Address</SelectItem>
            <SelectItem value="domain">Domain</SelectItem>
            <SelectItem value="hash">File Hash</SelectItem>
            <SelectItem value="url">URL</SelectItem>
            <SelectItem value="email">Email</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[40px_1fr_100px_80px_100px_80px_60px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span></span>
                <span>Value</span>
                <span>Threat</span>
                <span>Severity</span>
                <span>Source</span>
                <span>Seen</span>
                <span>Active</span>
              </div>
              {filtered.length === 0 ? (
                <div className="text-center text-sm text-muted-foreground py-12">No indicators found</div>
              ) : (
                filtered.map((ind) => {
                  const Icon = typeIcons[ind.indicatorType] || Globe;
                  return (
                    <div
                      key={ind.id}
                      className="grid grid-cols-[40px_1fr_100px_80px_100px_80px_60px] gap-2 px-4 py-2.5 border-b last:border-0 items-center"
                      data-testid={`intel-row-${ind.id}`}
                    >
                      <div className="flex items-center justify-center">
                        <Icon className="w-4 h-4 text-muted-foreground" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-xs font-mono truncate">{ind.value}</p>
                        {ind.description && (
                          <p className="text-[10px] text-muted-foreground truncate mt-0.5">{ind.description}</p>
                        )}
                      </div>
                      <span className="text-[10px] text-muted-foreground capitalize">{ind.threatType}</span>
                      <Badge className={`${severityClasses[ind.severity]} text-[9px] uppercase w-fit`}>
                        {ind.severity}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">{ind.source}</span>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {formatDate(ind.lastSeen as unknown as string)}
                      </span>
                      <Button
                        size="sm"
                        variant={ind.active ? "default" : "secondary"}
                        className="h-6 text-[10px] px-2"
                        onClick={() => toggleActive.mutate({ id: ind.id, active: !ind.active })}
                        data-testid={`button-toggle-${ind.id}`}
                      >
                        {ind.active ? "On" : "Off"}
                      </Button>
                    </div>
                  );
                })
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
