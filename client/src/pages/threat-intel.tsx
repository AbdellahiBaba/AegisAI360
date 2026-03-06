import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
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
import { Plus, Search, Globe, Hash, Link, Mail, Server, ShieldBan, Loader2 } from "lucide-react";
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
  const { t } = useTranslation();
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
      toast({ title: t("threatIntel.indicatorAdded") });
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

  const blockIp = useMutation({
    mutationFn: async ({ ip, reason }: { ip: string; reason: string }) => {
      const res = await apiRequest("POST", "/api/response/block-ip", { ip, reason });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: t("threatIntel.ipBlocked") });
    },
    onError: (err: Error) => {
      toast({ title: t("threatIntel.blockFailed"), description: err.message, variant: "destructive" });
    },
  });

  const sinkholeDomain = useMutation({
    mutationFn: async ({ domain }: { domain: string }) => {
      const res = await apiRequest("POST", "/api/response/sinkhole-domain", { domain });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: t("threatIntel.domainSinkholed") });
    },
    onError: (err: Error) => {
      toast({ title: t("threatIntel.sinkholeFailed"), description: err.message, variant: "destructive" });
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
        <h1 className="text-lg font-semibold tracking-wide">{t("threatIntel.title")}</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-indicator">
              <Plus className="w-4 h-4 me-1" />
              {t("threatIntel.addIoc")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t("threatIntel.addIndicator")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>{t("common.type")}</Label>
                  <Select value={indicatorType} onValueChange={setIndicatorType}>
                    <SelectTrigger data-testid="select-indicator-type"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip">{t("threatIntel.ipAddress")}</SelectItem>
                      <SelectItem value="domain">{t("threatIntel.domain")}</SelectItem>
                      <SelectItem value="hash">{t("threatIntel.fileHash")}</SelectItem>
                      <SelectItem value="url">{t("threatIntel.url")}</SelectItem>
                      <SelectItem value="email">{t("threatIntel.email")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>{t("threatIntel.threatType")}</Label>
                  <Select value={threatType} onValueChange={setThreatType}>
                    <SelectTrigger data-testid="select-threat-type"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="malware">{t("threatIntel.malware")}</SelectItem>
                      <SelectItem value="phishing">{t("threatIntel.phishing")}</SelectItem>
                      <SelectItem value="c2">{t("threatIntel.c2Server")}</SelectItem>
                      <SelectItem value="botnet">{t("threatIntel.botnet")}</SelectItem>
                      <SelectItem value="apt">{t("threatIntel.apt")}</SelectItem>
                      <SelectItem value="ransomware">{t("threatIntel.ransomware")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>{t("common.value")}</Label>
                <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder={t("threatIntel.valuePlaceholder")} data-testid="input-indicator-value" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>{t("common.severity")}</Label>
                  <Select value={severity} onValueChange={setSeverity}>
                    <SelectTrigger data-testid="select-indicator-severity"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">{t("common.critical")}</SelectItem>
                      <SelectItem value="high">{t("common.high")}</SelectItem>
                      <SelectItem value="medium">{t("common.medium")}</SelectItem>
                      <SelectItem value="low">{t("common.low")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>{t("common.source")}</Label>
                  <Input value={source} onChange={(e) => setSource(e.target.value)} placeholder={t("threatIntel.sourcePlaceholder")} data-testid="input-indicator-source" />
                </div>
              </div>
              <div className="space-y-2">
                <Label>{t("threatIntel.descriptionOptional")}</Label>
                <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("threatIntel.descriptionPlaceholder")} data-testid="input-indicator-description" />
              </div>
              <Button
                onClick={() => createIndicator.mutate()}
                disabled={!value || !source || createIndicator.isPending}
                className="w-full"
                data-testid="button-submit-indicator"
              >
                {createIndicator.isPending ? t("common.adding") : t("threatIntel.addIndicatorBtn")}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input placeholder={t("threatIntel.searchIndicators")} value={search} onChange={(e) => setSearch(e.target.value)} className="ps-9" data-testid="input-search-intel" />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[140px]" data-testid="select-type-filter">
            <SelectValue placeholder={t("common.type")} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t("threatIntel.allTypes")}</SelectItem>
            <SelectItem value="ip">{t("threatIntel.ipAddress")}</SelectItem>
            <SelectItem value="domain">{t("threatIntel.domain")}</SelectItem>
            <SelectItem value="hash">{t("threatIntel.fileHash")}</SelectItem>
            <SelectItem value="url">{t("threatIntel.url")}</SelectItem>
            <SelectItem value="email">{t("threatIntel.email")}</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[40px_1fr_100px_80px_100px_80px_60px_80px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span></span>
                <span>{t("common.value")}</span>
                <span>{t("threatIntel.threat")}</span>
                <span>{t("common.severity")}</span>
                <span>{t("common.source")}</span>
                <span>{t("threatIntel.seen")}</span>
                <span>{t("common.active")}</span>
                <span>{t("common.actions")}</span>
              </div>
              {filtered.length === 0 ? (
                <div className="text-center text-sm text-muted-foreground py-12">{t("threatIntel.noIndicators")}</div>
              ) : (
                filtered.map((ind) => {
                  const Icon = typeIcons[ind.indicatorType] || Globe;
                  return (
                    <div
                      key={ind.id}
                      className="grid grid-cols-[40px_1fr_100px_80px_100px_80px_60px_80px] gap-2 px-4 py-2.5 border-b last:border-0 items-center"
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
                        className="text-[10px]"
                        onClick={() => toggleActive.mutate({ id: ind.id, active: !ind.active })}
                        data-testid={`button-toggle-${ind.id}`}
                      >
                        {ind.active ? t("common.on") : t("common.off")}
                      </Button>
                      <div>
                        {ind.indicatorType === "ip" && (
                          <Button
                            size="sm"
                            variant="destructive"
                            className="text-[9px]"
                            onClick={() => {
                              if (window.confirm(t("threatIntel.blockIpConfirm", { value: ind.value }))) {
                                blockIp.mutate({ ip: ind.value, reason: `Threat intel IOC: ${ind.threatType}` });
                              }
                            }}
                            disabled={blockIp.isPending}
                            data-testid={`button-block-indicator-${ind.id}`}
                          >
                            <ShieldBan className="w-3 h-3 me-0.5" />
                            {t("common.block")}
                          </Button>
                        )}
                        {ind.indicatorType === "domain" && (
                          <Button
                            size="sm"
                            variant="destructive"
                            className="text-[9px]"
                            onClick={() => {
                              if (window.confirm(t("threatIntel.sinkholeConfirm", { value: ind.value }))) {
                                sinkholeDomain.mutate({ domain: ind.value });
                              }
                            }}
                            disabled={sinkholeDomain.isPending}
                            data-testid={`button-sinkhole-indicator-${ind.id}`}
                          >
                            <ShieldBan className="w-3 h-3 me-0.5" />
                            {t("common.sinkhole")}
                          </Button>
                        )}
                      </div>
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
