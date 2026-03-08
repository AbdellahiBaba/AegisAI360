import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Label } from "@/components/ui/label";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Plus, Search, Globe, Hash, Link, Mail, Server, ShieldBan, Loader2, Scan, AlertTriangle, CheckCircle, XCircle, ExternalLink, KeyRound } from "lucide-react";
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

interface ApiStatus {
  name: string;
  service: string;
  envVar: string | null;
  configured: boolean;
  hasDbKey: boolean;
  description: string;
  setupUrl: string;
  freeTier: string;
}

function ApiStatusSection() {
  const { data } = useQuery<{ apis: ApiStatus[] }>({
    queryKey: ["/api/threat-intel/api-status"],
  });
  const { toast } = useToast();
  const [editingService, setEditingService] = useState<string | null>(null);
  const [keyInputs, setKeyInputs] = useState<Record<string, string>>({});

  const saveKeyMutation = useMutation({
    mutationFn: async ({ service, apiKey }: { service: string; apiKey: string }) => {
      const res = await apiRequest("POST", "/api/threat-intel/api-keys", { service, apiKey });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel/api-status"] });
      setEditingService(null);
      setKeyInputs({});
      toast({ title: "API Key Saved" });
    },
    onError: (e: Error) => toast({ title: "Failed to save key", description: e.message, variant: "destructive" }),
  });

  const removeKeyMutation = useMutation({
    mutationFn: async (service: string) => {
      const res = await apiRequest("DELETE", `/api/threat-intel/api-keys/${service}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/threat-intel/api-status"] });
      toast({ title: "API Key Removed" });
    },
    onError: (e: Error) => toast({ title: "Failed to remove key", description: e.message, variant: "destructive" }),
  });

  if (!data) return null;

  const configuredCount = data.apis.filter(a => a.configured).length;
  const totalCount = data.apis.length;

  return (
    <Card data-testid="card-api-status">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center justify-between gap-2 flex-wrap">
          <span className="flex items-center gap-2">
            <KeyRound className="w-4 h-4" />
            API Configuration
          </span>
          <Badge variant={configuredCount === totalCount ? "default" : "secondary"} data-testid="badge-api-count">
            {configuredCount}/{totalCount} Active
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {data.apis.map((api) => (
            <div
              key={api.name}
              className="p-3 rounded-md bg-muted/30 space-y-2"
              data-testid={`api-status-${api.name.replace(/\s+/g, "-").toLowerCase()}`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  {api.configured ? (
                    <CheckCircle className="w-4 h-4 text-green-500 shrink-0" />
                  ) : (
                    <XCircle className="w-4 h-4 text-muted-foreground shrink-0" />
                  )}
                  <div className="min-w-0">
                    <p className="text-xs font-medium truncate">{api.name}</p>
                    <p className="text-[10px] text-muted-foreground">{api.description}</p>
                    <p className="text-[10px] text-muted-foreground">Free tier: {api.freeTier}</p>
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  {api.configured && (
                    <Badge variant="outline" className="text-[10px]">Active</Badge>
                  )}
                  {api.envVar && !api.hasDbKey && !api.configured && (
                    <a href={api.setupUrl} target="_blank" rel="noopener noreferrer">
                      <Button size="sm" variant="outline" className="text-[10px] gap-1 h-7" data-testid={`link-setup-${api.service}`}>
                        <ExternalLink className="w-3 h-3" /> Get Key
                      </Button>
                    </a>
                  )}
                  {api.envVar && (
                    <Button
                      size="sm"
                      variant={editingService === api.service ? "secondary" : "ghost"}
                      className="text-[10px] h-7"
                      onClick={() => {
                        setEditingService(editingService === api.service ? null : api.service);
                        setKeyInputs({});
                      }}
                      data-testid={`button-configure-${api.service}`}
                    >
                      {api.hasDbKey ? "Update Key" : "Add Key"}
                    </Button>
                  )}
                  {api.hasDbKey && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-[10px] h-7 text-destructive"
                      onClick={() => removeKeyMutation.mutate(api.service)}
                      disabled={removeKeyMutation.isPending}
                      data-testid={`button-remove-${api.service}`}
                    >
                      Remove
                    </Button>
                  )}
                </div>
              </div>
              {editingService === api.service && (
                <div className="flex gap-2 pt-1">
                  <Input
                    placeholder={`Enter ${api.name} API key`}
                    value={keyInputs[api.service] || ""}
                    onChange={(e) => setKeyInputs({ ...keyInputs, [api.service]: e.target.value })}
                    className="text-xs font-mono h-8"
                    type="password"
                    data-testid={`input-apikey-${api.service}`}
                  />
                  <Button
                    size="sm"
                    className="text-[10px] h-8"
                    disabled={!keyInputs[api.service] || saveKeyMutation.isPending}
                    onClick={() => saveKeyMutation.mutate({ service: api.service, apiKey: keyInputs[api.service] })}
                    data-testid={`button-save-${api.service}`}
                  >
                    {saveKeyMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : "Save"}
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function ThreatLookupSection() {
  const [lookupType, setLookupType] = useState("ip");
  const [lookupValue, setLookupValue] = useState("");
  const [lookupResult, setLookupResult] = useState<any>(null);
  const { toast } = useToast();

  const lookupMutation = useMutation({
    mutationFn: async () => {
      const endpoints: Record<string, { url: string; body: any }> = {
        ip: { url: "/api/threat-intel/ip", body: { ip: lookupValue } },
        domain: { url: "/api/threat-intel/otx-lookup", body: { indicator: lookupValue, type: "domain" } },
        url: { url: "/api/threat-intel/urlscan", body: { url: lookupValue } },
        hash: { url: "/api/threat-intel/hash", body: { hash: lookupValue } },
        safebrowsing: { url: "/api/threat-intel/safebrowsing", body: { url: lookupValue } },
      };
      const ep = endpoints[lookupType];
      const res = await apiRequest("POST", ep.url, ep.body);
      return res.json();
    },
    onSuccess: (data) => setLookupResult(data),
    onError: () => toast({ title: "Lookup failed", variant: "destructive" }),
  });

  return (
    <Card data-testid="card-threat-lookup">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm flex items-center gap-2">
          <Scan className="w-4 h-4" />
          Threat Intelligence Lookup
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-2">
          <Select value={lookupType} onValueChange={setLookupType}>
            <SelectTrigger className="w-[150px]" data-testid="select-lookup-type">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="ip">IP Reputation</SelectItem>
              <SelectItem value="domain">OTX Domain</SelectItem>
              <SelectItem value="url">URL Scan</SelectItem>
              <SelectItem value="hash">Hash Lookup</SelectItem>
              <SelectItem value="safebrowsing">Safe Browsing</SelectItem>
            </SelectContent>
          </Select>
          <Input
            value={lookupValue}
            onChange={(e) => setLookupValue(e.target.value)}
            placeholder={lookupType === "ip" ? "8.8.8.8" : lookupType === "hash" ? "SHA256 hash..." : "Enter value..."}
            className="flex-1"
            onKeyDown={(e) => { if (e.key === "Enter" && lookupValue) lookupMutation.mutate(); }}
            data-testid="input-lookup-value"
          />
          <Button onClick={() => lookupMutation.mutate()} disabled={!lookupValue || lookupMutation.isPending} data-testid="button-lookup">
            {lookupMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
          </Button>
        </div>

        {lookupResult && (
          <div className="p-3 bg-muted/50 rounded-lg text-sm space-y-2" data-testid="container-lookup-result">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <Badge variant="outline">{lookupResult.source}</Badge>
              {lookupResult.configured === false && (
                <Badge variant="secondary" className="text-xs gap-1">
                  <KeyRound className="w-3 h-3" />
                  API Key Required
                </Badge>
              )}
              {lookupResult.error && (
                <Badge variant="destructive" className="text-xs gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  Error
                </Badge>
              )}
            </div>

            {lookupResult.configured === false && (
              <div className="p-2 rounded-md bg-muted/50 space-y-1">
                <p className="text-xs text-muted-foreground">{lookupResult.message}</p>
                {lookupResult.setupInstructions && (
                  <p className="text-[10px] text-muted-foreground">{lookupResult.setupInstructions}</p>
                )}
                {lookupResult.setupUrl && (
                  <a
                    href={lookupResult.setupUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1 text-[10px] text-blue-500 hover:underline"
                    data-testid="link-result-setup"
                  >
                    <ExternalLink className="w-3 h-3" />
                    Get API Key
                  </a>
                )}
              </div>
            )}

            {lookupResult.error && !lookupResult.setupUrl && (
              <p className="text-xs text-destructive">{lookupResult.error}</p>
            )}

            {lookupResult.data && lookupType === "ip" && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                <div><span className="text-muted-foreground">Confidence:</span> <span className="font-medium">{lookupResult.data.abuseConfidenceScore}%</span></div>
                <div><span className="text-muted-foreground">Reports:</span> <span className="font-medium">{lookupResult.data.totalReports}</span></div>
                <div><span className="text-muted-foreground">Country:</span> <span className="font-medium">{lookupResult.data.countryCode}</span></div>
                <div><span className="text-muted-foreground">ISP:</span> <span className="font-medium">{lookupResult.data.isp}</span></div>
              </div>
            )}
            {lookupResult.data && lookupType === "domain" && (
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div><span className="text-muted-foreground">Pulses:</span> <span className="font-medium">{lookupResult.data.pulse_info?.count ?? lookupResult.data.pulseCount ?? "N/A"}</span></div>
                <div><span className="text-muted-foreground">Reputation:</span> <span className="font-medium">{lookupResult.data.reputation ?? "N/A"}</span></div>
              </div>
            )}
            {lookupResult.data && lookupType === "safebrowsing" && (
              <div className="text-xs">
                {lookupResult.data.safe ? (
                  <span className="text-green-500 font-medium flex items-center gap-1"><CheckCircle className="w-3 h-3" /> URL is safe</span>
                ) : (
                  <span className="text-red-500 font-medium flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Threats detected</span>
                )}
              </div>
            )}
            {lookupResult.data && lookupType === "hash" && (
              <div className="text-xs">
                <span className="text-muted-foreground">Status: </span>
                <span className="font-medium">{lookupResult.data.query_status || "unknown"}</span>
              </div>
            )}
            {lookupResult.data && lookupType === "url" && lookupResult.data.message && (
              <p className="text-xs text-muted-foreground">{lookupResult.data.message}</p>
            )}
            {lookupResult.message && lookupResult.configured !== false && <p className="text-xs text-muted-foreground">{lookupResult.message}</p>}
          </div>
        )}
      </CardContent>
    </Card>
  );
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

      <ApiStatusSection />

      <ThreatLookupSection />

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-530px)]">
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
