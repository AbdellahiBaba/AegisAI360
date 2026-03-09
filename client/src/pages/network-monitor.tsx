import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { NetworkDevice, NetworkScan } from "@shared/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Loader2, Wifi, WifiOff, Monitor, Smartphone, Tablet, Printer, Router,
  CircuitBoard, HelpCircle, Shield, ShieldOff, ShieldAlert, ShieldCheck,
  Ban, ArrowLeft, ArrowDownUp, Download, Upload, MapPin, Clock,
  Search, ScanLine, AlertTriangle, CheckCircle, XCircle, Trash2, Eye,
  Building2, User, StickyNote, Signal, Globe, Plus, Server, RefreshCw,
  Lock, Unlock, FileWarning, ExternalLink,
} from "lucide-react";
import { generateNetworkMonitorReportPDF } from "@/lib/reportGenerator";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

const DEVICE_ICONS: Record<string, React.ElementType> = {
  computer: Monitor, phone: Smartphone, tablet: Tablet, printer: Printer,
  router: Router, iot: CircuitBoard, unknown: HelpCircle, server: Server,
};

const AUTH_COLORS: Record<string, string> = {
  authorized: "bg-green-500/20 text-green-400 border-green-500/30",
  unauthorized: "bg-red-500/20 text-red-400 border-red-500/30",
  unknown: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  online: "bg-green-500",
  offline: "bg-zinc-500",
  blocked: "bg-red-500",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

function parseScanResults(device: NetworkDevice): any | null {
  if (!device.notes) return null;
  try {
    const parsed = JSON.parse(device.notes);
    if (parsed.summary) return parsed;
    return null;
  } catch {
    return null;
  }
}

function AssetScanResults({ device }: { device: NetworkDevice }) {
  const { t } = useTranslation();
  const scanData = parseScanResults(device);

  if (!scanData) {
    return (
      <Card>
        <CardContent className="p-6 text-center">
          <ScanLine className="w-6 h-6 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs text-muted-foreground" data-testid="text-no-scan-results">{t("networkMonitor.noScanResults")}</p>
        </CardContent>
      </Card>
    );
  }

  const { summary, ports, ssl, headers, vulnerabilities, scannedAt } = scanData;

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${summary.overallRisk === "critical" ? "bg-red-500/10" : summary.overallRisk === "high" ? "bg-orange-500/10" : summary.overallRisk === "medium" ? "bg-yellow-500/10" : "bg-green-500/10"}`}>
                {summary.overallRisk === "info" || summary.overallRisk === "low" ? (
                  <ShieldCheck className="w-5 h-5 text-green-400" />
                ) : (
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                )}
              </div>
              <div>
                <p className="text-sm font-bold" data-testid="text-scan-issues">
                  {summary.totalIssues} {t("networkMonitor.issuesFound")}
                </p>
                <p className="text-[10px] text-muted-foreground">
                  {t("networkMonitor.lastScanned")}: {new Date(scannedAt).toLocaleString()}
                </p>
              </div>
            </div>
            <div className="flex gap-2 flex-wrap">
              {summary.criticalIssues > 0 && <Badge variant="outline" className={SEVERITY_COLORS.critical}>{summary.criticalIssues} {t("common.critical")}</Badge>}
              {summary.highIssues > 0 && <Badge variant="outline" className={SEVERITY_COLORS.high}>{summary.highIssues} {t("common.high")}</Badge>}
              {summary.mediumIssues > 0 && <Badge variant="outline" className={SEVERITY_COLORS.medium}>{summary.mediumIssues} {t("common.medium")}</Badge>}
              {summary.lowIssues > 0 && <Badge variant="outline" className={SEVERITY_COLORS.low}>{summary.lowIssues} {t("common.low")}</Badge>}
            </div>
          </div>
        </CardContent>
      </Card>

      {summary.plainLanguage && summary.plainLanguage.length > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5" />
              {t("networkMonitor.findings")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="space-y-2">
              {summary.plainLanguage.map((msg: string, i: number) => (
                <div key={i} className="flex items-start gap-2 text-xs" data-testid={`text-finding-${i}`}>
                  <div className="w-1.5 h-1.5 rounded-full bg-muted-foreground/50 mt-1.5 flex-shrink-0" />
                  <p className="text-muted-foreground">{msg}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {ports && ports.openPorts && ports.openPorts.length > 0 && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              <Globe className="w-3.5 h-3.5" />
              {t("networkMonitor.openPorts")} ({ports.openPorts.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {ports.openPorts.map((p: any) => (
                <div key={p.port} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/30 text-xs" data-testid={`port-${p.port}`}>
                  <span className="font-mono font-bold">{p.port}</span>
                  <span className="text-muted-foreground">{p.service}</span>
                  <Badge variant="outline" className={`text-[8px] ${SEVERITY_COLORS[p.risk] || SEVERITY_COLORS.info}`}>
                    {p.risk}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {ssl && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              {ssl.valid ? <Lock className="w-3.5 h-3.5 text-green-400" /> : <Unlock className="w-3.5 h-3.5 text-red-400" />}
              {t("networkMonitor.sslCertificate")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.sslGrade")}</p>
                <p className="font-bold text-lg">{ssl.grade}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.sslExpiry")}</p>
                <p className={ssl.expired ? "text-red-400 font-bold" : ssl.expiringSoon ? "text-yellow-400" : ""}>
                  {ssl.expired ? t("networkMonitor.expired") : `${ssl.daysUntilExpiry} ${t("networkMonitor.daysLeft")}`}
                </p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.sslIssuer")}</p>
                <p className="truncate">{ssl.issuer}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.sslProtocol")}</p>
                <p>{ssl.protocol}</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {headers && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              <Shield className="w-3.5 h-3.5" />
              {t("networkMonitor.securityHeaders")} ({t("networkMonitor.score")}: {headers.score}%)
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="space-y-1">
              {headers.headers.map((h: any) => (
                <div key={h.header} className="flex items-center justify-between gap-2 text-xs py-1" data-testid={`header-${h.header}`}>
                  <div className="flex items-center gap-2">
                    {h.status === "pass" ? <CheckCircle className="w-3 h-3 text-green-400" /> : h.status === "warning" ? <AlertTriangle className="w-3 h-3 text-yellow-400" /> : <XCircle className="w-3 h-3 text-red-400" />}
                    <span className="font-mono text-[10px]">{h.header}</span>
                  </div>
                  <span className="text-[10px] text-muted-foreground">{h.description}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {vulnerabilities && vulnerabilities.vulnerabilities && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              <FileWarning className="w-3.5 h-3.5" />
              {t("networkMonitor.exposedPaths")} ({vulnerabilities.findings} {t("networkMonitor.found")})
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="space-y-1">
              {vulnerabilities.vulnerabilities.filter((v: any) => v.found).map((v: any, i: number) => (
                <div key={i} className="flex items-center justify-between gap-2 text-xs py-1" data-testid={`vuln-path-${i}`}>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline" className={`text-[8px] ${SEVERITY_COLORS[v.severity] || SEVERITY_COLORS.info}`}>
                      {v.severity}
                    </Badge>
                    <span className="font-mono text-[10px]">{v.path}</span>
                  </div>
                  <span className="text-[10px] text-muted-foreground">{v.name}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function AssetDetail({ device, onBack }: { device: NetworkDevice; onBack: () => void }) {
  const { t } = useTranslation();
  const { toast } = useToast();

  const deviceQuery = useQuery<NetworkDevice>({
    queryKey: ["/api/network/devices", device.id],
    refetchInterval: 5000,
  });
  const current = deviceQuery.data || device;
  const DeviceIcon = DEVICE_ICONS[current.deviceType] || Server;

  const rescanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/network/scan-asset/${current.id}`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.scanStarted") });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
        queryClient.invalidateQueries({ queryKey: ["/api/network/devices", current.id] });
        queryClient.invalidateQueries({ queryKey: ["/api/network/scans"] });
      }, 5000);
    },
    onError: () => toast({ title: t("networkMonitor.scanFailed"), variant: "destructive" }),
  });

  const blockMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/network/devices/${current.id}/block`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceBlocked") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
      onBack();
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  const deleteMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("DELETE", `/api/network/devices/${current.id}`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceRemoved") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
      onBack();
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <Button variant="ghost" size="sm" onClick={onBack} data-testid="button-back-device">
          <ArrowLeft className="w-4 h-4 ltr:mr-1 rtl:ml-1" />
          {t("support.back")}
        </Button>
        <DeviceIcon className="w-5 h-5 text-muted-foreground" />
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold truncate" data-testid="text-device-hostname">{current.hostname || current.ipAddress}</h3>
          <p className="text-[10px] text-muted-foreground">{current.ipAddress}</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button
            size="sm"
            onClick={() => rescanMutation.mutate()}
            disabled={rescanMutation.isPending}
            data-testid="button-rescan-asset"
          >
            {rescanMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin ltr:mr-1 rtl:ml-1" /> : <RefreshCw className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />}
            {t("networkMonitor.rescan")}
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => { if (confirm(t("networkMonitor.confirmBlock"))) blockMutation.mutate(); }}
            disabled={blockMutation.isPending}
            data-testid="button-block-device"
          >
            <Ban className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
            {t("networkMonitor.blockDevice")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => { if (confirm(t("networkMonitor.confirmRemove"))) deleteMutation.mutate(); }}
            disabled={deleteMutation.isPending}
            data-testid="button-remove-device"
          >
            <Trash2 className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
            {t("networkMonitor.removeDevice")}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-[10px] text-muted-foreground">{t("networkMonitor.ipAddress")}</p>
            <p className="text-xs font-mono font-bold" data-testid="text-detail-ip">{current.ipAddress}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-[10px] text-muted-foreground">{t("networkMonitor.serverInfo")}</p>
            <p className="text-xs font-mono" data-testid="text-detail-server">{current.os || "--"}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-[10px] text-muted-foreground">{t("networkMonitor.firstSeen")}</p>
            <p className="text-xs">{new Date(current.firstSeen).toLocaleDateString()}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 text-center">
            <p className="text-[10px] text-muted-foreground">{t("networkMonitor.lastSeen")}</p>
            <p className="text-xs">{new Date(current.lastSeen).toLocaleString()}</p>
          </CardContent>
        </Card>
      </div>

      <AssetScanResults device={current} />
    </div>
  );
}

export default function NetworkMonitorPage() {
  useDocumentTitle("Network Monitor");
  const { t } = useTranslation();
  const { toast } = useToast();
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [newTarget, setNewTarget] = useState("");
  const [showAddForm, setShowAddForm] = useState(false);

  const devicesQuery = useQuery<NetworkDevice[]>({
    queryKey: ["/api/network/devices"],
    refetchInterval: 10000,
  });

  const scansQuery = useQuery<NetworkScan[]>({
    queryKey: ["/api/network/scans"],
  });

  const addAssetMutation = useMutation({
    mutationFn: async (target: string) => {
      const res = await apiRequest("POST", "/api/network/assets", { target });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.assetAdded") });
      setNewTarget("");
      setShowAddForm(false);
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
        queryClient.invalidateQueries({ queryKey: ["/api/network/scans"] });
      }, 10000);
    },
    onError: (err: any) => toast({ title: err?.message || t("networkMonitor.addFailed"), variant: "destructive" }),
  });

  const scanAllMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/network/scan-all-assets");
      return res.json();
    },
    onSuccess: (data: any) => {
      if (data.status === "no_assets") {
        toast({ title: t("networkMonitor.noAssetsToScan") });
      } else {
        toast({ title: t("networkMonitor.scanAllStarted") });
        setTimeout(() => {
          queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
          queryClient.invalidateQueries({ queryKey: ["/api/network/scans"] });
        }, 15000);
      }
    },
    onError: () => toast({ title: t("networkMonitor.scanFailed"), variant: "destructive" }),
  });

  const blockMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("POST", `/api/network/devices/${id}/block`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceBlocked") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  if (selectedDevice) {
    return (
      <div className="p-4 max-w-5xl mx-auto">
        <AssetDetail device={selectedDevice} onBack={() => setSelectedDevice(null)} />
      </div>
    );
  }

  const devices = devicesQuery.data || [];
  const infrastructureAssets = devices.filter(d => d.deviceType === "server");
  const otherDevices = devices.filter(d => d.deviceType !== "server");

  const filtered = infrastructureAssets.filter(d => {
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      return (d.hostname?.toLowerCase().includes(s)) ||
             d.ipAddress.toLowerCase().includes(s);
    }
    return true;
  });

  const totalIssues = infrastructureAssets.reduce((sum, d) => {
    const scan = parseScanResults(d);
    return sum + (scan?.summary?.totalIssues || 0);
  }, 0);

  const criticalCount = infrastructureAssets.reduce((sum, d) => {
    const scan = parseScanResults(d);
    return sum + (scan?.summary?.criticalIssues || 0);
  }, 0);

  const assetsScanned = infrastructureAssets.filter(d => parseScanResults(d) !== null).length;

  return (
    <div className="p-4 max-w-6xl mx-auto space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2" data-testid="text-network-title">
            <Server className="w-5 h-5" />
            {t("networkMonitor.title")}
          </h1>
          <p className="text-xs text-muted-foreground">{t("networkMonitor.subtitle")}</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button
            size="sm"
            variant="outline"
            onClick={() => scanAllMutation.mutate()}
            disabled={scanAllMutation.isPending || infrastructureAssets.length === 0}
            data-testid="button-scan-all"
          >
            {scanAllMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            <span className="ltr:ml-1 rtl:mr-1">{t("networkMonitor.scanAllAssets")}</span>
          </Button>
          <Button
            size="sm"
            onClick={() => setShowAddForm(!showAddForm)}
            data-testid="button-add-asset"
          >
            <Plus className="w-3.5 h-3.5" />
            <span className="ltr:ml-1 rtl:mr-1">{t("networkMonitor.addAsset")}</span>
          </Button>
        </div>
      </div>

      {showAddForm && (
        <Card>
          <CardContent className="p-4">
            <div className="flex items-end gap-3 flex-wrap">
              <div className="flex-1 min-w-[250px]">
                <p className="text-xs font-medium mb-1">{t("networkMonitor.addAssetLabel")}</p>
                <Input
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder={t("networkMonitor.addAssetPlaceholder")}
                  className="text-xs"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && newTarget.trim()) {
                      addAssetMutation.mutate(newTarget.trim());
                    }
                  }}
                  data-testid="input-new-asset"
                />
                <p className="text-[10px] text-muted-foreground mt-1">{t("networkMonitor.addAssetHelp")}</p>
              </div>
              <Button
                size="sm"
                onClick={() => newTarget.trim() && addAssetMutation.mutate(newTarget.trim())}
                disabled={addAssetMutation.isPending || !newTarget.trim()}
                data-testid="button-submit-asset"
              >
                {addAssetMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin ltr:mr-1 rtl:ml-1" /> : <ScanLine className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />}
                {t("networkMonitor.addAndScan")}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setShowAddForm(false)} data-testid="button-cancel-add">
                {t("common.cancel")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between gap-1 mb-1">
              <Server className="w-4 h-4 text-primary" />
            </div>
            <p className="text-lg font-bold font-mono" data-testid="stat-assets">{infrastructureAssets.length}</p>
            <p className="text-[9px] text-muted-foreground">{t("networkMonitor.monitoredAssets")}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between gap-1 mb-1">
              <ScanLine className="w-4 h-4 text-blue-400" />
            </div>
            <p className="text-lg font-bold font-mono" data-testid="stat-scanned">{assetsScanned}</p>
            <p className="text-[9px] text-muted-foreground">{t("networkMonitor.assetsScanned")}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between gap-1 mb-1">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </div>
            <p className="text-lg font-bold font-mono" data-testid="stat-issues">{totalIssues}</p>
            <p className="text-[9px] text-muted-foreground">{t("networkMonitor.totalIssues")}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3">
            <div className="flex items-center justify-between gap-1 mb-1">
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <p className="text-lg font-bold font-mono" data-testid="stat-critical">{criticalCount}</p>
            <p className="text-[9px] text-muted-foreground">{t("networkMonitor.criticalIssues")}</p>
          </CardContent>
        </Card>
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex-1 min-w-[200px]">
          <div className="relative">
            <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder={t("networkMonitor.searchAssets")}
              className="text-xs ps-8"
              data-testid="input-search-devices"
            />
          </div>
        </div>
        {infrastructureAssets.length > 0 && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => generateNetworkMonitorReportPDF(infrastructureAssets)}
            data-testid="button-export-network-pdf"
          >
            <Download className="w-3.5 h-3.5 me-1.5" />
            Export PDF
          </Button>
        )}
      </div>

      <Card>
        <CardContent className="p-0">
          {devicesQuery.isLoading ? (
            <div className="p-8 flex justify-center"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
          ) : filtered.length === 0 ? (
            <div className="p-8 text-center">
              <Server className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground" data-testid="text-no-devices">
                {infrastructureAssets.length === 0 ? t("networkMonitor.noAssets") : t("networkMonitor.noMatchingAssets")}
              </p>
              {infrastructureAssets.length === 0 && (
                <Button size="sm" className="mt-3" onClick={() => setShowAddForm(true)} data-testid="button-add-first-asset">
                  <Plus className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
                  {t("networkMonitor.addFirstAsset")}
                </Button>
              )}
            </div>
          ) : (
            <ScrollArea className="h-[calc(100vh-480px)]">
              <div className="divide-y">
                {filtered.map(device => {
                  const scanData = parseScanResults(device);
                  const issues = scanData?.summary?.totalIssues || 0;
                  const risk = scanData?.summary?.overallRisk || "unknown";
                  const isScanning = !scanData;

                  return (
                    <div
                      key={device.id}
                      className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors cursor-pointer"
                      onClick={() => setSelectedDevice(device)}
                      data-testid={`device-row-${device.id}`}
                    >
                      <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-muted/50">
                        <Server className="w-4 h-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-xs font-medium truncate">{device.hostname || device.ipAddress}</p>
                          {isScanning && <Loader2 className="w-3 h-3 animate-spin text-muted-foreground" />}
                        </div>
                        <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                          <span className="font-mono">{device.ipAddress}</span>
                          {device.os && <span>{device.os}</span>}
                          {scanData?.scannedAt && (
                            <span className="flex items-center gap-0.5">
                              <Clock className="w-2.5 h-2.5" />
                              {new Date(scanData.scannedAt).toLocaleDateString()}
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        {scanData && (
                          <>
                            {issues > 0 ? (
                              <Badge variant="outline" className={`text-[9px] ${SEVERITY_COLORS[risk] || SEVERITY_COLORS.info}`}>
                                {issues} {t("networkMonitor.issues")}
                              </Badge>
                            ) : (
                              <Badge variant="outline" className="text-[9px] bg-green-500/20 text-green-400 border-green-500/30">
                                {t("networkMonitor.secure")}
                              </Badge>
                            )}
                          </>
                        )}
                      </div>
                      <div className="flex gap-1 flex-shrink-0">
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={(e) => { e.stopPropagation(); setSelectedDevice(device); }}
                          data-testid={`button-view-${device.id}`}
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </Button>
                        {device.status !== "blocked" && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (confirm(t("networkMonitor.confirmBlock"))) blockMutation.mutate(device.id);
                            }}
                            data-testid={`button-block-${device.id}`}
                          >
                            <Ban className="w-3.5 h-3.5" />
                          </Button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
