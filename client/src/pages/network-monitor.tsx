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
  Building2, User, StickyNote, Signal, Globe,
} from "lucide-react";

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(Math.abs(bytes)) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

const DEVICE_ICONS: Record<string, React.ElementType> = {
  computer: Monitor, phone: Smartphone, tablet: Tablet, printer: Printer,
  router: Router, iot: CircuitBoard, unknown: HelpCircle,
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

function SignalBar({ strength }: { strength: number | null }) {
  if (strength === null) return null;
  const level = strength > -40 ? 4 : strength > -55 ? 3 : strength > -70 ? 2 : 1;
  return (
    <div className="flex items-end gap-0.5 h-3">
      {[1, 2, 3, 4].map(i => (
        <div
          key={i}
          className={`w-1 rounded-sm ${i <= level ? "bg-green-400" : "bg-muted-foreground/20"}`}
          style={{ height: `${i * 25}%` }}
        />
      ))}
    </div>
  );
}

function DeviceDetail({ device, onBack }: { device: NetworkDevice; onBack: () => void }) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [notes, setNotes] = useState(device.notes || "");
  const [assignedUser, setAssignedUser] = useState(device.assignedUser || "");
  const [isCompany, setIsCompany] = useState(device.isCompanyDevice);

  const deviceQuery = useQuery<NetworkDevice>({
    queryKey: ["/api/network/devices", device.id],
    refetchInterval: 5000,
  });
  const current = deviceQuery.data || device;
  const DeviceIcon = DEVICE_ICONS[current.deviceType] || HelpCircle;

  const updateMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("PATCH", `/api/network/devices/${current.id}`, data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceUpdated") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
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

  const kickMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/network/devices/${current.id}/kick`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceKicked") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  const authorizeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/network/devices/${current.id}/authorize`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceAuthorized") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack} data-testid="button-back-device">
          <ArrowLeft className="w-4 h-4 ltr:mr-1 rtl:ml-1" />
          {t("support.back")}
        </Button>
        <DeviceIcon className="w-5 h-5 text-muted-foreground" />
        <div className="flex-1">
          <h3 className="text-sm font-semibold" data-testid="text-device-hostname">{current.hostname || current.macAddress}</h3>
          <p className="text-[10px] text-muted-foreground">{current.ipAddress} | {current.manufacturer}</p>
        </div>
        <Badge variant="outline" className={AUTH_COLORS[current.authorization]} data-testid="badge-device-auth">
          {t(`networkMonitor.${current.authorization}`)}
        </Badge>
        <div className={`w-2 h-2 rounded-full ${STATUS_COLORS[current.status]}`} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="md:col-span-2">
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs">{t("networkMonitor.deviceDetails")}</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.hostname")}</p>
                <p className="font-mono" data-testid="text-detail-hostname">{current.hostname || "--"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.ipAddress")}</p>
                <p className="font-mono" data-testid="text-detail-ip">{current.ipAddress}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.macAddress")}</p>
                <p className="font-mono" data-testid="text-detail-mac">{current.macAddress}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.manufacturer")}</p>
                <p>{current.manufacturer || "--"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.deviceType")}</p>
                <p>{t(`networkMonitor.${current.deviceType}`)}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.operatingSystem")}</p>
                <p>{current.os || "--"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.networkName")}</p>
                <p>{current.networkName || "--"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.location")}</p>
                <p className="flex items-center gap-1"><MapPin className="w-3 h-3" /> {current.location || "--"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.signalStrength")}</p>
                <div className="flex items-center gap-2">
                  <SignalBar strength={current.signalStrength} />
                  <span>{current.signalStrength !== null ? `${current.signalStrength} dBm` : "--"}</span>
                </div>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.firstSeen")}</p>
                <p>{new Date(current.firstSeen).toLocaleDateString()}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">{t("networkMonitor.lastSeen")}</p>
                <p>{new Date(current.lastSeen).toLocaleString()}</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3 mt-4 p-3 rounded-lg bg-muted/30">
              <div className="flex items-center gap-2">
                <Download className="w-4 h-4 text-blue-400" />
                <div>
                  <p className="text-[10px] text-muted-foreground">{t("networkMonitor.dataIn")}</p>
                  <p className="text-sm font-bold font-mono">{formatBytes(Number(current.dataIn))}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Upload className="w-4 h-4 text-green-400" />
                <div>
                  <p className="text-[10px] text-muted-foreground">{t("networkMonitor.dataOut")}</p>
                  <p className="text-sm font-bold font-mono">{formatBytes(Number(current.dataOut))}</p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-xs flex items-center gap-2">
                <Shield className="w-3.5 h-3.5" />
                Actions
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-2">
              {current.authorization !== "authorized" && current.status !== "blocked" && (
                <Button
                  size="sm"
                  className="w-full text-xs"
                  onClick={() => authorizeMutation.mutate()}
                  disabled={authorizeMutation.isPending}
                  data-testid="button-authorize-device"
                >
                  <ShieldCheck className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
                  {t("networkMonitor.authorizeDevice")}
                </Button>
              )}
              {current.status !== "blocked" && (
                <Button
                  variant="destructive"
                  size="sm"
                  className="w-full text-xs"
                  onClick={() => { if (confirm(t("networkMonitor.confirmBlock"))) blockMutation.mutate(); }}
                  disabled={blockMutation.isPending}
                  data-testid="button-block-device"
                >
                  <Ban className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
                  {t("networkMonitor.blockDevice")}
                </Button>
              )}
              {current.status === "online" && (
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full text-xs"
                  onClick={() => { if (confirm(t("networkMonitor.confirmKick"))) kickMutation.mutate(); }}
                  disabled={kickMutation.isPending}
                  data-testid="button-kick-device"
                >
                  <WifiOff className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
                  {t("networkMonitor.kickDevice")}
                </Button>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-xs flex items-center gap-2">
                <Building2 className="w-3.5 h-3.5" />
                {t("networkMonitor.companyDevice")}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs">{t("networkMonitor.companyDevice")}</span>
                <Switch
                  checked={isCompany}
                  onCheckedChange={(v) => {
                    setIsCompany(v);
                    updateMutation.mutate({ isCompanyDevice: v });
                  }}
                  data-testid="switch-company-device"
                />
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground mb-1">{t("networkMonitor.assignedUser")}</p>
                <Input
                  value={assignedUser}
                  onChange={(e) => setAssignedUser(e.target.value)}
                  onBlur={() => updateMutation.mutate({ assignedUser: assignedUser || null })}
                  className="text-xs"
                  placeholder="employee@company.com"
                  data-testid="input-assigned-user"
                />
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground mb-1">{t("networkMonitor.notes")}</p>
                <Textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  onBlur={() => updateMutation.mutate({ notes: notes || null })}
                  className="text-xs min-h-[60px]"
                  data-testid="input-notes"
                />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

export default function NetworkMonitorPage() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [selectedDevice, setSelectedDevice] = useState<NetworkDevice | null>(null);
  const [filterAuth, setFilterAuth] = useState("all");
  const [filterStatus, setFilterStatus] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [activeView, setActiveView] = useState<"devices" | "vulnerabilities">("devices");

  const devicesQuery = useQuery<NetworkDevice[]>({
    queryKey: ["/api/network/devices"],
    refetchInterval: 10000,
  });

  const scansQuery = useQuery<NetworkScan[]>({
    queryKey: ["/api/network/scans"],
  });

  const trafficQuery = useQuery<{ totalIn: number; totalOut: number; totalDevices: number; topDevices: any[] }>({
    queryKey: ["/api/network/traffic"],
    refetchInterval: 15000,
  });

  const scanMutation = useMutation({
    mutationFn: async (scanType: string) => {
      const res = await apiRequest("POST", "/api/network/scan", { scanType });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.scanStarted") });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
        queryClient.invalidateQueries({ queryKey: ["/api/network/scans"] });
        queryClient.invalidateQueries({ queryKey: ["/api/network/traffic"] });
      }, 2000);
    },
    onError: () => toast({ title: t("networkMonitor.scanFailed"), variant: "destructive" }),
  });

  const vulnScanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/network/scan/vulnerability");
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.scanStarted") });
      setTimeout(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/network/scans"] });
      }, 2000);
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
      queryClient.invalidateQueries({ queryKey: ["/api/network/traffic"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  const kickMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("POST", `/api/network/devices/${id}/kick`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceKicked") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  const authorizeMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("POST", `/api/network/devices/${id}/authorize`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("networkMonitor.deviceAuthorized") });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: t("networkMonitor.actionFailed"), variant: "destructive" }),
  });

  if (selectedDevice) {
    return (
      <div className="p-4 max-w-5xl mx-auto">
        <DeviceDetail device={selectedDevice} onBack={() => setSelectedDevice(null)} />
      </div>
    );
  }

  const devices = devicesQuery.data || [];
  const filtered = devices.filter(d => {
    if (filterAuth !== "all" && d.authorization !== filterAuth) return false;
    if (filterStatus !== "all" && d.status !== filterStatus) return false;
    if (searchTerm) {
      const s = searchTerm.toLowerCase();
      return (d.hostname?.toLowerCase().includes(s)) ||
             d.ipAddress.toLowerCase().includes(s) ||
             d.macAddress.toLowerCase().includes(s) ||
             (d.manufacturer?.toLowerCase().includes(s));
    }
    return true;
  });

  const stats = {
    total: devices.length,
    authorized: devices.filter(d => d.authorization === "authorized").length,
    unauthorized: devices.filter(d => d.authorization === "unauthorized").length,
    blocked: devices.filter(d => d.status === "blocked").length,
    online: devices.filter(d => d.status === "online").length,
    offline: devices.filter(d => d.status === "offline").length,
  };

  const latestVulnScan = (scansQuery.data || []).find(s => s.scanType === "vulnerability" && s.status === "completed");
  const vulns = latestVulnScan?.vulnerabilities as any[] || [];

  return (
    <div className="p-4 max-w-6xl mx-auto space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-lg font-bold flex items-center gap-2" data-testid="text-network-title">
            <Wifi className="w-5 h-5" />
            {t("networkMonitor.title")}
          </h1>
          <p className="text-xs text-muted-foreground">{t("networkMonitor.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => vulnScanMutation.mutate()}
            disabled={vulnScanMutation.isPending}
            data-testid="button-vuln-scan"
          >
            {vulnScanMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
            <span className="ltr:ml-1 rtl:mr-1">{t("networkMonitor.vulnScan")}</span>
          </Button>
          <Button
            size="sm"
            onClick={() => scanMutation.mutate("full")}
            disabled={scanMutation.isPending}
            data-testid="button-scan-network"
          >
            {scanMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ScanLine className="w-3.5 h-3.5" />}
            <span className="ltr:ml-1 rtl:mr-1">{t("networkMonitor.scanNetwork")}</span>
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        {[
          { label: t("networkMonitor.totalDevices"), value: stats.total, icon: Monitor, color: "text-primary", testId: "stat-total" },
          { label: t("networkMonitor.onlineDevices"), value: stats.online, icon: Wifi, color: "text-green-400", testId: "stat-online" },
          { label: t("networkMonitor.authorizedDevices"), value: stats.authorized, icon: ShieldCheck, color: "text-green-400", testId: "stat-authorized" },
          { label: t("networkMonitor.unauthorizedDevices"), value: stats.unauthorized, icon: ShieldOff, color: "text-red-400", testId: "stat-unauthorized" },
          { label: t("networkMonitor.blockedDevices"), value: stats.blocked, icon: Ban, color: "text-red-400", testId: "stat-blocked" },
          { label: t("networkMonitor.totalTraffic"), value: formatBytes((trafficQuery.data?.totalIn || 0) + (trafficQuery.data?.totalOut || 0)), icon: ArrowDownUp, color: "text-blue-400", testId: "stat-traffic" },
        ].map(stat => (
          <Card key={stat.testId}>
            <CardContent className="p-3">
              <div className="flex items-center justify-between mb-1">
                <stat.icon className={`w-4 h-4 ${stat.color}`} />
              </div>
              <p className="text-lg font-bold font-mono" data-testid={stat.testId}>{stat.value}</p>
              <p className="text-[9px] text-muted-foreground">{stat.label}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <div className="flex gap-1">
          <Button
            variant={activeView === "devices" ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveView("devices")}
            data-testid="button-view-devices"
          >
            <Monitor className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
            {t("networkMonitor.allDevices")}
          </Button>
          <Button
            variant={activeView === "vulnerabilities" ? "default" : "outline"}
            size="sm"
            onClick={() => setActiveView("vulnerabilities")}
            data-testid="button-view-vulns"
          >
            <ShieldAlert className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
            {t("networkMonitor.vulnerabilities")} {vulns.length > 0 && <Badge variant="destructive" className="ltr:ml-1 rtl:mr-1 text-[9px] px-1">{vulns.length}</Badge>}
          </Button>
        </div>
        {activeView === "devices" && (
          <>
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute start-2 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                <Input
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by hostname, IP, MAC..."
                  className="text-xs ps-8"
                  data-testid="input-search-devices"
                />
              </div>
            </div>
            <Select value={filterAuth} onValueChange={setFilterAuth}>
              <SelectTrigger className="w-[130px] text-xs" data-testid="select-filter-auth">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("common.all")}</SelectItem>
                <SelectItem value="authorized">{t("networkMonitor.authorized")}</SelectItem>
                <SelectItem value="unauthorized">{t("networkMonitor.unauthorized")}</SelectItem>
                <SelectItem value="unknown">{t("networkMonitor.unknown")}</SelectItem>
              </SelectContent>
            </Select>
            <Select value={filterStatus} onValueChange={setFilterStatus}>
              <SelectTrigger className="w-[120px] text-xs" data-testid="select-filter-status">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("common.all")}</SelectItem>
                <SelectItem value="online">{t("networkMonitor.online")}</SelectItem>
                <SelectItem value="offline">{t("networkMonitor.offline")}</SelectItem>
                <SelectItem value="blocked">{t("networkMonitor.blocked")}</SelectItem>
              </SelectContent>
            </Select>
          </>
        )}
      </div>

      {activeView === "devices" ? (
        <Card>
          <CardContent className="p-0">
            {devicesQuery.isLoading ? (
              <div className="p-8 flex justify-center"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
            ) : filtered.length === 0 ? (
              <div className="p-8 text-center">
                <Wifi className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground" data-testid="text-no-devices">{t("networkMonitor.noDevices")}</p>
              </div>
            ) : (
              <ScrollArea className="h-[calc(100vh-420px)]">
                <div className="divide-y">
                  {filtered.map(device => {
                    const DevIcon = DEVICE_ICONS[device.deviceType] || HelpCircle;
                    return (
                      <div
                        key={device.id}
                        className="flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors"
                        data-testid={`device-row-${device.id}`}
                      >
                        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-muted/50">
                          <DevIcon className="w-4 h-4 text-muted-foreground" />
                        </div>
                        <div
                          className="flex-1 min-w-0 cursor-pointer"
                          onClick={() => setSelectedDevice(device)}
                        >
                          <div className="flex items-center gap-2">
                            <p className="text-xs font-medium truncate">{device.hostname || device.macAddress}</p>
                            <div className={`w-1.5 h-1.5 rounded-full ${STATUS_COLORS[device.status]}`} />
                            {device.isCompanyDevice && (
                              <Badge variant="secondary" className="text-[8px] px-1 py-0 h-3.5">
                                <Building2 className="w-2.5 h-2.5 ltr:mr-0.5 rtl:ml-0.5" />
                                Corp
                              </Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                            <span className="font-mono">{device.ipAddress}</span>
                            <span>{device.manufacturer}</span>
                            {device.location && <span className="flex items-center gap-0.5"><MapPin className="w-2.5 h-2.5" />{device.location}</span>}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 text-xs">
                          <SignalBar strength={device.signalStrength} />
                          <div className="text-end min-w-[70px]">
                            <p className="text-[10px] text-muted-foreground flex items-center gap-1 justify-end">
                              <Download className="w-2.5 h-2.5" />{formatBytes(Number(device.dataIn))}
                            </p>
                            <p className="text-[10px] text-muted-foreground flex items-center gap-1 justify-end">
                              <Upload className="w-2.5 h-2.5" />{formatBytes(Number(device.dataOut))}
                            </p>
                          </div>
                          <Badge variant="outline" className={`text-[9px] min-w-[80px] justify-center ${AUTH_COLORS[device.authorization]}`}>
                            {t(`networkMonitor.${device.authorization}`)}
                          </Badge>
                        </div>
                        <div className="flex gap-1 flex-shrink-0">
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            onClick={() => setSelectedDevice(device)}
                            data-testid={`button-view-${device.id}`}
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </Button>
                          {device.authorization !== "authorized" && device.status !== "blocked" && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => authorizeMutation.mutate(device.id)}
                              data-testid={`button-auth-${device.id}`}
                            >
                              <ShieldCheck className="w-3.5 h-3.5" />
                            </Button>
                          )}
                          {device.status !== "blocked" && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => { if (confirm(t("networkMonitor.confirmBlock"))) blockMutation.mutate(device.id); }}
                              data-testid={`button-block-${device.id}`}
                            >
                              <Ban className="w-3.5 h-3.5" />
                            </Button>
                          )}
                          {device.status === "online" && (
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => { if (confirm(t("networkMonitor.confirmKick"))) kickMutation.mutate(device.id); }}
                              data-testid={`button-kick-${device.id}`}
                            >
                              <WifiOff className="w-3.5 h-3.5" />
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
      ) : (
        <div className="space-y-4">
          {vulns.length === 0 ? (
            <Card>
              <CardContent className="p-8 text-center">
                <ShieldCheck className="w-8 h-8 text-green-400 mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">{t("networkMonitor.noVulnerabilities")}</p>
                <Button size="sm" className="mt-3" onClick={() => vulnScanMutation.mutate()} disabled={vulnScanMutation.isPending} data-testid="button-run-vuln">
                  {t("networkMonitor.vulnScan")}
                </Button>
              </CardContent>
            </Card>
          ) : (
            <>
              {latestVulnScan && (
                <Card>
                  <CardContent className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-red-500/10">
                        <ShieldAlert className="w-5 h-5 text-red-400" />
                      </div>
                      <div>
                        <p className="text-sm font-bold" data-testid="text-risk-score">{t("networkMonitor.riskScore")}: {(latestVulnScan.results as any)?.riskScore || 0}/100</p>
                        <p className="text-[10px] text-muted-foreground">{vulns.length} {t("networkMonitor.vulnerabilities").toLowerCase()}</p>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground">
                      {new Date(latestVulnScan.completedAt || latestVulnScan.createdAt).toLocaleString()}
                    </p>
                  </CardContent>
                </Card>
              )}
              <div className="space-y-2">
                {vulns.map((vuln: any, i: number) => {
                  const severityColors: Record<string, string> = {
                    critical: "bg-red-500/20 text-red-400 border-red-500/30",
                    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
                    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
                    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
                    info: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
                  };
                  return (
                    <Card key={vuln.id || i}>
                      <CardContent className="p-4" data-testid={`vuln-card-${i}`}>
                        <div className="flex items-start gap-3">
                          <Badge variant="outline" className={`text-[9px] ${severityColors[vuln.severity] || ""}`}>
                            {vuln.severity.toUpperCase()}
                          </Badge>
                          <div className="flex-1">
                            <p className="text-xs font-semibold">{vuln.title}</p>
                            <p className="text-[10px] text-muted-foreground mt-1">{vuln.description}</p>
                            <div className="mt-2 p-2 rounded bg-muted/30 border border-border/50">
                              <p className="text-[10px] text-primary">{vuln.recommendation}</p>
                            </div>
                            {vuln.affectedDevice && (
                              <p className="text-[9px] text-muted-foreground mt-1 flex items-center gap-1">
                                <Router className="w-3 h-3" /> {vuln.affectedDevice}
                              </p>
                            )}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>
            </>
          )}
        </div>
      )}

      {trafficQuery.data && trafficQuery.data.topDevices.length > 0 && activeView === "devices" && (
        <Card>
          <CardHeader className="py-3 px-4">
            <CardTitle className="text-xs flex items-center gap-2">
              <ArrowDownUp className="w-3.5 h-3.5" />
              {t("networkMonitor.topDevicesByTraffic")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="space-y-2">
              {trafficQuery.data.topDevices.slice(0, 5).map((td: any) => {
                const maxTraffic = trafficQuery.data!.topDevices[0]?.total || 1;
                return (
                  <div key={td.id} className="flex items-center gap-3">
                    <div className="min-w-[120px]">
                      <p className="text-xs font-mono truncate">{td.hostname || td.ipAddress}</p>
                    </div>
                    <div className="flex-1 h-3 bg-muted/50 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary/40 rounded-full"
                        style={{ width: `${(td.total / maxTraffic) * 100}%` }}
                      />
                    </div>
                    <div className="text-[10px] text-muted-foreground font-mono min-w-[80px] text-end">
                      {formatBytes(td.total)}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
