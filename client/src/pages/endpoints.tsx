import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Loader2, Monitor, Cpu, MemoryStick, Wifi, WifiOff, Terminal, Send, RefreshCw, Clock, Activity, ArrowDown, ArrowUp, HardDrive, Globe, Server, Layers, Info, FileSearch, AlertTriangle, FileText, Shield, Download, ShieldAlert, ShieldOff, File, Hash, Trash2 } from "lucide-react";
import { useLocation } from "wouter";
import { exportToCsv } from "@/lib/csvExport";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { useAuth } from "@/hooks/use-auth";

const COMMANDS = [
  { value: "run_system_scan", labelKey: "endpoints.cmdSystemScan" },
  { value: "security_scan", labelKey: "endpoints.cmdSecurityAudit" },
  { value: "ping", labelKey: "endpoints.cmdPingTest" },
  { value: "process_list", labelKey: "endpoints.cmdListProcesses" },
  { value: "service_list", labelKey: "endpoints.cmdListServices" },
  { value: "wifi_list", labelKey: "endpoints.cmdWifiNetworks" },
  { value: "network_scan", labelKey: "endpoints.cmdNetworkScan" },
  { value: "disk_usage", labelKey: "endpoints.cmdDiskUsage" },
  { value: "packet_capture", labelKey: "endpoints.cmdPacketCapture" },
  { value: "arp_monitor", labelKey: "endpoints.cmdArpMonitor" },
  { value: "rogue_scan", labelKey: "endpoints.cmdRogueScan" },
  { value: "bandwidth_stats", labelKey: "endpoints.cmdBandwidthStats" },
  { value: "vuln_scan", labelKey: "endpoints.cmdVulnScan" },
  { value: "file_scan", labelKey: "endpoints.cmdFileScan" },
];

function UsageBar({ label, value, max, unit, color }: { label: string; value: number; max?: number; unit?: string; color?: string }) {
  const pct = max ? Math.min((value / max) * 100, 100) : Math.min(value, 100);
  const barColor = color || (pct > 90 ? "bg-red-500" : pct > 70 ? "bg-yellow-500" : "bg-green-500");

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2 text-sm">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono font-medium">
          {max ? `${value.toLocaleString()} / ${max.toLocaleString()} ${unit || ""}` : `${value.toFixed(1)}%`}
        </span>
      </div>
      <div className="h-2 rounded-full bg-muted">
        <div className={`h-full rounded-full transition-all ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function parseDiskUsage(diskStr: string): { drive: string; usedPct: number; usedGB: number; totalGB: number }[] {
  if (!diskStr || diskStr === "unknown") return [];
  const drives: { drive: string; usedPct: number; usedGB: number; totalGB: number }[] = [];
  const parts = diskStr.split(";").filter(s => s.trim());
  for (const part of parts) {
    const match = part.trim().match(/^(\S+)\s+([\d.]+)%\s+used\s+\((\d+)\s*GB\s*\/\s*(\d+)\s*GB\)/);
    if (match) {
      drives.push({
        drive: match[1],
        usedPct: parseFloat(match[2]),
        usedGB: parseInt(match[3]),
        totalGB: parseInt(match[4]),
      });
    }
  }
  if (drives.length === 0) {
    const linuxMatch = diskStr.trim().match(/(\S+)\s+(\d+)%\s+(\S+)\s+(\S+)/);
    if (linuxMatch) {
      drives.push({
        drive: linuxMatch[1] || "/",
        usedPct: parseInt(linuxMatch[2]),
        usedGB: 0,
        totalGB: 0,
      });
    }
  }
  return drives;
}

function parseProcessString(proc: string): { name: string; cpu: string; mem: string } {
  const linuxMatch = proc.match(/^(\S+)\s+CPU:([\d.]+)%\s+MEM:([\d.]+)%$/);
  if (linuxMatch) {
    return { name: linuxMatch[1], cpu: `${linuxMatch[2]}%`, mem: `${linuxMatch[3]}%` };
  }
  const winMatch = proc.match(/^(.+?)\s+\(Mem:\s*(.+?)\)$/);
  if (winMatch) {
    return { name: winMatch[1], cpu: "-", mem: winMatch[2] };
  }
  return { name: proc, cpu: "-", mem: "-" };
}

function SystemInfoPanel({ telemetry, agent }: { telemetry: any; agent: any }) {
  const { t } = useTranslation();
  if (!telemetry) {
    return (
      <Card data-testid="card-system-info-empty">
        <CardContent className="pt-6 text-center text-muted-foreground">
          <Info className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>{t("endpoints.noTelemetry")}</p>
          <p className="text-xs mt-1">{t("endpoints.telemetryHint")}</p>
        </CardContent>
      </Card>
    );
  }

  const cpuUsage = telemetry.cpuUsage ?? agent.cpuUsage ?? 0;
  const ramUsage = telemetry.ramUsage ?? agent.ramUsage ?? 0;
  const ramTotalMB = telemetry.ramTotalMB;
  const ramFreeMB = telemetry.ramFreeMB;
  const ramUsedMB = ramTotalMB && ramFreeMB ? ramTotalMB - ramFreeMB : null;
  const diskDrives = parseDiskUsage(telemetry.diskUsage);
  const topProcesses = telemetry.topProcesses || [];
  const netConnections = telemetry.netConnections;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card data-testid="card-sysinfo-hostname">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">{t("endpoints.hostname")}</p>
            <p className="font-medium text-sm truncate" data-testid="text-sysinfo-hostname">{telemetry.hostname || agent.hostname}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-os">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">{t("endpoints.osArch")}</p>
            <p className="font-medium text-sm truncate" data-testid="text-sysinfo-os">{telemetry.os || agent.os || "Unknown"}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-uptime">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">{t("endpoints.uptime")}</p>
            <p className="font-medium text-sm" data-testid="text-sysinfo-uptime">{telemetry.uptime || "N/A"}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-version">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">{t("endpoints.agentVersion")}</p>
            <p className="font-medium text-sm" data-testid="text-sysinfo-version">{telemetry.agentVersion || "N/A"}</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card data-testid="card-cpu-usage">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Cpu className="w-4 h-4" />
              {t("endpoints.cpuUsage")}
              {telemetry.cpus && <Badge variant="outline" className="text-xs">{telemetry.cpus} {t("endpoints.cores")}</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <UsageBar label="CPU" value={cpuUsage} />
          </CardContent>
        </Card>

        <Card data-testid="card-ram-usage">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <MemoryStick className="w-4 h-4" />
              {t("endpoints.memoryUsage")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <UsageBar label="RAM" value={ramUsage} />
            {ramTotalMB != null && ramFreeMB != null && (
              <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
                <span>Used: {ramUsedMB != null ? `${(ramUsedMB / 1024).toFixed(1)} GB` : "N/A"}</span>
                <span>Free: {(ramFreeMB / 1024).toFixed(1)} GB</span>
                <span>Total: {(ramTotalMB / 1024).toFixed(1)} GB</span>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {diskDrives.length > 0 && (
        <Card data-testid="card-disk-usage">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <HardDrive className="w-4 h-4" />
              {t("endpoints.diskUsage")}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {diskDrives.map((d, i) => (
              <div key={i} data-testid={`row-disk-${i}`}>
                <UsageBar
                  label={d.drive}
                  value={d.totalGB > 0 ? d.usedGB : d.usedPct}
                  max={d.totalGB > 0 ? d.totalGB : undefined}
                  unit={d.totalGB > 0 ? "GB" : undefined}
                />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card data-testid="card-network-info">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Globe className="w-4 h-4" />
              {t("endpoints.network")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">{t("endpoints.localIp")}</span>
                <span className="font-mono font-medium" data-testid="text-local-ip">{telemetry.localIP || agent.ip || "N/A"}</span>
              </div>
              {netConnections != null && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">{t("endpoints.activeConnections")}</span>
                  <Badge variant="outline" data-testid="text-net-connections">{netConnections}</Badge>
                </div>
              )}
              {telemetry.arch && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">{t("endpoints.architecture")}</span>
                  <span className="font-medium" data-testid="text-arch">{telemetry.arch}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        <Card data-testid="card-agent-meta">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Server className="w-4 h-4" />
              {t("endpoints.agentDetails")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">{t("endpoints.agentId")}</span>
                <span className="font-mono font-medium" data-testid="text-agent-id">{agent.id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">{t("endpoints.runMode")}</span>
                <Badge
                  variant={telemetry.runMode === "service" ? "default" : "secondary"}
                  data-testid="badge-run-mode"
                >
                  {telemetry.runMode === "service" ? t("endpoints.runModeService") : telemetry.runMode === "tray" ? t("endpoints.runModeTray") : telemetry.runMode === "terminal" ? t("endpoints.runModeTerminal") : telemetry.runMode || "Unknown"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">{t("endpoints.lastSeen")}</span>
                <span className="font-medium" data-testid="text-last-seen">{agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "N/A"}</span>
              </div>
              {telemetry.lastUpdated && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">{t("endpoints.telemetryUpdated")}</span>
                  <span className="text-xs text-muted-foreground" data-testid="text-telemetry-updated">{new Date(telemetry.lastUpdated).toLocaleString()}</span>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {topProcesses.length > 0 && (
        <Card data-testid="card-top-processes">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Layers className="w-4 h-4" />
              {t("endpoints.topProcesses")}
              <Badge variant="outline" className="text-xs">{topProcesses.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-muted-foreground">
                    <th className="text-left py-1.5 pe-4 font-medium">{t("endpoints.process")}</th>
                    <th className="text-right py-1.5 px-2 font-medium">{t("endpoints.cpu")}</th>
                    <th className="text-right py-1.5 ps-2 font-medium">{t("endpoints.memory")}</th>
                  </tr>
                </thead>
                <tbody>
                  {topProcesses.slice(0, 15).map((proc: string, i: number) => {
                    const parsed = parseProcessString(proc);
                    return (
                      <tr key={i} className="border-b border-muted/30" data-testid={`row-process-${i}`}>
                        <td className="py-1.5 pe-4 font-mono text-xs truncate max-w-[200px]">{parsed.name}</td>
                        <td className="py-1.5 px-2 text-right font-mono text-xs">{parsed.cpu}</td>
                        <td className="py-1.5 ps-2 text-right font-mono text-xs">{parsed.mem}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function parseFileScanFromCommand(cmd: any): any | null {
  if (cmd.command !== "file_scan" || cmd.status !== "done" || !cmd.result) return null;
  const marker = "__FILE_SCAN_JSON__:";
  const idx = cmd.result.indexOf(marker);
  if (idx === -1) return null;
  try {
    return JSON.parse(cmd.result.substring(idx + marker.length));
  } catch {
    return null;
  }
}

function formatBytes(b: number): string {
  if (b > 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
  if (b > 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b > 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

function FileScanResults({ commands }: { commands: any[] | undefined }) {
  const { t } = useTranslation();
  const fileScanCommands = commands?.filter(c => c.command === "file_scan") || [];

  if (fileScanCommands.length === 0) {
    return (
      <Card data-testid="card-no-file-scans">
        <CardContent className="pt-6 text-center text-muted-foreground">
          <FileSearch className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>{t("endpoints.noFileScans")}</p>
          <p className="text-xs mt-1">{t("endpoints.fileScanHint")}</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {fileScanCommands.map((cmd: any) => {
        const report = parseFileScanFromCommand(cmd);
        const isPending = cmd.status === "pending";
        const isFailed = cmd.status === "failed";

        return (
          <Card key={cmd.id} data-testid={`card-file-scan-${cmd.id}`}>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileSearch className="w-4 h-4" />
                  {t("endpoints.fileScan")}
                  <span className="text-xs text-muted-foreground font-normal">
                    {new Date(cmd.createdAt).toLocaleString()}
                  </span>
                </CardTitle>
                <Badge variant={cmd.status === "done" ? "default" : cmd.status === "failed" ? "destructive" : "secondary"}>
                  {isPending && <Loader2 className="w-3 h-3 me-1 animate-spin" />}
                  {cmd.status}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {isPending && (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  {t("endpoints.scanInProgress")}
                </div>
              )}
              {isFailed && (
                <div className="flex items-center gap-2 text-sm text-destructive">
                  <AlertTriangle className="w-4 h-4" />
                  {t("endpoints.scanFailed")}
                </div>
              )}
              {report && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    <div className="text-center p-2 bg-muted/30 rounded" data-testid="stat-total-files">
                      <p className="text-lg font-bold">{report.totalFiles?.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground">{t("endpoints.totalFiles")}</p>
                    </div>
                    <div className="text-center p-2 bg-muted/30 rounded" data-testid="stat-executables">
                      <p className="text-lg font-bold">{report.executables?.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground">{t("endpoints.executables")}</p>
                    </div>
                    <div className="text-center p-2 bg-muted/30 rounded" data-testid="stat-recent">
                      <p className="text-lg font-bold">{report.recentFiles?.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground">{t("endpoints.recent24h")}</p>
                    </div>
                    <div className={`text-center p-2 rounded ${report.suspiciousFiles > 0 ? "bg-destructive/10" : "bg-muted/30"}`} data-testid="stat-suspicious">
                      <p className={`text-lg font-bold ${report.suspiciousFiles > 0 ? "text-destructive" : ""}`}>{report.suspiciousFiles}</p>
                      <p className="text-xs text-muted-foreground">{t("endpoints.suspicious")}</p>
                    </div>
                    <div className="text-center p-2 bg-muted/30 rounded" data-testid="stat-duration">
                      <p className="text-lg font-bold">{report.duration || "N/A"}</p>
                      <p className="text-xs text-muted-foreground">{t("endpoints.duration")}</p>
                    </div>
                  </div>

                  {report.scannedDirs && report.scannedDirs.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-muted-foreground mb-1">{t("endpoints.scannedDirectories")}</p>
                      <div className="flex flex-wrap gap-1">
                        {report.scannedDirs.map((dir: string, i: number) => (
                          <Badge key={i} variant="outline" className="text-xs font-mono" data-testid={`badge-dir-${i}`}>{dir}</Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.files && report.files.filter((f: any) => f.isSuspicious).length > 0 && (
                    <div>
                      <p className="text-sm font-medium flex items-center gap-1 mb-2">
                        <AlertTriangle className="w-4 h-4 text-destructive" />
                        {t("endpoints.suspiciousFiles")}
                      </p>
                      <div className="space-y-1">
                        {report.files.filter((f: any) => f.isSuspicious).map((file: any, i: number) => (
                          <div key={i} className="flex items-center justify-between gap-2 p-2 bg-destructive/5 rounded text-sm" data-testid={`row-suspicious-file-${i}`}>
                            <div className="min-w-0 flex-1">
                              <p className="font-mono text-xs truncate">{file.path}</p>
                              <p className="text-xs text-muted-foreground">{file.reason}</p>
                            </div>
                            <div className="text-right text-xs text-muted-foreground shrink-0">
                              <p>{formatBytes(file.size)}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.files && report.files.filter((f: any) => f.isRecent && !f.isSuspicious).length > 0 && (
                    <div>
                      <p className="text-sm font-medium flex items-center gap-1 mb-2">
                        <Clock className="w-4 h-4" />
                        {t("endpoints.recentModifiedExe")}
                      </p>
                      <div className="space-y-1 max-h-48 overflow-y-auto">
                        {report.files.filter((f: any) => f.isRecent && !f.isSuspicious).slice(0, 20).map((file: any, i: number) => (
                          <div key={i} className="flex items-center justify-between gap-2 p-2 bg-muted/30 rounded text-sm" data-testid={`row-recent-file-${i}`}>
                            <div className="min-w-0 flex-1">
                              <p className="font-mono text-xs truncate">{file.path}</p>
                            </div>
                            <div className="text-right text-xs text-muted-foreground shrink-0">
                              <p>{formatBytes(file.size)}</p>
                              {file.modifiedAt && <p>{new Date(file.modifiedAt).toLocaleString()}</p>}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {report.suspiciousFiles === 0 && (
                    <div className="flex items-center gap-2 p-3 bg-green-500/10 rounded text-sm" data-testid="text-scan-clean">
                      <Shield className="w-4 h-4 text-green-600" />
                      <span>{t("endpoints.systemClean")}</span>
                    </div>
                  )}
                </div>
              )}

              {!report && cmd.status === "done" && cmd.result && (
                <pre className="text-xs font-mono bg-muted/30 p-3 rounded overflow-x-auto max-h-48 whitespace-pre-wrap">
                  {cmd.result.split("__FILE_SCAN_JSON__:")[0]}
                </pre>
              )}
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}

export default function Endpoints() {
  useDocumentTitle("Endpoints");
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const [, navigate] = useLocation();
  const [selectedAgent, setSelectedAgent] = useState<number | null>(null);
  const [agentToDelete, setAgentToDelete] = useState<{ id: number; hostname: string } | null>(null);
  const [command, setCommand] = useState("");
  const [params, setParams] = useState("");
  const [activeTab, setActiveTab] = useState("overview");

  const { data: agents, isLoading } = useQuery<any[]>({
    queryKey: ["/api/agent/list"],
    refetchInterval: 15000,
  });

  const { data: agentDetail } = useQuery<any>({
    queryKey: ["/api/agent", selectedAgent],
    enabled: !!selectedAgent,
    refetchInterval: 10000,
  });

  const { data: commands } = useQuery<any[]>({
    queryKey: ["/api/agent", selectedAgent, "commands"],
    enabled: !!selectedAgent,
    refetchInterval: 5000,
  });

  const { data: bandwidthLogs } = useQuery<any[]>({
    queryKey: ["/api/bandwidth", selectedAgent],
    queryFn: () => fetch(`/api/bandwidth/${selectedAgent}`).then(r => r.json()),
    enabled: !!selectedAgent,
    refetchInterval: 10000,
  });

  const [isolateDialogOpen, setIsolateDialogOpen] = useState(false);
  const [fileRetrievePath, setFileRetrievePath] = useState("");
  const [fileRetrieveDialogOpen, setFileRetrieveDialogOpen] = useState(false);

  const sendCommandMutation = useMutation({
    mutationFn: async (data: { agentId: number; command: string; params?: string }) => {
      const res = await apiRequest("POST", "/api/agent/send-command", data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("endpoints.commandSent") });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent, "commands"] });
    },
    onError: () => {
      toast({ title: t("endpoints.commandSendFailed"), variant: "destructive" });
    },
  });

  const isolateMutation = useMutation({
    mutationFn: async (agentId: number) => {
      const res = await apiRequest("POST", `/api/agent/${agentId}/isolate`, {});
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Host isolation initiated" });
      setIsolateDialogOpen(false);
      queryClient.invalidateQueries({ queryKey: ["/api/agent/list"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent] });
    },
    onError: () => {
      toast({ title: "Failed to isolate host", variant: "destructive" });
    },
  });

  const unisolateMutation = useMutation({
    mutationFn: async (agentId: number) => {
      const res = await apiRequest("POST", `/api/agent/${agentId}/unisolate`, {});
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Host isolation released" });
      queryClient.invalidateQueries({ queryKey: ["/api/agent/list"] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent] });
    },
    onError: () => {
      toast({ title: "Failed to release isolation", variant: "destructive" });
    },
  });

  const fileRetrieveMutation = useMutation({
    mutationFn: async (data: { agentId: number; path: string }) => {
      const res = await apiRequest("POST", "/api/agent/send-command", {
        agentId: data.agentId,
        command: "file_retrieve",
        params: JSON.stringify({ path: data.path }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "File retrieval requested" });
      setFileRetrieveDialogOpen(false);
      setFileRetrievePath("");
      queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent, "commands"] });
    },
    onError: () => {
      toast({ title: "Failed to request file", variant: "destructive" });
    },
  });

  const deleteAgentMutation = useMutation({
    mutationFn: async (agentId: number) => {
      const res = await apiRequest("DELETE", `/api/agent/${agentId}`);
      return res.json();
    },
    onSuccess: (_, agentId) => {
      toast({ title: "Agent removed", description: "The agent has been permanently deleted." });
      if (selectedAgent === agentId) setSelectedAgent(null);
      setAgentToDelete(null);
      queryClient.invalidateQueries({ queryKey: ["/api/agent/list"] });
    },
    onError: () => {
      toast({ title: "Failed to delete agent", variant: "destructive" });
    },
  });

  const getStatusColor = (status: string) => {
    if (status === "online") return "bg-green-500";
    if (status === "offline") return "bg-red-500";
    return "bg-yellow-500";
  };

  const timeSince = (date: string) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64" data-testid="loading-endpoints">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-xl md:text-2xl font-bold" data-testid="text-endpoints-title">{t("endpoints.title")}</h1>
          <p className="text-muted-foreground text-sm">{t("endpoints.agentsRegistered", { count: agents?.length || 0 })}</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              exportToCsv(
                "endpoints-agents",
                ["ID", "Hostname", "OS", "IP", "Status", "CPU Usage %", "RAM Usage %", "Last Seen"],
                (agents || []).map((a: any) => [
                  a.id,
                  a.hostname || "",
                  a.os || "",
                  a.ip || "",
                  a.status || "",
                  a.cpuUsage ?? "",
                  a.ramUsage ?? "",
                  a.lastSeen ? new Date(a.lastSeen).toISOString() : "",
                ])
              );
            }}
            disabled={!agents || agents.length === 0}
            data-testid="button-export-csv"
          >
            <Download className="w-4 h-4 me-1" />
            {t("common.exportCsv", "Export CSV")}
          </Button>
          <Button onClick={() => navigate("/download-agent")} data-testid="button-download-agent">
            <Monitor className="w-4 h-4 me-2" />
            {t("endpoints.deployNewAgent")}
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-2">
          {agents?.length === 0 && (
            <Card data-testid="card-no-agents">
              <CardContent className="pt-6 text-center text-muted-foreground">
                {t("endpoints.noAgents")}
              </CardContent>
            </Card>
          )}
          {agents?.map((agent: any) => (
            <Card
              key={agent.id}
              className={`cursor-pointer transition-colors hover:border-primary/50 ${selectedAgent === agent.id ? "border-primary" : ""}`}
              onClick={() => setSelectedAgent(agent.id)}
              data-testid={`card-agent-${agent.id}`}
            >
              <CardContent className="pt-4 pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${getStatusColor(agent.status)}`} />
                    <span className="font-medium text-sm">{agent.hostname}</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className="text-xs">{agent.os || "Unknown"}</Badge>
                    {(user?.role === "admin" || user?.isSuperAdmin) && (
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-6 w-6 text-muted-foreground hover:text-red-400 hover:bg-red-500/10"
                        onClick={(e) => { e.stopPropagation(); setAgentToDelete({ id: agent.id, hostname: agent.hostname }); }}
                        data-testid={`button-delete-agent-${agent.id}`}
                        title="Remove agent"
                      >
                        <Trash2 className="w-3 h-3" />
                      </Button>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground flex-wrap">
                  <span>{agent.ip || "No IP"}</span>
                  <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{timeSince(agent.lastSeen)}</span>
                  {agent.isIsolated && (
                    <Badge variant="destructive" className="text-xs" data-testid={`badge-isolated-${agent.id}`}>
                      <ShieldAlert className="w-3 h-3 me-1" />
                      ISOLATED
                    </Badge>
                  )}
                  {agent.telemetry?.runMode && (
                    <Badge variant="outline" className="text-xs" data-testid={`badge-runmode-${agent.id}`}>
                      {agent.telemetry.runMode === "service" ? t("endpoints.runModeService") : agent.telemetry.runMode === "tray" ? t("endpoints.runModeTray") : t("endpoints.runModeTerminal")}
                    </Badge>
                  )}
                </div>
                {(agent.cpuUsage !== null || agent.ramUsage !== null) && (
                  <div className="flex gap-4 mt-2 text-xs">
                    {agent.cpuUsage !== null && <span className="flex items-center gap-1"><Cpu className="w-3 h-3" />CPU: {agent.cpuUsage}%</span>}
                    {agent.ramUsage !== null && <span className="flex items-center gap-1"><MemoryStick className="w-3 h-3" />RAM: {agent.ramUsage}%</span>}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        <div className="lg:col-span-2 space-y-4">
          {selectedAgent && agentDetail ? (
            <>
              <Card data-testid="card-agent-detail">
                <CardHeader>
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <CardTitle className="flex items-center gap-2">
                      <Monitor className="w-5 h-5" />
                      {agentDetail.hostname}
                    </CardTitle>
                    <div className="flex gap-2 flex-wrap">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={agentDetail.status !== "online" || sendCommandMutation.isPending}
                        onClick={() => sendCommandMutation.mutate({ agentId: selectedAgent!, command: "file_scan" })}
                        data-testid="button-file-scan"
                      >
                        <FileSearch className="w-4 h-4 me-1" />
                        {t("endpoints.fileScan")}
                      </Button>
                      <Dialog open={fileRetrieveDialogOpen} onOpenChange={setFileRetrieveDialogOpen}>
                        <DialogTrigger asChild>
                          <Button size="sm" variant="outline" disabled={agentDetail.status !== "online"} data-testid="button-file-retrieve">
                            <File className="w-4 h-4 me-1" />
                            Retrieve File
                          </Button>
                        </DialogTrigger>
                        <DialogContent>
                          <DialogHeader>
                            <DialogTitle>Retrieve File from Endpoint</DialogTitle>
                            <DialogDescription>Enter the full path to the file you want to retrieve (max 10MB).</DialogDescription>
                          </DialogHeader>
                          <Input
                            placeholder="C:\Users\admin\Documents\file.txt"
                            value={fileRetrievePath}
                            onChange={(e) => setFileRetrievePath(e.target.value)}
                            data-testid="input-file-retrieve-path"
                          />
                          <DialogFooter>
                            <Button
                              disabled={!fileRetrievePath.trim() || fileRetrieveMutation.isPending}
                              onClick={() => fileRetrieveMutation.mutate({ agentId: selectedAgent!, path: fileRetrievePath })}
                              data-testid="button-submit-file-retrieve"
                            >
                              {fileRetrieveMutation.isPending && <Loader2 className="w-4 h-4 me-1 animate-spin" />}
                              Retrieve
                            </Button>
                          </DialogFooter>
                        </DialogContent>
                      </Dialog>
                      <Button size="sm" variant="outline" onClick={() => navigate(`/endpoints/${selectedAgent}/terminal`)} data-testid="button-open-terminal">
                        <Terminal className="w-4 h-4 me-1" />
                        {t("endpoints.terminal")}
                      </Button>
                      {agentDetail.isIsolated ? (
                        <Button
                          size="sm"
                          variant="outline"
                          className="border-green-500 text-green-600 hover:bg-green-50"
                          disabled={unisolateMutation.isPending}
                          onClick={() => unisolateMutation.mutate(selectedAgent!)}
                          data-testid="button-unisolate"
                        >
                          {unisolateMutation.isPending ? <Loader2 className="w-4 h-4 me-1 animate-spin" /> : <ShieldOff className="w-4 h-4 me-1" />}
                          Release Isolation
                        </Button>
                      ) : (
                        <Dialog open={isolateDialogOpen} onOpenChange={setIsolateDialogOpen}>
                          <DialogTrigger asChild>
                            <Button size="sm" variant="destructive" disabled={agentDetail.status !== "online"} data-testid="button-isolate">
                              <ShieldAlert className="w-4 h-4 me-1" />
                              Isolate Host
                            </Button>
                          </DialogTrigger>
                          <DialogContent>
                            <DialogHeader>
                              <DialogTitle>Isolate Host</DialogTitle>
                              <DialogDescription>
                                This will block ALL network traffic on this endpoint except management communication. The host will be completely cut off from the network. Are you sure?
                              </DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                              <Button variant="outline" onClick={() => setIsolateDialogOpen(false)} data-testid="button-cancel-isolate">Cancel</Button>
                              <Button
                                variant="destructive"
                                disabled={isolateMutation.isPending}
                                onClick={() => isolateMutation.mutate(selectedAgent!)}
                                data-testid="button-confirm-isolate"
                              >
                                {isolateMutation.isPending && <Loader2 className="w-4 h-4 me-1 animate-spin" />}
                                Confirm Isolation
                              </Button>
                            </DialogFooter>
                          </DialogContent>
                        </Dialog>
                      )}
                      {agentDetail.isIsolated && (
                        <Badge variant="destructive" data-testid="badge-detail-isolated">
                          <ShieldAlert className="w-3 h-3 me-1" />
                          ISOLATED
                        </Badge>
                      )}
                      <Badge className={agentDetail.status === "online" ? "bg-green-600" : "bg-red-600"}>
                        {agentDetail.status === "online" ? <Wifi className="w-3 h-3 me-1" /> : <WifiOff className="w-3 h-3 me-1" />}
                        {agentDetail.status}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div><span className="text-muted-foreground">OS:</span> <span className="font-medium">{agentDetail.os || "Unknown"}</span></div>
                    <div><span className="text-muted-foreground">IP:</span> <span className="font-medium">{agentDetail.ip || "N/A"}</span></div>
                    <div><span className="text-muted-foreground">CPU:</span> <span className="font-medium">{agentDetail.cpuUsage ?? "N/A"}%</span></div>
                    <div><span className="text-muted-foreground">RAM:</span> <span className="font-medium">{agentDetail.ramUsage ?? "N/A"}%</span></div>
                  </div>
                </CardContent>
              </Card>

              <Tabs value={activeTab} onValueChange={setActiveTab} data-testid="tabs-agent-detail">
                <TabsList className="w-full justify-start flex-wrap">
                  <TabsTrigger value="overview" data-testid="tab-overview">{t("endpoints.tabSystemInfo")}</TabsTrigger>
                  <TabsTrigger value="commands" data-testid="tab-commands">{t("endpoints.tabCommands")}</TabsTrigger>
                  <TabsTrigger value="file-scans" data-testid="tab-file-scans">{t("endpoints.tabFileScans")}</TabsTrigger>
                  <TabsTrigger value="retrieved-files" data-testid="tab-retrieved-files">Retrieved Files</TabsTrigger>
                  <TabsTrigger value="bandwidth" data-testid="tab-bandwidth">{t("endpoints.tabBandwidth")}</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-4">
                  <SystemInfoPanel telemetry={agentDetail.telemetry} agent={agentDetail} />
                </TabsContent>

                <TabsContent value="commands" className="mt-4 space-y-4">
                  <Card data-testid="card-send-command">
                    <CardHeader>
                      <CardTitle className="text-lg">{t("endpoints.sendCommand")}</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex gap-2 flex-col sm:flex-row">
                        <Select value={command} onValueChange={setCommand}>
                          <SelectTrigger className="w-full sm:w-[200px]" data-testid="select-command">
                            <SelectValue placeholder={t("endpoints.selectCommand")} />
                          </SelectTrigger>
                          <SelectContent>
                            {COMMANDS.map((c) => (
                              <SelectItem key={c.value} value={c.value}>{t(c.labelKey)}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Input
                          placeholder={t("endpoints.paramsOptional")}
                          value={params}
                          onChange={(e) => setParams(e.target.value)}
                          className="flex-1"
                          data-testid="input-command-params"
                        />
                        <Button
                          disabled={!command || sendCommandMutation.isPending}
                          onClick={() => { sendCommandMutation.mutate({ agentId: selectedAgent!, command, params: params || undefined }); setCommand(""); setParams(""); }}
                          data-testid="button-send-command"
                        >
                          <Send className="w-4 h-4" />
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  <Card data-testid="card-command-history">
                    <CardHeader>
                      <div className="flex items-center justify-between gap-2">
                        <CardTitle className="text-lg">{t("endpoints.commandHistory")}</CardTitle>
                        <Button size="sm" variant="ghost" onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent, "commands"] })} data-testid="button-refresh-commands">
                          <RefreshCw className="w-4 h-4" />
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {!commands?.length ? (
                        <p className="text-muted-foreground text-sm text-center py-4">{t("endpoints.noCommandsSent")}</p>
                      ) : (
                        <div className="space-y-2 max-h-80 overflow-y-auto">
                          {commands.map((cmd: any) => (
                            <div key={cmd.id} className="flex items-center justify-between gap-2 p-2 bg-muted/50 rounded text-sm" data-testid={`row-command-${cmd.id}`}>
                              <div>
                                <span className="font-mono">{cmd.command}</span>
                                {cmd.params && <span className="text-muted-foreground ms-2">{cmd.params}</span>}
                              </div>
                              <div className="flex items-center gap-2">
                                <Badge variant={cmd.status === "done" ? "default" : cmd.status === "failed" ? "destructive" : "secondary"}>
                                  {cmd.status}
                                </Badge>
                                <span className="text-xs text-muted-foreground">{timeSince(cmd.createdAt)}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="file-scans" className="mt-4">
                  <FileScanResults commands={commands} />
                </TabsContent>

                <TabsContent value="retrieved-files" className="mt-4">
                  <Card data-testid="card-retrieved-files">
                    <CardHeader>
                      <CardTitle className="text-lg flex items-center gap-2">
                        <File className="w-4 h-4" />
                        Retrieved Files
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      {(() => {
                        const fileCommands = (commands || []).filter((c: any) => c.command === "file_retrieve");
                        if (fileCommands.length === 0) return <p className="text-sm text-muted-foreground text-center py-4">No files retrieved yet. Use the "Retrieve File" button to fetch files from this endpoint.</p>;
                        return (
                          <div className="space-y-2">
                            {fileCommands.map((cmd: any) => {
                              const isPending = cmd.status === "pending";
                              const isDone = cmd.status === "done";
                              let fileInfo: any = null;
                              if (isDone && cmd.result) {
                                const idx = cmd.result.indexOf("__FILE_RETRIEVE_JSON__:");
                                const match = idx !== -1 ? [null, cmd.result.substring(idx + "__FILE_RETRIEVE_JSON__:".length)] : null;
                                if (match) {
                                  try { fileInfo = JSON.parse(match[1]); } catch {}
                                }
                              }
                              const hasError = fileInfo?.error;
                              return (
                                <div key={cmd.id} className="flex items-center justify-between gap-3 p-3 bg-muted/30 rounded" data-testid={`row-retrieved-file-${cmd.id}`}>
                                  <div className="min-w-0 flex-1">
                                    {isPending && (
                                      <div className="flex items-center gap-2 text-sm">
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        <span className="text-muted-foreground">Retrieving file...</span>
                                        {cmd.params && <span className="font-mono text-xs truncate">{JSON.parse(cmd.params).path}</span>}
                                      </div>
                                    )}
                                    {hasError && (
                                      <div className="flex items-center gap-2 text-sm text-destructive">
                                        <AlertTriangle className="w-4 h-4" />
                                        <span>{fileInfo.error}</span>
                                      </div>
                                    )}
                                    {fileInfo && !hasError && (
                                      <div className="space-y-1">
                                        <p className="font-medium text-sm flex items-center gap-2">
                                          <FileText className="w-4 h-4" />
                                          {fileInfo.name}
                                        </p>
                                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                                          <span>Size: {fileInfo.sizeFormatted}</span>
                                          <span className="flex items-center gap-1"><Hash className="w-3 h-3" />SHA256: {fileInfo.sha256?.substring(0, 16)}...</span>
                                          <span>Modified: {new Date(fileInfo.modifiedAt).toLocaleString()}</span>
                                        </div>
                                      </div>
                                    )}
                                    {cmd.status === "failed" && (
                                      <div className="flex items-center gap-2 text-sm text-destructive">
                                        <AlertTriangle className="w-4 h-4" />
                                        <span>Failed to retrieve file</span>
                                      </div>
                                    )}
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0">
                                    <Badge variant={isDone ? (hasError ? "destructive" : "default") : cmd.status === "failed" ? "destructive" : "secondary"}>
                                      {isPending && <Loader2 className="w-3 h-3 me-1 animate-spin" />}
                                      {cmd.status}
                                    </Badge>
                                    {fileInfo && !hasError && (
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() => window.open(`/api/agent/${selectedAgent}/files/${cmd.id}/download`, "_blank")}
                                        data-testid={`button-download-file-${cmd.id}`}
                                      >
                                        <Download className="w-4 h-4 me-1" />
                                        Download
                                      </Button>
                                    )}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        );
                      })()}
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="bandwidth" className="mt-4">
                  {bandwidthLogs && bandwidthLogs.length > 0 ? (
                    <Card data-testid="card-bandwidth">
                      <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2">
                          <Activity className="w-4 h-4" />
                          {t("endpoints.bandwidthMonitor")}
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {bandwidthLogs.slice(0, 6).map((log: any, i: number) => {
                            const formatBytes = (b: number) => {
                              if (b > 1073741824) return `${(b / 1073741824).toFixed(1)} GB`;
                              if (b > 1048576) return `${(b / 1048576).toFixed(1)} MB`;
                              if (b > 1024) return `${(b / 1024).toFixed(1)} KB`;
                              return `${b} B`;
                            };
                            return (
                              <div key={i} className="flex items-center justify-between gap-2 p-2 rounded bg-muted/30" data-testid={`row-bandwidth-${i}`}>
                                <span className="text-sm font-mono">{log.interfaceName}</span>
                                <div className="flex items-center gap-4 text-xs">
                                  <span className="flex items-center gap-1 text-green-500">
                                    <ArrowDown className="w-3 h-3" />
                                    {formatBytes(Number(log.bytesIn))}
                                  </span>
                                  <span className="flex items-center gap-1 text-blue-500">
                                    <ArrowUp className="w-3 h-3" />
                                    {formatBytes(Number(log.bytesOut))}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card>
                      <CardContent className="pt-6 text-center text-muted-foreground">
                        {t("endpoints.noBandwidthData")}
                      </CardContent>
                    </Card>
                  )}
                </TabsContent>
              </Tabs>
            </>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center text-muted-foreground">
                {t("endpoints.selectAgent")}
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <AlertDialog open={!!agentToDelete} onOpenChange={(open) => { if (!open) setAgentToDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove agent permanently?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete <strong>{agentToDelete?.hostname}</strong> from the platform. The agent service on that machine will disconnect on its next heartbeat. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel data-testid="button-cancel-delete-agent">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => agentToDelete && deleteAgentMutation.mutate(agentToDelete.id)}
              disabled={deleteAgentMutation.isPending}
              data-testid="button-confirm-delete-agent"
            >
              {deleteAgentMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : null}
              Remove agent
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
