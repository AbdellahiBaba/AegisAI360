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
import { Loader2, Monitor, Cpu, MemoryStick, Wifi, WifiOff, Terminal, Send, RefreshCw, Clock, Activity, ArrowDown, ArrowUp, HardDrive, Globe, Server, Layers, Info } from "lucide-react";
import { useLocation } from "wouter";

const COMMANDS = [
  { value: "run_system_scan", label: "System Scan" },
  { value: "security_scan", label: "Security Audit" },
  { value: "ping", label: "Ping Test" },
  { value: "process_list", label: "List Processes" },
  { value: "service_list", label: "List Services" },
  { value: "wifi_list", label: "WiFi Networks" },
  { value: "network_scan", label: "Network Scan" },
  { value: "disk_usage", label: "Disk Usage" },
  { value: "packet_capture", label: "Packet Capture" },
  { value: "arp_monitor", label: "ARP Monitor" },
  { value: "rogue_scan", label: "Rogue Scan" },
  { value: "bandwidth_stats", label: "Bandwidth Stats" },
  { value: "vuln_scan", label: "Vuln Scan" },
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
  if (!telemetry) {
    return (
      <Card data-testid="card-system-info-empty">
        <CardContent className="pt-6 text-center text-muted-foreground">
          <Info className="w-8 h-8 mx-auto mb-2 opacity-50" />
          <p>No detailed telemetry data available yet.</p>
          <p className="text-xs mt-1">Telemetry data will appear once the agent sends system information.</p>
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
            <p className="text-xs text-muted-foreground">Hostname</p>
            <p className="font-medium text-sm truncate" data-testid="text-sysinfo-hostname">{telemetry.hostname || agent.hostname}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-os">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">OS / Arch</p>
            <p className="font-medium text-sm truncate" data-testid="text-sysinfo-os">{telemetry.os || agent.os || "Unknown"}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-uptime">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">Uptime</p>
            <p className="font-medium text-sm" data-testid="text-sysinfo-uptime">{telemetry.uptime || "N/A"}</p>
          </CardContent>
        </Card>
        <Card data-testid="card-sysinfo-version">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">Agent Version</p>
            <p className="font-medium text-sm" data-testid="text-sysinfo-version">{telemetry.agentVersion || "N/A"}</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card data-testid="card-cpu-usage">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Cpu className="w-4 h-4" />
              CPU Usage
              {telemetry.cpus && <Badge variant="outline" className="text-xs">{telemetry.cpus} cores</Badge>}
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
              Memory Usage
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
              Disk Usage
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
              Network
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Local IP</span>
                <span className="font-mono font-medium" data-testid="text-local-ip">{telemetry.localIP || agent.ip || "N/A"}</span>
              </div>
              {netConnections != null && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Active Connections</span>
                  <Badge variant="outline" data-testid="text-net-connections">{netConnections}</Badge>
                </div>
              )}
              {telemetry.arch && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Architecture</span>
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
              Agent Details
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Agent ID</span>
                <span className="font-mono font-medium" data-testid="text-agent-id">{agent.id}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Last Seen</span>
                <span className="font-medium" data-testid="text-last-seen">{agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : "N/A"}</span>
              </div>
              {telemetry.lastUpdated && (
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Telemetry Updated</span>
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
              Top Processes
              <Badge variant="outline" className="text-xs">{topProcesses.length}</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-muted-foreground">
                    <th className="text-left py-1.5 pe-4 font-medium">Process</th>
                    <th className="text-right py-1.5 px-2 font-medium">CPU</th>
                    <th className="text-right py-1.5 ps-2 font-medium">Memory</th>
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

export default function Endpoints() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [selectedAgent, setSelectedAgent] = useState<number | null>(null);
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

  const sendCommandMutation = useMutation({
    mutationFn: async (data: { agentId: number; command: string; params?: string }) => {
      const res = await apiRequest("POST", "/api/agent/send-command", data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Command sent" });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent, "commands"] });
    },
    onError: () => {
      toast({ title: "Failed to send command", variant: "destructive" });
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
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-endpoints-title">Endpoint Agents</h1>
          <p className="text-muted-foreground text-sm">{agents?.length || 0} agents registered</p>
        </div>
        <Button onClick={() => navigate("/download-agent")} data-testid="button-download-agent">
          <Monitor className="w-4 h-4 me-2" />
          Deploy New Agent
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-2">
          {agents?.length === 0 && (
            <Card data-testid="card-no-agents">
              <CardContent className="pt-6 text-center text-muted-foreground">
                No agents registered yet. Deploy an agent to get started.
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
                  <Badge variant="outline" className="text-xs">{agent.os || "Unknown"}</Badge>
                </div>
                <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                  <span>{agent.ip || "No IP"}</span>
                  <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{timeSince(agent.lastSeen)}</span>
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
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" onClick={() => navigate(`/endpoints/${selectedAgent}/terminal`)} data-testid="button-open-terminal">
                        <Terminal className="w-4 h-4 me-1" />
                        Terminal
                      </Button>
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
                  <TabsTrigger value="overview" data-testid="tab-overview">System Info</TabsTrigger>
                  <TabsTrigger value="commands" data-testid="tab-commands">Commands</TabsTrigger>
                  <TabsTrigger value="bandwidth" data-testid="tab-bandwidth">Bandwidth</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-4">
                  <SystemInfoPanel telemetry={agentDetail.telemetry} agent={agentDetail} />
                </TabsContent>

                <TabsContent value="commands" className="mt-4 space-y-4">
                  <Card data-testid="card-send-command">
                    <CardHeader>
                      <CardTitle className="text-lg">Send Command</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="flex gap-2">
                        <Select value={command} onValueChange={setCommand}>
                          <SelectTrigger className="w-[200px]" data-testid="select-command">
                            <SelectValue placeholder="Select command" />
                          </SelectTrigger>
                          <SelectContent>
                            {COMMANDS.map((c) => (
                              <SelectItem key={c.value} value={c.value}>{c.label}</SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                        <Input
                          placeholder="Parameters (optional)"
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
                        <CardTitle className="text-lg">Command History</CardTitle>
                        <Button size="sm" variant="ghost" onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/agent", selectedAgent, "commands"] })} data-testid="button-refresh-commands">
                          <RefreshCw className="w-4 h-4" />
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      {!commands?.length ? (
                        <p className="text-muted-foreground text-sm text-center py-4">No commands sent yet</p>
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

                <TabsContent value="bandwidth" className="mt-4">
                  {bandwidthLogs && bandwidthLogs.length > 0 ? (
                    <Card data-testid="card-bandwidth">
                      <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2">
                          <Activity className="w-4 h-4" />
                          Bandwidth Monitor
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
                        No bandwidth data available yet. Send a "Bandwidth Stats" command to collect data.
                      </CardContent>
                    </Card>
                  )}
                </TabsContent>
              </Tabs>
            </>
          ) : (
            <Card>
              <CardContent className="pt-6 text-center text-muted-foreground">
                Select an agent from the list to view details
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
