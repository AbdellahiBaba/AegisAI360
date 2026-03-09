import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Loader2, Shield, Radar, Network, Bug, Search, Plus, RefreshCw,
  AlertTriangle, CheckCircle, Clock, Monitor, Wifi,
} from "lucide-react";

const RISKY_PORTS = new Set([21, 23, 25, 53, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017]);

const TABS = [
  { id: "rogue", label: "Rogue Device Detection", icon: Radar },
  { id: "arp", label: "ARP Monitor", icon: Network },
  { id: "vuln", label: "Vulnerability Scanner", icon: Bug },
] as const;

type TabId = typeof TABS[number]["id"];

function AgentSelector({ value, onChange, testId }: { value: string; onChange: (v: string) => void; testId: string }) {
  const { data: agents, isLoading } = useQuery<any[]>({
    queryKey: ["/api/agent/list"],
    refetchInterval: 15000,
  });

  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger data-testid={testId}>
        <SelectValue placeholder={isLoading ? "Loading agents..." : "Select agent"} />
      </SelectTrigger>
      <SelectContent>
        {agents?.map((agent: any) => (
          <SelectItem key={agent.id} value={String(agent.id)}>
            {agent.hostname} ({agent.ip || "No IP"})
          </SelectItem>
        ))}
        {(!agents || agents.length === 0) && !isLoading && (
          <SelectItem value="_none" disabled>No agents available</SelectItem>
        )}
      </SelectContent>
    </Select>
  );
}

function parseRogueDevices(result: string): Array<{ ip: string; mac: string; hostname: string; manufacturer: string; suspicious: boolean }> {
  if (!result) return [];
  try {
    const parsed = JSON.parse(result);
    if (Array.isArray(parsed)) {
      return parsed.map((d: any) => ({
        ip: d.ip || d.IP || "",
        mac: d.mac || d.MAC || "",
        hostname: d.hostname || d.Hostname || "Unknown",
        manufacturer: d.manufacturer || d.Manufacturer || d.vendor || "Unknown",
        suspicious: d.suspicious || d.unknown || !d.known || d.manufacturer === "Unknown" || d.vendor === "Unknown" || false,
      }));
    }
  } catch {}
  const devices: Array<{ ip: string; mac: string; hostname: string; manufacturer: string; suspicious: boolean }> = [];
  const lines = result.split("\n").filter(Boolean);
  for (const line of lines) {
    const parts = line.split(/[\t,|]+/).map(s => s.trim());
    if (parts.length >= 2) {
      const ip = parts[0];
      const mac = parts[1];
      const hostname = parts[2] || "Unknown";
      const manufacturer = parts[3] || "Unknown";
      devices.push({
        ip,
        mac,
        hostname,
        manufacturer,
        suspicious: manufacturer === "Unknown" || hostname === "Unknown",
      });
    }
  }
  return devices;
}

function parseVulnResult(result: string): Array<{ port: number; service: string; state: string; risk: string }> {
  if (!result) return [];
  try {
    const parsed = JSON.parse(result);
    if (Array.isArray(parsed)) {
      return parsed.map((p: any) => ({
        port: p.port || p.Port || 0,
        service: p.service || p.Service || "unknown",
        state: p.state || p.State || "open",
        risk: RISKY_PORTS.has(p.port || p.Port || 0) ? "high" : (p.risk || "low"),
      }));
    }
    if (parsed.ports && Array.isArray(parsed.ports)) {
      return parsed.ports.map((p: any) => ({
        port: p.port || 0,
        service: p.service || "unknown",
        state: p.state || "open",
        risk: RISKY_PORTS.has(p.port || 0) ? "high" : (p.risk || "low"),
      }));
    }
  } catch {}
  const ports: Array<{ port: number; service: string; state: string; risk: string }> = [];
  const lines = result.split("\n").filter(Boolean);
  for (const line of lines) {
    const match = line.match(/(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)/);
    if (match) {
      const port = parseInt(match[1]);
      ports.push({
        port,
        service: match[4]?.trim() || "unknown",
        state: match[3],
        risk: RISKY_PORTS.has(port) ? "high" : "low",
      });
    }
  }
  return ports;
}

function RogueDetectionTab() {
  const { toast } = useToast();
  const [agentId, setAgentId] = useState("");

  const { data: commands } = useQuery<any[]>({
    queryKey: ["/api/agent", agentId, "commands"],
    queryFn: () => fetch(`/api/agent/${agentId}/commands`).then(r => r.json()),
    enabled: !!agentId,
    refetchInterval: 5000,
  });

  const latestRogueScan = useMemo(() => {
    if (!commands) return null;
    return commands.find((c: any) => c.command === "rogue_scan" && c.status === "done") || null;
  }, [commands]);

  const devices = useMemo(() => {
    if (!latestRogueScan?.result) return [];
    return parseRogueDevices(latestRogueScan.result);
  }, [latestRogueScan]);

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/agent/send-command", {
        agentId: parseInt(agentId),
        command: "rogue_scan",
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Rogue scan initiated" });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", agentId, "commands"] });
    },
    onError: () => toast({ title: "Failed to start scan", variant: "destructive" }),
  });

  const addKnownMutation = useMutation({
    mutationFn: async (device: { ip: string; mac: string; hostname: string; manufacturer: string }) => {
      const res = await apiRequest("POST", "/api/network/devices", {
        ipAddress: device.ip,
        macAddress: device.mac,
        hostname: device.hostname,
        manufacturer: device.manufacturer,
        deviceType: "unknown",
        status: "online",
        authStatus: "authorized",
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Device added as known" });
      queryClient.invalidateQueries({ queryKey: ["/api/network/devices"] });
    },
    onError: () => toast({ title: "Failed to add device", variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-end gap-3 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <Label className="text-xs mb-1 block">Agent</Label>
              <AgentSelector value={agentId} onChange={setAgentId} testId="select-rogue-agent" />
            </div>
            <Button
              onClick={() => scanMutation.mutate()}
              disabled={!agentId || scanMutation.isPending}
              data-testid="button-rogue-scan"
            >
              {scanMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin me-2" /> : <Radar className="w-4 h-4 me-2" />}
              Scan Network
            </Button>
          </div>
        </CardContent>
      </Card>

      {latestRogueScan && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Monitor className="w-4 h-4" />
              Discovered Devices ({devices.length})
            </CardTitle>
            <Badge variant="outline" className="text-xs">
              <Clock className="w-3 h-3 me-1" />
              {new Date(latestRogueScan.updatedAt || latestRogueScan.createdAt).toLocaleString()}
            </Badge>
          </CardHeader>
          <CardContent>
            {devices.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4" data-testid="text-no-rogue-devices">No devices discovered in scan result</p>
            ) : (
              <div className="space-y-2">
                {devices.map((device, idx) => (
                  <div
                    key={`${device.mac}-${idx}`}
                    className={`flex items-center justify-between gap-3 p-3 rounded-md flex-wrap ${
                      device.suspicious ? "bg-amber-500/10 border border-amber-500/30" : "bg-muted/30"
                    }`}
                    data-testid={`row-rogue-device-${idx}`}
                  >
                    <div className="flex items-center gap-4 flex-wrap">
                      <div>
                        <p className="text-xs font-mono font-bold" data-testid={`text-rogue-ip-${idx}`}>{device.ip}</p>
                        <p className="text-[10px] text-muted-foreground">{device.mac}</p>
                      </div>
                      <div>
                        <p className="text-xs">{device.hostname}</p>
                        <p className="text-[10px] text-muted-foreground">{device.manufacturer}</p>
                      </div>
                      {device.suspicious && (
                        <Badge variant="outline" className="bg-amber-500/20 text-amber-400 border-amber-500/30">
                          <AlertTriangle className="w-3 h-3 me-1" />
                          Suspicious
                        </Badge>
                      )}
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => addKnownMutation.mutate(device)}
                      disabled={addKnownMutation.isPending}
                      data-testid={`button-add-known-${idx}`}
                    >
                      <Plus className="w-3 h-3 me-1" />
                      Add Known
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {!latestRogueScan && agentId && (
        <Card>
          <CardContent className="pt-6 text-center text-muted-foreground text-sm" data-testid="text-no-rogue-results">
            No rogue scan results yet. Click "Scan Network" to start.
          </CardContent>
        </Card>
      )}
    </div>
  );
}

const ALERT_TYPE_STYLES: Record<string, string> = {
  mac_change: "bg-red-500/20 text-red-400 border-red-500/30",
  new_device: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  duplicate_ip: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

function ArpMonitorTab() {
  const { toast } = useToast();
  const [agentId, setAgentId] = useState("");

  const { data: arpAlerts, isLoading: alertsLoading } = useQuery<any[]>({
    queryKey: ["/api/arp-alerts"],
    refetchInterval: 10000,
  });

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/agent/send-command", {
        agentId: parseInt(agentId),
        command: "arp_monitor",
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "ARP scan initiated" });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", agentId, "commands"] });
    },
    onError: () => toast({ title: "Failed to start ARP scan", variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="pt-6">
          <div className="flex items-end gap-3 flex-wrap">
            <div className="flex-1 min-w-[200px]">
              <Label className="text-xs mb-1 block">Agent</Label>
              <AgentSelector value={agentId} onChange={setAgentId} testId="select-arp-agent" />
            </div>
            <Button
              onClick={() => scanMutation.mutate()}
              disabled={!agentId || scanMutation.isPending}
              data-testid="button-arp-scan"
            >
              {scanMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin me-2" /> : <Network className="w-4 h-4 me-2" />}
              Start ARP Scan
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            ARP Alerts
          </CardTitle>
          <Button
            size="icon"
            variant="ghost"
            onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/arp-alerts"] })}
            data-testid="button-refresh-arp"
          >
            <RefreshCw className="w-4 h-4" />
          </Button>
        </CardHeader>
        <CardContent>
          {alertsLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : !arpAlerts || arpAlerts.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-4" data-testid="text-no-arp-alerts">No ARP alerts detected</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="text-left py-2 px-2">IP Address</th>
                    <th className="text-left py-2 px-2">Old MAC</th>
                    <th className="text-left py-2 px-2">New MAC</th>
                    <th className="text-left py-2 px-2">Alert Type</th>
                    <th className="text-left py-2 px-2">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {arpAlerts.map((alert: any, idx: number) => (
                    <tr key={alert.id || idx} className="border-b border-border/50" data-testid={`row-arp-alert-${idx}`}>
                      <td className="py-2 px-2 font-mono" data-testid={`text-arp-ip-${idx}`}>{alert.ip || alert.ipAddress}</td>
                      <td className="py-2 px-2 font-mono text-muted-foreground">{alert.oldMac || alert.old_mac || "—"}</td>
                      <td className="py-2 px-2 font-mono">{alert.newMac || alert.new_mac || alert.mac || "—"}</td>
                      <td className="py-2 px-2">
                        <Badge
                          variant="outline"
                          className={ALERT_TYPE_STYLES[alert.alertType || alert.type] || "bg-muted/30"}
                          data-testid={`badge-arp-type-${idx}`}
                        >
                          {alert.alertType || alert.type || "unknown"}
                        </Badge>
                      </td>
                      <td className="py-2 px-2 text-muted-foreground">
                        {alert.createdAt ? new Date(alert.createdAt).toLocaleString() : alert.timestamp || "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function VulnScannerTab() {
  const { toast } = useToast();
  const [agentId, setAgentId] = useState("");
  const [target, setTarget] = useState("");
  const [portRange, setPortRange] = useState("");

  const { data: commands } = useQuery<any[]>({
    queryKey: ["/api/agent", agentId, "commands"],
    enabled: !!agentId,
    refetchInterval: 5000,
  });

  const latestVulnScan = useMemo(() => {
    if (!commands) return null;
    return commands.find((c: any) => c.command === "vuln_scan" && c.status === "done") || null;
  }, [commands]);

  const scanResults = useMemo(() => {
    if (!latestVulnScan?.result) return [];
    return parseVulnResult(latestVulnScan.result);
  }, [latestVulnScan]);

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/agent/send-command", {
        agentId: parseInt(agentId),
        command: "vuln_scan",
        params: JSON.stringify({ target, portRange: portRange || "1-1024" }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Vulnerability scan initiated" });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", agentId, "commands"] });
    },
    onError: () => toast({ title: "Failed to start scan", variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="pt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
            <div>
              <Label className="text-xs mb-1 block">Agent</Label>
              <AgentSelector value={agentId} onChange={setAgentId} testId="select-vuln-agent" />
            </div>
            <div>
              <Label className="text-xs mb-1 block">Target IP</Label>
              <Input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.1"
                data-testid="input-vuln-target"
              />
            </div>
            <div>
              <Label className="text-xs mb-1 block">Port Range</Label>
              <Input
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                placeholder="1-1024"
                data-testid="input-vuln-port-range"
              />
            </div>
            <Button
              onClick={() => scanMutation.mutate()}
              disabled={!agentId || !target || scanMutation.isPending}
              data-testid="button-vuln-scan"
            >
              {scanMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin me-2" /> : <Search className="w-4 h-4 me-2" />}
              Scan
            </Button>
          </div>
        </CardContent>
      </Card>

      {latestVulnScan && (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between gap-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Bug className="w-4 h-4" />
              Scan Results ({scanResults.length} ports)
            </CardTitle>
            <Badge variant="outline" className="text-xs">
              <Clock className="w-3 h-3 me-1" />
              {new Date(latestVulnScan.updatedAt || latestVulnScan.createdAt).toLocaleString()}
            </Badge>
          </CardHeader>
          <CardContent>
            {scanResults.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-4" data-testid="text-no-vuln-results">No open ports detected</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border text-muted-foreground">
                      <th className="text-left py-2 px-2">Port</th>
                      <th className="text-left py-2 px-2">Service</th>
                      <th className="text-left py-2 px-2">State</th>
                      <th className="text-left py-2 px-2">Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.map((port, idx) => (
                      <tr
                        key={port.port}
                        className={`border-b border-border/50 ${port.risk === "high" ? "bg-red-500/5" : ""}`}
                        data-testid={`row-vuln-port-${idx}`}
                      >
                        <td className="py-2 px-2 font-mono font-bold" data-testid={`text-vuln-port-${idx}`}>{port.port}</td>
                        <td className="py-2 px-2">{port.service}</td>
                        <td className="py-2 px-2">
                          <Badge variant="outline" className="bg-green-500/20 text-green-400 border-green-500/30">
                            {port.state}
                          </Badge>
                        </td>
                        <td className="py-2 px-2">
                          <Badge
                            variant="outline"
                            className={port.risk === "high" ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-blue-500/20 text-blue-400 border-blue-500/30"}
                            data-testid={`badge-vuln-risk-${idx}`}
                          >
                            {port.risk}
                          </Badge>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {!latestVulnScan && agentId && (
        <Card>
          <CardContent className="pt-6 text-center text-muted-foreground text-sm" data-testid="text-no-vuln-scan">
            No vulnerability scan results yet. Enter a target and click "Scan".
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function NetworkSecurityPage() {
  useDocumentTitle("Network Security");
  const [activeTab, setActiveTab] = useState<TabId>("rogue");

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2" data-testid="text-network-security-title">
          <Shield className="w-6 h-6" />
          Network Security
        </h1>
        <p className="text-sm text-muted-foreground">Rogue device detection, ARP monitoring, and vulnerability scanning</p>
      </div>

      <div className="flex gap-1 border-b border-border">
        {TABS.map((tab) => {
          const Icon = tab.icon;
          return (
            <Button
              key={tab.id}
              variant="ghost"
              className={`rounded-b-none ${activeTab === tab.id ? "border-b-2 border-primary" : ""}`}
              onClick={() => setActiveTab(tab.id)}
              data-testid={`tab-${tab.id}`}
            >
              <Icon className="w-4 h-4 me-2" />
              {tab.label}
            </Button>
          );
        })}
      </div>

      {activeTab === "rogue" && <RogueDetectionTab />}
      {activeTab === "arp" && <ArpMonitorTab />}
      {activeTab === "vuln" && <VulnScannerTab />}
    </div>
  );
}