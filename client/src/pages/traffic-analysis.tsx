import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Activity, Wifi, AlertTriangle, Globe, Server, Radio, Loader2 } from "lucide-react";

interface CaptureData {
  protocols: { tcp: number; udp: number; icmp: number; other: number };
  topSourceIPs: string[];
  topDestIPs: string[];
  dnsQueries: string[];
  suspiciousConnections: { ip: string; port: number; reason: string }[];
  totalPackets: number;
}

interface PacketCapture {
  id: number;
  agentId: number;
  captureData: any;
  packetCount: number;
  createdAt: string;
  duration: number;
}

function normalizeCaptureData(raw: any): CaptureData | null {
  if (!raw) return null;
  const protocols = { tcp: 0, udp: 0, icmp: 0, other: 0 };
  if (raw.protocolStats || raw.protocols) {
    const ps = raw.protocolStats || raw.protocols;
    if (typeof ps === "object") {
      for (const [key, val] of Object.entries(ps)) {
        const k = key.toLowerCase();
        if (k === "tcp") protocols.tcp = Number(val) || 0;
        else if (k === "udp") protocols.udp = Number(val) || 0;
        else if (k === "icmp") protocols.icmp = Number(val) || 0;
        else protocols.other += Number(val) || 0;
      }
    }
  }

  let topSourceIPs: string[] = [];
  if (raw.topSourceIPs) {
    if (Array.isArray(raw.topSourceIPs)) {
      topSourceIPs = raw.topSourceIPs;
    } else if (typeof raw.topSourceIPs === "object") {
      topSourceIPs = Object.entries(raw.topSourceIPs)
        .sort((a: any, b: any) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => `${ip} (${count})`);
    }
  }

  let topDestIPs: string[] = [];
  if (raw.topDestIPs) {
    if (Array.isArray(raw.topDestIPs)) {
      topDestIPs = raw.topDestIPs;
    } else if (typeof raw.topDestIPs === "object") {
      topDestIPs = Object.entries(raw.topDestIPs)
        .sort((a: any, b: any) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => `${ip} (${count})`);
    }
  }

  const dnsQueries = raw.dnsQueries || [];

  let suspiciousConnections: CaptureData["suspiciousConnections"] = [];
  if (raw.suspiciousConnections && Array.isArray(raw.suspiciousConnections)) {
    suspiciousConnections = raw.suspiciousConnections.map((c: any) => ({
      ip: c.ip || c.source || c.destination || c.Source || c.Destination || "",
      port: c.port || c.Port || 0,
      reason: c.reason || c.Reason || "unknown",
    }));
  }

  const totalPackets = raw.totalPackets || raw.packetCount || raw.PacketCount ||
    protocols.tcp + protocols.udp + protocols.icmp + protocols.other;

  return { protocols, topSourceIPs, topDestIPs, dnsQueries, suspiciousConnections, totalPackets };
}

const DURATIONS = [
  { value: "10", label: "10 seconds" },
  { value: "30", label: "30 seconds" },
  { value: "60", label: "60 seconds" },
];

const PROTOCOL_COLORS: Record<string, string> = {
  tcp: "bg-blue-500",
  udp: "bg-green-500",
  icmp: "bg-yellow-500",
  other: "bg-purple-500",
};

const PROTOCOL_LABELS: Record<string, string> = {
  tcp: "TCP",
  udp: "UDP",
  icmp: "ICMP",
  other: "Other",
};

function ProtocolBar({ protocols }: { protocols: CaptureData["protocols"] }) {
  const total = protocols.tcp + protocols.udp + protocols.icmp + protocols.other;
  if (total === 0) return null;

  const entries = Object.entries(protocols).filter(([, v]) => v > 0);

  return (
    <div className="space-y-2">
      <div className="flex rounded-md overflow-hidden h-4" data-testid="bar-protocol-distribution">
        {entries.map(([key, value]) => (
          <div
            key={key}
            className={`${PROTOCOL_COLORS[key]} transition-all`}
            style={{ width: `${(value / total) * 100}%` }}
            title={`${PROTOCOL_LABELS[key]}: ${value} (${((value / total) * 100).toFixed(1)}%)`}
          />
        ))}
      </div>
      <div className="flex gap-4 flex-wrap">
        {entries.map(([key, value]) => (
          <div key={key} className="flex items-center gap-1.5 text-xs" data-testid={`legend-protocol-${key}`}>
            <div className={`w-2.5 h-2.5 rounded-sm ${PROTOCOL_COLORS[key]}`} />
            <span className="text-muted-foreground">{PROTOCOL_LABELS[key]}</span>
            <span className="font-medium">{value}</span>
            <span className="text-muted-foreground">({((value / total) * 100).toFixed(1)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function TrafficAnalysis() {
  const { toast } = useToast();
  const [selectedAgent, setSelectedAgent] = useState<string>("");
  const [duration, setDuration] = useState<string>("30");

  const { data: agents, isLoading: agentsLoading } = useQuery<any[]>({
    queryKey: ["/api/agent/list"],
    refetchInterval: 15000,
  });

  const agentId = selectedAgent ? parseInt(selectedAgent) : null;

  const { data: captures, isLoading: capturesLoading } = useQuery<PacketCapture[]>({
    queryKey: ["/api/packet-captures", agentId],
    queryFn: () => fetch(`/api/packet-captures/${agentId}`).then(r => r.json()),
    enabled: !!agentId,
    refetchInterval: 5000,
  });

  const startCaptureMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/agent/send-command", {
        agentId: agentId!,
        command: "packet_capture",
        params: JSON.stringify({ duration: parseInt(duration) }),
      });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: "Packet capture started", description: `Capturing for ${duration}s on selected agent` });
      queryClient.invalidateQueries({ queryKey: ["/api/packet-captures", agentId] });
      queryClient.invalidateQueries({ queryKey: ["/api/agent", agentId, "commands"] });
    },
    onError: () => {
      toast({ title: "Failed to start capture", variant: "destructive" });
    },
  });

  const latestCapture = captures?.length ? captures[0] : null;
  const captureData = latestCapture ? normalizeCaptureData(latestCapture.captureData) : null;

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2" data-testid="text-traffic-title">
            <Activity className="w-6 h-6" />
            Traffic Analysis
          </h1>
          <p className="text-sm text-muted-foreground">Capture and analyze network traffic from endpoint agents</p>
        </div>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3 space-y-0 pb-4">
          <CardTitle className="text-lg flex items-center gap-2">
            <Radio className="w-5 h-5" />
            Capture Controls
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3 flex-wrap">
            <Select value={selectedAgent} onValueChange={setSelectedAgent}>
              <SelectTrigger className="w-[220px]" data-testid="select-agent">
                <SelectValue placeholder="Select agent" />
              </SelectTrigger>
              <SelectContent>
                {agentsLoading ? (
                  <div className="p-2"><Skeleton className="h-6 w-full" /></div>
                ) : agents?.length ? (
                  agents.map((agent: any) => (
                    <SelectItem key={agent.id} value={String(agent.id)}>
                      {agent.hostname || `Agent #${agent.id}`}
                    </SelectItem>
                  ))
                ) : (
                  <div className="p-2 text-xs text-muted-foreground">No agents available</div>
                )}
              </SelectContent>
            </Select>

            <Select value={duration} onValueChange={setDuration}>
              <SelectTrigger className="w-[160px]" data-testid="select-duration">
                <SelectValue placeholder="Duration" />
              </SelectTrigger>
              <SelectContent>
                {DURATIONS.map((d) => (
                  <SelectItem key={d.value} value={d.value}>{d.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Button
              onClick={() => startCaptureMutation.mutate()}
              disabled={!agentId || startCaptureMutation.isPending}
              data-testid="button-start-capture"
            >
              {startCaptureMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin me-2" />
              ) : (
                <Wifi className="w-4 h-4 me-2" />
              )}
              Start Capture
            </Button>
          </div>
        </CardContent>
      </Card>

      {!agentId && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <Server className="w-10 h-10 mx-auto mb-3 opacity-40" />
            <p data-testid="text-select-agent-prompt">Select an agent to view traffic captures</p>
          </CardContent>
        </Card>
      )}

      {agentId && capturesLoading && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}>
              <CardContent className="p-4 space-y-3">
                <Skeleton className="h-4 w-1/3" />
                <Skeleton className="h-20 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {agentId && !capturesLoading && captureData && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs text-muted-foreground">Total Packets</span>
                  <Activity className="w-4 h-4 text-muted-foreground" />
                </div>
                <p className="text-2xl font-bold" data-testid="text-total-packets">{captureData.totalPackets.toLocaleString()}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs text-muted-foreground">DNS Queries</span>
                  <Globe className="w-4 h-4 text-muted-foreground" />
                </div>
                <p className="text-2xl font-bold" data-testid="text-dns-count">{captureData.dnsQueries?.length || 0}</p>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs text-muted-foreground">Suspicious Connections</span>
                  <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                </div>
                <p className="text-2xl font-bold" data-testid="text-suspicious-count">
                  {captureData.suspiciousConnections?.length || 0}
                </p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Protocol Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <ProtocolBar protocols={captureData.protocols} />
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Server className="w-4 h-4" />
                  Top Source IPs
                </CardTitle>
              </CardHeader>
              <CardContent>
                {captureData.topSourceIPs?.length ? (
                  <div className="space-y-1.5">
                    {captureData.topSourceIPs.map((ip, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded-md bg-muted/30 text-sm font-mono" data-testid={`text-source-ip-${i}`}>
                        <Badge variant="outline" className="text-[10px] font-mono">{i + 1}</Badge>
                        {ip}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground text-center py-4">No source IPs captured</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  Top Destination IPs
                </CardTitle>
              </CardHeader>
              <CardContent>
                {captureData.topDestIPs?.length ? (
                  <div className="space-y-1.5">
                    {captureData.topDestIPs.map((ip, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded-md bg-muted/30 text-sm font-mono" data-testid={`text-dest-ip-${i}`}>
                        <Badge variant="outline" className="text-[10px] font-mono">{i + 1}</Badge>
                        {ip}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground text-center py-4">No destination IPs captured</p>
                )}
              </CardContent>
            </Card>
          </div>

          {captureData.dnsQueries?.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <Globe className="w-4 h-4" />
                  DNS Queries
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  {captureData.dnsQueries.map((query, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded-md bg-muted/30 text-xs font-mono truncate" data-testid={`text-dns-query-${i}`}>
                      <Globe className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                      <span className="truncate">{query}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {captureData.suspiciousConnections?.length > 0 && (
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-base flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                  Suspicious Connections
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {captureData.suspiciousConnections.map((conn, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between gap-3 p-3 rounded-md border border-red-500/30 bg-red-500/5 flex-wrap"
                      data-testid={`row-suspicious-${i}`}
                    >
                      <div className="flex items-center gap-3 flex-wrap">
                        <AlertTriangle className="w-4 h-4 text-red-500 flex-shrink-0" />
                        <span className="text-sm font-mono font-medium">{conn.ip}</span>
                        <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30 text-[10px]">
                          Port {conn.port}
                        </Badge>
                      </div>
                      <span className="text-xs text-red-400">{conn.reason}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {agentId && !capturesLoading && captures && captures.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Capture History
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm" data-testid="table-capture-history">
                <thead>
                  <tr className="border-b border-border text-left">
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">Timestamp</th>
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">Status</th>
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">Packets</th>
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">TCP</th>
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">UDP</th>
                    <th className="py-2 pe-4 text-xs text-muted-foreground font-medium">Suspicious</th>
                  </tr>
                </thead>
                <tbody>
                  {captures.map((capture, i) => {
                    const data = normalizeCaptureData(capture.captureData);
                    return (
                      <tr key={capture.id} className="border-b border-border/50" data-testid={`row-capture-${capture.id}`}>
                        <td className="py-2 pe-4 text-xs">{new Date(capture.createdAt).toLocaleString()}</td>
                        <td className="py-2 pe-4">
                          <Badge variant="default">{capture.duration}s</Badge>
                        </td>
                        <td className="py-2 pe-4 font-mono text-xs">{data?.totalPackets?.toLocaleString() || capture.packetCount?.toLocaleString() || "—"}</td>
                        <td className="py-2 pe-4 font-mono text-xs">{data?.protocols?.tcp?.toLocaleString() || "—"}</td>
                        <td className="py-2 pe-4 font-mono text-xs">{data?.protocols?.udp?.toLocaleString() || "—"}</td>
                        <td className="py-2 pe-4">
                          {data?.suspiciousConnections?.length ? (
                            <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-[10px]">
                              {data.suspiciousConnections.length}
                            </Badge>
                          ) : (
                            <span className="text-xs text-muted-foreground">0</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {agentId && !capturesLoading && (!captures || captures.length === 0) && (
        <Card>
          <CardContent className="py-12 text-center text-muted-foreground">
            <Radio className="w-10 h-10 mx-auto mb-3 opacity-40" />
            <p data-testid="text-no-captures">No captures yet. Start a packet capture to analyze traffic.</p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
