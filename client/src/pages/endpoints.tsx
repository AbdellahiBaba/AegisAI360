import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Monitor, Cpu, MemoryStick, Wifi, WifiOff, Terminal, Send, RefreshCw, Clock } from "lucide-react";
import { useLocation } from "wouter";

const COMMANDS = [
  { value: "run_system_scan", label: "System Scan" },
  { value: "list_processes", label: "List Processes" },
  { value: "scan_directory", label: "Scan Directory" },
  { value: "ping", label: "Ping Test" },
  { value: "kill_process", label: "Kill Process" },
  { value: "isolate_network", label: "Isolate Network" },
  { value: "restore_network", label: "Restore Network" },
];

export default function Endpoints() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [, navigate] = useLocation();
  const [selectedAgent, setSelectedAgent] = useState<number | null>(null);
  const [command, setCommand] = useState("");
  const [params, setParams] = useState("");

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
                  <div className="flex items-center justify-between">
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
                  <div className="flex items-center justify-between">
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
                        <div key={cmd.id} className="flex items-center justify-between p-2 bg-muted/50 rounded text-sm" data-testid={`row-command-${cmd.id}`}>
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
