import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState, useRef, useEffect } from "react";
import { useParams, useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Terminal, ArrowLeft, AlertTriangle, Send } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface TerminalEntry {
  id: number;
  command: string;
  status: string;
  result?: string;
  timestamp: string;
}

export default function AgentTerminal() {
  useDocumentTitle("Agent Terminal");
  const params = useParams<{ agentId: string }>();
  const agentId = parseInt(params.agentId || "0");
  const [, navigate] = useLocation();
  const { toast } = useToast();
  const [input, setInput] = useState("");
  const [entries, setEntries] = useState<TerminalEntry[]>([]);
  const outputRef = useRef<HTMLDivElement>(null);

  const { data: agent, isLoading } = useQuery<any>({
    queryKey: ["/api/agent", agentId],
    enabled: !!agentId,
  });

  const { data: cmdHistory } = useQuery<any[]>({
    queryKey: ["/api/agent", agentId, "commands"],
    enabled: !!agentId,
    refetchInterval: 3000,
  });

  useEffect(() => {
    if (cmdHistory) {
      const terminalCmds = cmdHistory
        .filter((c: any) => c.command === "terminal_exec")
        .map((c: any) => ({
          id: c.id,
          command: c.params ? JSON.parse(c.params).cmd : "",
          status: c.status,
          result: c.result,
          timestamp: c.createdAt,
        }))
        .reverse();
      setEntries(terminalCmds);
    }
  }, [cmdHistory]);

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [entries]);

  const executeMutation = useMutation({
    mutationFn: async (command: string) => {
      const res = await apiRequest("POST", "/api/agent/terminal/execute", { agentId, command });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/agent", agentId, "commands"] });
    },
    onError: (error: any) => {
      let msg = "Command failed";
      try { msg = JSON.parse(error.message.split(": ").slice(1).join(": ")).error || msg; } catch {}
      toast({ title: "Error", description: msg, variant: "destructive" });
    },
  });

  const handleSubmit = () => {
    const cmd = input.trim();
    if (!cmd) return;
    executeMutation.mutate(cmd);
    setInput("");
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4 max-w-5xl mx-auto">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Button size="sm" variant="ghost" onClick={() => navigate("/endpoints")} data-testid="button-back-endpoints">
            <ArrowLeft className="w-4 h-4" />
          </Button>
          <div>
            <h1 className="text-xl font-bold flex items-center gap-2" data-testid="text-terminal-title">
              <Terminal className="w-5 h-5" />
              Terminal: {agent?.hostname || "Agent"}
            </h1>
            <p className="text-xs text-muted-foreground">{agent?.os} - {agent?.ip}</p>
          </div>
        </div>
        <Badge className={agent?.status === "online" ? "bg-green-600" : "bg-red-600"}>
          {agent?.status}
        </Badge>
      </div>

      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 flex items-center gap-2 text-sm text-yellow-700 dark:text-yellow-400" data-testid="banner-terminal-warning">
        <AlertTriangle className="w-4 h-4 shrink-0" />
        All commands are logged and audited. Destructive commands are blocked.
      </div>

      <Card className="bg-gray-950 text-green-400 border-gray-800" data-testid="card-terminal">
        <CardHeader className="pb-2 border-b border-gray-800">
          <CardTitle className="text-sm font-mono text-gray-400 flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            {agent?.hostname}@aegis ~ $
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div ref={outputRef} className="font-mono text-xs p-4 min-h-[400px] max-h-[500px] overflow-y-auto space-y-2" data-testid="container-terminal-output">
            {entries.length === 0 && (
              <div className="text-gray-500">Ready. Type a command and press Enter.</div>
            )}
            {entries.map((entry) => (
              <div key={entry.id} className="space-y-1" data-testid={`terminal-entry-${entry.id}`}>
                <div className="flex items-center gap-2">
                  <span className="text-cyan-400">$</span>
                  <span className="text-green-300">{entry.command}</span>
                  <Badge variant="outline" className={`text-[10px] ${entry.status === "done" ? "text-green-400 border-green-700" : entry.status === "failed" ? "text-red-400 border-red-700" : "text-yellow-400 border-yellow-700"}`}>
                    {entry.status}
                  </Badge>
                </div>
                {entry.result && (
                  <pre className="text-gray-300 whitespace-pre-wrap ps-6">{entry.result}</pre>
                )}
                {entry.status === "pending" && (
                  <div className="ps-6 text-yellow-500 flex items-center gap-1">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Waiting for agent response...
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="border-t border-gray-800 p-3">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-mono text-sm">$</span>
              <Input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") handleSubmit(); }}
                placeholder="Enter command..."
                className="bg-transparent border-none text-green-400 font-mono text-sm focus-visible:ring-0 placeholder:text-gray-600"
                disabled={executeMutation.isPending || agent?.status !== "online"}
                data-testid="input-terminal-command"
              />
              <Button size="sm" variant="ghost" onClick={handleSubmit} disabled={executeMutation.isPending || !input.trim()} className="text-green-400 hover:text-green-300" data-testid="button-terminal-send">
                <Send className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
