import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import {
  Play, Shield, Zap, Package, UserX, Bug, Cpu, Wifi,
  Target, Lock, Search, Mail, Database, Skull, Loader2,
} from "lucide-react";

interface Scenario {
  id: string;
  name: string;
  description: string;
  mitre: string[];
}

const SCENARIO_META: Record<string, { icon: typeof Shield; category: string }> = {
  brute_force: { icon: Lock, category: "Credential Attack" },
  ransomware: { icon: Skull, category: "Malware" },
  phishing: { icon: Mail, category: "Social Engineering" },
  port_scan: { icon: Search, category: "Reconnaissance" },
  data_exfil: { icon: Database, category: "Data Theft" },
  apt: { icon: Target, category: "Advanced Threat" },
  supply_chain: { icon: Package, category: "Supply Chain" },
  insider_threat: { icon: UserX, category: "Insider Threat" },
  zero_day: { icon: Bug, category: "Zero-Day" },
  cryptojacking: { icon: Cpu, category: "Cryptojacking" },
  ddos: { icon: Wifi, category: "DDoS" },
};

export default function ThreatSimulationPage() {
  const { toast } = useToast();
  const [runningScenario, setRunningScenario] = useState<string | null>(null);

  const { data: scenarios, isLoading } = useQuery<Scenario[]>({
    queryKey: ["/api/simulate/scenarios"],
  });

  const runSimulation = useMutation({
    mutationFn: async (scenarioId: string) => {
      const res = await apiRequest("POST", `/api/simulate/${scenarioId}`);
      return res.json();
    },
    onMutate: (scenarioId) => {
      setRunningScenario(scenarioId);
    },
    onSuccess: (data, scenarioId) => {
      toast({
        title: "Simulation Started",
        description: `${data.scenario} is generating security events...`,
      });
      setTimeout(() => {
        setRunningScenario(null);
        queryClient.invalidateQueries({ queryKey: ["/api/events"] });
        queryClient.invalidateQueries({ queryKey: ["/api/alerts"] });
        toast({
          title: "Simulation Complete",
          description: `Events have been generated. Check the Security Events page.`,
        });
      }, 5000);
    },
    onError: () => {
      setRunningScenario(null);
      toast({
        title: "Simulation Failed",
        description: "Failed to run the simulation. You may need admin privileges.",
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 overflow-auto h-full">
      <div className="flex items-center gap-3 flex-wrap">
        <Zap className="w-6 h-6 text-primary" />
        <div>
          <h1 className="text-2xl font-bold" data-testid="text-page-title">Threat Simulation</h1>
          <p className="text-sm text-muted-foreground" data-testid="text-page-description">
            Run attack emulations to test your security posture and generate realistic security events
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {scenarios?.map((scenario) => {
          const meta = SCENARIO_META[scenario.id] || { icon: Shield, category: "Attack" };
          const Icon = meta.icon;
          const isRunning = runningScenario === scenario.id;

          return (
            <Card key={scenario.id} data-testid={`card-scenario-${scenario.id}`}>
              <CardHeader className="flex flex-row items-start justify-between gap-2 pb-3">
                <div className="flex items-center gap-3 flex-wrap min-w-0">
                  <div className="flex items-center justify-center w-10 h-10 rounded-md bg-primary/10">
                    <Icon className="w-5 h-5 text-primary" />
                  </div>
                  <div className="min-w-0">
                    <CardTitle className="text-base" data-testid={`text-scenario-name-${scenario.id}`}>
                      {scenario.name}
                    </CardTitle>
                    <Badge variant="secondary" className="mt-1" data-testid={`badge-category-${scenario.id}`}>
                      {meta.category}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground" data-testid={`text-scenario-desc-${scenario.id}`}>
                  {scenario.description}
                </p>

                {scenario.mitre && scenario.mitre.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-xs font-medium text-muted-foreground">MITRE ATT&CK Techniques</p>
                    <div className="flex flex-wrap gap-1">
                      {scenario.mitre.map((technique) => (
                        <Badge
                          key={technique}
                          variant="outline"
                          className="text-xs font-mono"
                          data-testid={`badge-mitre-${scenario.id}-${technique}`}
                        >
                          {technique}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <Button
                  className="w-full"
                  onClick={() => runSimulation.mutate(scenario.id)}
                  disabled={isRunning || runningScenario !== null}
                  data-testid={`button-run-${scenario.id}`}
                >
                  {isRunning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      Running...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      Run Simulation
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
