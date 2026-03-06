import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Crosshair, Target, Shield } from "lucide-react";

interface AttackMapData {
  techniques: { techniqueId: string; tactic: string; count: number }[];
  totalEvents: number;
}

const TACTICS_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

const techniqueNames: Record<string, string> = {
  T1078: "Valid Accounts",
  T1059: "Command & Scripting Interpreter",
  T1021: "Remote Services",
  T1048: "Exfiltration Over Alt Protocol",
  T1190: "Exploit Public-Facing App",
  T1566: "Phishing",
  T1071: "Application Layer Protocol",
  T1486: "Data Encrypted for Impact",
  T1053: "Scheduled Task/Job",
  T1055: "Process Injection",
  T1003: "OS Credential Dumping",
  T1027: "Obfuscated Files/Info",
  T1046: "Network Service Discovery",
  T1567: "Exfil Over Web Service",
  T1189: "Drive-by Compromise",
  T1091: "Replication Through Media",
  T1548: "Abuse Elevation Control",
  T1210: "Exploitation of Remote Services",
  T1595: "Active Scanning",
};

function getHeatColor(count: number, max: number) {
  if (count === 0) return "bg-muted";
  const intensity = count / max;
  if (intensity >= 0.7) return "bg-severity-critical";
  if (intensity >= 0.4) return "bg-severity-high";
  if (intensity >= 0.2) return "bg-severity-medium";
  return "bg-primary/40";
}

function getHeatTextColor(count: number, max: number) {
  if (count === 0) return "text-muted-foreground";
  const intensity = count / max;
  if (intensity >= 0.4) return "text-white";
  return "text-foreground";
}

export default function AttackMap() {
  const { data, isLoading } = useQuery<AttackMapData>({
    queryKey: ["/api/attack-map/stats"],
    refetchInterval: 15000,
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <div className="grid gap-3"><Skeleton className="h-[500px] w-full" /></div>
      </div>
    );
  }

  const techniques = data?.techniques || [];
  const maxCount = Math.max(...techniques.map((t) => t.count), 1);
  const tacticGroups: Record<string, typeof techniques> = {};
  for (const t of techniques) {
    if (!tacticGroups[t.tactic]) tacticGroups[t.tactic] = [];
    tacticGroups[t.tactic].push(t);
  }

  const totalTechniques = techniques.length;
  const coveredTactics = Object.keys(tacticGroups).length;
  const topTechnique = techniques.sort((a, b) => b.count - a.count)[0];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase">MITRE ATT&CK Heatmap</h1>
        <p className="text-xs text-muted-foreground">Technique coverage and detection frequency across the ATT&CK matrix</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Total Events</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-events">{data?.totalEvents || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Techniques Detected</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-techniques">{totalTechniques}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Tactics Covered</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-tactics">{coveredTactics}/{TACTICS_ORDER.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Top Technique</span>
          <p className="text-sm font-bold font-mono mt-1 text-severity-critical" data-testid="stat-top-technique">
            {topTechnique ? `${topTechnique.techniqueId} (${topTechnique.count})` : "N/A"}
          </p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <Target className="w-4 h-4 text-primary" />ATT&CK Matrix Coverage
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="w-full">
            <div className="min-w-[800px]">
              <div className="grid gap-1">
                {TACTICS_ORDER.map((tactic) => {
                  const tacticTechniques = tacticGroups[tactic] || [];
                  return (
                    <div key={tactic} className="flex items-stretch gap-1" data-testid={`tactic-row-${tactic.toLowerCase().replace(/\s+/g, '-')}`}>
                      <div className="w-44 flex-shrink-0 flex items-center px-2 py-1.5 bg-muted rounded text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                        {tactic}
                      </div>
                      <div className="flex-1 flex flex-wrap gap-1">
                        {tacticTechniques.length > 0 ? (
                          tacticTechniques.map((t) => (
                            <div
                              key={t.techniqueId}
                              className={`px-2 py-1.5 rounded cursor-default transition-all hover:ring-1 hover:ring-primary ${getHeatColor(t.count, maxCount)}`}
                              title={`${t.techniqueId}: ${techniqueNames[t.techniqueId] || t.techniqueId}\nDetections: ${t.count}`}
                              data-testid={`technique-cell-${t.techniqueId}`}
                            >
                              <div className={`text-[10px] font-mono font-bold ${getHeatTextColor(t.count, maxCount)}`}>
                                {t.techniqueId}
                              </div>
                              <div className={`text-[9px] ${getHeatTextColor(t.count, maxCount)} opacity-80`}>
                                {t.count}
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="px-2 py-1.5 rounded bg-muted/50 text-[10px] text-muted-foreground italic flex items-center">
                            No detections
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-primary" />Detection Frequency
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px]">
              <div className="space-y-2">
                {techniques.sort((a, b) => b.count - a.count).map((t) => (
                  <div key={t.techniqueId} className="flex items-center gap-3" data-testid={`freq-row-${t.techniqueId}`}>
                    <span className="text-xs font-mono font-bold w-14 flex-shrink-0 text-primary">{t.techniqueId}</span>
                    <div className="flex-1">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-[11px] truncate">{techniqueNames[t.techniqueId] || t.techniqueId}</span>
                        <span className="text-[10px] font-mono text-muted-foreground ml-2">{t.count}</span>
                      </div>
                      <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
                        <div
                          className={`h-full rounded-full ${getHeatColor(t.count, maxCount)}`}
                          style={{ width: `${(t.count / maxCount) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />Mitigation Recommendations
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px]">
              <div className="space-y-3">
                {techniques.sort((a, b) => b.count - a.count).slice(0, 5).map((t) => (
                  <div key={t.techniqueId} className="p-3 rounded-md bg-muted/50 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="secondary" className="text-[10px] font-mono">{t.techniqueId}</Badge>
                      <span className="text-xs font-medium">{techniqueNames[t.techniqueId] || t.techniqueId}</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      Tactic: {t.tactic} · Detected {t.count} time{t.count !== 1 ? "s" : ""}. Review detection rules and ensure endpoint coverage for this technique.
                    </p>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex items-center gap-4 flex-wrap">
            <span className="text-xs text-muted-foreground uppercase tracking-wider">Heat Scale:</span>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-muted" /> <span className="text-[10px] text-muted-foreground">None</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-primary/40" /> <span className="text-[10px] text-muted-foreground">Low</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-medium" /> <span className="text-[10px] text-muted-foreground">Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-high" /> <span className="text-[10px] text-muted-foreground">High</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-critical" /> <span className="text-[10px] text-muted-foreground">Critical</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
