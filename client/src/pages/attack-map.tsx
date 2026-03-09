import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useTranslation } from "react-i18next";
import { Crosshair, Target, Shield } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

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
  useDocumentTitle("Attack Map");
  const { t } = useTranslation();
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
        <h1 className="text-lg font-bold tracking-wider uppercase">{t("attackMap.title")}</h1>
        <p className="text-xs text-muted-foreground">{t("attackMap.subtitle")}</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("attackMap.totalEvents")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-events">{data?.totalEvents || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("attackMap.techniquesDetected")}</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-techniques">{totalTechniques}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("attackMap.tacticsCovered")}</span>
          <p className="text-2xl font-bold font-mono text-primary mt-1" data-testid="stat-tactics">{coveredTactics}/{TACTICS_ORDER.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("attackMap.topTechnique")}</span>
          <p className="text-sm font-bold font-mono mt-1 text-severity-critical" data-testid="stat-top-technique">
            {topTechnique ? `${topTechnique.techniqueId} (${topTechnique.count})` : t("common.noData")}
          </p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <Target className="w-4 h-4 text-primary" />{t("attackMap.matrixCoverage")}
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
                            {t("attackMap.noDetections")}
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
              <Crosshair className="w-4 h-4 text-primary" />{t("attackMap.detectionFrequency")}
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
                        <span className="text-[10px] font-mono text-muted-foreground ms-2">{t.count}</span>
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
              <Shield className="w-4 h-4 text-primary" />{t("attackMap.mitigationRecs")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[300px]">
              <div className="space-y-3">
                {techniques.sort((a, b) => b.count - a.count).slice(0, 5).map((tech) => (
                  <div key={tech.techniqueId} className="p-3 rounded-md bg-muted/50 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="secondary" className="text-[10px] font-mono">{tech.techniqueId}</Badge>
                      <span className="text-xs font-medium">{techniqueNames[tech.techniqueId] || tech.techniqueId}</span>
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      {t("attackMap.tacticLabel")}: {tech.tactic} · {t("attackMap.detectedTimes", { count: tech.count })}
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
            <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("attackMap.heatScale")}:</span>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-muted" /> <span className="text-[10px] text-muted-foreground">{t("common.none")}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-primary/40" /> <span className="text-[10px] text-muted-foreground">{t("common.low")}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-medium" /> <span className="text-[10px] text-muted-foreground">{t("common.medium")}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-high" /> <span className="text-[10px] text-muted-foreground">{t("common.high")}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-severity-critical" /> <span className="text-[10px] text-muted-foreground">{t("common.critical")}</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
