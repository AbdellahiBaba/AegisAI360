import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import {
  Eye, Search, AlertTriangle, ShieldAlert, ShieldCheck, Globe, Mail,
  Calendar, Users, Lock, Loader2, ChevronDown, ChevronUp, ExternalLink, Download,
} from "lucide-react";
import { generateDarkWebReportPDF } from "@/lib/reportGenerator";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface BreachResult {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  severity: "critical" | "high" | "medium" | "low";
  riskScore: number;
  recommendations: string[];
  logoPath: string | null;
}

interface DarkWebCheckResult {
  query: string;
  queryType: "domain" | "email";
  totalBreaches: number;
  totalExposedRecords: number;
  overallRiskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low" | "none";
  breaches: BreachResult[];
  exposedDataTypes: { type: string; count: number }[];
  timeline: { date: string; breachName: string; records: number }[];
  recommendations: string[];
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  none: "bg-green-500/10 text-green-400 border-green-500/20",
};

const riskLevelLabels: Record<string, string> = {
  critical: "Critical Risk",
  high: "High Risk",
  medium: "Medium Risk",
  low: "Low Risk",
  none: "No Breaches Found",
};

function formatNumber(n: number): string {
  if (n >= 1000000000) return (n / 1000000000).toFixed(1) + "B";
  if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
  if (n >= 1000) return (n / 1000).toFixed(1) + "K";
  return n.toString();
}

function RiskScoreCircle({ score, size = 120 }: { score: number; size?: number }) {
  const radius = (size - 12) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  let color = "text-green-400";
  if (score >= 80) color = "text-red-400";
  else if (score >= 60) color = "text-orange-400";
  else if (score >= 40) color = "text-yellow-400";
  else if (score > 0) color = "text-blue-400";

  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg className="transform -rotate-90" width={size} height={size}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth="6"
          fill="none"
          className="text-muted/30"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          stroke="currentColor"
          strokeWidth="6"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={color}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-2xl font-bold font-mono ${color}`} data-testid="text-risk-score">{score}</span>
        <span className="text-[9px] text-muted-foreground uppercase tracking-wider">Risk</span>
      </div>
    </div>
  );
}

function BreachCard({ breach }: { breach: BreachResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <Card data-testid={`card-breach-${breach.name}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-semibold text-sm" data-testid={`text-breach-name-${breach.name}`}>{breach.title}</h3>
              <Badge className={severityColors[breach.severity]} data-testid={`badge-severity-${breach.name}`}>
                {breach.severity.toUpperCase()}
              </Badge>
              {breach.isVerified && (
                <Badge variant="secondary" className="text-[10px]">Verified</Badge>
              )}
            </div>
            <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
              <span className="flex items-center gap-1">
                <Calendar className="w-3 h-3" />
                {new Date(breach.breachDate).toLocaleDateString()}
              </span>
              <span className="flex items-center gap-1">
                <Users className="w-3 h-3" />
                {formatNumber(breach.pwnCount)} records
              </span>
              {breach.domain && (
                <span className="flex items-center gap-1">
                  <Globe className="w-3 h-3" />
                  {breach.domain}
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="text-right">
              <div className="text-lg font-bold font-mono" data-testid={`text-breach-risk-${breach.name}`}>{breach.riskScore}</div>
              <div className="text-[9px] text-muted-foreground uppercase">Risk Score</div>
            </div>
            <Button
              variant="ghost"
              size="icon"
              onClick={() => setExpanded(!expanded)}
              data-testid={`button-expand-breach-${breach.name}`}
            >
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap gap-1 mt-2">
          {breach.dataClasses.map((dc) => (
            <Badge key={dc} variant="outline" className="text-[10px]">{dc}</Badge>
          ))}
        </div>

        {expanded && (
          <div className="mt-4 space-y-3 border-t pt-3">
            <div>
              <h4 className="text-xs font-semibold mb-1">Description</h4>
              <p className="text-xs text-muted-foreground">{breach.description?.replace(/<[^>]*>/g, '')}</p>
            </div>
            <div>
              <h4 className="text-xs font-semibold mb-1">Recommended Actions</h4>
              <ul className="space-y-1">
                {breach.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-muted-foreground">
                    <ShieldCheck className="w-3 h-3 mt-0.5 text-primary flex-shrink-0" />
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function DarkWebMonitor() {
  useDocumentTitle("Dark Web Monitor");
  const [searchQuery, setSearchQuery] = useState("");
  const [searchType, setSearchType] = useState<"domain" | "email">("domain");
  const [result, setResult] = useState<DarkWebCheckResult | null>(null);
  const { toast } = useToast();

  const { data: recentBreaches, isLoading: loadingBreaches } = useQuery<BreachResult[]>({
    queryKey: ["/api/darkweb/breaches"],
  });

  const checkMutation = useMutation({
    mutationFn: async () => {
      const endpoint = searchType === "domain" ? "/api/darkweb/check-domain" : "/api/darkweb/check-email";
      const res = await apiRequest("POST", endpoint, { query: searchQuery });
      return res.json();
    },
    onSuccess: (data: DarkWebCheckResult) => {
      setResult(data);
      if (data.totalBreaches > 0) {
        toast({
          title: "Exposure Detected",
          description: `Found ${data.totalBreaches} breach(es) affecting ${data.query}`,
          variant: "destructive",
        });
      } else {
        toast({
          title: "No Breaches Found",
          description: `No known breaches found for ${data.query}`,
        });
      }
    },
    onError: () => {
      toast({
        title: "Search Failed",
        description: "Could not complete the dark web check. Please try again.",
        variant: "destructive",
      });
    },
  });

  const handleSearch = () => {
    if (!searchQuery.trim()) return;
    checkMutation.mutate();
  };

  return (
    <div className="p-4 space-y-4 max-w-7xl mx-auto">
      <div className="flex items-center gap-3 flex-wrap">
        <Eye className="w-5 h-5 text-primary" />
        <div>
          <h1 className="text-lg font-bold" data-testid="text-page-title">Dark Web Monitor</h1>
          <p className="text-xs text-muted-foreground">Detect credential exposure in known data breaches</p>
        </div>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex gap-1">
              <Button
                variant={searchType === "domain" ? "default" : "outline"}
                size="sm"
                onClick={() => setSearchType("domain")}
                data-testid="button-search-domain"
              >
                <Globe className="w-3.5 h-3.5 mr-1" />
                Domain
              </Button>
              <Button
                variant={searchType === "email" ? "default" : "outline"}
                size="sm"
                onClick={() => setSearchType("email")}
                data-testid="button-search-email"
              >
                <Mail className="w-3.5 h-3.5 mr-1" />
                Email
              </Button>
            </div>
            <div className="flex-1 flex gap-2">
              <Input
                placeholder={searchType === "domain" ? "Enter domain (e.g., example.com)" : "Enter email address"}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="flex-1"
                data-testid="input-search-query"
              />
              <Button
                onClick={handleSearch}
                disabled={checkMutation.isPending || !searchQuery.trim()}
                data-testid="button-search"
              >
                {checkMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Search className="w-4 h-4" />
                )}
                <span className="ml-1.5">Check</span>
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {checkMutation.isPending && (
        <div className="space-y-3">
          <Skeleton className="h-32 w-full" />
          <Skeleton className="h-24 w-full" />
        </div>
      )}

      {result && !checkMutation.isPending && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={async () => { await generateDarkWebReportPDF(result); }}
              data-testid="button-export-darkweb-pdf"
            >
              <Download className="w-3.5 h-3.5 me-1.5" />
              Export PDF
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="md:col-span-1">
              <CardContent className="p-4 flex flex-col items-center justify-center">
                <RiskScoreCircle score={result.overallRiskScore} />
                <Badge className={`mt-2 ${severityColors[result.riskLevel]}`} data-testid="badge-risk-level">
                  {riskLevelLabels[result.riskLevel]}
                </Badge>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-1">
                  <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Total Breaches</span>
                </div>
                <div className="text-2xl font-bold font-mono" data-testid="text-total-breaches">{result.totalBreaches}</div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Users className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Exposed Records</span>
                </div>
                <div className="text-2xl font-bold font-mono" data-testid="text-exposed-records">{formatNumber(result.totalExposedRecords)}</div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-1">
                  <Lock className="w-4 h-4 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Data Types Exposed</span>
                </div>
                <div className="text-2xl font-bold font-mono" data-testid="text-data-types">{result.exposedDataTypes.length}</div>
              </CardContent>
            </Card>
          </div>

          <Tabs defaultValue="breaches">
            <TabsList>
              <TabsTrigger value="breaches" data-testid="tab-breaches">
                Breaches ({result.breaches.length})
              </TabsTrigger>
              <TabsTrigger value="timeline" data-testid="tab-timeline">
                Timeline
              </TabsTrigger>
              <TabsTrigger value="data-types" data-testid="tab-data-types">
                Data Types
              </TabsTrigger>
              <TabsTrigger value="recommendations" data-testid="tab-recommendations">
                Remediation
              </TabsTrigger>
            </TabsList>

            <TabsContent value="breaches" className="space-y-3 mt-3">
              {result.breaches
                .sort((a, b) => b.riskScore - a.riskScore)
                .map((breach) => (
                  <BreachCard key={breach.name} breach={breach} />
                ))}
              {result.breaches.length === 0 && (
                <Card>
                  <CardContent className="p-8 text-center">
                    <ShieldCheck className="w-12 h-12 mx-auto text-green-400 mb-3" />
                    <h3 className="font-semibold" data-testid="text-no-breaches">No Breaches Found</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      No known data breaches were found for this {result.queryType}.
                    </p>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="timeline" className="mt-3">
              <Card>
                <CardContent className="p-4">
                  {result.timeline.length > 0 ? (
                    <div className="space-y-3">
                      {result.timeline.map((event, i) => (
                        <div key={i} className="flex items-center gap-4" data-testid={`timeline-event-${i}`}>
                          <div className="flex flex-col items-center">
                            <div className="w-2.5 h-2.5 rounded-full bg-primary" />
                            {i < result.timeline.length - 1 && <div className="w-px h-8 bg-border" />}
                          </div>
                          <div className="flex-1 flex items-center justify-between gap-2 flex-wrap">
                            <div>
                              <span className="text-sm font-medium">{event.breachName}</span>
                              <span className="text-xs text-muted-foreground ml-2">
                                {new Date(event.date).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}
                              </span>
                            </div>
                            <Badge variant="secondary" className="text-[10px]">{formatNumber(event.records)} records</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground text-center py-4">No timeline data available</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="data-types" className="mt-3">
              <Card>
                <CardContent className="p-4 space-y-3">
                  {result.exposedDataTypes.map((dt) => (
                    <div key={dt.type} data-testid={`datatype-${dt.type}`}>
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="text-sm">{dt.type}</span>
                        <span className="text-xs text-muted-foreground font-mono">
                          {dt.count} breach{dt.count !== 1 ? "es" : ""}
                        </span>
                      </div>
                      <Progress value={(dt.count / result.totalBreaches) * 100} className="h-1.5" />
                    </div>
                  ))}
                  {result.exposedDataTypes.length === 0 && (
                    <p className="text-sm text-muted-foreground text-center py-4">No data types exposed</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="recommendations" className="mt-3">
              <Card>
                <CardContent className="p-4">
                  <ul className="space-y-2">
                    {result.recommendations.map((rec, i) => (
                      <li key={i} className="flex items-start gap-2" data-testid={`recommendation-${i}`}>
                        <AlertTriangle className="w-4 h-4 mt-0.5 text-primary flex-shrink-0" />
                        <span className="text-sm">{rec}</span>
                      </li>
                    ))}
                  </ul>
                  {result.recommendations.length === 0 && (
                    <p className="text-sm text-muted-foreground text-center py-4">No recommendations at this time</p>
                  )}
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      )}

      {!result && !checkMutation.isPending && (
        <div>
          <h2 className="text-sm font-semibold mb-3">Recent Known Breaches</h2>
          {loadingBreaches ? (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-20 w-full" />
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {(recentBreaches || []).slice(0, 10).map((breach: BreachResult) => (
                <BreachCard key={breach.name} breach={breach} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
