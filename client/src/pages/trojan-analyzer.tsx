import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Bug, Loader2, Search, Shield, FileCode, Database, Copy, Check,
  AlertTriangle, Activity, Globe, Server, FolderOpen, Hash,
  ChevronRight, Eye, Download, Users, Target, Crosshair,
  Grid3X3, Mail, Link, FileText,
} from "lucide-react";
import { generateTrojanAnalysisReportPDF } from "@/lib/reportGenerator";

const severityColor: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-muted text-muted-foreground",
};

const categoryColor: Record<string, string> = {
  RAT: "bg-severity-critical text-white",
  Banking: "bg-severity-high text-white",
  Stealer: "bg-severity-medium text-black",
  Mobile: "bg-primary text-primary-foreground",
  Cryptominer: "bg-severity-low text-white",
  C2: "bg-severity-critical text-white",
  Loader: "bg-severity-high text-white",
  Ransomware: "bg-severity-critical text-white",
  Worm: "bg-severity-high text-white",
  Rootkit: "bg-severity-critical text-white",
};

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={handleCopy}
      data-testid="button-copy-code"
    >
      {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
    </Button>
  );
}

function CodeBlock({ code, title }: { code: string; title: string }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span className="text-xs font-medium">{title}</span>
        <CopyButton text={code} />
      </div>
      <pre className="p-3 rounded-md bg-muted/50 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-all max-h-96 overflow-y-auto" data-testid={`code-block-${title.toLowerCase().replace(/\s+/g, "-")}`}>
        {code}
      </pre>
    </div>
  );
}

function HashLookupTab() {
  const { toast } = useToast();
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<any>(null);

  const mutation = useMutation({
    mutationFn: async (hashValue: string) => {
      const res = await apiRequest("POST", "/api/trojan/lookup", { hash: hashValue });
      return res.json();
    },
    onSuccess: (data) => setResult(data),
    onError: () => toast({ title: "Hash lookup failed", variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="Enter MD5, SHA1, or SHA256 hash..."
            className="ps-9 font-mono text-xs"
            data-testid="input-trojan-hash"
            onKeyDown={(e) => e.key === "Enter" && hash.trim() && mutation.mutate(hash.trim())}
          />
        </div>
        <Button
          onClick={() => mutation.mutate(hash.trim())}
          disabled={!hash.trim() || mutation.isPending}
          data-testid="button-trojan-lookup"
        >
          {mutation.isPending ? (
            <><Loader2 className="w-4 h-4 me-2 animate-spin" />Analyzing</>
          ) : (
            <><Search className="w-4 h-4 me-2" />Lookup</>
          )}
        </Button>
      </div>

      {mutation.isPending && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">Querying MalwareBazaar & knowledge base...</span>
          </CardContent>
        </Card>
      )}

      {result && !mutation.isPending && (
        <div className="space-y-3">
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => generateTrojanAnalysisReportPDF(result)}
              data-testid="button-export-trojan-pdf"
            >
              <Download className="w-3.5 h-3.5 me-1.5" />
              Export PDF
            </Button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <Card><CardContent className="p-3 text-center">
              <p className="text-[10px] text-muted-foreground uppercase">Family</p>
              <p className="text-sm font-bold font-mono" data-testid="text-trojan-family">{result.family || "Unknown"}</p>
            </CardContent></Card>
            <Card><CardContent className="p-3 text-center">
              <p className="text-[10px] text-muted-foreground uppercase">Category</p>
              {result.category ? (
                <Badge className={`text-[10px] ${categoryColor[result.category] || "bg-muted text-muted-foreground"}`} data-testid="text-trojan-category">
                  {result.category}
                </Badge>
              ) : (
                <span className="text-sm text-muted-foreground" data-testid="text-trojan-category">N/A</span>
              )}
            </CardContent></Card>
            <Card><CardContent className="p-3 text-center">
              <p className="text-[10px] text-muted-foreground uppercase">Risk Score</p>
              <p className={`text-lg font-bold font-mono ${
                (result.riskScore || 0) >= 80 ? "text-severity-critical" :
                (result.riskScore || 0) >= 60 ? "text-severity-high" :
                (result.riskScore || 0) >= 40 ? "text-severity-medium" : "text-muted-foreground"
              }`} data-testid="text-trojan-risk">{result.riskScore || 0}/100</p>
            </CardContent></Card>
            <Card><CardContent className="p-3 text-center">
              <p className="text-[10px] text-muted-foreground uppercase">Detection</p>
              <p className="text-sm font-mono" data-testid="text-trojan-detection">{result.detectionRate || "N/A"}</p>
            </CardContent></Card>
          </div>

          {result.firstSeen && (
            <Card>
              <CardContent className="p-4 space-y-2">
                <div className="flex justify-between text-xs flex-wrap gap-1"><span className="text-muted-foreground">First Seen</span><span className="font-mono" data-testid="text-trojan-first-seen">{result.firstSeen}</span></div>
                <div className="flex justify-between text-xs flex-wrap gap-1"><span className="text-muted-foreground">Last Seen</span><span className="font-mono" data-testid="text-trojan-last-seen">{result.lastSeen || "N/A"}</span></div>
                {result.description && (
                  <div className="text-xs text-muted-foreground pt-2 border-t" data-testid="text-trojan-description">{result.description}</div>
                )}
              </CardContent>
            </Card>
          )}

          {result.c2Infrastructure && result.c2Infrastructure.length > 0 && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                  <Globe className="w-4 h-4 text-severity-high" />
                  Known C2 Infrastructure
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-1">
                {result.c2Infrastructure.map((c2: string, i: number) => (
                  <div key={i} className="text-xs font-mono p-1.5 rounded bg-muted/50" data-testid={`text-c2-${i}`}>{c2}</div>
                ))}
              </CardContent>
            </Card>
          )}

          {result.mitreTechniques && result.mitreTechniques.length > 0 && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  MITRE ATT&CK Techniques
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3">
                <div className="flex flex-wrap gap-1.5">
                  {result.mitreTechniques.map((tech: any, i: number) => (
                    <Badge key={i} variant="secondary" className="text-[10px] font-mono" data-testid={`badge-mitre-${i}`}>
                      {typeof tech === "string" ? tech : `${tech.id} - ${tech.name}`}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {result.knowledgeBaseMatch && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                  <Database className="w-4 h-4 text-primary" />
                  Knowledge Base Match
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-2">
                {result.knowledgeBaseMatch.aliases && (
                  <div className="flex flex-wrap gap-1">
                    {result.knowledgeBaseMatch.aliases.map((alias: string, i: number) => (
                      <Badge key={i} variant="outline" className="text-[10px]">{alias}</Badge>
                    ))}
                  </div>
                )}
                {result.knowledgeBaseMatch.behaviorProfile && (
                  <p className="text-xs text-muted-foreground">{result.knowledgeBaseMatch.behaviorProfile}</p>
                )}
              </CardContent>
            </Card>
          )}

          {!result.family && !result.malwareBazaarResult && (
            <Card>
              <CardContent className="p-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-severity-medium" />
                <span className="text-xs text-muted-foreground">No matches found in MalwareBazaar or knowledge base for this hash.</span>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function BehaviorAnalysisTab() {
  const { toast } = useToast();
  const [networkConnections, setNetworkConnections] = useState("");
  const [registryMods, setRegistryMods] = useState("");
  const [filePaths, setFilePaths] = useState("");
  const [processNames, setProcessNames] = useState("");
  const [mutexNames, setMutexNames] = useState("");
  const [result, setResult] = useState<any>(null);

  const mutation = useMutation({
    mutationFn: async (indicators: any) => {
      const res = await apiRequest("POST", "/api/trojan/classify", { indicators });
      return res.json();
    },
    onSuccess: (data) => setResult(data),
    onError: () => toast({ title: "Classification failed", variant: "destructive" }),
  });

  const handleSubmit = () => {
    const indicators = {
      networkConnections: networkConnections.split("\n").filter(Boolean),
      registryChanges: registryMods.split("\n").filter(Boolean),
      fileOperations: filePaths.split("\n").filter(Boolean),
      processNames: processNames.split("\n").filter(Boolean),
      mutexNames: mutexNames.split("\n").filter(Boolean),
    };
    mutation.mutate(indicators);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Activity className="w-4 h-4 text-primary" />
            Observed Indicators
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-3">
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
              <Globe className="w-3 h-3" /> Network Connections (one per line)
            </label>
            <Textarea
              value={networkConnections}
              onChange={(e) => setNetworkConnections(e.target.value)}
              placeholder="192.168.1.100:4444&#10;evil-c2.example.com:8080"
              className="font-mono text-xs resize-none"
              rows={3}
              data-testid="input-behavior-network"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
              <FolderOpen className="w-3 h-3" /> Registry Modifications (one per line)
            </label>
            <Textarea
              value={registryMods}
              onChange={(e) => setRegistryMods(e.target.value)}
              placeholder="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware"
              className="font-mono text-xs resize-none"
              rows={3}
              data-testid="input-behavior-registry"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
              <FileCode className="w-3 h-3" /> File Paths Created/Modified (one per line)
            </label>
            <Textarea
              value={filePaths}
              onChange={(e) => setFilePaths(e.target.value)}
              placeholder="C:\Users\victim\AppData\Local\Temp\payload.exe"
              className="font-mono text-xs resize-none"
              rows={3}
              data-testid="input-behavior-files"
            />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
                <Server className="w-3 h-3" /> Process Names (one per line)
              </label>
              <Textarea
                value={processNames}
                onChange={(e) => setProcessNames(e.target.value)}
                placeholder="svchost.exe&#10;rundll32.exe"
                className="font-mono text-xs resize-none"
                rows={3}
                data-testid="input-behavior-processes"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-[11px] text-muted-foreground font-medium flex items-center gap-1.5">
                <Hash className="w-3 h-3" /> Mutex Names (one per line)
              </label>
              <Textarea
                value={mutexNames}
                onChange={(e) => setMutexNames(e.target.value)}
                placeholder="Global\MutexName123"
                className="font-mono text-xs resize-none"
                rows={3}
                data-testid="input-behavior-mutexes"
              />
            </div>
          </div>
          <Button
            onClick={handleSubmit}
            disabled={mutation.isPending}
            data-testid="button-classify-behavior"
          >
            {mutation.isPending ? (
              <><Loader2 className="w-4 h-4 me-2 animate-spin" />Classifying</>
            ) : (
              <><Activity className="w-4 h-4 me-2" />Classify Behavior</>
            )}
          </Button>
        </CardContent>
      </Card>

      {mutation.isPending && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">Analyzing behavioral indicators...</span>
          </CardContent>
        </Card>
      )}

      {result && !mutation.isPending && (
        <div className="space-y-3">
          {result.matchedFamily && (
            <Card>
              <CardContent className="p-4 space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <Bug className="w-4 h-4 text-severity-critical" />
                    <span className="text-sm font-semibold" data-testid="text-matched-family">{result.matchedFamily}</span>
                  </div>
                  <Badge className={`text-[10px] ${
                    (result.confidence || 0) >= 80 ? "bg-severity-critical text-white" :
                    (result.confidence || 0) >= 60 ? "bg-severity-high text-white" :
                    (result.confidence || 0) >= 40 ? "bg-severity-medium text-black" : "bg-muted text-muted-foreground"
                  }`} data-testid="text-confidence">
                    {result.confidence || 0}% Confidence
                  </Badge>
                </div>
                {result.category && (
                  <Badge variant="outline" className="text-[10px]" data-testid="text-behavior-category">{result.category}</Badge>
                )}
                {result.description && (
                  <p className="text-xs text-muted-foreground" data-testid="text-behavior-description">{result.description}</p>
                )}
              </CardContent>
            </Card>
          )}

          {result.matchedIndicators && result.matchedIndicators.length > 0 && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                  <Eye className="w-4 h-4 text-severity-high" />
                  Matched Indicators
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-1">
                {result.matchedIndicators.map((ind: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 p-2 rounded bg-muted/50" data-testid={`matched-indicator-${i}`}>
                    <ChevronRight className="w-3 h-3 mt-0.5 text-severity-high flex-shrink-0" />
                    <div className="min-w-0">
                      <span className="text-xs font-medium">{ind.type || ind.category || "Indicator"}</span>
                      <p className="text-[11px] text-muted-foreground font-mono break-all">{ind.value || ind.indicator || JSON.stringify(ind)}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {result.behavioralBreakdown && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase">Behavioral Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-2">
                {Object.entries(result.behavioralBreakdown).map(([key, val]: [string, any]) => (
                  <div key={key} className="space-y-1">
                    <div className="flex items-center justify-between text-xs flex-wrap gap-1">
                      <span className="text-muted-foreground capitalize">{key.replace(/([A-Z])/g, " $1").trim()}</span>
                      <span className="font-mono font-medium">{typeof val === "number" ? `${val}%` : String(val)}</span>
                    </div>
                    {typeof val === "number" && (
                      <div className="w-full h-1.5 rounded-full bg-muted">
                        <div
                          className={`h-full rounded-full ${val >= 70 ? "bg-severity-critical" : val >= 40 ? "bg-severity-medium" : "bg-primary"}`}
                          style={{ width: `${Math.min(val, 100)}%` }}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </CardContent>
            </Card>
          )}

          {!result.matchedFamily && (
            <Card>
              <CardContent className="p-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-severity-medium" />
                <span className="text-xs text-muted-foreground">No known Trojan family matched the provided indicators.</span>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function DetectionRulesTab() {
  const { toast } = useToast();
  const [selectedFamily, setSelectedFamily] = useState("");
  const [yaraRule, setYaraRule] = useState<string | null>(null);
  const [sigmaRule, setSigmaRule] = useState<string | null>(null);

  const { data: families, isLoading: familiesLoading } = useQuery<any>({
    queryKey: ["/api/trojan/families"],
  });

  const yaraMutation = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/yara-rule", { family });
      return res.json();
    },
    onSuccess: (data) => setYaraRule(data.rule || data.yaraRule || JSON.stringify(data, null, 2)),
    onError: () => toast({ title: "YARA rule generation failed", variant: "destructive" }),
  });

  const sigmaMutation = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/sigma-rule", { family });
      return res.json();
    },
    onSuccess: (data) => setSigmaRule(data.rule || data.sigmaRule || JSON.stringify(data, null, 2)),
    onError: () => toast({ title: "Sigma rule generation failed", variant: "destructive" }),
  });

  const handleGenerate = () => {
    if (!selectedFamily) return;
    setYaraRule(null);
    setSigmaRule(null);
    yaraMutation.mutate(selectedFamily);
    sigmaMutation.mutate(selectedFamily);
  };

  const familyList: string[] = Array.isArray(families) ? families.map((f: any) => typeof f === "string" ? f : f.name || f.family) : [];

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Select value={selectedFamily} onValueChange={setSelectedFamily}>
          <SelectTrigger className="flex-1" data-testid="select-trojan-family-rules">
            <SelectValue placeholder="Select Trojan family..." />
          </SelectTrigger>
          <SelectContent>
            {familiesLoading ? (
              <div className="p-2 text-xs text-muted-foreground">Loading families...</div>
            ) : (
              familyList.map((f) => (
                <SelectItem key={f} value={f}>{f}</SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
        <Button
          onClick={handleGenerate}
          disabled={!selectedFamily || yaraMutation.isPending || sigmaMutation.isPending}
          data-testid="button-generate-rules"
        >
          {yaraMutation.isPending || sigmaMutation.isPending ? (
            <><Loader2 className="w-4 h-4 me-2 animate-spin" />Generating</>
          ) : (
            <><FileCode className="w-4 h-4 me-2" />Generate Rules</>
          )}
        </Button>
      </div>

      {(yaraMutation.isPending || sigmaMutation.isPending) && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">Generating detection rules for {selectedFamily}...</span>
          </CardContent>
        </Card>
      )}

      {yaraRule && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <FileCode className="w-4 h-4 text-primary" />
              YARA Rule
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <CodeBlock code={yaraRule} title="YARA Rule" />
          </CardContent>
        </Card>
      )}

      {sigmaRule && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <FileCode className="w-4 h-4 text-primary" />
              Sigma Rule
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <CodeBlock code={sigmaRule} title="Sigma Rule" />
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function IOCExplorerTab() {
  const { toast } = useToast();
  const [selectedFamily, setSelectedFamily] = useState("");
  const [iocs, setIocs] = useState<any>(null);

  const { data: families, isLoading: familiesLoading } = useQuery<any>({
    queryKey: ["/api/trojan/families"],
  });

  const mutation = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/iocs", { family });
      return res.json();
    },
    onSuccess: (data) => setIocs(data),
    onError: () => toast({ title: "IOC extraction failed", variant: "destructive" }),
  });

  const familyList: string[] = Array.isArray(families) ? families.map((f: any) => typeof f === "string" ? f : f.name || f.family) : [];

  const iocTypeIcons: Record<string, React.ElementType> = {
    ips: Globe,
    domains: Globe,
    fileHashes: Hash,
    hashes: Hash,
    mutexes: Server,
    registryKeys: FolderOpen,
    filePaths: FileCode,
    networkSignatures: Activity,
    c2Ports: Server,
  };

  const exportIOCs = () => {
    if (!iocs) return;
    const text = JSON.stringify(iocs, null, 2);
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedFamily}-iocs.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Select value={selectedFamily} onValueChange={setSelectedFamily}>
          <SelectTrigger className="flex-1" data-testid="select-trojan-family-iocs">
            <SelectValue placeholder="Select Trojan family..." />
          </SelectTrigger>
          <SelectContent>
            {familiesLoading ? (
              <div className="p-2 text-xs text-muted-foreground">Loading families...</div>
            ) : (
              familyList.map((f) => (
                <SelectItem key={f} value={f}>{f}</SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
        <Button
          onClick={() => mutation.mutate(selectedFamily)}
          disabled={!selectedFamily || mutation.isPending}
          data-testid="button-extract-iocs"
        >
          {mutation.isPending ? (
            <><Loader2 className="w-4 h-4 me-2 animate-spin" />Extracting</>
          ) : (
            <><Database className="w-4 h-4 me-2" />Extract IOCs</>
          )}
        </Button>
      </div>

      {mutation.isPending && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">Extracting IOCs for {selectedFamily}...</span>
          </CardContent>
        </Card>
      )}

      {iocs && !mutation.isPending && (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground">
              IOCs for <span className="font-semibold text-foreground">{selectedFamily}</span>
            </span>
            <Button variant="outline" size="sm" onClick={exportIOCs} data-testid="button-export-iocs">
              <Copy className="w-3.5 h-3.5 me-1.5" />
              Export JSON
            </Button>
          </div>

          {Object.entries(iocs).map(([type, values]: [string, any]) => {
            if (!values || (Array.isArray(values) && values.length === 0)) return null;
            const IconComp = iocTypeIcons[type] || Database;
            const items = Array.isArray(values) ? values : [values];
            if (items.length === 0) return null;

            return (
              <Card key={type}>
                <CardHeader className="pb-2 pt-3 px-4">
                  <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                    <IconComp className="w-4 h-4 text-primary" />
                    {type.replace(/([A-Z])/g, " $1").trim()}
                    <Badge variant="secondary" className="text-[10px] ml-auto">{items.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="px-4 pb-3">
                  <div className="space-y-1 max-h-60 overflow-y-auto">
                    {items.map((val: any, i: number) => (
                      <div key={i} className="text-xs font-mono p-1.5 rounded bg-muted/50 break-all" data-testid={`ioc-${type}-${i}`}>
                        {typeof val === "string" ? val : JSON.stringify(val)}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}

function IOCExtractorTab() {
  const { toast } = useToast();
  const [text, setText] = useState("");
  const [result, setResult] = useState<any>(null);

  const mutation = useMutation({
    mutationFn: async (inputText: string) => {
      const res = await apiRequest("POST", "/api/trojan/extract-iocs-text", { text: inputText });
      return res.json();
    },
    onSuccess: (data) => setResult(data),
    onError: () => toast({ title: "IOC extraction failed", variant: "destructive" }),
  });

  const iocTypeConfig: Record<string, { icon: React.ElementType; label: string }> = {
    ips: { icon: Globe, label: "IP Addresses" },
    domains: { icon: Globe, label: "Domains" },
    urls: { icon: Link, label: "URLs" },
    emails: { icon: Mail, label: "Email Addresses" },
    filePaths: { icon: FileCode, label: "File Paths" },
    registryKeys: { icon: FolderOpen, label: "Registry Keys" },
    mutexNames: { icon: Server, label: "Mutex Names" },
  };

  const totalIOCs = result ? (
    (result.ips?.length || 0) + (result.domains?.length || 0) + (result.urls?.length || 0) +
    (result.emails?.length || 0) + (result.filePaths?.length || 0) + (result.registryKeys?.length || 0) +
    (result.mutexNames?.length || 0) + (result.hashes?.md5?.length || 0) + (result.hashes?.sha1?.length || 0) +
    (result.hashes?.sha256?.length || 0)
  ) : 0;

  const exportAll = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "extracted-iocs.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <FileText className="w-4 h-4 text-primary" />
            Paste Text for IOC Extraction
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-3">
          <Textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste malware analysis reports, threat intelligence feeds, incident logs, or any text containing IOCs..."
            className="font-mono text-xs resize-none"
            rows={8}
            data-testid="input-ioc-text"
          />
          <Button
            onClick={() => mutation.mutate(text)}
            disabled={!text.trim() || mutation.isPending}
            data-testid="button-extract-iocs-text"
          >
            {mutation.isPending ? (
              <><Loader2 className="w-4 h-4 me-2 animate-spin" />Extracting</>
            ) : (
              <><Target className="w-4 h-4 me-2" />Extract IOCs</>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && !mutation.isPending && (
        <div className="space-y-3">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-xs text-muted-foreground">
              Found <span className="font-semibold text-foreground" data-testid="text-ioc-count">{totalIOCs}</span> indicators
            </span>
            <Button variant="outline" size="sm" onClick={exportAll} data-testid="button-export-extracted-iocs">
              <Download className="w-3.5 h-3.5 me-1.5" />Export JSON
            </Button>
          </div>

          {Object.entries(iocTypeConfig).map(([key, cfg]) => {
            const items = result[key];
            if (!items || (Array.isArray(items) && items.length === 0)) return null;
            const IconComp = cfg.icon;
            return (
              <Card key={key}>
                <CardHeader className="pb-2 pt-3 px-4">
                  <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                    <IconComp className="w-4 h-4 text-primary" />
                    {cfg.label}
                    <Badge variant="secondary" className="text-[10px] ml-auto">{items.length}</Badge>
                  </CardTitle>
                </CardHeader>
                <CardContent className="px-4 pb-3">
                  <div className="space-y-1 max-h-48 overflow-y-auto">
                    {items.map((val: string, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 text-xs font-mono p-1.5 rounded bg-muted/50 break-all" data-testid={`extracted-ioc-${key}-${i}`}>
                        <span>{val}</span>
                        <CopyButton text={val} />
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            );
          })}

          {result.hashes && (result.hashes.md5?.length > 0 || result.hashes.sha1?.length > 0 || result.hashes.sha256?.length > 0) && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
                  <Hash className="w-4 h-4 text-primary" />
                  File Hashes
                  <Badge variant="secondary" className="text-[10px] ml-auto">
                    {(result.hashes.md5?.length || 0) + (result.hashes.sha1?.length || 0) + (result.hashes.sha256?.length || 0)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-2">
                {result.hashes.sha256?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-muted-foreground font-medium">SHA-256</span>
                    {result.hashes.sha256.map((h: string, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 text-xs font-mono p-1.5 rounded bg-muted/50 break-all" data-testid={`extracted-hash-sha256-${i}`}>
                        <span>{h}</span>
                        <CopyButton text={h} />
                      </div>
                    ))}
                  </div>
                )}
                {result.hashes.sha1?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-muted-foreground font-medium">SHA-1</span>
                    {result.hashes.sha1.map((h: string, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 text-xs font-mono p-1.5 rounded bg-muted/50 break-all" data-testid={`extracted-hash-sha1-${i}`}>
                        <span>{h}</span>
                        <CopyButton text={h} />
                      </div>
                    ))}
                  </div>
                )}
                {result.hashes.md5?.length > 0 && (
                  <div className="space-y-1">
                    <span className="text-[10px] text-muted-foreground font-medium">MD5</span>
                    {result.hashes.md5.map((h: string, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 text-xs font-mono p-1.5 rounded bg-muted/50 break-all" data-testid={`extracted-hash-md5-${i}`}>
                        <span>{h}</span>
                        <CopyButton text={h} />
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {totalIOCs === 0 && (
            <Card>
              <CardContent className="p-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-severity-medium" />
                <span className="text-xs text-muted-foreground">No IOCs could be extracted from the provided text.</span>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatProfileTab() {
  const { toast } = useToast();
  const [selectedFamily, setSelectedFamily] = useState("");
  const [heatmap, setHeatmap] = useState<any>(null);
  const [actor, setActor] = useState<any>(null);
  const [killChain, setKillChain] = useState<any>(null);

  const { data: families, isLoading: familiesLoading } = useQuery<any>({
    queryKey: ["/api/trojan/families"],
  });

  const heatmapMut = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/mitre-heatmap", { family });
      return res.json();
    },
    onSuccess: (data) => setHeatmap(data),
    onError: () => toast({ title: "Heatmap generation failed", variant: "destructive" }),
  });

  const actorMut = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/threat-actor", { family });
      return res.json();
    },
    onSuccess: (data) => setActor(data),
  });

  const killChainMut = useMutation({
    mutationFn: async (family: string) => {
      const res = await apiRequest("POST", "/api/trojan/kill-chain", { family });
      return res.json();
    },
    onSuccess: (data) => setKillChain(data),
    onError: () => toast({ title: "Kill chain mapping failed", variant: "destructive" }),
  });

  const handleAnalyze = () => {
    if (!selectedFamily) return;
    setHeatmap(null);
    setActor(null);
    setKillChain(null);
    heatmapMut.mutate(selectedFamily);
    actorMut.mutate(selectedFamily);
    killChainMut.mutate(selectedFamily);
  };

  const familyList: string[] = Array.isArray(families) ? families.map((f: any) => typeof f === "string" ? f : f.name || f.family) : [];
  const isLoading = heatmapMut.isPending || actorMut.isPending || killChainMut.isPending;

  const coverageColor = (coverage: number) => {
    if (coverage >= 66) return "bg-severity-critical";
    if (coverage >= 33) return "bg-severity-medium";
    if (coverage > 0) return "bg-primary";
    return "bg-muted";
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <Select value={selectedFamily} onValueChange={setSelectedFamily}>
          <SelectTrigger className="flex-1" data-testid="select-trojan-family-profile">
            <SelectValue placeholder="Select Trojan family..." />
          </SelectTrigger>
          <SelectContent>
            {familiesLoading ? (
              <div className="p-2 text-xs text-muted-foreground">Loading families...</div>
            ) : (
              familyList.map((f) => (
                <SelectItem key={f} value={f}>{f}</SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
        <Button
          onClick={handleAnalyze}
          disabled={!selectedFamily || isLoading}
          data-testid="button-analyze-profile"
        >
          {isLoading ? (
            <><Loader2 className="w-4 h-4 me-2 animate-spin" />Analyzing</>
          ) : (
            <><Crosshair className="w-4 h-4 me-2" />Analyze</>
          )}
        </Button>
      </div>

      {isLoading && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">Building threat profile for {selectedFamily}...</span>
          </CardContent>
        </Card>
      )}

      {actor && actor.found && !isLoading && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <Users className="w-4 h-4 text-severity-critical" />
              Threat Actor Attribution
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4 space-y-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div>
                <p className="text-sm font-semibold" data-testid="text-actor-name">{actor.actor.name}</p>
                <p className="text-[11px] text-muted-foreground">{actor.actor.origin}</p>
              </div>
              <Badge variant="outline" className="text-[10px]" data-testid="text-actor-since">Active since {actor.actor.activeSince}</Badge>
            </div>
            <p className="text-xs text-muted-foreground" data-testid="text-actor-description">{actor.actor.description}</p>
            <div className="space-y-1.5">
              <span className="text-[10px] text-muted-foreground font-medium">Aliases</span>
              <div className="flex flex-wrap gap-1">
                {actor.actor.aliases.map((alias: string, i: number) => (
                  <Badge key={i} variant="secondary" className="text-[10px]">{alias}</Badge>
                ))}
              </div>
            </div>
            <div className="space-y-1.5">
              <span className="text-[10px] text-muted-foreground font-medium">Target Sectors</span>
              <div className="flex flex-wrap gap-1">
                {actor.actor.targetSectors.map((sector: string, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px]">{sector}</Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {killChain && !isLoading && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <Target className="w-4 h-4 text-severity-high" />
              Cyber Kill Chain Mapping
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="space-y-2">
              {killChain.phases.map((phase: any, i: number) => (
                <div
                  key={i}
                  className={`flex items-start gap-3 p-2.5 rounded-md ${phase.active ? "bg-muted/50" : "opacity-40"}`}
                  data-testid={`killchain-phase-${i}`}
                >
                  <div className={`w-7 h-7 rounded-md flex items-center justify-center text-[10px] font-bold flex-shrink-0 ${
                    phase.active ? "bg-severity-critical text-white" : "bg-muted text-muted-foreground"
                  }`}>
                    {phase.order}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold">{phase.phase}</span>
                      {phase.active && <Badge variant="secondary" className="text-[9px]">Active</Badge>}
                    </div>
                    <p className="text-[10px] text-muted-foreground">{phase.description}</p>
                    {phase.techniques.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {phase.techniques.map((t: string, j: number) => (
                          <span key={j} className="text-[10px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {heatmap && !isLoading && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <Grid3X3 className="w-4 h-4 text-primary" />
              MITRE ATT&CK Heatmap
              <span className="text-[10px] text-muted-foreground font-normal ml-auto">
                {heatmap.heatmap.coveredTactics}/{heatmap.heatmap.totalTactics} tactics covered
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {heatmap.heatmap.tactics.map((tactic: any, i: number) => (
                <div
                  key={i}
                  className={`p-2 rounded-md border ${tactic.coverage > 0 ? "border-severity-critical/30" : "border-muted"}`}
                  data-testid={`heatmap-tactic-${i}`}
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-[9px] font-medium truncate">{tactic.tactic}</span>
                    {tactic.coverage > 0 && (
                      <span className="text-[9px] font-mono text-severity-critical">{tactic.techniques.length}</span>
                    )}
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-muted">
                    <div
                      className={`h-full rounded-full transition-all ${coverageColor(tactic.coverage)}`}
                      style={{ width: `${Math.max(tactic.coverage, tactic.coverage > 0 ? 10 : 0)}%` }}
                    />
                  </div>
                  {tactic.techniques.length > 0 && (
                    <div className="mt-1.5 space-y-0.5">
                      {tactic.techniques.map((tech: any, j: number) => (
                        <p key={j} className="text-[8px] font-mono text-muted-foreground truncate" title={`${tech.id} - ${tech.name}`}>
                          {tech.id}
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-3 pt-3 border-t flex-wrap">
              <span className="text-[10px] text-muted-foreground" data-testid="text-heatmap-total">
                Total Techniques: <span className="font-semibold text-foreground">{heatmap.heatmap.totalTechniques}</span>
              </span>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                <span>Coverage:</span>
                <span className="inline-block w-3 h-3 rounded-sm bg-primary" /> Low
                <span className="inline-block w-3 h-3 rounded-sm bg-severity-medium" /> Medium
                <span className="inline-block w-3 h-3 rounded-sm bg-severity-critical" /> High
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {!isLoading && !heatmap && !actor && !killChain && selectedFamily && (
        <Card>
          <CardContent className="p-4 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-severity-medium" />
            <span className="text-xs text-muted-foreground">Select a family and click Analyze to view threat profile.</span>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

export default function TrojanAnalyzerPage() {
  return (
    <div className="p-4 md:p-6 space-y-4 max-w-5xl mx-auto">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" data-testid="text-trojan-analyzer-title">
          <Bug className="w-5 h-5 text-primary" />
          Trojan Analyzer
        </h1>
        <p className="text-xs text-muted-foreground mt-1">
          Real malware analysis — hash lookup, behavioral classification, detection rules, IOC extraction, MITRE mapping & threat actor attribution
        </p>
      </div>

      <Tabs defaultValue="hash-lookup" className="space-y-4">
        <TabsList className="flex flex-wrap w-full gap-1">
          <TabsTrigger value="hash-lookup" data-testid="tab-hash-lookup" className="text-xs flex-1 min-w-0">
            <Search className="w-3.5 h-3.5 me-1.5" />Hash
          </TabsTrigger>
          <TabsTrigger value="behavior" data-testid="tab-behavior" className="text-xs flex-1 min-w-0">
            <Activity className="w-3.5 h-3.5 me-1.5" />Behavior
          </TabsTrigger>
          <TabsTrigger value="detection-rules" data-testid="tab-detection-rules" className="text-xs flex-1 min-w-0">
            <FileCode className="w-3.5 h-3.5 me-1.5" />Rules
          </TabsTrigger>
          <TabsTrigger value="ioc-explorer" data-testid="tab-ioc-explorer" className="text-xs flex-1 min-w-0">
            <Database className="w-3.5 h-3.5 me-1.5" />IOCs
          </TabsTrigger>
          <TabsTrigger value="ioc-extractor" data-testid="tab-ioc-extractor" className="text-xs flex-1 min-w-0">
            <Target className="w-3.5 h-3.5 me-1.5" />Extract
          </TabsTrigger>
          <TabsTrigger value="threat-profile" data-testid="tab-threat-profile" className="text-xs flex-1 min-w-0">
            <Crosshair className="w-3.5 h-3.5 me-1.5" />Profile
          </TabsTrigger>
        </TabsList>

        <TabsContent value="hash-lookup">
          <HashLookupTab />
        </TabsContent>
        <TabsContent value="behavior">
          <BehaviorAnalysisTab />
        </TabsContent>
        <TabsContent value="detection-rules">
          <DetectionRulesTab />
        </TabsContent>
        <TabsContent value="ioc-explorer">
          <IOCExplorerTab />
        </TabsContent>
        <TabsContent value="ioc-extractor">
          <IOCExtractorTab />
        </TabsContent>
        <TabsContent value="threat-profile">
          <ThreatProfileTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
