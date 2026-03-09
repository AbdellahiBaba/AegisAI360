import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import {
  Mail, Shield, ShieldAlert, ShieldCheck, ShieldX, AlertTriangle,
  Clock, Link2, Globe, Hash, AtSign, Loader2, ArrowRight, Search, Download,
} from "lucide-react";
import { generateEmailAnalysisReportPDF } from "@/lib/reportGenerator";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface AuthResult {
  protocol: string;
  result: string;
  details: string;
}

interface PhishingIndicator {
  type: string;
  severity: string;
  description: string;
  evidence: string;
}

interface ExtractedIOC {
  type: string;
  value: string;
  context: string;
}

interface EmailHop {
  index: number;
  from: string;
  by: string;
  timestamp: string;
  delay: string;
  protocol: string;
}

interface AnalysisResult {
  headers: Record<string, string>;
  hops: EmailHop[];
  authResults: AuthResult[];
  phishingIndicators: PhishingIndicator[];
  iocs: ExtractedIOC[];
  verdict: string;
  confidenceScore: number;
  riskScore: number;
  summary: string;
  senderInfo: {
    from: string;
    replyTo: string;
    returnPath: string;
    displayName: string;
    domain: string;
    mismatch: boolean;
  };
  subject: string;
  totalHops: number;
  totalDelay: string;
}

function VerdictBadge({ verdict, confidence }: { verdict: string; confidence: number }) {
  const config: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline"; icon: typeof ShieldCheck }> = {
    clean: { label: "Clean", variant: "default", icon: ShieldCheck },
    suspicious: { label: "Suspicious", variant: "secondary", icon: AlertTriangle },
    likely_phishing: { label: "Likely Phishing", variant: "destructive", icon: ShieldAlert },
    confirmed_phishing: { label: "Confirmed Phishing", variant: "destructive", icon: ShieldX },
  };
  const c = config[verdict] || config.suspicious;
  const Icon = c.icon;

  return (
    <div className="flex items-center gap-2" data-testid="verdict-badge">
      <Badge variant={c.variant} className="text-sm px-3 py-1">
        <Icon className="w-4 h-4 mr-1.5" />
        {c.label}
      </Badge>
      <span className="text-sm text-muted-foreground">
        {confidence}% confidence
      </span>
    </div>
  );
}

function AuthBadge({ result }: { result: AuthResult }) {
  const colorMap: Record<string, string> = {
    pass: "bg-green-500/15 text-green-700 dark:text-green-400 border-green-500/30",
    fail: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30",
    softfail: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border-orange-500/30",
    neutral: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/30",
    none: "bg-muted text-muted-foreground border-border",
    unknown: "bg-muted text-muted-foreground border-border",
    temperror: "bg-orange-500/15 text-orange-700 dark:text-orange-400 border-orange-500/30",
    permerror: "bg-red-500/15 text-red-700 dark:text-red-400 border-red-500/30",
  };

  return (
    <div className="flex flex-col gap-1" data-testid={`auth-result-${result.protocol.toLowerCase()}`}>
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono font-semibold">{result.protocol}</span>
        <span className={`text-xs px-2 py-0.5 rounded-md border ${colorMap[result.result] || colorMap.unknown}`}>
          {result.result.toUpperCase()}
        </span>
      </div>
      <span className="text-xs text-muted-foreground truncate max-w-md">{result.details}</span>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const variants: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
    critical: "destructive",
    high: "destructive",
    medium: "secondary",
    low: "outline",
    info: "outline",
  };
  return <Badge variant={variants[severity] || "secondary"} className="text-[10px]">{severity}</Badge>;
}

function IOCIcon({ type }: { type: string }) {
  switch (type) {
    case "url": return <Link2 className="w-3.5 h-3.5" />;
    case "ip": return <Globe className="w-3.5 h-3.5" />;
    case "email": return <AtSign className="w-3.5 h-3.5" />;
    case "hash": return <Hash className="w-3.5 h-3.5" />;
    case "domain": return <Globe className="w-3.5 h-3.5" />;
    default: return <Search className="w-3.5 h-3.5" />;
  }
}

export default function EmailAnalyzerPage() {
  useDocumentTitle("Email Analyzer");
  const [rawEmail, setRawEmail] = useState("");

  const analyzeMutation = useMutation<AnalysisResult, Error>({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/email/analyze", { rawEmail });
      return res.json();
    },
  });

  const result = analyzeMutation.data;

  return (
    <div className="p-4 space-y-4 max-w-7xl mx-auto">
      <div className="flex items-center gap-3 flex-wrap">
        <Mail className="w-6 h-6 text-primary" />
        <h1 className="text-xl font-bold" data-testid="text-page-title">Email Security Analyzer</h1>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Paste Raw Email Headers / Source</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Textarea
            value={rawEmail}
            onChange={(e) => setRawEmail(e.target.value)}
            placeholder={"Paste the full raw email source or headers here...\n\nYou can get this from:\n- Gmail: Open email → ⋮ → Show original\n- Outlook: Open email → File → Properties → Internet Headers\n- Thunderbird: View → Message Source"}
            className="min-h-[200px] font-mono text-xs"
            data-testid="input-raw-email"
          />
          <Button
            onClick={() => analyzeMutation.mutate()}
            disabled={!rawEmail.trim() || analyzeMutation.isPending}
            data-testid="button-analyze"
          >
            {analyzeMutation.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Search className="w-4 h-4 mr-2" />
            )}
            Analyze Email
          </Button>
        </CardContent>
      </Card>

      {analyzeMutation.isError && (
        <Card>
          <CardContent className="pt-4">
            <p className="text-sm text-destructive" data-testid="text-error">
              Analysis failed: {analyzeMutation.error?.message || "Unknown error"}
            </p>
          </CardContent>
        </Card>
      )}

      {result && (
        <>
          <div className="flex justify-end">
            <Button
              variant="outline"
              size="sm"
              onClick={() => generateEmailAnalysisReportPDF(result)}
              data-testid="button-export-email-pdf"
            >
              <Download className="w-3.5 h-3.5 me-1.5" />
              Export PDF
            </Button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4 space-y-2">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Verdict</p>
                <VerdictBadge verdict={result.verdict} confidence={result.confidenceScore} />
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 space-y-2">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Risk Score</p>
                <div className="flex items-center gap-3">
                  <span className="text-2xl font-bold font-mono" data-testid="text-risk-score">{result.riskScore}</span>
                  <span className="text-sm text-muted-foreground">/ 100</span>
                  <div className="flex-1 h-2 rounded-full bg-muted overflow-visible">
                    <div
                      className={`h-full rounded-full transition-all ${
                        result.riskScore >= 70 ? "bg-red-500" :
                        result.riskScore >= 45 ? "bg-orange-500" :
                        result.riskScore >= 20 ? "bg-yellow-500" :
                        "bg-green-500"
                      }`}
                      style={{ width: `${result.riskScore}%` }}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-4 space-y-2">
                <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Routing</p>
                <div className="flex items-center gap-4">
                  <div>
                    <span className="text-2xl font-bold font-mono" data-testid="text-hop-count">{result.totalHops}</span>
                    <span className="text-sm text-muted-foreground ml-1">hops</span>
                  </div>
                  <div>
                    <Clock className="w-4 h-4 text-muted-foreground inline mr-1" />
                    <span className="text-sm font-mono" data-testid="text-total-delay">{result.totalDelay}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardContent className="pt-4">
              <p className="text-sm" data-testid="text-summary">{result.summary}</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm">Authentication Results</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {result.authResults.map((auth) => (
                  <AuthBadge key={auth.protocol} result={auth} />
                ))}
              </div>
            </CardContent>
          </Card>

          <Tabs defaultValue="indicators" className="w-full">
            <TabsList data-testid="tabs-analysis">
              <TabsTrigger value="indicators" data-testid="tab-indicators">
                Phishing Indicators ({result.phishingIndicators.length})
              </TabsTrigger>
              <TabsTrigger value="hops" data-testid="tab-hops">
                Email Route ({result.totalHops})
              </TabsTrigger>
              <TabsTrigger value="iocs" data-testid="tab-iocs">
                IOCs ({result.iocs.length})
              </TabsTrigger>
              <TabsTrigger value="headers" data-testid="tab-headers">
                Headers
              </TabsTrigger>
              <TabsTrigger value="sender" data-testid="tab-sender">
                Sender Info
              </TabsTrigger>
            </TabsList>

            <TabsContent value="indicators" className="mt-3">
              <Card>
                <CardContent className="pt-4">
                  {result.phishingIndicators.length === 0 ? (
                    <div className="flex items-center gap-2 text-sm text-muted-foreground py-4">
                      <ShieldCheck className="w-5 h-5 text-green-500" />
                      No phishing indicators detected
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.phishingIndicators.map((indicator, i) => (
                        <div key={i} className="flex items-start gap-3 p-3 rounded-md border" data-testid={`indicator-${i}`}>
                          <SeverityBadge severity={indicator.severity} />
                          <div className="flex-1 min-w-0 space-y-1">
                            <p className="text-sm font-medium">{indicator.description}</p>
                            <p className="text-xs text-muted-foreground font-mono break-all">{indicator.evidence}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="hops" className="mt-3">
              <Card>
                <CardContent className="pt-4">
                  {result.hops.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-4">No routing information found in headers</p>
                  ) : (
                    <div className="space-y-2">
                      {result.hops.map((hop, i) => (
                        <div key={i} className="flex items-center gap-3 p-3 rounded-md border" data-testid={`hop-${i}`}>
                          <div className="flex flex-col items-center gap-1">
                            <div className="w-7 h-7 rounded-full bg-primary/10 flex items-center justify-center">
                              <span className="text-xs font-mono font-bold text-primary">{i + 1}</span>
                            </div>
                            {i < result.hops.length - 1 && <ArrowRight className="w-3 h-3 text-muted-foreground rotate-90" />}
                          </div>
                          <div className="flex-1 min-w-0 space-y-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-xs font-mono font-medium truncate">{hop.from}</span>
                              <ArrowRight className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                              <span className="text-xs font-mono font-medium truncate">{hop.by}</span>
                            </div>
                            <div className="flex items-center gap-3 flex-wrap">
                              <Badge variant="outline" className="text-[10px]">{hop.protocol}</Badge>
                              <span className="text-[10px] text-muted-foreground">{hop.timestamp}</span>
                              {hop.delay && (
                                <span className="text-[10px] text-muted-foreground">
                                  <Clock className="w-3 h-3 inline mr-0.5" />{hop.delay}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="iocs" className="mt-3">
              <Card>
                <CardContent className="pt-4">
                  {result.iocs.length === 0 ? (
                    <p className="text-sm text-muted-foreground py-4">No IOCs extracted</p>
                  ) : (
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead className="w-20">Type</TableHead>
                          <TableHead>Value</TableHead>
                          <TableHead className="w-48">Context</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {result.iocs.map((ioc, i) => (
                          <TableRow key={i} data-testid={`ioc-${i}`}>
                            <TableCell>
                              <div className="flex items-center gap-1.5">
                                <IOCIcon type={ioc.type} />
                                <span className="text-xs font-mono uppercase">{ioc.type}</span>
                              </div>
                            </TableCell>
                            <TableCell className="font-mono text-xs break-all max-w-md">{ioc.value}</TableCell>
                            <TableCell className="text-xs text-muted-foreground">{ioc.context}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="headers" className="mt-3">
              <Card>
                <CardContent className="pt-4">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-40">Header</TableHead>
                        <TableHead>Value</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {Object.entries(result.headers)
                        .filter(([key]) => !key.startsWith("received"))
                        .slice(0, 50)
                        .map(([key, value], i) => (
                          <TableRow key={i} data-testid={`header-${i}`}>
                            <TableCell className="font-mono text-xs font-medium align-top">{key}</TableCell>
                            <TableCell className="font-mono text-xs break-all max-w-lg text-muted-foreground">{value}</TableCell>
                          </TableRow>
                        ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="sender" className="mt-3">
              <Card>
                <CardContent className="pt-4 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">From</p>
                      <p className="text-sm font-mono" data-testid="text-sender-from">{result.senderInfo.from}</p>
                    </div>
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Display Name</p>
                      <p className="text-sm" data-testid="text-sender-display">{result.senderInfo.displayName || "(none)"}</p>
                    </div>
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Reply-To</p>
                      <p className="text-sm font-mono" data-testid="text-sender-reply">{result.senderInfo.replyTo}</p>
                    </div>
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Return-Path</p>
                      <p className="text-sm font-mono" data-testid="text-sender-return">{result.senderInfo.returnPath}</p>
                    </div>
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Domain</p>
                      <p className="text-sm font-mono" data-testid="text-sender-domain">{result.senderInfo.domain}</p>
                    </div>
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Address Mismatch</p>
                      {result.senderInfo.mismatch ? (
                        <Badge variant="destructive" data-testid="badge-mismatch">Mismatch Detected</Badge>
                      ) : (
                        <Badge variant="secondary" data-testid="badge-mismatch">No Mismatch</Badge>
                      )}
                    </div>
                  </div>
                  <div className="space-y-2">
                    <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Subject</p>
                    <p className="text-sm" data-testid="text-subject">{result.subject}</p>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      )}
    </div>
  );
}
