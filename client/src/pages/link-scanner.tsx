import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Loader2, Search, Shield, ShieldCheck, ShieldX, ShieldAlert,
  AlertTriangle, CheckCircle, Info, Globe, Lock, Wifi, Eye,
  Download, Clock, XCircle, ExternalLink,
} from "lucide-react";
import { generateLinkScannerReportPDF } from "@/lib/reportGenerator";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface CheckResult {
  name: string;
  status: "clean" | "warning" | "danger" | "error";
  details: string;
  source: string;
}

interface Finding {
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
}

interface LinkScanResult {
  url: string;
  overallRisk: "safe" | "suspicious" | "malicious" | "unknown";
  riskScore: number;
  checks: CheckResult[];
  findings: Finding[];
  scannedAt: string;
}

interface ScanHistoryEntry {
  url: string;
  overallRisk: string;
  riskScore: number;
  scannedAt: string;
}

const riskConfig: Record<string, { label: string; color: string; bgColor: string; icon: typeof Shield }> = {
  safe: { label: "Safe", color: "text-green-500", bgColor: "bg-green-500", icon: ShieldCheck },
  suspicious: { label: "Suspicious", color: "text-yellow-500", bgColor: "bg-yellow-500", icon: ShieldAlert },
  malicious: { label: "Malicious", color: "text-red-500", bgColor: "bg-red-500", icon: ShieldX },
  unknown: { label: "Unknown", color: "text-muted-foreground", bgColor: "bg-muted-foreground", icon: Shield },
};

const checkStatusConfig: Record<string, { label: string; color: string; icon: typeof CheckCircle }> = {
  clean: { label: "Clean", color: "text-green-500", icon: CheckCircle },
  warning: { label: "Warning", color: "text-yellow-500", icon: AlertTriangle },
  danger: { label: "Danger", color: "text-red-500", icon: XCircle },
  error: { label: "Error", color: "text-muted-foreground", icon: Info },
};

const severityConfig: Record<string, { color: string; badgeVariant: string }> = {
  critical: { color: "bg-red-500/10 text-red-500 border-red-500/20", badgeVariant: "destructive" },
  high: { color: "bg-orange-500/10 text-orange-500 border-orange-500/20", badgeVariant: "destructive" },
  medium: { color: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20", badgeVariant: "secondary" },
  low: { color: "bg-blue-500/10 text-blue-500 border-blue-500/20", badgeVariant: "secondary" },
  info: { color: "bg-green-500/10 text-green-500 border-green-500/20", badgeVariant: "secondary" },
};

const checkIconMap: Record<string, typeof Globe> = {
  "Google Safe Browsing": Shield,
  "URLScan.io": Eye,
  "Heuristic Analysis": Search,
  "DNS Resolution": Wifi,
  "SSL/TLS Certificate": Lock,
  "URL Validation": Globe,
};

function getRiskScoreColor(score: number): string {
  if (score >= 60) return "text-red-500";
  if (score >= 30) return "text-yellow-500";
  return "text-green-500";
}

function getRiskScoreStroke(score: number): string {
  if (score >= 60) return "stroke-red-500";
  if (score >= 30) return "stroke-yellow-500";
  return "stroke-green-500";
}

function getRiskScoreTrack(score: number): string {
  if (score >= 60) return "stroke-red-500/20";
  if (score >= 30) return "stroke-yellow-500/20";
  return "stroke-green-500/20";
}

export default function LinkScannerPage() {
  useDocumentTitle("Link Scanner");
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<LinkScanResult | null>(null);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const { toast } = useToast();

  const scanMutation = useMutation({
    mutationFn: async (targetUrl: string) => {
      const res = await apiRequest("POST", "/api/link-scanner/scan", { url: targetUrl });
      return res.json() as Promise<LinkScanResult>;
    },
    onSuccess: (data) => {
      setResult(data);
      setHistory((prev) => [
        { url: data.url, overallRisk: data.overallRisk, riskScore: data.riskScore, scannedAt: data.scannedAt },
        ...prev.filter((h) => h.url !== data.url),
      ].slice(0, 20));
    },
    onError: (error: Error) => {
      toast({
        title: "Scan Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleScan = () => {
    const trimmed = url.trim();
    if (!trimmed) return;
    let scanUrl = trimmed;
    if (!scanUrl.startsWith("http://") && !scanUrl.startsWith("https://")) {
      scanUrl = "https://" + scanUrl;
      setUrl(scanUrl);
    }
    scanMutation.mutate(scanUrl);
  };

  const handleExportPDF = () => {
    if (!result) return;
    try {
      generateLinkScannerReportPDF(result);
      toast({ title: "Report Exported", description: "PDF report has been downloaded." });
    } catch {
      toast({ title: "Export Failed", description: "Could not generate the PDF report.", variant: "destructive" });
    }
  };

  const risk = result ? riskConfig[result.overallRisk] || riskConfig.unknown : null;
  const circumference = 2 * Math.PI * 54;
  const strokeDashoffset = result ? circumference - (result.riskScore / 100) * circumference : circumference;

  return (
    <div className="p-4 space-y-4 max-w-6xl mx-auto">
      <div className="flex items-center gap-3 flex-wrap">
        <Globe className="w-5 h-5 text-primary" />
        <h1 className="text-lg font-bold" data-testid="text-page-title">Link Scanner</h1>
        <Badge variant="secondary" className="text-[10px]" data-testid="badge-tool-type">URL Analysis</Badge>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex gap-2">
            <Input
              placeholder="Enter URL to scan (e.g., https://example.com)"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              data-testid="input-url"
              className="flex-1 font-mono text-sm"
            />
            <Button
              onClick={handleScan}
              disabled={scanMutation.isPending || !url.trim()}
              data-testid="button-scan"
            >
              {scanMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              <span className="ml-2">Scan</span>
            </Button>
          </div>
        </CardContent>
      </Card>

      {scanMutation.isPending && (
        <Card>
          <CardContent className="p-8 flex flex-col items-center gap-4">
            <div className="relative">
              <Loader2 className="w-12 h-12 animate-spin text-primary" />
              <Shield className="w-5 h-5 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
            </div>
            <div className="text-center space-y-1">
              <p className="text-sm font-medium" data-testid="text-scanning-status">Scanning URL...</p>
              <p className="text-xs text-muted-foreground">Running Google Safe Browsing, URLScan.io, Heuristic Analysis, DNS, and SSL checks</p>
            </div>
          </CardContent>
        </Card>
      )}

      {result && !scanMutation.isPending && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="md:col-span-1">
              <CardContent className="p-6 flex flex-col items-center gap-4">
                <div className="relative w-32 h-32">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
                    <circle
                      cx="60" cy="60" r="54"
                      fill="none"
                      strokeWidth="8"
                      className={getRiskScoreTrack(result.riskScore)}
                    />
                    <circle
                      cx="60" cy="60" r="54"
                      fill="none"
                      strokeWidth="8"
                      strokeLinecap="round"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      className={`${getRiskScoreStroke(result.riskScore)} transition-all duration-1000`}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className={`text-3xl font-bold ${getRiskScoreColor(result.riskScore)}`} data-testid="text-risk-score">
                      {result.riskScore}
                    </span>
                    <span className="text-[10px] text-muted-foreground">/ 100</span>
                  </div>
                </div>

                {risk && (
                  <div className="flex items-center gap-2" data-testid="text-risk-verdict">
                    <risk.icon className={`w-5 h-5 ${risk.color}`} />
                    <span className={`text-sm font-bold uppercase ${risk.color}`}>{risk.label}</span>
                  </div>
                )}

                <div className="text-center space-y-1 w-full">
                  <p className="text-xs text-muted-foreground truncate font-mono" title={result.url} data-testid="text-scanned-url">
                    {result.url}
                  </p>
                  <p className="text-[10px] text-muted-foreground" data-testid="text-scan-time">
                    Scanned: {new Date(result.scannedAt).toLocaleString()}
                  </p>
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleExportPDF}
                  data-testid="button-export-pdf"
                  className="w-full"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export PDF Report
                </Button>
              </CardContent>
            </Card>

            <Card className="md:col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Security Checks</CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0 space-y-2">
                {result.checks.map((check, idx) => {
                  const status = checkStatusConfig[check.status] || checkStatusConfig.error;
                  const CheckIcon = checkIconMap[check.name] || Globe;
                  return (
                    <div
                      key={idx}
                      className="flex items-start gap-3 p-3 rounded-md border"
                      data-testid={`card-check-${idx}`}
                    >
                      <CheckIcon className="w-4 h-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                      <div className="flex-1 min-w-0 space-y-0.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold" data-testid={`text-check-name-${idx}`}>{check.name}</span>
                          <Badge
                            variant="secondary"
                            className={`text-[9px] ${check.status === "clean" ? "bg-green-500/10 text-green-500" : check.status === "warning" ? "bg-yellow-500/10 text-yellow-500" : check.status === "danger" ? "bg-red-500/10 text-red-500" : "bg-muted"}`}
                            data-testid={`badge-check-status-${idx}`}
                          >
                            <status.icon className="w-3 h-3 mr-1" />
                            {status.label}
                          </Badge>
                        </div>
                        <p className="text-[11px] text-muted-foreground" data-testid={`text-check-details-${idx}`}>{check.details}</p>
                        <p className="text-[9px] text-muted-foreground/60">{check.source}</p>
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          </div>

          {result.findings.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4" />
                  Findings ({result.findings.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="p-4 pt-0 space-y-2">
                {result.findings.map((finding, idx) => {
                  const sev = severityConfig[finding.severity] || severityConfig.info;
                  return (
                    <div
                      key={idx}
                      className={`flex items-start gap-3 p-3 rounded-md border ${sev.color}`}
                      data-testid={`card-finding-${idx}`}
                    >
                      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      <div className="flex-1 min-w-0 space-y-0.5">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold" data-testid={`text-finding-title-${idx}`}>{finding.title}</span>
                          <Badge variant="secondary" className="text-[9px] uppercase">
                            {finding.severity}
                          </Badge>
                        </div>
                        <p className="text-[11px] opacity-80" data-testid={`text-finding-desc-${idx}`}>{finding.description}</p>
                      </div>
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {history.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Clock className="w-4 h-4" />
              Recent Scans
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4 pt-0">
            <div className="space-y-1.5">
              {history.map((entry, idx) => {
                const entryRisk = riskConfig[entry.overallRisk] || riskConfig.unknown;
                return (
                  <div
                    key={idx}
                    className="flex items-center gap-3 p-2 rounded-md hover-elevate cursor-pointer"
                    onClick={() => {
                      setUrl(entry.url);
                      scanMutation.mutate(entry.url);
                    }}
                    data-testid={`row-history-${idx}`}
                  >
                    <entryRisk.icon className={`w-4 h-4 flex-shrink-0 ${entryRisk.color}`} />
                    <span className="text-xs font-mono truncate flex-1 min-w-0" data-testid={`text-history-url-${idx}`}>
                      {entry.url}
                    </span>
                    <Badge
                      variant="secondary"
                      className={`text-[9px] ${entry.overallRisk === "safe" ? "bg-green-500/10 text-green-500" : entry.overallRisk === "suspicious" ? "bg-yellow-500/10 text-yellow-500" : entry.overallRisk === "malicious" ? "bg-red-500/10 text-red-500" : ""}`}
                      data-testid={`badge-history-risk-${idx}`}
                    >
                      {entry.riskScore}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground flex-shrink-0">
                      {new Date(entry.scannedAt).toLocaleTimeString()}
                    </span>
                    <ExternalLink className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
