import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useTranslation } from "react-i18next";
import {
  Radar, Globe, ShieldCheck, FileSearch, Bug, Loader2, Clock,
  CheckCircle2, XCircle, AlertTriangle, Search, ShieldBan, Bell, Info, Lock,
  Network, FolderSearch, Cpu, Shield, Landmark, Database, Code, Download,
} from "lucide-react";
import type { ScanResult } from "@shared/schema";
import { generateScannerReportPDF } from "@/lib/reportGenerator";

const severityColor: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-muted text-muted-foreground",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge className={`text-[10px] ${severityColor[severity] || severityColor.info}`}>
      {severity.toUpperCase()}
    </Badge>
  );
}

function useRemediation() {
  const { toast } = useToast();
  const { t } = useTranslation();

  const mutation = useMutation({
    mutationFn: async (payload: { actionType: string; target: string; details: Record<string, any> }) => {
      const res = await apiRequest("POST", "/api/scan/remediate", payload);
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: t("scanner.remediationApplied"), description: data.message });
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
    },
    onError: () => {
      toast({ title: t("scanner.remediationFailed"), variant: "destructive" });
    },
  });

  return mutation;
}

function RemediationButton({
  icon: Icon,
  label,
  explanation,
  onClick,
  isPending,
  testId,
}: {
  icon: React.ElementType;
  label: string;
  explanation: string;
  onClick: () => void;
  isPending: boolean;
  testId: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          size="sm"
          variant="outline"
          onClick={onClick}
          disabled={isPending}
          data-testid={testId}
          className="text-[10px] gap-1"
        >
          {isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Icon className="w-3 h-3" />}
          {label}
        </Button>
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-[250px] text-xs">
        {explanation}
      </TooltipContent>
    </Tooltip>
  );
}

function ScannerTab({
  title,
  icon: Icon,
  placeholder,
  scanType,
  endpoint,
  renderResults,
}: {
  title: string;
  icon: React.ElementType;
  placeholder: string;
  scanType: string;
  endpoint: string;
  renderResults: (data: any, target: string) => React.ReactNode;
}) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [target, setTarget] = useState("");
  const [scanResults, setScanResults] = useState<any>(null);
  const [lastTarget, setLastTarget] = useState("");
  const [polling, setPolling] = useState(false);

  const scanMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", endpoint, { target });
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: t("scanner.scanStarted"), description: `${title} - ${target}` });
      setPolling(true);
      setLastTarget(target);
      pollForResults(data.id);
    },
    onError: () => {
      toast({ title: t("scanner.scanFailed"), variant: "destructive" });
    },
  });

  const pollForResults = async (scanId: number) => {
    let attempts = 0;
    const maxAttempts = 30;
    const interval = setInterval(async () => {
      attempts++;
      try {
        const res = await fetch("/api/scan/history");
        const history = await res.json();
        const result = history.find((s: ScanResult) => s.id === scanId);
        if (result && result.status !== "running") {
          clearInterval(interval);
          setPolling(false);
          setScanResults(result.results ? JSON.parse(result.results) : null);
          queryClient.invalidateQueries({ queryKey: ["/api/scan/history"] });
        }
      } catch {}
      if (attempts >= maxAttempts) {
        clearInterval(interval);
        setPolling(false);
      }
    }, 2000);
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search className="absolute start-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={placeholder}
            className="ps-9 font-mono text-xs"
            data-testid={`input-scan-${scanType}`}
            onKeyDown={(e) => e.key === "Enter" && target && scanMutation.mutate()}
          />
        </div>
        <Button
          onClick={() => scanMutation.mutate()}
          disabled={!target || scanMutation.isPending || polling}
          data-testid={`button-scan-${scanType}`}
        >
          {scanMutation.isPending || polling ? (
            <><Loader2 className="w-4 h-4 me-2 animate-spin" />{t("scanner.scanning")}</>
          ) : (
            <><Icon className="w-4 h-4 me-2" />{t("scanner.scan")}</>
          )}
        </Button>
      </div>
      {(scanMutation.isPending || polling) && (
        <Card>
          <CardContent className="p-6 flex items-center justify-center gap-3">
            <Loader2 className="w-5 h-5 animate-spin text-primary" />
            <span className="text-xs text-muted-foreground font-mono">{t("scanner.scanInProgress")}</span>
          </CardContent>
        </Card>
      )}
      {scanResults && !polling && renderResults(scanResults, lastTarget)}
    </div>
  );
}

function PortScanResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const dangerousPorts = data.openPorts?.filter((p: any) => p.risk === "high" || p.risk === "critical" || p.risk === "medium") || [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.portsScanned")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-ports-scanned">{data.portsScanned}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.openPorts")}</p>
          <p className="text-lg font-bold font-mono text-severity-high" data-testid="text-open-ports">{data.openPorts?.length || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.closedPorts")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-closed-ports">{data.closedPorts}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={data.riskLevel || "info"} />
        </CardContent></Card>
      </div>

      {dangerousPorts.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <ShieldBan className="w-4 h-4 text-severity-high" />
              {t("scanner.remediationRecommendations")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-2">
            {dangerousPorts.map((p: any) => (
              <div key={p.port} className="flex items-center justify-between gap-2 p-2 rounded bg-muted/50" data-testid={`remediation-port-${p.port}`}>
                <div className="flex-1">
                  <p className="text-xs font-medium">{t("scanner.portRiskExplanation", { port: p.port, service: p.service })}</p>
                  <p className="text-[10px] text-muted-foreground">{t("scanner.portRiskWhy", { service: p.service })}</p>
                </div>
                <RemediationButton
                  icon={ShieldBan}
                  label={t("scanner.blockPort")}
                  explanation={t("scanner.blockPortExplanation", { port: p.port })}
                  onClick={() => remediation.mutate({ actionType: "block_port", target, details: { port: p.port, service: p.service } })}
                  isPending={remediation.isPending}
                  testId={`button-block-port-${p.port}`}
                />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {data.openPorts?.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("scanner.port")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.service")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.status")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.risk")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.openPorts.map((p: any) => (
                  <TableRow key={p.port} data-testid={`port-row-${p.port}`}>
                    <TableCell className="font-mono text-xs">{p.port}</TableCell>
                    <TableCell className="text-xs">{p.service}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px] text-severity-high border-severity-high">OPEN</Badge></TableCell>
                    <TableCell><SeverityBadge severity={p.risk} /></TableCell>
                    <TableCell>
                      {(p.risk === "high" || p.risk === "critical" || p.risk === "medium") && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="text-[10px] gap-1"
                          onClick={() => remediation.mutate({ actionType: "block_port", target, details: { port: p.port, service: p.service } })}
                          disabled={remediation.isPending}
                          data-testid={`button-block-port-inline-${p.port}`}
                        >
                          <ShieldBan className="w-3 h-3" />
                          {t("scanner.blockPort")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function DNSResults({ data }: { data: any }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.domain")}</p>
          <p className="text-sm font-mono font-bold" data-testid="text-dns-domain">{data.domain}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.totalRecords")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-dns-records">{data.totalRecords}</p>
        </CardContent></Card>
      </div>
      {Object.entries(data.records || {}).map(([type, values]: [string, any]) => (
        <Card key={type}>
          <CardHeader className="pb-1 pt-3 px-4">
            <CardTitle className="text-xs font-mono tracking-wider">{type} {t("scanner.records")}</CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3">
            <div className="space-y-1">
              {values.map((v: string, i: number) => (
                <div key={i} className="text-xs font-mono p-1.5 rounded bg-muted/50" data-testid={`dns-record-${type}-${i}`}>{v}</div>
              ))}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function SSLResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;
  const gradeColor = data.grade === "A" ? "text-green-500" : data.grade === "B" ? "text-blue-500" : data.grade === "C" ? "text-yellow-500" : "text-red-500";

  const hasIssues = data.expired || data.expiringSoon || data.selfSigned || data.grade !== "A";

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.grade")}</p>
          <p className={`text-2xl font-bold font-mono ${gradeColor}`} data-testid="text-ssl-grade">{data.grade}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.daysLeft")}</p>
          <p className={`text-lg font-bold font-mono ${data.daysUntilExpiry < 30 ? "text-severity-high" : ""}`} data-testid="text-ssl-days">{data.daysUntilExpiry}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.protocol")}</p>
          <p className="text-sm font-mono" data-testid="text-ssl-protocol">{data.protocol}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.valid")}</p>
          {data.valid ? <CheckCircle2 className="w-5 h-5 text-green-500 mx-auto" /> : <XCircle className="w-5 h-5 text-red-500 mx-auto" />}
        </CardContent></Card>
      </div>

      {hasIssues && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <ShieldBan className="w-4 h-4 text-severity-high" />
              {t("scanner.remediationRecommendations")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-2">
            {data.expired && (
              <div className="flex items-center justify-between gap-2 p-2 rounded bg-muted/50" data-testid="remediation-ssl-expired">
                <div className="flex-1">
                  <p className="text-xs font-medium">{t("scanner.sslExpiredExplanation")}</p>
                  <p className="text-[10px] text-muted-foreground">{t("scanner.sslExpiredWhy")}</p>
                </div>
                <RemediationButton
                  icon={Bell}
                  label={t("scanner.monitorSSL")}
                  explanation={t("scanner.monitorSSLExplanation")}
                  onClick={() => remediation.mutate({ actionType: "monitor_ssl", target, details: { daysUntilExpiry: data.daysUntilExpiry, expired: true } })}
                  isPending={remediation.isPending}
                  testId="button-monitor-ssl-expired"
                />
              </div>
            )}
            {data.expiringSoon && !data.expired && (
              <div className="flex items-center justify-between gap-2 p-2 rounded bg-muted/50" data-testid="remediation-ssl-expiring">
                <div className="flex-1">
                  <p className="text-xs font-medium">{t("scanner.sslExpiringExplanation", { days: data.daysUntilExpiry })}</p>
                  <p className="text-[10px] text-muted-foreground">{t("scanner.sslExpiringWhy")}</p>
                </div>
                <RemediationButton
                  icon={Bell}
                  label={t("scanner.monitorSSL")}
                  explanation={t("scanner.monitorSSLExplanation")}
                  onClick={() => remediation.mutate({ actionType: "monitor_ssl", target, details: { daysUntilExpiry: data.daysUntilExpiry } })}
                  isPending={remediation.isPending}
                  testId="button-monitor-ssl-expiring"
                />
              </div>
            )}
            {data.selfSigned && (
              <div className="flex items-center justify-between gap-2 p-2 rounded bg-muted/50" data-testid="remediation-ssl-selfsigned">
                <div className="flex-1">
                  <p className="text-xs font-medium">{t("scanner.sslSelfSignedExplanation")}</p>
                  <p className="text-[10px] text-muted-foreground">{t("scanner.sslSelfSignedWhy")}</p>
                </div>
                <RemediationButton
                  icon={Bell}
                  label={t("scanner.monitorSSL")}
                  explanation={t("scanner.monitorSSLExplanation")}
                  onClick={() => remediation.mutate({ actionType: "monitor_ssl", target, details: { daysUntilExpiry: data.daysUntilExpiry, selfSigned: true } })}
                  isPending={remediation.isPending}
                  testId="button-monitor-ssl-selfsigned"
                />
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-4 space-y-2">
          <div className="flex justify-between text-xs"><span className="text-muted-foreground">{t("scanner.issuer")}</span><span className="font-mono" data-testid="text-ssl-issuer">{data.issuer}</span></div>
          <div className="flex justify-between text-xs"><span className="text-muted-foreground">{t("scanner.subject")}</span><span className="font-mono" data-testid="text-ssl-subject">{data.subject}</span></div>
          <div className="flex justify-between text-xs"><span className="text-muted-foreground">{t("scanner.validFrom")}</span><span className="font-mono">{data.validFrom}</span></div>
          <div className="flex justify-between text-xs"><span className="text-muted-foreground">{t("scanner.validTo")}</span><span className="font-mono">{data.validTo}</span></div>
          <div className="flex justify-between text-xs"><span className="text-muted-foreground">{t("scanner.cipher")}</span><span className="font-mono">{data.cipher}</span></div>
          {data.selfSigned && <Badge variant="destructive" className="text-[10px]">{t("scanner.selfSigned")}</Badge>}
          {data.expired && <Badge variant="destructive" className="text-[10px]">{t("scanner.expired")}</Badge>}
          {data.expiringSoon && <Badge className="text-[10px] bg-severity-medium text-black">{t("scanner.expiringSoon")}</Badge>}
        </CardContent>
      </Card>
    </div>
  );
}

function HeaderResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;
  const gradeColor = data.grade === "A" ? "text-green-500" : data.grade === "B" ? "text-blue-500" : data.grade === "C" ? "text-yellow-500" : "text-red-500";

  const missingHeaders = data.headers?.filter((h: any) => h.status === "fail") || [];

  const headerRecommendations: Record<string, string> = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Permitted-Cross-Domain-Policies": "none",
  };

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.grade")}</p>
          <p className={`text-2xl font-bold font-mono ${gradeColor}`} data-testid="text-header-grade">{data.grade}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.score")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-header-score">{data.score}%</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.findings")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-header-findings">{data.findings}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.server")}</p>
          <p className="text-xs font-mono truncate" data-testid="text-header-server">{data.serverInfo}</p>
        </CardContent></Card>
      </div>

      {missingHeaders.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <Info className="w-4 h-4 text-primary" />
              {t("scanner.remediationRecommendations")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-2">
            {missingHeaders.map((h: any) => (
              <div key={h.header} className="p-2 rounded bg-muted/50 space-y-1" data-testid={`remediation-header-${h.header}`}>
                <p className="text-xs font-medium">{t("scanner.missingHeaderExplanation", { header: h.header })}</p>
                <p className="text-[10px] text-muted-foreground">{t("scanner.headerWhyImportant", { description: h.description })}</p>
                <div className="flex items-center gap-2 mt-1">
                  <Lock className="w-3 h-3 text-muted-foreground shrink-0" />
                  <code className="text-[10px] font-mono bg-background p-1 rounded flex-1 overflow-x-auto">
                    {h.header}: {headerRecommendations[h.header] || "recommended-value"}
                  </code>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase">{t("scanner.header")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.status")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.value")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.headers?.map((h: any) => (
                <TableRow key={h.header} data-testid={`header-row-${h.header}`}>
                  <TableCell>
                    <div><span className="text-xs font-mono">{h.header}</span></div>
                    <div className="text-[10px] text-muted-foreground">{h.description}</div>
                  </TableCell>
                  <TableCell>
                    {h.status === "pass" ? <CheckCircle2 className="w-4 h-4 text-green-500" /> :
                      h.status === "warning" ? <AlertTriangle className="w-4 h-4 text-yellow-500" /> :
                        <XCircle className="w-4 h-4 text-red-500" />}
                  </TableCell>
                  <TableCell className="text-[10px] font-mono max-w-[200px] truncate">{h.value}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function VulnResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const dangerousVulns = data.vulnerabilities?.filter((v: any) => v.found && v.severity !== "info") || [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.checksRun")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-vuln-checks">{data.totalChecks}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.findings")}</p>
          <p className="text-lg font-bold font-mono text-severity-high" data-testid="text-vuln-findings">{data.findings}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={data.riskLevel || "info"} />
        </CardContent></Card>
      </div>

      {dangerousVulns.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <ShieldBan className="w-4 h-4 text-severity-high" />
              {t("scanner.remediationRecommendations")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-2">
            {dangerousVulns.map((v: any) => (
              <div key={v.path} className="flex items-center justify-between gap-2 p-2 rounded bg-muted/50" data-testid={`remediation-vuln-${v.path}`}>
                <div className="flex-1">
                  <p className="text-xs font-medium">{t("scanner.vulnPathExplanation", { name: v.name, path: v.path })}</p>
                  <p className="text-[10px] text-muted-foreground">{t("scanner.vulnPathWhy", { name: v.name })}</p>
                </div>
                <RemediationButton
                  icon={ShieldBan}
                  label={t("scanner.blockPath")}
                  explanation={t("scanner.blockPathExplanation", { path: v.path })}
                  onClick={() => remediation.mutate({ actionType: "block_path", target, details: { path: v.path, name: v.name, severity: v.severity } })}
                  isPending={remediation.isPending}
                  testId={`button-block-path-${v.path}`}
                />
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase">{t("scanner.path")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.name")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.status")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.severity")}</TableHead>
                <TableHead className="text-[10px] uppercase">{t("common.action")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.vulnerabilities?.filter((v: any) => v.found || v.severity !== "info").map((v: any) => (
                <TableRow key={v.path} data-testid={`vuln-row-${v.path}`}>
                  <TableCell className="font-mono text-xs">{v.path}</TableCell>
                  <TableCell className="text-xs">{v.name}</TableCell>
                  <TableCell>
                    {v.found ? <Badge variant="destructive" className="text-[10px]">{t("scanner.found")}</Badge> :
                      <Badge variant="secondary" className="text-[10px]">{t("scanner.notFound")}</Badge>}
                  </TableCell>
                  <TableCell><SeverityBadge severity={v.severity} /></TableCell>
                  <TableCell>
                    {v.found && v.severity !== "info" && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="text-[10px] gap-1"
                        onClick={() => remediation.mutate({ actionType: "block_path", target, details: { path: v.path, name: v.name, severity: v.severity } })}
                        disabled={remediation.isPending}
                        data-testid={`button-block-path-inline-${v.path}`}
                      >
                        <ShieldBan className="w-3 h-3" />
                        {t("scanner.blockPath")}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function SubdomainResults({ data }: { data: any }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const interestingPrefixes = ["admin", "staging", "dev", "api", "test", "beta", "internal", "vpn", "db", "dashboard", "jenkins", "git"];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.domain")}</p>
          <p className="text-sm font-mono font-bold" data-testid="text-subdomain-domain">{data.domain}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.subdomainsFound")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-subdomains-count">{data.totalFound || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">DNS</p>
          <p className="text-lg font-bold font-mono" data-testid="text-subdomains-dns">{data.sources?.dns || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">crt.sh</p>
          <p className="text-lg font-bold font-mono" data-testid="text-subdomains-crtsh">{data.sources?.crtsh || 0}</p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{t("scanner.subdomainWhatThisMeans")}</p>
        </CardContent>
      </Card>

      {data.subdomains?.length > 0 ? (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("scanner.subdomain")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.ipAddress")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.source")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.status")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.subdomains.map((s: any, i: number) => {
                  const isInteresting = interestingPrefixes.some(p => s.subdomain?.startsWith(p + "."));
                  return (
                    <TableRow key={i} data-testid={`subdomain-row-${i}`}>
                      <TableCell className="font-mono text-xs">{s.subdomain}</TableCell>
                      <TableCell className="font-mono text-xs">{s.ips?.join(", ") || "-"}</TableCell>
                      <TableCell><Badge variant="outline" className="text-[10px]">{s.source}</Badge></TableCell>
                      <TableCell>
                        {isInteresting && <Badge className="text-[10px] bg-severity-medium text-black">{t("scanner.interesting")}</Badge>}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <Card><CardContent className="p-4 text-center text-xs text-muted-foreground">{t("scanner.noSubdomains")}</CardContent></Card>
      )}
    </div>
  );
}

function DirBruteResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const foundPaths = data.foundPaths?.filter((p: any) => p.found) || [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.dirPathsFound")}</p>
          <p className="text-lg font-bold font-mono text-severity-high" data-testid="text-dir-found">{foundPaths.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.checksRun")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-dir-total">{data.totalScanned || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={data.riskLevel || "info"} />
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("common.time")}</p>
          <p className="text-sm font-mono" data-testid="text-dir-duration">{data.scanDuration ? `${(data.scanDuration / 1000).toFixed(1)}s` : "-"}</p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{t("scanner.dirWhatThisMeans")}</p>
        </CardContent>
      </Card>

      {foundPaths.length > 0 ? (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("scanner.path")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.statusCode")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.size")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.category")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.severity")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.action")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {foundPaths.map((p: any, i: number) => (
                  <TableRow key={i} data-testid={`dir-row-${i}`}>
                    <TableCell className="font-mono text-xs">{p.path}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px] font-mono">{p.statusCode}</Badge></TableCell>
                    <TableCell className="text-xs font-mono">{p.contentLength ? `${p.contentLength}B` : "-"}</TableCell>
                    <TableCell><Badge variant="secondary" className="text-[10px]">{p.category}</Badge></TableCell>
                    <TableCell><SeverityBadge severity={p.severity} /></TableCell>
                    <TableCell>
                      {(p.severity === "high" || p.severity === "critical") && (
                        <RemediationButton
                          icon={ShieldBan}
                          label={t("scanner.blockThisPath")}
                          explanation={t("scanner.blockPathExplanation", { path: p.path })}
                          onClick={() => remediation.mutate({ actionType: "block_path", target, details: { path: p.path, severity: p.severity } })}
                          isPending={remediation.isPending}
                          testId={`button-block-dir-${i}`}
                        />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <Card><CardContent className="p-4 text-center text-xs text-muted-foreground">{t("scanner.noDirResults")}</CardContent></Card>
      )}
    </div>
  );
}

function TechFPResults({ data }: { data: any }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const categoryLabels: Record<string, string> = {
    webServer: t("scanner.webServer"),
    language: t("scanner.language"),
    framework: t("scanner.framework"),
    cms: t("scanner.cms"),
    cdn: t("scanner.cdn"),
    jsLibrary: t("scanner.jsLibrary"),
  };

  const technologies = data.technologies || [];

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.technologyDetected")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-tech-count">{technologies.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.server")}</p>
          <p className="text-sm font-mono truncate" data-testid="text-tech-server">{data.serverHeader || "-"}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={data.riskLevel || "info"} />
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{t("scanner.techWhatThisMeans")}</p>
        </CardContent>
      </Card>

      {technologies.length > 0 ? (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("scanner.category")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.technology")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.version")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.confidence")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {technologies.map((tech: any, i: number) => (
                  <TableRow key={i} data-testid={`tech-row-${i}`}>
                    <TableCell><Badge variant="secondary" className="text-[10px]">{categoryLabels[tech.category] || tech.category}</Badge></TableCell>
                    <TableCell className="text-xs font-medium">{tech.name}</TableCell>
                    <TableCell className="text-xs font-mono">{tech.version || "-"}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[10px] ${tech.confidence === "high" ? "border-green-500 text-green-600" : tech.confidence === "medium" ? "border-yellow-500 text-yellow-600" : ""}`}>
                        {tech.confidence || "low"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : (
        <Card><CardContent className="p-4 text-center text-xs text-muted-foreground">{t("scanner.noTechDetected")}</CardContent></Card>
      )}
    </div>
  );
}

function WAFResults({ data }: { data: any }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const wafDetected = data.detected || data.wafDetected;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.wafDetected")}</p>
          {wafDetected ? <CheckCircle2 className="w-5 h-5 text-green-500 mx-auto" data-testid="icon-waf-detected" /> : <XCircle className="w-5 h-5 text-severity-high mx-auto" data-testid="icon-waf-not-detected" />}
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.wafType")}</p>
          <p className="text-sm font-mono font-bold" data-testid="text-waf-type">{data.wafName || data.wafType || "-"}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.wafConfidence")}</p>
          <Badge variant="outline" className={`text-[10px] ${data.confidence === "high" ? "border-green-500 text-green-600" : data.confidence === "medium" ? "border-yellow-500 text-yellow-600" : ""}`} data-testid="text-waf-confidence">
            {data.confidence || "-"}
          </Badge>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{wafDetected ? t("scanner.wafWhatThisMeans") : t("scanner.noWafDetected")}</p>
        </CardContent>
      </Card>

      {wafDetected && data.bypassSuggestions?.length > 0 && (
        <Card>
          <CardHeader className="pb-2 pt-3 px-4">
            <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-severity-medium" />
              {t("scanner.bypassSuggestions")}
            </CardTitle>
          </CardHeader>
          <CardContent className="px-4 pb-3 space-y-1">
            {data.bypassSuggestions.map((suggestion: string, i: number) => (
              <div key={i} className="text-xs p-2 rounded bg-muted/50" data-testid={`waf-bypass-${i}`}>{suggestion}</div>
            ))}
          </CardContent>
        </Card>
      )}

      {data.signatures?.length > 0 && (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("scanner.whatThisMeans")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.confidence")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.signatures.map((sig: any, i: number) => (
                  <TableRow key={i} data-testid={`waf-sig-${i}`}>
                    <TableCell className="text-xs">{sig.description || sig.name}</TableCell>
                    <TableCell><Badge variant="outline" className="text-[10px]">{sig.confidence}</Badge></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function WHOISResults({ data }: { data: any }) {
  const { t } = useTranslation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const fields = [
    { label: t("scanner.domain"), value: data.domain, testId: "text-whois-domain" },
    { label: t("scanner.registrar"), value: data.registrar, testId: "text-whois-registrar" },
    { label: t("scanner.registrantOrg"), value: data.registrantOrg || data.registrant, testId: "text-whois-registrant" },
    { label: t("scanner.creationDate"), value: data.creationDate, testId: "text-whois-created" },
    { label: t("scanner.expiryDate"), value: data.expiryDate, testId: "text-whois-expiry" },
    { label: t("scanner.nameservers"), value: Array.isArray(data.nameservers) ? data.nameservers.join(", ") : data.nameservers, testId: "text-whois-ns" },
  ].filter(f => f.value);

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{t("scanner.whoisWhatThisMeans")}</p>
        </CardContent>
      </Card>

      {fields.length > 0 ? (
        <Card>
          <CardContent className="p-4 space-y-2">
            {fields.map((f) => (
              <div key={f.testId} className="flex justify-between gap-2 text-xs">
                <span className="text-muted-foreground shrink-0">{f.label}</span>
                <span className="font-mono text-end" data-testid={f.testId}>{f.value}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : (
        <Card><CardContent className="p-4 text-center text-xs text-muted-foreground">{t("scanner.noWhoisData")}</CardContent></Card>
      )}
    </div>
  );
}

function SQLiResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const vulnerabilities = data.findings || data.vulnerabilities || [];
  const hasVulns = vulnerabilities.length > 0;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.sqliVulnerabilities")}</p>
          <p className={`text-lg font-bold font-mono ${hasVulns ? "text-severity-high" : ""}`} data-testid="text-sqli-count">{vulnerabilities.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.checksRun")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-sqli-checks">{data.totalTests || data.payloadsTested || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={hasVulns ? "critical" : "info"} />
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{hasVulns ? t("scanner.sqliWhatThisMeans") : t("scanner.noSqliFound")}</p>
        </CardContent>
      </Card>

      {hasVulns && (
        <div className="space-y-3">
          {vulnerabilities.map((v: any, i: number) => (
            <Card key={i} data-testid={`sqli-vuln-${i}`}>
              <CardHeader className="pb-2 pt-3 px-4">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <CardTitle className="text-xs font-medium flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-severity-critical" />
                    {v.type || v.vulnerabilityType || "SQL Injection"}
                  </CardTitle>
                  <SeverityBadge severity={v.severity || "critical"} />
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-2">
                <div className="text-xs space-y-1">
                  <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.payload")}:</span><code className="font-mono bg-muted/50 px-1 rounded break-all">{v.payload}</code></div>
                  {v.parameter && <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.context")}:</span><span className="font-mono">{v.parameter}</span></div>}
                  {v.evidence && <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.found")}:</span><span className="font-mono text-severity-high">{v.evidence}</span></div>}
                </div>
                <div className="p-2 rounded bg-muted/50">
                  <p className="text-[10px] text-muted-foreground font-medium uppercase mb-1">{t("scanner.remediation")}</p>
                  <p className="text-xs">{t("scanner.sqliRemediation")}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <RemediationButton
                    icon={Bell}
                    label={t("scanner.createAlertRule")}
                    explanation={t("scanner.sqliRemediation")}
                    onClick={() => remediation.mutate({ actionType: "create_alert", target, details: { type: "sqli", payload: v.payload, parameter: v.parameter } })}
                    isPending={remediation.isPending}
                    testId={`button-sqli-alert-${i}`}
                  />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

function XSSResults({ data, target }: { data: any; target: string }) {
  const { t } = useTranslation();
  const remediation = useRemediation();
  if (data.error) return <Card><CardContent className="p-4 text-xs text-destructive">{data.error}</CardContent></Card>;

  const vulnerabilities = data.findings || data.vulnerabilities || [];
  const hasVulns = vulnerabilities.length > 0;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.xssVulnerabilities")}</p>
          <p className={`text-lg font-bold font-mono ${hasVulns ? "text-severity-high" : ""}`} data-testid="text-xss-count">{vulnerabilities.length}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.checksRun")}</p>
          <p className="text-lg font-bold font-mono" data-testid="text-xss-checks">{data.totalTests || data.payloadsTested || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-3 text-center">
          <p className="text-[10px] text-muted-foreground uppercase">{t("scanner.riskLevel")}</p>
          <SeverityBadge severity={hasVulns ? "high" : "info"} />
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-medium tracking-wider uppercase flex items-center gap-2">
            <Info className="w-4 h-4 text-primary" />
            {t("scanner.whatThisMeans")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-3">
          <p className="text-xs text-muted-foreground">{hasVulns ? t("scanner.xssWhatThisMeans") : t("scanner.noXssFound")}</p>
        </CardContent>
      </Card>

      {hasVulns && (
        <div className="space-y-3">
          {vulnerabilities.map((v: any, i: number) => (
            <Card key={i} data-testid={`xss-vuln-${i}`}>
              <CardHeader className="pb-2 pt-3 px-4">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <CardTitle className="text-xs font-medium flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-severity-high" />
                    {v.type || "XSS"}
                  </CardTitle>
                  <SeverityBadge severity={v.severity || "high"} />
                </div>
              </CardHeader>
              <CardContent className="px-4 pb-3 space-y-2">
                <div className="text-xs space-y-1">
                  <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.payload")}:</span><code className="font-mono bg-muted/50 px-1 rounded break-all">{v.payload}</code></div>
                  {v.parameter && <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.injectionPoint")}:</span><span className="font-mono">{v.parameter}</span></div>}
                  {v.context && <div className="flex gap-2"><span className="text-muted-foreground shrink-0">{t("scanner.xssContext")}:</span><Badge variant="outline" className="text-[10px]">{v.context}</Badge></div>}
                </div>
                <div className="p-2 rounded bg-muted/50">
                  <p className="text-[10px] text-muted-foreground font-medium uppercase mb-1">{t("scanner.remediation")}</p>
                  <p className="text-xs">{t("scanner.xssRemediation")}</p>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <RemediationButton
                    icon={Bell}
                    label={t("scanner.createAlertRule")}
                    explanation={t("scanner.xssRemediation")}
                    onClick={() => remediation.mutate({ actionType: "create_alert", target, details: { type: "xss", payload: v.payload, parameter: v.parameter } })}
                    isPending={remediation.isPending}
                    testId={`button-xss-alert-${i}`}
                  />
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}

export default function ScannerPage() {
  const { t } = useTranslation();
  const { data: history, isLoading } = useQuery<ScanResult[]>({ queryKey: ["/api/scan/history"] });
  const [tabGroup, setTabGroup] = useState<"recon" | "attack">("recon");

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase" data-testid="text-scanner-title">{t("scanner.title")}</h1>
        <p className="text-xs text-muted-foreground">{t("scanner.subtitle")}</p>
      </div>

      <div className="flex gap-2">
        <Button
          variant={tabGroup === "recon" ? "default" : "outline"}
          size="sm"
          onClick={() => setTabGroup("recon")}
          data-testid="button-group-recon"
        >
          <Search className="w-3.5 h-3.5 me-1.5" />
          {t("scanner.reconnaissance")}
        </Button>
        <Button
          variant={tabGroup === "attack" ? "default" : "outline"}
          size="sm"
          onClick={() => setTabGroup("attack")}
          data-testid="button-group-attack"
        >
          <Bug className="w-3.5 h-3.5 me-1.5" />
          {t("scanner.attack")}
        </Button>
      </div>

      {tabGroup === "recon" && (
        <Tabs defaultValue="ports" className="space-y-4">
          <TabsList className="w-full justify-start flex-wrap h-auto gap-1 bg-transparent p-0">
            <TabsTrigger value="ports" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-ports">
              <Radar className="w-3.5 h-3.5 me-1.5" />{t("scanner.portScanner")}
            </TabsTrigger>
            <TabsTrigger value="dns" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-dns">
              <Globe className="w-3.5 h-3.5 me-1.5" />{t("scanner.dnsLookup")}
            </TabsTrigger>
            <TabsTrigger value="ssl" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-ssl">
              <ShieldCheck className="w-3.5 h-3.5 me-1.5" />{t("scanner.sslChecker")}
            </TabsTrigger>
            <TabsTrigger value="headers" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-headers">
              <FileSearch className="w-3.5 h-3.5 me-1.5" />{t("scanner.headerAudit")}
            </TabsTrigger>
            <TabsTrigger value="vuln" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-vuln">
              <Bug className="w-3.5 h-3.5 me-1.5" />{t("scanner.vulnScan")}
            </TabsTrigger>
            <TabsTrigger value="subdomains" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-subdomains">
              <Network className="w-3.5 h-3.5 me-1.5" />{t("scanner.subdomains")}
            </TabsTrigger>
            <TabsTrigger value="dirbrute" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-dirbrute">
              <FolderSearch className="w-3.5 h-3.5 me-1.5" />{t("scanner.dirBruteforce")}
            </TabsTrigger>
            <TabsTrigger value="techfp" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-techfp">
              <Cpu className="w-3.5 h-3.5 me-1.5" />{t("scanner.techFingerprint")}
            </TabsTrigger>
            <TabsTrigger value="whois" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-whois">
              <Landmark className="w-3.5 h-3.5 me-1.5" />{t("scanner.whois")}
            </TabsTrigger>
            <TabsTrigger value="waf" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-waf">
              <Shield className="w-3.5 h-3.5 me-1.5" />{t("scanner.wafDetect")}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="ports">
            <ScannerTab
              title={t("scanner.portScanner")}
              icon={Radar}
              placeholder={t("scanner.portPlaceholder")}
              scanType="ports"
              endpoint="/api/scan/ports"
              renderResults={(data, target) => <PortScanResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="dns">
            <ScannerTab
              title={t("scanner.dnsLookup")}
              icon={Globe}
              placeholder={t("scanner.dnsPlaceholder")}
              scanType="dns"
              endpoint="/api/scan/dns"
              renderResults={(data) => <DNSResults data={data} />}
            />
          </TabsContent>

          <TabsContent value="ssl">
            <ScannerTab
              title={t("scanner.sslChecker")}
              icon={ShieldCheck}
              placeholder={t("scanner.sslPlaceholder")}
              scanType="ssl"
              endpoint="/api/scan/ssl"
              renderResults={(data, target) => <SSLResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="headers">
            <ScannerTab
              title={t("scanner.headerAudit")}
              icon={FileSearch}
              placeholder={t("scanner.headerPlaceholder")}
              scanType="headers"
              endpoint="/api/scan/headers"
              renderResults={(data, target) => <HeaderResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="vuln">
            <ScannerTab
              title={t("scanner.vulnScan")}
              icon={Bug}
              placeholder={t("scanner.vulnPlaceholder")}
              scanType="vuln"
              endpoint="/api/scan/vulnerabilities"
              renderResults={(data, target) => <VulnResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="subdomains">
            <ScannerTab
              title={t("scanner.subdomains")}
              icon={Network}
              placeholder={t("scanner.subdomainPlaceholder")}
              scanType="subdomains"
              endpoint="/api/scan/subdomains"
              renderResults={(data) => <SubdomainResults data={data} />}
            />
          </TabsContent>

          <TabsContent value="dirbrute">
            <ScannerTab
              title={t("scanner.dirBruteforce")}
              icon={FolderSearch}
              placeholder={t("scanner.dirBrutePlaceholder")}
              scanType="dirbrute"
              endpoint="/api/scan/dirbrute"
              renderResults={(data, target) => <DirBruteResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="techfp">
            <ScannerTab
              title={t("scanner.techFingerprint")}
              icon={Cpu}
              placeholder={t("scanner.techFpPlaceholder")}
              scanType="techfp"
              endpoint="/api/scan/techfp"
              renderResults={(data) => <TechFPResults data={data} />}
            />
          </TabsContent>

          <TabsContent value="whois">
            <ScannerTab
              title={t("scanner.whois")}
              icon={Landmark}
              placeholder={t("scanner.whoisPlaceholder")}
              scanType="whois"
              endpoint="/api/scan/whois"
              renderResults={(data) => <WHOISResults data={data} />}
            />
          </TabsContent>

          <TabsContent value="waf">
            <ScannerTab
              title={t("scanner.wafDetect")}
              icon={Shield}
              placeholder={t("scanner.wafPlaceholder")}
              scanType="waf"
              endpoint="/api/scan/waf"
              renderResults={(data) => <WAFResults data={data} />}
            />
          </TabsContent>
        </Tabs>
      )}

      {tabGroup === "attack" && (
        <Tabs defaultValue="sqli" className="space-y-4">
          <TabsList className="w-full justify-start flex-wrap h-auto gap-1 bg-transparent p-0">
            <TabsTrigger value="sqli" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-sqli">
              <Database className="w-3.5 h-3.5 me-1.5" />{t("scanner.sqliTest")}
            </TabsTrigger>
            <TabsTrigger value="xss" className="text-xs data-[state=active]:bg-primary/10" data-testid="tab-xss">
              <Code className="w-3.5 h-3.5 me-1.5" />{t("scanner.xssTest")}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="sqli">
            <ScannerTab
              title={t("scanner.sqliTest")}
              icon={Database}
              placeholder={t("scanner.sqliPlaceholder")}
              scanType="sqli"
              endpoint="/api/scan/sqli"
              renderResults={(data, target) => <SQLiResults data={data} target={target} />}
            />
          </TabsContent>

          <TabsContent value="xss">
            <ScannerTab
              title={t("scanner.xssTest")}
              icon={Code}
              placeholder={t("scanner.xssPlaceholder")}
              scanType="xss"
              endpoint="/api/scan/xss"
              renderResults={(data, target) => <XSSResults data={data} target={target} />}
            />
          </TabsContent>
        </Tabs>
      )}

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Clock className="w-4 h-4 text-primary" />{t("scanner.scanHistory")}
            </CardTitle>
            {history && history.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => generateScannerReportPDF(history)}
                data-testid="button-export-scanner-pdf"
              >
                <Download className="w-3.5 h-3.5 me-1.5" />
                Export PDF
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading ? (
            <div className="p-4"><Skeleton className="h-20 w-full" /></div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase">{t("common.type")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.target")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.status")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("scanner.findings")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.severity")}</TableHead>
                  <TableHead className="text-[10px] uppercase">{t("common.time")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {history?.length === 0 && (
                  <TableRow><TableCell colSpan={6} className="text-center text-xs text-muted-foreground py-6">{t("scanner.noScans")}</TableCell></TableRow>
                )}
                {history?.map((scan) => (
                  <TableRow key={scan.id} data-testid={`scan-history-${scan.id}`}>
                    <TableCell><Badge variant="outline" className="text-[10px] font-mono">{scan.scanType}</Badge></TableCell>
                    <TableCell className="text-xs font-mono">{scan.target}</TableCell>
                    <TableCell>
                      <Badge variant={scan.status === "completed" ? "default" : scan.status === "failed" ? "destructive" : "secondary"} className="text-[10px]">
                        {scan.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono">{scan.findings ?? "-"}</TableCell>
                    <TableCell>{scan.severity ? <SeverityBadge severity={scan.severity} /> : "-"}</TableCell>
                    <TableCell className="text-[10px] text-muted-foreground font-mono">
                      {new Date(scan.createdAt!).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
