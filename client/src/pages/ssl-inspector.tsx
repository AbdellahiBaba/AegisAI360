import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Loader2, Search, Shield, ShieldCheck, ShieldX, Clock, Link2, AlertTriangle, CheckCircle, Info, Lock } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

interface ChainCert {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  signatureAlgorithm: string;
  isCA: boolean;
  depth: number;
}

interface SSLResult {
  domain: string;
  ip: string;
  port: number;
  grade: string;
  gradeColor: string;
  certificate: {
    subject: Record<string, string>;
    issuer: Record<string, string>;
    validFrom: string;
    validTo: string;
    serialNumber: string;
    fingerprint: string;
    fingerprint256: string;
    keySize: number;
    signatureAlgorithm: string;
    subjectAltNames: string[];
    isCA: boolean;
  };
  chain: ChainCert[];
  protocols: Record<string, boolean>;
  daysUntilExpiration: number;
  isExpired: boolean;
  isSelfSigned: boolean;
  hasHSTS: boolean;
  findings: Finding[];
  recommendations: string[];
  scannedAt: string;
}

const severityConfig: Record<string, { color: string; icon: typeof AlertTriangle }> = {
  critical: { color: "bg-red-500/10 text-red-500 border-red-500/20", icon: ShieldX },
  high: { color: "bg-orange-500/10 text-orange-500 border-orange-500/20", icon: AlertTriangle },
  medium: { color: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20", icon: AlertTriangle },
  low: { color: "bg-blue-500/10 text-blue-500 border-blue-500/20", icon: Info },
  info: { color: "bg-green-500/10 text-green-500 border-green-500/20", icon: CheckCircle },
};

export default function SSLInspectorPage() {
  const [domain, setDomain] = useState("");
  const { toast } = useToast();

  const inspectMutation = useMutation({
    mutationFn: async (target: string) => {
      const res = await apiRequest("POST", "/api/ssl/inspect", { domain: target });
      return res.json() as Promise<SSLResult>;
    },
    onError: (error: Error) => {
      toast({
        title: "Inspection Failed",
        description: error.message,
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) return;
    inspectMutation.mutate(domain.trim());
  };

  const result = inspectMutation.data;

  return (
    <div className="p-4 space-y-4 max-w-6xl mx-auto">
      <div className="flex items-center gap-3 flex-wrap">
        <Lock className="w-5 h-5 text-primary" />
        <h1 className="text-lg font-bold" data-testid="text-page-title">SSL/TLS Certificate Inspector</h1>
      </div>
      <p className="text-sm text-muted-foreground">
        Analyze SSL/TLS certificate security, protocol support, and configuration for any public domain.
      </p>

      <Card>
        <CardContent className="pt-4">
          <form onSubmit={handleSubmit} className="flex gap-2 flex-wrap">
            <Input
              placeholder="Enter domain (e.g., example.com)"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="flex-1 min-w-[200px]"
              data-testid="input-domain"
            />
            <Button type="submit" disabled={inspectMutation.isPending || !domain.trim()} data-testid="button-inspect">
              {inspectMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Search className="w-4 h-4" />
              )}
              <span className="ml-1">Inspect</span>
            </Button>
          </form>
        </CardContent>
      </Card>

      {inspectMutation.isPending && (
        <Card>
          <CardContent className="flex items-center justify-center py-12 gap-3">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
            <span className="text-sm text-muted-foreground">Connecting to {domain} and analyzing certificate...</span>
          </CardContent>
        </Card>
      )}

      {result && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card>
              <CardContent className="pt-4 flex flex-col items-center gap-2">
                <div
                  className="w-20 h-20 rounded-full flex items-center justify-center text-3xl font-bold text-white"
                  style={{ backgroundColor: result.gradeColor }}
                  data-testid="text-grade"
                >
                  {result.grade}
                </div>
                <span className="text-sm font-medium">Security Grade</span>
                <span className="text-xs text-muted-foreground">{result.domain}</span>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-4 space-y-2">
                <div className="flex items-center gap-2">
                  <Clock className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Certificate Validity</span>
                </div>
                <div className="space-y-1">
                  <div className="flex justify-between gap-2 text-xs">
                    <span className="text-muted-foreground">Valid From</span>
                    <span data-testid="text-valid-from">{new Date(result.certificate.validFrom).toLocaleDateString()}</span>
                  </div>
                  <div className="flex justify-between gap-2 text-xs">
                    <span className="text-muted-foreground">Valid To</span>
                    <span data-testid="text-valid-to">{new Date(result.certificate.validTo).toLocaleDateString()}</span>
                  </div>
                  <div className="flex justify-between gap-2 text-xs">
                    <span className="text-muted-foreground">Days Left</span>
                    <Badge
                      variant={result.isExpired ? "destructive" : result.daysUntilExpiration < 30 ? "secondary" : "default"}
                      data-testid="text-days-left"
                    >
                      {result.isExpired ? "EXPIRED" : `${result.daysUntilExpiration} days`}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="pt-4 space-y-2">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm font-medium">Protocol Support</span>
                </div>
                <div className="space-y-1">
                  {Object.entries(result.protocols).map(([proto, supported]) => (
                    <div key={proto} className="flex justify-between gap-2 text-xs items-center">
                      <span className="text-muted-foreground">{proto}</span>
                      <Badge
                        variant={supported ? (proto.includes("1.0") || proto.includes("1.1") ? "secondary" : "default") : "outline"}
                        data-testid={`badge-proto-${proto.replace(/\s+/g, "-").toLowerCase()}`}
                      >
                        {supported ? (proto.includes("1.0") || proto.includes("1.1") ? "Deprecated" : "Supported") : "Not Supported"}
                      </Badge>
                    </div>
                  ))}
                  <div className="flex justify-between gap-2 text-xs items-center">
                    <span className="text-muted-foreground">HSTS</span>
                    <Badge variant={result.hasHSTS ? "default" : "outline"} data-testid="badge-hsts">
                      {result.hasHSTS ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" />
                Certificate Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <DetailRow label="Subject" value={Object.values(result.certificate.subject).join(", ") || "N/A"} testId="text-subject" />
                <DetailRow label="Issuer" value={Object.values(result.certificate.issuer).join(", ") || "N/A"} testId="text-issuer" />
                <DetailRow label="Key Size" value={`${result.certificate.keySize} bits`} testId="text-key-size" />
                <DetailRow label="Signature Algorithm" value={result.certificate.signatureAlgorithm} testId="text-sig-alg" />
                <DetailRow label="Serial Number" value={result.certificate.serialNumber} testId="text-serial" />
                <DetailRow label="IP Address" value={result.ip} testId="text-ip" />
                <DetailRow label="Fingerprint (SHA-1)" value={result.certificate.fingerprint} testId="text-fingerprint" />
                <DetailRow label="Fingerprint (SHA-256)" value={result.certificate.fingerprint256} testId="text-fingerprint256" />
              </div>
              {result.certificate.subjectAltNames.length > 0 && (
                <div className="mt-3">
                  <span className="text-xs text-muted-foreground block mb-1">Subject Alternative Names</span>
                  <div className="flex flex-wrap gap-1">
                    {result.certificate.subjectAltNames.slice(0, 20).map((san, i) => (
                      <Badge key={i} variant="outline" className="text-[10px]" data-testid={`badge-san-${i}`}>
                        {san}
                      </Badge>
                    ))}
                    {result.certificate.subjectAltNames.length > 20 && (
                      <Badge variant="secondary" className="text-[10px]">
                        +{result.certificate.subjectAltNames.length - 20} more
                      </Badge>
                    )}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {result.chain.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Link2 className="w-4 h-4" />
                  Certificate Chain ({result.chain.length} certificates)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {result.chain.map((cert, i) => (
                    <div
                      key={i}
                      className="flex items-start gap-3 p-2 rounded-md border text-xs"
                      data-testid={`card-chain-cert-${i}`}
                    >
                      <div className="flex flex-col items-center gap-1 min-w-[60px]">
                        <Badge variant={i === 0 ? "default" : "secondary"} className="text-[10px]">
                          {i === 0 ? "Leaf" : i === result.chain.length - 1 ? "Root" : "Intermediate"}
                        </Badge>
                        <span className="text-muted-foreground text-[10px]">Depth {cert.depth}</span>
                      </div>
                      <div className="flex-1 space-y-0.5 min-w-0">
                        <div className="font-medium truncate">{cert.subject}</div>
                        <div className="text-muted-foreground truncate">Issued by: {cert.issuer}</div>
                        <div className="text-muted-foreground">
                          Valid: {new Date(cert.validFrom).toLocaleDateString()} - {new Date(cert.validTo).toLocaleDateString()}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Findings ({result.findings.length})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {result.findings.map((finding, i) => {
                  const config = severityConfig[finding.severity] || severityConfig.info;
                  const IconComp = config.icon;
                  return (
                    <div
                      key={finding.id + i}
                      className={`flex items-start gap-3 p-3 rounded-md border ${config.color}`}
                      data-testid={`card-finding-${i}`}
                    >
                      <IconComp className="w-4 h-4 mt-0.5 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-medium">{finding.title}</span>
                          <Badge variant="outline" className="text-[10px] uppercase">
                            {finding.severity}
                          </Badge>
                        </div>
                        <p className="text-xs mt-0.5 opacity-80">{finding.description}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {result.recommendations.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <CheckCircle className="w-4 h-4" />
                  Recommendations
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1.5">
                  {result.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2 text-sm" data-testid={`text-rec-${i}`}>
                      <span className="text-primary mt-0.5">&#8226;</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          <div className="text-xs text-muted-foreground text-center">
            Scanned at {new Date(result.scannedAt).toLocaleString()}
          </div>
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value, testId }: { label: string; value: string; testId: string }) {
  return (
    <div className="space-y-0.5">
      <span className="text-xs text-muted-foreground">{label}</span>
      <p className="text-xs font-mono break-all" data-testid={testId}>{value}</p>
    </div>
  );
}
