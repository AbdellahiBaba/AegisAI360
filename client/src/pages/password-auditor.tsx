import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Separator } from "@/components/ui/separator";
import {
  KeyRound, Shield, AlertTriangle, CheckCircle2, XCircle,
  Clock, Copy, RefreshCw, Eye, EyeOff, Search, Loader2,
  FileText, Lock, Zap, Download,
} from "lucide-react";
import { generatePasswordAuditReportPDF } from "@/lib/reportGenerator";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface AnalysisResult {
  score: number;
  strength: string;
  strengthColor: string;
  entropy: number;
  composition: {
    length: number;
    uppercase: number;
    lowercase: number;
    digits: number;
    special: number;
    spaces: number;
    uniqueChars: number;
  };
  crackTime: {
    onlineThrottled: string;
    onlineUnthrottled: string;
    offlineSlow: string;
    offlineFast: string;
    gpuCluster: string;
  };
  weaknesses: string[];
  suggestions: string[];
  patterns: string[];
  isCommon: boolean;
  nistCompliance: {
    compliant: boolean;
    checks: Array<{ rule: string; passed: boolean; description: string }>;
  };
}

interface BreachResult {
  breached: boolean;
  occurrences: number;
  message: string;
}

interface PolicyAuditResult {
  overallScore: number;
  grade: string;
  findings: Array<{
    category: string;
    rule: string;
    status: "pass" | "fail" | "warning";
    recommendation: string;
    nistReference: string;
  }>;
  summary: { total: number; pass: number; warning: number; fail: number };
}

function getScoreColor(score: number): string {
  if (score >= 90) return "text-emerald-500";
  if (score >= 70) return "text-green-500";
  if (score >= 50) return "text-yellow-500";
  if (score >= 30) return "text-orange-500";
  return "text-red-500";
}

function getScoreBg(score: number): string {
  if (score >= 90) return "bg-emerald-500";
  if (score >= 70) return "bg-green-500";
  if (score >= 50) return "bg-yellow-500";
  if (score >= 30) return "bg-orange-500";
  return "bg-red-500";
}

function getGradeBadgeVariant(grade: string): "default" | "secondary" | "destructive" | "outline" {
  if (grade === "A") return "default";
  if (grade === "B") return "secondary";
  return "destructive";
}

export default function PasswordAuditorPage() {
  useDocumentTitle("Password Auditor");
  const { toast } = useToast();
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [breachResult, setBreachResult] = useState<BreachResult | null>(null);
  const [policyResult, setPolicyResult] = useState<PolicyAuditResult | null>(null);
  const [generatedPasswords, setGeneratedPasswords] = useState<string[]>([]);

  const [genLength, setGenLength] = useState(16);
  const [genUppercase, setGenUppercase] = useState(true);
  const [genLowercase, setGenLowercase] = useState(true);
  const [genDigits, setGenDigits] = useState(true);
  const [genSpecial, setGenSpecial] = useState(true);
  const [genExcludeAmbiguous, setGenExcludeAmbiguous] = useState(false);

  const [policyMinLength, setPolicyMinLength] = useState(8);
  const [policyMaxLength, setPolicyMaxLength] = useState(64);
  const [policyRequireUpper, setPolicyRequireUpper] = useState(true);
  const [policyRequireLower, setPolicyRequireLower] = useState(true);
  const [policyRequireDigits, setPolicyRequireDigits] = useState(true);
  const [policyRequireSpecial, setPolicyRequireSpecial] = useState(true);
  const [policyPreventCommon, setPolicyPreventCommon] = useState(true);
  const [policyMaxAge, setPolicyMaxAge] = useState(0);
  const [policyMfa, setPolicyMfa] = useState(false);
  const [policyLockoutThreshold, setPolicyLockoutThreshold] = useState(5);

  const analyzeMutation = useMutation({
    mutationFn: async (pw: string) => {
      const res = await apiRequest("POST", "/api/password/analyze", { password: pw });
      return res.json();
    },
    onSuccess: (data) => setAnalysis(data),
  });

  const breachMutation = useMutation({
    mutationFn: async (pw: string) => {
      const res = await apiRequest("POST", "/api/password/check-breach", { password: pw });
      return res.json();
    },
    onSuccess: (data) => setBreachResult(data),
  });

  const policyMutation = useMutation({
    mutationFn: async (policy: any) => {
      const res = await apiRequest("POST", "/api/password/policy-audit", policy);
      return res.json();
    },
    onSuccess: (data) => setPolicyResult(data),
  });

  const generateMutation = useMutation({
    mutationFn: async (opts: any) => {
      const res = await apiRequest("POST", "/api/password/generate", opts);
      return res.json();
    },
    onSuccess: (data) => setGeneratedPasswords(data.passwords),
  });

  const handleAnalyze = () => {
    if (!password.trim()) return;
    analyzeMutation.mutate(password);
    breachMutation.mutate(password);
  };

  const handlePolicyAudit = () => {
    policyMutation.mutate({
      minLength: policyMinLength,
      maxLength: policyMaxLength,
      requireUppercase: policyRequireUpper,
      requireLowercase: policyRequireLower,
      requireDigits: policyRequireDigits,
      requireSpecial: policyRequireSpecial,
      preventCommon: policyPreventCommon,
      maxAge: policyMaxAge,
      mfaRequired: policyMfa,
      lockoutThreshold: policyLockoutThreshold,
    });
  };

  const handleGenerate = () => {
    generateMutation.mutate({
      length: genLength,
      includeUppercase: genUppercase,
      includeLowercase: genLowercase,
      includeDigits: genDigits,
      includeSpecial: genSpecial,
      excludeAmbiguous: genExcludeAmbiguous,
      count: 5,
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied to clipboard" });
  };

  return (
    <div className="p-4 space-y-4 max-w-7xl mx-auto">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-3 flex-wrap">
          <KeyRound className="w-6 h-6 text-primary" />
          <h1 className="text-xl font-bold" data-testid="text-page-title">Password Security Auditor</h1>
          <Badge variant="outline" data-testid="badge-tool-type">Security Tool</Badge>
        </div>
        {(analysis || policyResult) && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => generatePasswordAuditReportPDF(analysis, breachResult, policyResult)}
            data-testid="button-export-password-pdf"
          >
            <Download className="w-3.5 h-3.5 me-1.5" />
            Export PDF
          </Button>
        )}
      </div>

      <Tabs defaultValue="analyze" className="space-y-4">
        <TabsList data-testid="tabs-password-auditor">
          <TabsTrigger value="analyze" data-testid="tab-analyze">
            <Search className="w-3.5 h-3.5 mr-1.5" />
            Analyze
          </TabsTrigger>
          <TabsTrigger value="policy" data-testid="tab-policy">
            <FileText className="w-3.5 h-3.5 mr-1.5" />
            Policy Audit
          </TabsTrigger>
          <TabsTrigger value="generator" data-testid="tab-generator">
            <Zap className="w-3.5 h-3.5 mr-1.5" />
            Generator
          </TabsTrigger>
        </TabsList>

        <TabsContent value="analyze" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Lock className="w-4 h-4" />
                Password Strength Analyzer
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Input
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter a password to analyze..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
                    data-testid="input-password"
                    className="pr-10"
                  />
                  <Button
                    variant="ghost"
                    size="icon"
                    className="absolute right-0 top-0"
                    onClick={() => setShowPassword(!showPassword)}
                    data-testid="button-toggle-visibility"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </Button>
                </div>
                <Button
                  onClick={handleAnalyze}
                  disabled={!password.trim() || analyzeMutation.isPending}
                  data-testid="button-analyze"
                >
                  {analyzeMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1.5" /> : <Search className="w-4 h-4 mr-1.5" />}
                  Analyze
                </Button>
              </div>

              <p className="text-xs text-muted-foreground">
                Passwords are analyzed locally and checked against breach databases using k-anonymity (only first 5 chars of hash sent).
              </p>
            </CardContent>
          </Card>

          {analysis && (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Strength Score</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center gap-4">
                    <div className={`text-4xl font-bold font-mono ${getScoreColor(analysis.score)}`} data-testid="text-score">
                      {analysis.score}
                    </div>
                    <div>
                      <Badge className={`${getScoreBg(analysis.score)} text-white border-0`} data-testid="badge-strength">
                        {analysis.strength}
                      </Badge>
                      <p className="text-xs text-muted-foreground mt-1">
                        Entropy: {analysis.entropy} bits
                      </p>
                    </div>
                  </div>
                  <Progress value={analysis.score} className="h-2" data-testid="progress-score" />

                  <Separator />

                  <div className="space-y-2">
                    <h4 className="text-sm font-medium">Composition</h4>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Length</span>
                        <span className="font-mono" data-testid="text-length">{analysis.composition.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Unique chars</span>
                        <span className="font-mono" data-testid="text-unique">{analysis.composition.uniqueChars}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Uppercase</span>
                        <span className="font-mono">{analysis.composition.uppercase}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Lowercase</span>
                        <span className="font-mono">{analysis.composition.lowercase}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Digits</span>
                        <span className="font-mono">{analysis.composition.digits}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Special</span>
                        <span className="font-mono">{analysis.composition.special}</span>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Clock className="w-4 h-4" />
                    Time to Crack
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {[
                      { label: "Online (throttled)", value: analysis.crackTime.onlineThrottled, desc: "~10 guesses/sec" },
                      { label: "Online (unthrottled)", value: analysis.crackTime.onlineUnthrottled, desc: "~100 guesses/sec" },
                      { label: "Offline (slow hash)", value: analysis.crackTime.offlineSlow, desc: "~10K guesses/sec" },
                      { label: "Offline (fast hash)", value: analysis.crackTime.offlineFast, desc: "~10B guesses/sec" },
                      { label: "GPU cluster", value: analysis.crackTime.gpuCluster, desc: "~1T guesses/sec" },
                    ].map((item) => (
                      <div key={item.label} className="flex items-center justify-between gap-2">
                        <div>
                          <span className="text-xs font-medium">{item.label}</span>
                          <p className="text-[10px] text-muted-foreground">{item.desc}</p>
                        </div>
                        <Badge variant="outline" className="font-mono text-xs" data-testid={`badge-crack-${item.label.replace(/\s+/g, "-").toLowerCase()}`}>
                          {item.value}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {breachResult && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <Shield className="w-4 h-4" />
                      Breach Exposure
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-start gap-3">
                      {breachResult.breached ? (
                        <XCircle className="w-8 h-8 text-red-500 flex-shrink-0" />
                      ) : breachResult.occurrences === -1 ? (
                        <AlertTriangle className="w-8 h-8 text-yellow-500 flex-shrink-0" />
                      ) : (
                        <CheckCircle2 className="w-8 h-8 text-green-500 flex-shrink-0" />
                      )}
                      <div>
                        <p className="text-sm font-medium" data-testid="text-breach-status">
                          {breachResult.breached ? "Password Found in Breaches" : breachResult.occurrences === -1 ? "Check Unavailable" : "Not Found in Breaches"}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1" data-testid="text-breach-message">
                          {breachResult.message}
                        </p>
                        {breachResult.breached && (
                          <Badge variant="destructive" className="mt-2" data-testid="badge-breach-count">
                            {breachResult.occurrences.toLocaleString()} occurrences
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">NIST SP 800-63B Compliance</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-2 mb-3">
                    {analysis.nistCompliance.compliant ? (
                      <Badge variant="default" data-testid="badge-nist-status">Compliant</Badge>
                    ) : (
                      <Badge variant="destructive" data-testid="badge-nist-status">Non-Compliant</Badge>
                    )}
                  </div>
                  <div className="space-y-2">
                    {analysis.nistCompliance.checks.map((check, i) => (
                      <div key={i} className="flex items-start gap-2">
                        {check.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                        )}
                        <div>
                          <p className="text-xs font-medium">{check.rule}</p>
                          <p className="text-[10px] text-muted-foreground">{check.description}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {(analysis.weaknesses.length > 0 || analysis.suggestions.length > 0) && (
                <Card className="md:col-span-2">
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Findings & Recommendations
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-4 md:grid-cols-2">
                      {analysis.weaknesses.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium text-red-500">Weaknesses</h4>
                          {analysis.weaknesses.map((w, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <XCircle className="w-3.5 h-3.5 text-red-500 flex-shrink-0 mt-0.5" />
                              <span className="text-xs" data-testid={`text-weakness-${i}`}>{w}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {analysis.suggestions.length > 0 && (
                        <div className="space-y-2">
                          <h4 className="text-sm font-medium text-green-500">Suggestions</h4>
                          {analysis.suggestions.map((s, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-green-500 flex-shrink-0 mt-0.5" />
                              <span className="text-xs" data-testid={`text-suggestion-${i}`}>{s}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="policy" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Password Policy Configuration
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-xs">Minimum Length: {policyMinLength}</Label>
                    <Slider
                      min={1}
                      max={32}
                      step={1}
                      value={[policyMinLength]}
                      onValueChange={([v]) => setPolicyMinLength(v)}
                      data-testid="slider-min-length"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">Maximum Length: {policyMaxLength}</Label>
                    <Slider
                      min={16}
                      max={128}
                      step={1}
                      value={[policyMaxLength]}
                      onValueChange={([v]) => setPolicyMaxLength(v)}
                      data-testid="slider-max-length"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">Password Expiry (days, 0 = never): {policyMaxAge}</Label>
                    <Slider
                      min={0}
                      max={365}
                      step={1}
                      value={[policyMaxAge]}
                      onValueChange={([v]) => setPolicyMaxAge(v)}
                      data-testid="slider-max-age"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label className="text-xs">Lockout Threshold: {policyLockoutThreshold}</Label>
                    <Slider
                      min={0}
                      max={20}
                      step={1}
                      value={[policyLockoutThreshold]}
                      onValueChange={([v]) => setPolicyLockoutThreshold(v)}
                      data-testid="slider-lockout"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  {[
                    { label: "Require Uppercase", value: policyRequireUpper, setter: setPolicyRequireUpper, id: "switch-upper" },
                    { label: "Require Lowercase", value: policyRequireLower, setter: setPolicyRequireLower, id: "switch-lower" },
                    { label: "Require Digits", value: policyRequireDigits, setter: setPolicyRequireDigits, id: "switch-digits" },
                    { label: "Require Special Characters", value: policyRequireSpecial, setter: setPolicyRequireSpecial, id: "switch-special" },
                    { label: "Prevent Common Passwords", value: policyPreventCommon, setter: setPolicyPreventCommon, id: "switch-common" },
                    { label: "Require MFA", value: policyMfa, setter: setPolicyMfa, id: "switch-mfa" },
                  ].map((item) => (
                    <div key={item.id} className="flex items-center justify-between">
                      <Label className="text-xs">{item.label}</Label>
                      <Switch
                        checked={item.value}
                        onCheckedChange={item.setter}
                        data-testid={item.id}
                      />
                    </div>
                  ))}
                </div>
              </div>

              <Button onClick={handlePolicyAudit} disabled={policyMutation.isPending} data-testid="button-audit-policy">
                {policyMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1.5" /> : <Shield className="w-4 h-4 mr-1.5" />}
                Audit Policy
              </Button>
            </CardContent>
          </Card>

          {policyResult && (
            <div className="grid gap-4 md:grid-cols-3">
              <Card>
                <CardContent className="pt-6 flex flex-col items-center gap-2">
                  <div className={`text-5xl font-bold font-mono ${getScoreColor(policyResult.overallScore)}`} data-testid="text-policy-score">
                    {policyResult.overallScore}%
                  </div>
                  <Badge variant={getGradeBadgeVariant(policyResult.grade)} className="text-lg px-3" data-testid="badge-policy-grade">
                    Grade: {policyResult.grade}
                  </Badge>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                      <div className="text-2xl font-bold text-green-500" data-testid="text-policy-pass">{policyResult.summary.pass}</div>
                      <p className="text-xs text-muted-foreground">Pass</p>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-yellow-500" data-testid="text-policy-warn">{policyResult.summary.warning}</div>
                      <p className="text-xs text-muted-foreground">Warning</p>
                    </div>
                    <div>
                      <div className="text-2xl font-bold text-red-500" data-testid="text-policy-fail">{policyResult.summary.fail}</div>
                      <p className="text-xs text-muted-foreground">Fail</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6 space-y-2">
                  <Progress value={policyResult.overallScore} className="h-2" />
                  <p className="text-xs text-muted-foreground text-center">
                    {policyResult.summary.pass} of {policyResult.summary.total} checks passed
                  </p>
                </CardContent>
              </Card>

              <Card className="md:col-span-3">
                <CardHeader>
                  <CardTitle className="text-base">Detailed Findings</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {policyResult.findings.map((finding, i) => (
                      <div key={i} className="flex items-start gap-3 p-3 rounded-md bg-muted/30">
                        {finding.status === "pass" ? (
                          <CheckCircle2 className="w-4 h-4 text-green-500 flex-shrink-0 mt-0.5" />
                        ) : finding.status === "warning" ? (
                          <AlertTriangle className="w-4 h-4 text-yellow-500 flex-shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-4 h-4 text-red-500 flex-shrink-0 mt-0.5" />
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-medium">{finding.rule}</span>
                            <Badge variant="outline" className="text-[10px]">{finding.category}</Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mt-1">{finding.recommendation}</p>
                          <p className="text-[10px] text-muted-foreground/60 mt-1 font-mono">{finding.nistReference}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="generator" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Zap className="w-4 h-4" />
                Secure Password Generator
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-6 md:grid-cols-2">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label className="text-xs">Length: {genLength}</Label>
                    <Slider
                      min={8}
                      max={64}
                      step={1}
                      value={[genLength]}
                      onValueChange={([v]) => setGenLength(v)}
                      data-testid="slider-gen-length"
                    />
                  </div>
                </div>

                <div className="space-y-3">
                  {[
                    { label: "Uppercase (A-Z)", value: genUppercase, setter: setGenUppercase, id: "switch-gen-upper" },
                    { label: "Lowercase (a-z)", value: genLowercase, setter: setGenLowercase, id: "switch-gen-lower" },
                    { label: "Digits (0-9)", value: genDigits, setter: setGenDigits, id: "switch-gen-digits" },
                    { label: "Special (!@#$%)", value: genSpecial, setter: setGenSpecial, id: "switch-gen-special" },
                    { label: "Exclude Ambiguous (Il1O0)", value: genExcludeAmbiguous, setter: setGenExcludeAmbiguous, id: "switch-gen-ambiguous" },
                  ].map((item) => (
                    <div key={item.id} className="flex items-center justify-between">
                      <Label className="text-xs">{item.label}</Label>
                      <Switch
                        checked={item.value}
                        onCheckedChange={item.setter}
                        data-testid={item.id}
                      />
                    </div>
                  ))}
                </div>
              </div>

              <Button onClick={handleGenerate} disabled={generateMutation.isPending} data-testid="button-generate">
                {generateMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-1.5" /> : <RefreshCw className="w-4 h-4 mr-1.5" />}
                Generate Passwords
              </Button>

              {generatedPasswords.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-sm font-medium">Generated Passwords</h4>
                  {generatedPasswords.map((pw, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded-md bg-muted/30">
                      <code className="flex-1 text-xs font-mono break-all" data-testid={`text-generated-${i}`}>{pw}</code>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => copyToClipboard(pw)}
                        data-testid={`button-copy-${i}`}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
