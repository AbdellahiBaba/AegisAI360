import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useTranslation } from "react-i18next";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Key, Hash, Shield, Loader2, CheckCircle2, XCircle,
  AlertTriangle, Info, Lock, Eye, EyeOff,
} from "lucide-react";

const strengthColors: Record<string, string> = {
  "Very Weak": "bg-severity-critical",
  "Weak": "bg-severity-high",
  "Fair": "bg-severity-medium",
  "Strong": "bg-status-online",
  "Very Strong": "bg-primary",
};

const strengthScoreColors: Record<string, string> = {
  "Very Weak": "text-severity-critical",
  "Weak": "text-severity-high",
  "Fair": "text-severity-medium",
  "Strong": "text-status-online",
  "Very Strong": "text-primary",
};

function HashIdentifierSection() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [hash, setHash] = useState("");
  const [result, setResult] = useState<{
    hash: string;
    possibleTypes: Array<{ type: string; confidence: number; description: string }>;
    mostLikely: string;
  } | null>(null);

  const mutation = useMutation({
    mutationFn: async (hashValue: string) => {
      const res = await apiRequest("POST", "/api/scan/hash-id", { hash: hashValue });
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
    },
    onError: () => {
      toast({ title: t("hashTools.noHashIdentified"), variant: "destructive" });
    },
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Hash className="w-4 h-4 text-primary" />
          {t("hashTools.hashIdentifier")}
        </CardTitle>
        <p className="text-xs text-muted-foreground">{t("hashTools.hashIdentifierDesc")}</p>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder={t("hashTools.hashPlaceholder")}
            className="font-mono text-xs"
            data-testid="input-hash-identify"
          />
          <Button
            onClick={() => mutation.mutate(hash)}
            disabled={!hash.trim() || mutation.isPending}
            data-testid="button-identify-hash"
          >
            {mutation.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> {t("hashTools.identifying")}</>
            ) : (
              t("hashTools.identify")
            )}
          </Button>
        </div>

        {result && result.possibleTypes.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-status-online" />
              <span className="text-sm font-medium">
                {t("hashTools.hashType")}: <span className="text-primary font-semibold">{result.mostLikely}</span>
              </span>
            </div>
            <div className="text-xs text-muted-foreground">
              {t("hashTools.hashLength")}: {result.hash.length} {t("hashTools.possibleTypes")}: {result.possibleTypes.length}
            </div>
            <div className="space-y-2">
              {result.possibleTypes.map((pt, i) => (
                <div key={i} className="flex items-center justify-between gap-2 p-2 rounded-md bg-muted/50" data-testid={`hash-type-result-${i}`}>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-semibold">{pt.type}</span>
                      <Badge variant="secondary" className="text-[10px]">{pt.confidence}%</Badge>
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{pt.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {result && result.possibleTypes.length === 0 && (
          <div className="flex items-center gap-2 p-3 rounded-md bg-muted/50">
            <AlertTriangle className="w-4 h-4 text-severity-medium" />
            <span className="text-xs text-muted-foreground">{t("hashTools.noHashIdentified")}</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HashCrackerSection() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [hash, setHash] = useState("");
  const [hashType, setHashType] = useState("");
  const [result, setResult] = useState<{
    hash: string;
    hashType: string;
    cracked: boolean;
    password: string;
    attempts: number;
    timeTaken: string;
  } | null>(null);

  const mutation = useMutation({
    mutationFn: async (payload: { hash: string; hashType?: string }) => {
      const res = await apiRequest("POST", "/api/scan/hash-crack", payload);
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
    },
    onError: () => {
      toast({ title: "Hash cracking failed", variant: "destructive" });
    },
  });

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Lock className="w-4 h-4 text-primary" />
          {t("hashTools.hashCracker")}
        </CardTitle>
        <p className="text-xs text-muted-foreground">{t("hashTools.hashCrackerDesc")}</p>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Input
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder={t("hashTools.hashPlaceholder")}
            className="font-mono text-xs"
            data-testid="input-hash-crack"
          />
          <div className="flex gap-2">
            <Select value={hashType} onValueChange={setHashType}>
              <SelectTrigger className="flex-1" data-testid="select-hash-type">
                <SelectValue placeholder={t("hashTools.selectHashType")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="auto">Auto-detect</SelectItem>
                <SelectItem value="MD5">MD5</SelectItem>
                <SelectItem value="SHA-1">SHA-1</SelectItem>
                <SelectItem value="SHA-256">SHA-256</SelectItem>
                <SelectItem value="SHA-512">SHA-512</SelectItem>
                <SelectItem value="bcrypt">bcrypt</SelectItem>
              </SelectContent>
            </Select>
            <Button
              onClick={() => mutation.mutate({ hash, hashType: hashType === "auto" ? undefined : hashType || undefined })}
              disabled={!hash.trim() || mutation.isPending}
              data-testid="button-crack-hash"
            >
              {mutation.isPending ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> {t("hashTools.cracking")}</>
              ) : (
                t("hashTools.crack")
              )}
            </Button>
          </div>
        </div>

        {result && (
          <div className="space-y-3">
            {result.cracked ? (
              <div className="p-3 rounded-md border border-severity-critical/30 bg-severity-critical/5">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-severity-critical" />
                  <span className="text-sm font-semibold text-severity-critical">{t("hashTools.cracked")}</span>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">{t("hashTools.crackedPassword")}:</span>
                    <code className="text-xs font-mono bg-muted px-2 py-0.5 rounded" data-testid="text-cracked-password">{result.password}</code>
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    {t("hashTools.hashType")}: {result.hashType} | Attempts: {result.attempts.toLocaleString()} | Time: {result.timeTaken}
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-3 rounded-md bg-muted/50">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle2 className="w-4 h-4 text-status-online" />
                  <span className="text-sm font-medium">{t("hashTools.notCracked")}</span>
                </div>
                <p className="text-[11px] text-muted-foreground">{t("hashTools.notCrackedDesc")}</p>
                {result.timeTaken && (
                  <p className="text-[11px] text-muted-foreground mt-1">{result.timeTaken}</p>
                )}
              </div>
            )}

            <div className="flex items-start gap-2 p-2 rounded-md bg-muted/30">
              <Info className="w-3.5 h-3.5 text-muted-foreground mt-0.5 flex-shrink-0" />
              <p className="text-[11px] text-muted-foreground">{t("hashTools.hashCrackWhatThisMeans")}</p>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function PasswordAnalyzerSection() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [result, setResult] = useState<{
    password: string;
    score: number;
    strength: string;
    entropy: number;
    crackTime: { bruteForce: string; dictionary: string; gpu: string };
    weaknesses: string[];
    suggestions: string[];
    composition: { length: number; uppercase: number; lowercase: number; digits: number; special: number; spaces: number };
  } | null>(null);

  const mutation = useMutation({
    mutationFn: async (pw: string) => {
      const res = await apiRequest("POST", "/api/scan/password-analyze", { password: pw });
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
    },
    onError: () => {
      toast({ title: "Password analysis failed", variant: "destructive" });
    },
  });

  const getStrengthLabel = (strength: string) => {
    const map: Record<string, string> = {
      "Very Weak": t("hashTools.veryWeak"),
      "Weak": t("hashTools.weak"),
      "Fair": t("hashTools.fair"),
      "Strong": t("hashTools.strong"),
      "Very Strong": t("hashTools.veryStrong"),
    };
    return map[strength] || strength;
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Shield className="w-4 h-4 text-primary" />
          {t("hashTools.passwordAnalyzer")}
        </CardTitle>
        <p className="text-xs text-muted-foreground">{t("hashTools.passwordAnalyzerDesc")}</p>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={t("hashTools.passwordPlaceholder")}
              className="pr-9"
              data-testid="input-password-analyze"
            />
            <Button
              variant="ghost"
              size="icon"
              className="absolute right-0 top-0"
              onClick={() => setShowPassword(!showPassword)}
              data-testid="button-toggle-password"
            >
              {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </Button>
          </div>
          <Button
            onClick={() => mutation.mutate(password)}
            disabled={!password || mutation.isPending}
            data-testid="button-analyze-password"
          >
            {mutation.isPending ? (
              <><Loader2 className="w-4 h-4 animate-spin" /> {t("hashTools.analyzing")}</>
            ) : (
              t("hashTools.analyze")
            )}
          </Button>
        </div>

        {result && (
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-sm font-medium">{t("hashTools.strength")}</span>
                <span className={`text-sm font-semibold ${strengthScoreColors[result.strength] || ""}`} data-testid="text-password-strength">
                  {getStrengthLabel(result.strength)}
                </span>
              </div>
              <Progress value={result.score} className="h-2" />
              <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground flex-wrap">
                <span>{t("hashTools.entropy")}: {result.entropy.toFixed(1)} {t("hashTools.bits")}</span>
                <span data-testid="text-password-score">{result.score}/100</span>
              </div>
            </div>

            <div className="p-3 rounded-md bg-muted/50 space-y-2">
              <div className="flex items-center gap-2">
                <Info className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                <span className="text-xs font-medium">
                  {result.score <= 40
                    ? t("hashTools.couldBeCracked", { time: result.crackTime.gpu })
                    : t("hashTools.wouldTake", { time: result.crackTime.bruteForce })}
                </span>
              </div>
            </div>

            <div className="space-y-2">
              <span className="text-xs font-medium">{t("hashTools.crackTime")}</span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                <div className="p-2 rounded-md bg-muted/50">
                  <div className="text-[10px] text-muted-foreground">{t("hashTools.bruteForce")}</div>
                  <div className="text-xs font-mono font-medium" data-testid="text-crack-bruteforce">{result.crackTime.bruteForce}</div>
                </div>
                <div className="p-2 rounded-md bg-muted/50">
                  <div className="text-[10px] text-muted-foreground">{t("hashTools.dictionary")}</div>
                  <div className="text-xs font-mono font-medium" data-testid="text-crack-dictionary">{result.crackTime.dictionary}</div>
                </div>
                <div className="p-2 rounded-md bg-muted/50">
                  <div className="text-[10px] text-muted-foreground">{t("hashTools.gpu")}</div>
                  <div className="text-xs font-mono font-medium" data-testid="text-crack-gpu">{result.crackTime.gpu}</div>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-6 gap-1 text-center">
              {[
                { label: "Len", val: result.composition.length },
                { label: "A-Z", val: result.composition.uppercase },
                { label: "a-z", val: result.composition.lowercase },
                { label: "0-9", val: result.composition.digits },
                { label: "!@#", val: result.composition.special },
                { label: "Spc", val: result.composition.spaces },
              ].map((item) => (
                <div key={item.label} className="p-1.5 rounded-md bg-muted/50">
                  <div className="text-[10px] text-muted-foreground">{item.label}</div>
                  <div className="text-xs font-mono font-semibold">{item.val}</div>
                </div>
              ))}
            </div>

            {result.weaknesses.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-medium flex items-center gap-1.5">
                  <XCircle className="w-3.5 h-3.5 text-severity-high" />
                  {t("hashTools.weaknesses")}
                </span>
                <div className="space-y-1">
                  {result.weaknesses.map((w, i) => (
                    <div key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5 p-1.5 rounded bg-severity-high/5" data-testid={`text-weakness-${i}`}>
                      <AlertTriangle className="w-3 h-3 text-severity-high mt-0.5 flex-shrink-0" />
                      {w}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.suggestions.length > 0 && (
              <div className="space-y-1.5">
                <span className="text-xs font-medium flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-status-online" />
                  {t("hashTools.suggestions")}
                </span>
                <div className="space-y-1">
                  {result.suggestions.map((s, i) => (
                    <div key={i} className="text-[11px] text-muted-foreground flex items-start gap-1.5 p-1.5 rounded bg-status-online/5" data-testid={`text-suggestion-${i}`}>
                      <Info className="w-3 h-3 text-status-online mt-0.5 flex-shrink-0" />
                      {s}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function HashToolsPage() {
  useDocumentTitle("Hash Tools");
  const { t } = useTranslation();

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-lg font-semibold flex items-center gap-2" data-testid="text-hash-tools-title">
          <Key className="w-5 h-5 text-primary" />
          {t("hashTools.title")}
        </h1>
        <p className="text-xs text-muted-foreground mt-1">{t("hashTools.subtitle")}</p>
      </div>

      <HashIdentifierSection />
      <HashCrackerSection />
      <PasswordAnalyzerSection />
    </div>
  );
}
