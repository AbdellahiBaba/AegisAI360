import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Download, Copy, Key, Monitor, Apple, Terminal as TerminalIcon, CheckCircle, AlertCircle, Settings, Shield } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function DownloadAgent() {
  useDocumentTitle("Download Agent");
  const { t } = useTranslation();
  const { toast } = useToast();
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);

  const { data: tokens, isLoading } = useQuery<any[]>({
    queryKey: ["/api/agent/device-tokens"],
  });

  const generateTokenMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/agent/device-token/create", {});
      return res.json();
    },
    onSuccess: (data) => {
      setGeneratedToken(data.token);
      queryClient.invalidateQueries({ queryKey: ["/api/agent/device-tokens"] });
      toast({ title: t("downloadAgent.tokenGenerated") });
    },
    onError: (error: any) => {
      toast({ title: t("downloadAgent.tokenGenerateFailed"), description: error.message, variant: "destructive" });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: t("downloadAgent.copiedToClipboard") });
  };

  const availableTokens = tokens?.filter((t: any) => !t.used) || [];

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold" data-testid="text-download-title">{t("downloadAgent.title")}</h1>
        <p className="text-muted-foreground text-sm">{t("downloadAgent.subtitle")}</p>
      </div>

      <Card data-testid="card-download-agent">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="w-5 h-5" />
            {t("downloadAgent.step1Title")}
          </CardTitle>
          <CardDescription>{t("downloadAgent.step1Desc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="border-2 border-primary" data-testid="card-download-windows">
              <CardContent className="pt-6 text-center">
                <Monitor className="w-10 h-10 mx-auto mb-3 text-blue-500" />
                <h3 className="font-medium">{t("downloadAgent.windows")}</h3>
                <p className="text-xs text-muted-foreground mt-1">{t("downloadAgent.windowsDesc")}</p>
                <Badge className="mt-2" variant="default">{t("downloadAgent.readyToDownload")}</Badge>
                <a href="/downloads/AegisAI360-Agent.exe" download className="block mt-3">
                  <Button className="w-full" data-testid="button-download-windows">
                    <Download className="w-4 h-4 me-2" />
                    {t("downloadAgent.downloadExe")}
                  </Button>
                </a>
              </CardContent>
            </Card>

            <Card className="border-dashed" data-testid="card-download-linux">
              <CardContent className="pt-6 text-center">
                <TerminalIcon className="w-10 h-10 mx-auto mb-3 text-orange-500" />
                <h3 className="font-medium">{t("downloadAgent.linux")}</h3>
                <p className="text-xs text-muted-foreground mt-1">{t("downloadAgent.linuxDesc")}</p>
                <Button className="mt-3 w-full" variant="outline" disabled data-testid="button-download-linux">
                  {t("downloadAgent.comingSoon")}
                </Button>
              </CardContent>
            </Card>

            <Card className="border-dashed" data-testid="card-download-macos">
              <CardContent className="pt-6 text-center">
                <Apple className="w-10 h-10 mx-auto mb-3 text-gray-500" />
                <h3 className="font-medium">{t("downloadAgent.macos")}</h3>
                <p className="text-xs text-muted-foreground mt-1">{t("downloadAgent.macosDesc")}</p>
                <Button className="mt-3 w-full" variant="outline" disabled data-testid="button-download-macos">
                  {t("downloadAgent.comingSoon")}
                </Button>
              </CardContent>
            </Card>
          </div>
        </CardContent>
      </Card>

      <Card data-testid="card-generate-token">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="w-5 h-5" />
            {t("downloadAgent.step2Title")}
          </CardTitle>
          <CardDescription>{t("downloadAgent.step2Desc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            onClick={() => generateTokenMutation.mutate()}
            disabled={generateTokenMutation.isPending}
            data-testid="button-generate-token"
          >
            {generateTokenMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin me-2" /> : <Key className="w-4 h-4 me-2" />}
            {t("downloadAgent.generateNewToken")}
          </Button>

          {generatedToken && (
            <div className="flex items-center gap-2 p-3 bg-muted rounded-lg" data-testid="container-generated-token">
              <Input value={generatedToken} readOnly className="font-mono text-xs" data-testid="input-token-value" />
              <Button size="sm" variant="outline" onClick={() => copyToClipboard(generatedToken)} data-testid="button-copy-token">
                <Copy className="w-4 h-4" />
              </Button>
            </div>
          )}

          {tokens && tokens.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">{t("downloadAgent.yourTokens")}</h4>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {tokens.slice(0, 10).map((tk: any) => (
                  <div key={tk.id} className="flex items-center justify-between text-xs p-2 bg-muted/50 rounded" data-testid={`row-token-${tk.id}`}>
                    <div className="flex items-center gap-2">
                      {tk.used ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <AlertCircle className="w-3 h-3 text-yellow-500" />
                      )}
                      <span className="font-mono">{tk.token.slice(0, 24)}...</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={tk.used ? "default" : "secondary"}>{tk.used ? t("downloadAgent.used") : t("downloadAgent.available")}</Badge>
                      {!tk.used && (
                        <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => copyToClipboard(tk.token)} data-testid={`button-copy-token-${tk.id}`}>
                          <Copy className="w-3 h-3" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card data-testid="card-run-instructions">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TerminalIcon className="w-5 h-5" />
            {t("downloadAgent.step3Title")}
          </CardTitle>
          <CardDescription>{t("downloadAgent.step3Desc")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-primary" />
              <h4 className="text-sm font-medium" data-testid="text-method-doubleclick">{t("downloadAgent.optionATitle")}</h4>
            </div>
            <p className="text-sm text-muted-foreground mb-2" dangerouslySetInnerHTML={{ __html: t("downloadAgent.optionADesc") }} />
            <p className="text-xs text-amber-500 font-medium">
              {t("downloadAgent.optionANote")}
            </p>
          </div>

          <div className="border-t pt-4">
            <div className="flex items-center gap-2 mb-2">
              <TerminalIcon className="w-4 h-4 text-primary" />
              <h4 className="text-sm font-medium" data-testid="text-method-cli">{t("downloadAgent.optionBTitle")}</h4>
            </div>
            <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-sm space-y-2" data-testid="code-run-command">
              <p className="text-zinc-500">:: Open Command Prompt as Administrator, then:</p>
              <p>cd %USERPROFILE%\Downloads</p>
              <p className="text-zinc-500 mt-3">:: Run the agent with your server URL and device token</p>
              <p>AegisAI360-Agent.exe https://aegisai360.com {availableTokens.length > 0 ? availableTokens[0].token : "YOUR_DEVICE_TOKEN"}</p>
            </div>

            {availableTokens.length > 0 && (
              <div className="flex items-center gap-2 mt-3">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(`AegisAI360-Agent.exe https://aegisai360.com ${availableTokens[0].token}`)}
                  data-testid="button-copy-run-command"
                >
                  <Copy className="w-4 h-4 me-2" />
                  {t("downloadAgent.copyFullCommand")}
                </Button>
                <span className="text-xs text-muted-foreground">{t("downloadAgent.usingFirstToken")}</span>
              </div>
            )}
          </div>

          <div className="border-t pt-4">
            <div className="flex items-center gap-2 mb-2">
              <Settings className="w-4 h-4 text-primary" />
              <h4 className="text-sm font-medium" data-testid="text-method-service">{t("downloadAgent.optionCTitle")}</h4>
            </div>
            <p className="text-sm text-muted-foreground mb-2">
              {t("downloadAgent.optionCDesc")}
            </p>
            <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-sm space-y-2" data-testid="code-service-commands">
              <p className="text-zinc-500">:: First, run setup to save your configuration</p>
              <p>AegisAI360-Agent.exe --setup</p>
              <p className="text-zinc-500 mt-3">:: Then install as a Windows service (run as Administrator)</p>
              <p>AegisAI360-Agent.exe --install</p>
              <p className="text-zinc-500 mt-3">:: Start the service</p>
              <p>sc start AegisAI360Agent</p>
              <p className="text-zinc-500 mt-3">:: Other commands</p>
              <p>AegisAI360-Agent.exe --status     :: Check service status</p>
              <p>AegisAI360-Agent.exe --uninstall   :: Remove the service</p>
            </div>
          </div>

          <div className="mt-4 space-y-2 text-sm text-muted-foreground">
            <p className="font-medium text-foreground">{t("downloadAgent.whatHappens")}</p>
            <ul className="list-disc list-inside space-y-1 ms-2">
              <li>{t("downloadAgent.connectStep1")}</li>
              <li>{t("downloadAgent.connectStep2")}</li>
              <li>{t("downloadAgent.connectStep3")}</li>
              <li>{t("downloadAgent.connectStep4")}</li>
              <li>{t("downloadAgent.connectStep5")}</li>
              <li>{t("downloadAgent.connectStep6")}</li>
              <li>{t("downloadAgent.connectStep7")}</li>
              <li>{t("downloadAgent.connectStep8")}</li>
            </ul>
          </div>

          <div className="mt-4 p-3 bg-muted/50 rounded text-sm" data-testid="text-service-persistence-note">
            <p className="font-medium mb-1 flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              {t("downloadAgent.servicePersistence")}
            </p>
            <p className="text-muted-foreground" dangerouslySetInnerHTML={{ __html: t("downloadAgent.servicePersistenceDesc") }} />
          </div>

          <div className="mt-4 p-3 bg-muted/50 rounded text-sm" data-testid="text-config-note">
            <p className="font-medium mb-1">{t("downloadAgent.configFileReference")}</p>
            <p className="text-muted-foreground" dangerouslySetInnerHTML={{ __html: t("downloadAgent.configFileDesc") }} />
            <pre className="bg-zinc-950 text-zinc-100 rounded p-3 mt-2 text-xs overflow-x-auto">{`{
  "serverUrl": "https://aegisai360.com",
  "apiKey": "${availableTokens.length > 0 ? availableTokens[0].token : "agt_YOUR_TOKEN_HERE"}",
  "heartbeatInterval": 30,
  "commandPollInterval": 5,
  "telemetryInterval": 30,
  "updateCheckInterval": 300
}`}</pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
