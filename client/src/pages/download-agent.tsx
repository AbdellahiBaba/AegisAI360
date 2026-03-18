import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import {
  Loader2, Download, Copy, Key, Monitor, Apple, Terminal as TerminalIcon,
  CheckCircle, AlertCircle, Settings, Shield, Cloud, RefreshCw, Lock,
  Zap, Server, Package,
} from "lucide-react";
import { SiUbuntu, SiDebian } from "react-icons/si";
import { FaRedhat, FaWindows, FaLinux } from "react-icons/fa";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function DownloadAgent() {
  useDocumentTitle("Download Agent | AegisAI360");
  const { t } = useTranslation();
  const { toast } = useToast();
  const qc = useQueryClient();
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [linuxPkgType, setLinuxPkgType] = useState<"deb" | "rpm" | "sh">("sh");

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
      qc.invalidateQueries({ queryKey: ["/api/agent/device-tokens"] });
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
  const firstToken = availableTokens[0]?.token || "YOUR_DEVICE_TOKEN";

  const downloadLinux = (type: "deb" | "rpm" | "sh") => {
    const url = `/api/deploy/package/${type}?token=${encodeURIComponent(firstToken)}`;
    window.location.href = url;
  };

  return (
    <div className="p-4 md:p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold" data-testid="text-download-title">{t("downloadAgent.title")}</h1>
        <p className="text-muted-foreground text-sm">{t("downloadAgent.subtitle")}</p>
      </div>

      {/* Cloud feature badges */}
      <div className="flex flex-wrap gap-2">
        {[
          { icon: Cloud, label: "Cloud Connected", desc: "Always synced to aegisai360.com" },
          { icon: RefreshCw, label: "Auto Updates", desc: "Agent updates itself automatically" },
          { icon: Lock, label: "Admin Block", desc: "Super admin can suspend any agent" },
          { icon: Zap, label: "Real-time", desc: "Heartbeat every 60 seconds" },
        ].map(({ icon: Icon, label, desc }) => (
          <div key={label} className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-border/50 bg-muted/30 text-xs">
            <Icon className="w-3 h-3 text-primary" />
            <span className="font-medium">{label}</span>
            <span className="text-muted-foreground hidden sm:inline">— {desc}</span>
          </div>
        ))}
      </div>

      {/* Step 1: Download */}
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
            {/* Windows */}
            <Card className="border-2 border-primary" data-testid="card-download-windows">
              <CardContent className="pt-6 text-center">
                <FaWindows className="w-10 h-10 mx-auto mb-3 text-blue-400" />
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

            {/* Linux — fully enabled */}
            <Card className="border-2 border-orange-500/50" data-testid="card-download-linux">
              <CardContent className="pt-5">
                <div className="text-center mb-3">
                  <FaLinux className="w-10 h-10 mx-auto mb-2 text-orange-400" />
                  <h3 className="font-medium">Linux Agent</h3>
                  <p className="text-xs text-muted-foreground">Ubuntu · Debian · CentOS · RHEL</p>
                  <Badge className="mt-1 bg-orange-500/10 text-orange-400 border-orange-500/30">Available</Badge>
                </div>

                {/* Package type selector */}
                <div className="grid grid-cols-3 gap-1 mb-3">
                  {(["sh", "deb", "rpm"] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setLinuxPkgType(t)}
                      className={`text-[10px] font-mono py-1 rounded border transition-all ${linuxPkgType === t ? "border-orange-500 bg-orange-500/15 text-orange-300" : "border-border/40 text-muted-foreground hover:border-border"}`}
                      data-testid={`tab-linux-${t}`}
                    >
                      .{t}
                    </button>
                  ))}
                </div>

                <div className="text-[10px] text-muted-foreground mb-2 text-center">
                  {linuxPkgType === "sh" && "Universal — works on any distro"}
                  {linuxPkgType === "deb" && "Debian/Ubuntu — installs via dpkg"}
                  {linuxPkgType === "rpm" && "CentOS/RHEL — yum/dnf compatible"}
                </div>

                <Button
                  className="w-full bg-orange-500 hover:bg-orange-600 text-white"
                  onClick={() => downloadLinux(linuxPkgType)}
                  data-testid="button-download-linux"
                >
                  <Download className="w-4 h-4 me-2" />
                  Download .{linuxPkgType} Installer
                </Button>

                <p className="text-[10px] text-muted-foreground text-center mt-1.5">
                  Token pre-embedded — one command install
                </p>
              </CardContent>
            </Card>

            {/* macOS */}
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

      {/* Step 2: Token */}
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
                      {tk.used ? <CheckCircle className="w-3 h-3 text-green-500" /> : <AlertCircle className="w-3 h-3 text-yellow-500" />}
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

      {/* Step 3: Run instructions — tabbed Windows / Linux */}
      <Card data-testid="card-run-instructions">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <TerminalIcon className="w-5 h-5" />
            {t("downloadAgent.step3Title")}
          </CardTitle>
          <CardDescription>{t("downloadAgent.step3Desc")}</CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="linux">
            <TabsList className="mb-4">
              <TabsTrigger value="linux" className="gap-2 text-xs" data-testid="tab-instructions-linux">
                <FaLinux className="w-3.5 h-3.5" /> Linux
              </TabsTrigger>
              <TabsTrigger value="windows" className="gap-2 text-xs" data-testid="tab-instructions-windows">
                <FaWindows className="w-3.5 h-3.5" /> Windows
              </TabsTrigger>
            </TabsList>

            {/* Linux instructions */}
            <TabsContent value="linux" className="space-y-5">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Package className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-medium">Option A — Pre-packaged installer (recommended)</h4>
                </div>
                <p className="text-xs text-muted-foreground mb-2">
                  Download the installer above (with your token pre-embedded), then run as root:
                </p>

                <Tabs defaultValue="sh" className="mt-2">
                  <TabsList className="h-7">
                    <TabsTrigger value="sh" className="text-[10px] h-6 px-2">Universal .sh</TabsTrigger>
                    <TabsTrigger value="deb" className="text-[10px] h-6 px-2">Ubuntu/Debian .deb</TabsTrigger>
                    <TabsTrigger value="rpm" className="text-[10px] h-6 px-2">CentOS/RHEL .rpm</TabsTrigger>
                  </TabsList>

                  <TabsContent value="sh">
                    <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-xs space-y-1.5 mt-2" data-testid="code-linux-sh">
                      <p className="text-zinc-500"># Download and run the universal installer</p>
                      <p>curl -fsSL "/api/deploy/package/sh?token={firstToken}" | sudo bash</p>
                      <p className="text-zinc-500 mt-2"># OR run the downloaded file</p>
                      <p>sudo bash aegisai360-agent_8.2.1_linux.sh</p>
                    </div>
                    <Button size="sm" variant="outline" className="mt-2 gap-2 text-xs" onClick={() => copyToClipboard(`sudo bash aegisai360-agent_8.2.1_linux.sh`)}>
                      <Copy className="w-3 h-3" /> Copy command
                    </Button>
                  </TabsContent>

                  <TabsContent value="deb">
                    <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-xs space-y-1.5 mt-2" data-testid="code-linux-deb">
                      <p className="text-zinc-500"># Run the .deb installer script (builds and installs the package)</p>
                      <p>sudo bash aegisai360-agent_8.2.1_amd64.deb.sh</p>
                      <p className="text-zinc-500 mt-2"># Verify installation</p>
                      <p>dpkg -l | grep aegisai360</p>
                      <p>systemctl status aegisai360-agent</p>
                    </div>
                  </TabsContent>

                  <TabsContent value="rpm">
                    <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-xs space-y-1.5 mt-2" data-testid="code-linux-rpm">
                      <p className="text-zinc-500"># Run the CentOS/RHEL installer</p>
                      <p>sudo bash aegisai360-agent_8.2.1_x86_64.rpm.sh</p>
                      <p className="text-zinc-500 mt-2"># Verify service</p>
                      <p>systemctl status aegisai360-agent</p>
                    </div>
                  </TabsContent>
                </Tabs>
              </div>

              <div className="border-t pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <Server className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-medium">Option B — Manual one-liner with token</h4>
                </div>
                <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-xs space-y-1.5" data-testid="code-linux-oneliner">
                  <p className="text-zinc-500"># Full install in one command (requires curl, node)</p>
                  <p>curl -fsSL "/api/deploy/package/sh?token={firstToken}" | sudo bash</p>
                </div>
                <Button size="sm" variant="outline" className="mt-2 gap-2 text-xs"
                  onClick={() => copyToClipboard(`curl -fsSL "/api/deploy/package/sh?token=${firstToken}" | sudo bash`)}>
                  <Copy className="w-3 h-3" /> Copy one-liner
                </Button>
              </div>

              <div className="border-t pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <Settings className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-medium">Manage the agent service</h4>
                </div>
                <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-xs space-y-1.5" data-testid="code-linux-service">
                  <p className="text-zinc-500"># Check status</p>
                  <p>sudo systemctl status aegisai360-agent</p>
                  <p className="text-zinc-500 mt-2"># View live logs</p>
                  <p>sudo journalctl -u aegisai360-agent -f</p>
                  <p className="text-zinc-500 mt-2"># Restart / stop</p>
                  <p>sudo systemctl restart aegisai360-agent</p>
                  <p>sudo systemctl stop aegisai360-agent</p>
                  <p className="text-zinc-500 mt-2"># Uninstall completely</p>
                  <p>sudo systemctl disable --now aegisai360-agent && sudo rm -rf /opt/aegisai360-agent</p>
                </div>
              </div>

              {/* Cloud control info */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
                {[
                  { icon: Cloud, title: "Cloud Connected", text: "Agent sends heartbeats every 60s to aegisai360.com. No inbound ports required — outbound HTTPS only." },
                  { icon: Lock, title: "Admin Suspension", text: "Super admin can suspend any agent instantly. The service stops on the next heartbeat (within 60s)." },
                  { icon: RefreshCw, title: "Auto Updates", text: "Agent polls for updates on each startup. New versions appear in the dashboard with a notification." },
                ].map(({ icon: Icon, title, text }) => (
                  <div key={title} className="p-3 rounded-lg border border-border/40 bg-muted/20 space-y-1">
                    <div className="flex items-center gap-1.5 text-xs font-semibold">
                      <Icon className="w-3.5 h-3.5 text-primary" />{title}
                    </div>
                    <p className="text-[10px] text-muted-foreground leading-relaxed">{text}</p>
                  </div>
                ))}
              </div>
            </TabsContent>

            {/* Windows instructions */}
            <TabsContent value="windows" className="space-y-5">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-medium" data-testid="text-method-doubleclick">{t("downloadAgent.optionATitle")}</h4>
                </div>
                <p className="text-sm text-muted-foreground mb-2" dangerouslySetInnerHTML={{ __html: t("downloadAgent.optionADesc") }} />
                <p className="text-xs text-amber-500 font-medium">{t("downloadAgent.optionANote")}</p>
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
                  <p>AegisAI360-Agent.exe https://aegisai360.com {firstToken}</p>
                </div>
                {availableTokens.length > 0 && (
                  <Button variant="outline" size="sm" className="mt-2" onClick={() => copyToClipboard(`AegisAI360-Agent.exe https://aegisai360.com ${firstToken}`)} data-testid="button-copy-run-command">
                    <Copy className="w-4 h-4 me-2" />{t("downloadAgent.copyFullCommand")}
                  </Button>
                )}
              </div>

              <div className="border-t pt-4">
                <div className="flex items-center gap-2 mb-2">
                  <Settings className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-medium" data-testid="text-method-service">{t("downloadAgent.optionCTitle")}</h4>
                </div>
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
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {/* What happens section */}
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="w-4 h-4" /> What happens after installation
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {[
              t("downloadAgent.connectStep1"),
              t("downloadAgent.connectStep2"),
              t("downloadAgent.connectStep3"),
              t("downloadAgent.connectStep4"),
              t("downloadAgent.connectStep5"),
              t("downloadAgent.connectStep6"),
              "Super admin can block or suspend the agent from the dashboard at any time",
              "If subscription lapses, all agents are automatically disconnected within 60 seconds",
            ].map((step, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className="flex-shrink-0 w-4 h-4 rounded-full bg-primary/20 text-primary text-[9px] flex items-center justify-center font-bold mt-0.5">{i + 1}</span>
                <span className="text-muted-foreground">{step}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
