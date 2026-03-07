import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Download, Copy, Key, Monitor, Apple, Terminal as TerminalIcon, CheckCircle, AlertCircle } from "lucide-react";

export default function DownloadAgent() {
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
      toast({ title: "Device token generated" });
    },
    onError: (error: any) => {
      toast({ title: "Error", description: error.message || "Failed to generate token", variant: "destructive" });
    },
  });

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied to clipboard" });
  };

  const availableTokens = tokens?.filter((t: any) => !t.used) || [];

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold" data-testid="text-download-title">Deploy Endpoint Agent</h1>
        <p className="text-muted-foreground text-sm">Download the agent, generate a token, and run it on your endpoints</p>
      </div>

      <Card data-testid="card-download-agent">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="w-5 h-5" />
            Step 1: Download the Agent
          </CardTitle>
          <CardDescription>Download the pre-compiled agent for your operating system</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="border-2 border-primary" data-testid="card-download-windows">
              <CardContent className="pt-6 text-center">
                <Monitor className="w-10 h-10 mx-auto mb-3 text-blue-500" />
                <h3 className="font-medium">Windows</h3>
                <p className="text-xs text-muted-foreground mt-1">Windows 10/11, Server 2019+</p>
                <Badge className="mt-2" variant="default">Ready to Download</Badge>
                <a href="/downloads/AegisAI360-Agent.exe" download className="block mt-3">
                  <Button className="w-full" data-testid="button-download-windows">
                    <Download className="w-4 h-4 me-2" />
                    Download .exe (7 MB)
                  </Button>
                </a>
              </CardContent>
            </Card>

            <Card className="border-dashed" data-testid="card-download-linux">
              <CardContent className="pt-6 text-center">
                <TerminalIcon className="w-10 h-10 mx-auto mb-3 text-orange-500" />
                <h3 className="font-medium">Linux</h3>
                <p className="text-xs text-muted-foreground mt-1">Ubuntu, CentOS, Debian</p>
                <Button className="mt-3 w-full" variant="outline" disabled data-testid="button-download-linux">
                  Coming Soon
                </Button>
              </CardContent>
            </Card>

            <Card className="border-dashed" data-testid="card-download-macos">
              <CardContent className="pt-6 text-center">
                <Apple className="w-10 h-10 mx-auto mb-3 text-gray-500" />
                <h3 className="font-medium">macOS</h3>
                <p className="text-xs text-muted-foreground mt-1">macOS 12 Monterey+</p>
                <Button className="mt-3 w-full" variant="outline" disabled data-testid="button-download-macos">
                  Coming Soon
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
            Step 2: Generate Device Token
          </CardTitle>
          <CardDescription>Each agent needs a unique device token to register with the platform</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button
            onClick={() => generateTokenMutation.mutate()}
            disabled={generateTokenMutation.isPending}
            data-testid="button-generate-token"
          >
            {generateTokenMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin me-2" /> : <Key className="w-4 h-4 me-2" />}
            Generate New Token
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
              <h4 className="text-sm font-medium mb-2">Your Tokens</h4>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {tokens.slice(0, 10).map((t: any) => (
                  <div key={t.id} className="flex items-center justify-between text-xs p-2 bg-muted/50 rounded" data-testid={`row-token-${t.id}`}>
                    <div className="flex items-center gap-2">
                      {t.used ? (
                        <CheckCircle className="w-3 h-3 text-green-500" />
                      ) : (
                        <AlertCircle className="w-3 h-3 text-yellow-500" />
                      )}
                      <span className="font-mono">{t.token.slice(0, 24)}...</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant={t.used ? "default" : "secondary"}>{t.used ? "Used" : "Available"}</Badge>
                      {!t.used && (
                        <Button size="sm" variant="ghost" className="h-6 px-2" onClick={() => copyToClipboard(t.token)} data-testid={`button-copy-token-${t.id}`}>
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
            Step 3: Run the Agent
          </CardTitle>
          <CardDescription>Open Command Prompt (or PowerShell) and run the agent with your token</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="bg-zinc-950 text-zinc-100 rounded-lg p-4 font-mono text-sm space-y-2" data-testid="code-run-command">
            <p className="text-zinc-500">:: Navigate to your Downloads folder</p>
            <p>cd %USERPROFILE%\Downloads</p>
            <p className="text-zinc-500 mt-3">:: Run the agent with your server URL and device token</p>
            <p>AegisAI360-Agent.exe https://aegisai360.com {availableTokens.length > 0 ? availableTokens[0].token : "YOUR_DEVICE_TOKEN"}</p>
          </div>

          {availableTokens.length > 0 && (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => copyToClipboard(`AegisAI360-Agent.exe https://aegisai360.com ${availableTokens[0].token}`)}
                data-testid="button-copy-run-command"
              >
                <Copy className="w-4 h-4 me-2" />
                Copy Full Command
              </Button>
              <span className="text-xs text-muted-foreground">Using your first available token</span>
            </div>
          )}

          <div className="mt-4 space-y-2 text-sm text-muted-foreground">
            <p className="font-medium text-foreground">What happens next:</p>
            <ul className="list-disc list-inside space-y-1 ms-2">
              <li>The agent registers with AegisAI360 using the device token (one-time use)</li>
              <li>It starts sending heartbeats with CPU/RAM metrics every 30 seconds</li>
              <li>It polls for commands from the dashboard every 5 seconds</li>
              <li>You will see the endpoint appear in your dashboard within seconds</li>
            </ul>
          </div>

          <div className="mt-4 p-3 bg-muted/50 rounded text-sm" data-testid="text-config-note">
            <p className="font-medium mb-1">Alternative: Config File</p>
            <p className="text-muted-foreground">
              Instead of passing arguments on the command line, you can create a <code className="text-primary">config.json</code> file
              in the same folder as the .exe:
            </p>
            <pre className="bg-zinc-950 text-zinc-100 rounded p-3 mt-2 text-xs overflow-x-auto">{`{
  "serverUrl": "https://aegisai360.com",
  "apiKey": "${availableTokens.length > 0 ? availableTokens[0].token : "agt_YOUR_TOKEN_HERE"}"
}`}</pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
