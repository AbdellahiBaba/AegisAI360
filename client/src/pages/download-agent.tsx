import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Download, Copy, Key, Monitor, Apple, Terminal as TerminalIcon, Package } from "lucide-react";

export default function DownloadAgent() {
  const { toast } = useToast();
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);

  const { data: tokens, isLoading } = useQuery<any[]>({
    queryKey: ["/api/agent/device-tokens"],
  });

  const { data: billing } = useQuery<any>({
    queryKey: ["/api/billing/status"],
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

  const copyToken = () => {
    if (generatedToken) {
      navigator.clipboard.writeText(generatedToken);
      toast({ title: "Copied to clipboard" });
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-4xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold" data-testid="text-download-title">Deploy Endpoint Agent</h1>
        <p className="text-muted-foreground text-sm">Generate a device token and install the agent on your endpoints</p>
      </div>

      <Card data-testid="card-generate-token">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="w-5 h-5" />
            Step 1: Generate Device Token
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
              <Button size="sm" variant="outline" onClick={copyToken} data-testid="button-copy-token">
                <Copy className="w-4 h-4" />
              </Button>
            </div>
          )}

          {tokens && tokens.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Recent Tokens</h4>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {tokens.slice(0, 10).map((t: any) => (
                  <div key={t.id} className="flex items-center justify-between text-xs p-2 bg-muted/50 rounded" data-testid={`row-token-${t.id}`}>
                    <span className="font-mono">{t.token.slice(0, 20)}...</span>
                    <Badge variant={t.used ? "default" : "secondary"}>{t.used ? "Used" : "Available"}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card data-testid="card-download-agent">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="w-5 h-5" />
            Step 2: Download Agent
          </CardTitle>
          <CardDescription>Download and install the agent for your operating system</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card data-testid="card-download-windows">
              <CardContent className="pt-6 text-center">
                <Monitor className="w-10 h-10 mx-auto mb-3 text-blue-500" />
                <h3 className="font-medium">Windows</h3>
                <p className="text-xs text-muted-foreground mt-1">Windows 10/11, Server 2019+</p>
                <Badge className="mt-2">Installer Available</Badge>
                <a href="/docs/agent" className="block mt-3">
                  <Button className="w-full" variant="outline" data-testid="button-download-windows">
                    <Package className="w-4 h-4 me-2" />
                    Build Instructions
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

          <div className="mt-4 p-3 bg-muted/50 rounded text-sm text-muted-foreground" data-testid="text-agent-note">
            The Windows installer bundle (Go agent + NSIS installer + WinSW service wrapper) is available in the <code className="text-primary">/installer</code> directory. See the <a href="/docs/agent" className="text-primary underline">documentation</a> for build instructions and the full API reference.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
