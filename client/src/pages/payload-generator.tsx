import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Terminal, Loader2, Copy, Check, AlertTriangle, Shield,
  Code, Globe, Cpu, Lock, FileCode, Braces,
} from "lucide-react";

function DisclaimerBanner() {
  return (
    <Alert className="border-severity-medium/50 bg-severity-medium/10 mb-4">
      <AlertTriangle className="w-4 h-4 text-severity-medium" />
      <AlertDescription className="text-xs" data-testid="text-disclaimer">
        <span className="font-semibold">Educational Use Only</span> — These tools generate real payloads for authorized penetration testing, security research, and defensive training in controlled lab environments. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
      </AlertDescription>
    </Alert>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      size="icon"
      variant="ghost"
      onClick={handleCopy}
      data-testid="button-copy-payload"
    >
      {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
    </Button>
  );
}

function CodeBlock({ code, title }: { code: string; title?: string }) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2 pt-3 px-4">
        <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
          <Code className="w-4 h-4" />
          {title || "Generated Payload"}
        </CardTitle>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="text-[9px] font-mono">
            {code.length} bytes
          </Badge>
          <CopyButton text={code} />
        </div>
      </CardHeader>
      <CardContent className="px-4 pb-4">
        <pre
          className="text-xs font-mono bg-muted/50 p-3 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-[400px] overflow-y-auto"
          data-testid="text-payload-output"
        >
          {code}
        </pre>
      </CardContent>
    </Card>
  );
}

function EncodingSection({ payload }: { payload: string }) {
  const { toast } = useToast();
  const [encoding, setEncoding] = useState("base64");
  const [encodedResult, setEncodedResult] = useState<string | null>(null);

  const encodeMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/payload/encode", { payload, encoding });
      return res.json();
    },
    onSuccess: (data) => {
      setEncodedResult(data.encoded);
    },
    onError: () => {
      toast({ title: "Encoding failed", variant: "destructive" });
    },
  });

  if (!payload) return null;

  return (
    <Card>
      <CardHeader className="pb-2 pt-3 px-4">
        <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
          <Braces className="w-4 h-4" />
          Payload Encoding
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4 pb-4 space-y-3">
        <div className="flex gap-2">
          <Select value={encoding} onValueChange={setEncoding}>
            <SelectTrigger className="flex-1" data-testid="select-encoding">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="base64">Base64</SelectItem>
              <SelectItem value="url">URL Encoding</SelectItem>
              <SelectItem value="hex">Hex</SelectItem>
              <SelectItem value="unicode">Unicode</SelectItem>
              <SelectItem value="double">Double Encoding</SelectItem>
              <SelectItem value="powershell">PowerShell Encoded</SelectItem>
            </SelectContent>
          </Select>
          <Button
            onClick={() => encodeMutation.mutate()}
            disabled={encodeMutation.isPending}
            data-testid="button-encode"
          >
            {encodeMutation.isPending ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              "Encode"
            )}
          </Button>
        </div>
        {encodedResult && (
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[10px] text-muted-foreground uppercase font-mono">Encoded Output</span>
              <CopyButton text={encodedResult} />
            </div>
            <pre
              className="text-xs font-mono bg-muted/50 p-3 rounded-md overflow-x-auto whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto"
              data-testid="text-encoded-output"
            >
              {encodedResult}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ReverseBindShellTab() {
  const { toast } = useToast();
  const [language, setLanguage] = useState("python");
  const [shellType, setShellType] = useState<"reverse" | "bind">("reverse");
  const [ip, setIp] = useState("10.0.0.1");
  const [port, setPort] = useState("4444");
  const [encrypted, setEncrypted] = useState(false);
  const [protocol, setProtocol] = useState<"tcp" | "udp">("tcp");
  const [result, setResult] = useState<any>(null);

  const { data: languages, isLoading: langLoading } = useQuery<any>({
    queryKey: ["/api/payload/languages"],
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      const endpoint = shellType === "reverse" ? "/api/payload/reverse-shell" : "/api/payload/bind-shell";
      const body = shellType === "reverse"
        ? { language, ip, port: parseInt(port), options: { encrypted, protocol } }
        : { language, port: parseInt(port) };
      const res = await apiRequest("POST", endpoint, body);
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Payload generated", description: `${language} ${shellType} shell ready` });
    },
    onError: () => {
      toast({ title: "Generation failed", variant: "destructive" });
    },
  });

  const shellLanguages = languages?.reverseShell || [];

  return (
    <div className="space-y-4">
      <DisclaimerBanner />

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            Shell Generator
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Language</Label>
              {langLoading ? (
                <Skeleton className="h-9 w-full" />
              ) : (
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger data-testid="select-shell-language">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {shellLanguages.map((lang: string) => (
                      <SelectItem key={lang} value={lang}>{lang.charAt(0).toUpperCase() + lang.slice(1)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Shell Type</Label>
              <Select value={shellType} onValueChange={(v) => setShellType(v as "reverse" | "bind")}>
                <SelectTrigger data-testid="select-shell-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="reverse">Reverse Shell</SelectItem>
                  <SelectItem value="bind">Bind Shell</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {shellType === "reverse" && (
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">LHOST (Listener IP)</Label>
                <Input
                  value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="10.0.0.1"
                  className="font-mono text-xs"
                  data-testid="input-shell-ip"
                />
              </div>
            )}

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">
                {shellType === "reverse" ? "LPORT (Listener Port)" : "Port"}
              </Label>
              <Input
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="4444"
                className="font-mono text-xs"
                data-testid="input-shell-port"
              />
            </div>
          </div>

          {shellType === "reverse" && (
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center gap-2">
                <Switch
                  checked={encrypted}
                  onCheckedChange={setEncrypted}
                  data-testid="switch-encrypted"
                />
                <Label className="text-xs">Encrypted</Label>
              </div>
              <div className="space-y-1.5">
                <Select value={protocol} onValueChange={(v) => setProtocol(v as "tcp" | "udp")}>
                  <SelectTrigger className="w-24" data-testid="select-protocol">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <Button
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending || (!ip && shellType === "reverse") || !port}
            data-testid="button-generate-shell"
          >
            {generateMutation.isPending ? (
              <><Loader2 className="w-4 h-4 me-2 animate-spin" />Generating...</>
            ) : (
              <><Terminal className="w-4 h-4 me-2" />Generate {shellType === "reverse" ? "Reverse" : "Bind"} Shell</>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <>
          <CodeBlock code={result.payload} title={`${result.language} ${result.type}`} />
          {result.notes && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Educational Notes
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <p className="text-xs text-muted-foreground whitespace-pre-wrap" data-testid="text-shell-notes">
                  {result.notes}
                </p>
              </CardContent>
            </Card>
          )}
          <EncodingSection payload={result.payload} />
        </>
      )}
    </div>
  );
}

function WebShellTab() {
  const { toast } = useToast();
  const [language, setLanguage] = useState("php");
  const [fileManager, setFileManager] = useState(true);
  const [commandExec, setCommandExec] = useState(true);
  const [upload, setUpload] = useState(false);
  const [authentication, setAuthentication] = useState(false);
  const [password, setPassword] = useState("");
  const [obfuscation, setObfuscation] = useState(false);
  const [result, setResult] = useState<any>(null);

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/payload/web-shell", {
        language,
        options: { fileManager, commandExec, upload, authentication, password: authentication ? password : undefined, obfuscation },
      });
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Web shell generated", description: `${language.toUpperCase()} web shell ready` });
    },
    onError: () => {
      toast({ title: "Generation failed", variant: "destructive" });
    },
  });

  return (
    <div className="space-y-4">
      <DisclaimerBanner />

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Web Shell Generator
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Language</Label>
              <Select value={language} onValueChange={setLanguage}>
                <SelectTrigger data-testid="select-webshell-language">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="php">PHP</SelectItem>
                  <SelectItem value="aspx">ASPX</SelectItem>
                  <SelectItem value="jsp">JSP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-3">
            <Label className="text-xs text-muted-foreground uppercase font-mono">Features</Label>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="flex items-center gap-2">
                <Switch
                  checked={fileManager}
                  onCheckedChange={setFileManager}
                  data-testid="switch-file-manager"
                />
                <Label className="text-xs">File Manager</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={commandExec}
                  onCheckedChange={setCommandExec}
                  data-testid="switch-command-exec"
                />
                <Label className="text-xs">Command Exec</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={upload}
                  onCheckedChange={setUpload}
                  data-testid="switch-upload"
                />
                <Label className="text-xs">File Upload</Label>
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <Label className="text-xs text-muted-foreground uppercase font-mono">Security & Obfuscation</Label>
            <div className="flex flex-wrap gap-4">
              <div className="flex items-center gap-2">
                <Switch
                  checked={authentication}
                  onCheckedChange={setAuthentication}
                  data-testid="switch-authentication"
                />
                <Label className="text-xs">Authentication</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch
                  checked={obfuscation}
                  onCheckedChange={setObfuscation}
                  data-testid="switch-obfuscation"
                />
                <Label className="text-xs">Obfuscation</Label>
              </div>
            </div>
            {authentication && (
              <div className="space-y-1.5 max-w-xs">
                <Label className="text-xs text-muted-foreground">Password</Label>
                <Input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter shell password"
                  className="font-mono text-xs"
                  data-testid="input-webshell-password"
                />
              </div>
            )}
          </div>

          <Button
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending || (authentication && !password)}
            data-testid="button-generate-webshell"
          >
            {generateMutation.isPending ? (
              <><Loader2 className="w-4 h-4 me-2 animate-spin" />Generating...</>
            ) : (
              <><FileCode className="w-4 h-4 me-2" />Generate Web Shell</>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <>
          <CodeBlock code={result.payload} title={`${result.language} Web Shell`} />
          {result.notes && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Educational Notes
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <p className="text-xs text-muted-foreground whitespace-pre-wrap" data-testid="text-webshell-notes">
                  {result.notes}
                </p>
              </CardContent>
            </Card>
          )}
          <EncodingSection payload={result.payload} />
        </>
      )}
    </div>
  );
}

function MeterpreterTab() {
  const { toast } = useToast();
  const [platform, setPlatform] = useState("windows");
  const [arch, setArch] = useState("x64");
  const [payloadType, setPayloadType] = useState("reverse_tcp");
  const [lhost, setLhost] = useState("10.0.0.1");
  const [lport, setLport] = useState("4444");
  const [encoder, setEncoder] = useState("x86/shikata_ga_nai");
  const [iterations, setIterations] = useState("5");
  const [result, setResult] = useState<any>(null);

  const { data: languages, isLoading: langLoading } = useQuery<any>({
    queryKey: ["/api/payload/languages"],
  });

  const generateMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/payload/meterpreter", {
        platform,
        arch,
        payloadType,
        options: {
          lhost,
          lport: parseInt(lport),
          encoder,
          iterations: parseInt(iterations),
        },
      });
      return res.json();
    },
    onSuccess: (data) => {
      setResult(data);
      toast({ title: "Meterpreter stager generated", description: `${platform}/${arch} command ready` });
    },
    onError: () => {
      toast({ title: "Generation failed", variant: "destructive" });
    },
  });

  const meterpreterConfig = languages?.meterpreter;
  const encoders = meterpreterConfig?.encoders || [];

  return (
    <div className="space-y-4">
      <DisclaimerBanner />

      <Card>
        <CardHeader className="pb-2 pt-3 px-4">
          <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
            <Cpu className="w-4 h-4" />
            Meterpreter Stager Generator
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Platform</Label>
              {langLoading ? (
                <Skeleton className="h-9 w-full" />
              ) : (
                <Select value={platform} onValueChange={setPlatform}>
                  <SelectTrigger data-testid="select-meterpreter-platform">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(meterpreterConfig?.platforms || ["windows", "linux", "android", "osx"]).map((p: string) => (
                      <SelectItem key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Architecture</Label>
              <Select value={arch} onValueChange={setArch}>
                <SelectTrigger data-testid="select-meterpreter-arch">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(meterpreterConfig?.architectures || ["x86", "x64", "arm"]).map((a: string) => (
                    <SelectItem key={a} value={a}>{a.toUpperCase()}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Payload Type</Label>
              <Select value={payloadType} onValueChange={setPayloadType}>
                <SelectTrigger data-testid="select-meterpreter-payload-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {(meterpreterConfig?.payloadTypes || ["reverse_tcp", "reverse_https", "bind_tcp"]).map((pt: string) => (
                    <SelectItem key={pt} value={pt}>{pt.replace(/_/g, " ").toUpperCase()}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">LHOST</Label>
              <Input
                value={lhost}
                onChange={(e) => setLhost(e.target.value)}
                placeholder="10.0.0.1"
                className="font-mono text-xs"
                data-testid="input-meterpreter-lhost"
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">LPORT</Label>
              <Input
                value={lport}
                onChange={(e) => setLport(e.target.value)}
                placeholder="4444"
                className="font-mono text-xs"
                data-testid="input-meterpreter-lport"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Encoder</Label>
              <Select value={encoder} onValueChange={setEncoder}>
                <SelectTrigger data-testid="select-meterpreter-encoder">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {encoders.map((enc: string) => (
                    <SelectItem key={enc} value={enc}>{enc}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Iterations</Label>
              <Input
                type="number"
                value={iterations}
                onChange={(e) => setIterations(e.target.value)}
                min={1}
                max={20}
                className="font-mono text-xs"
                data-testid="input-meterpreter-iterations"
              />
            </div>
          </div>

          <Button
            onClick={() => generateMutation.mutate()}
            disabled={generateMutation.isPending || !lhost || !lport}
            data-testid="button-generate-meterpreter"
          >
            {generateMutation.isPending ? (
              <><Loader2 className="w-4 h-4 me-2 animate-spin" />Generating...</>
            ) : (
              <><Cpu className="w-4 h-4 me-2" />Generate Meterpreter Command</>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <>
          <CodeBlock code={result.command || result.payload} title="msfvenom Command" />
          {result.notes && (
            <Card>
              <CardHeader className="pb-2 pt-3 px-4">
                <CardTitle className="text-xs font-mono tracking-wider uppercase flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  Educational Notes
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4">
                <p className="text-xs text-muted-foreground whitespace-pre-wrap" data-testid="text-meterpreter-notes">
                  {result.notes}
                </p>
              </CardContent>
            </Card>
          )}
          {(result.command || result.payload) && (
            <EncodingSection payload={result.command || result.payload} />
          )}
        </>
      )}
    </div>
  );
}

export default function PayloadGeneratorPage() {
  return (
    <div className="p-4 space-y-4 max-w-5xl mx-auto">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Terminal className="w-5 h-5 text-primary" />
          <h1 className="text-lg font-bold font-mono tracking-tight" data-testid="text-page-title">
            Payload Generator
          </h1>
        </div>
        <Badge variant="secondary" className="text-[9px] font-mono">EDUCATIONAL</Badge>
        <Badge className="text-[9px] font-mono bg-severity-medium text-black">LAB USE ONLY</Badge>
      </div>

      <Tabs defaultValue="shell" className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="shell" data-testid="tab-shell" className="text-xs gap-1.5">
            <Terminal className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Reverse/Bind Shell</span>
            <span className="sm:hidden">Shell</span>
          </TabsTrigger>
          <TabsTrigger value="webshell" data-testid="tab-webshell" className="text-xs gap-1.5">
            <Globe className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Web Shell</span>
            <span className="sm:hidden">Web</span>
          </TabsTrigger>
          <TabsTrigger value="meterpreter" data-testid="tab-meterpreter" className="text-xs gap-1.5">
            <Cpu className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Meterpreter</span>
            <span className="sm:hidden">Msf</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="shell">
          <ReverseBindShellTab />
        </TabsContent>

        <TabsContent value="webshell">
          <WebShellTab />
        </TabsContent>

        <TabsContent value="meterpreter">
          <MeterpreterTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
