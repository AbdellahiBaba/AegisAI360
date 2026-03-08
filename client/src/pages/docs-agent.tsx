import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { BookOpen, Terminal, Shield, Key, Monitor, Code, AlertTriangle, Package, Download } from "lucide-react";

export default function DocsAgent() {
  return (
    <div className="p-4 md:p-6 space-y-6 max-w-5xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2" data-testid="text-docs-title">
          <BookOpen className="w-6 h-6" />
          Agent Documentation
        </h1>
        <p className="text-muted-foreground text-sm">Complete guide to deploying and managing endpoint agents</p>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList data-testid="tabs-docs" className="flex-wrap">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="installer">Installer</TabsTrigger>
          <TabsTrigger value="registration">Registration</TabsTrigger>
          <TabsTrigger value="commands">Commands</TabsTrigger>
          <TabsTrigger value="terminal">Terminal</TabsTrigger>
          <TabsTrigger value="api">API Reference</TabsTrigger>
          <TabsTrigger value="plans">Plans</TabsTrigger>
        </TabsList>

        <TabsContent value="overview">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Monitor className="w-5 h-5" />Endpoint Agent System</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <p>The AegisAI360 Endpoint Agent is a lightweight process that runs on your endpoints (servers, workstations, laptops) and communicates with the SOC platform to provide real-time monitoring, command execution, and threat detection.</p>
              <h3>Architecture</h3>
              <ul>
                <li><strong>Device Token</strong> - A unique token generated via the dashboard, used once to register an agent</li>
                <li><strong>Agent Registration</strong> - The agent registers with hostname, OS, and IP using the device token</li>
                <li><strong>Heartbeat</strong> - The agent sends periodic heartbeats with CPU/RAM metrics</li>
                <li><strong>Log Ingestion</strong> - Security events from the endpoint are sent to the SOC platform</li>
                <li><strong>Command Polling</strong> - The agent polls for pending commands and executes them</li>
              </ul>
              <h3>Security Notes</h3>
              <ul>
                <li>Device tokens are single-use and cannot be reused after registration</li>
                <li>All agent communication uses the device token for authentication</li>
                <li>Terminal commands are restricted to a safe whitelist</li>
                <li>All terminal activity is logged in audit logs</li>
                <li>Destructive commands (rm, del, format, etc.) are always blocked</li>
              </ul>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="installer">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Package className="w-5 h-5" />Windows Installer Bundle</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <p>A complete Windows installer bundle is available in the <code>/installer</code> directory. It includes a Go-based agent, WinSW service wrapper, and NSIS installer script.</p>

              <h3>Bundle Contents</h3>
              <table>
                <thead>
                  <tr><th>File</th><th>Description</th></tr>
                </thead>
                <tbody>
                  <tr><td><code>main.go</code></td><td>Complete Go agent source code</td></tr>
                  <tr><td><code>AegisAI360Agent.xml</code></td><td>WinSW service wrapper configuration</td></tr>
                  <tr><td><code>installer.nsi</code></td><td>NSIS installer script</td></tr>
                  <tr><td><code>README.txt</code></td><td>Detailed build instructions</td></tr>
                </tbody>
              </table>

              <h3>Step 1: Build the Agent</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`# Native Windows build
go build -o agent.exe main.go

# Cross-compile from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o agent.exe main.go`}</pre>

              <h3>Step 2: Download WinSW</h3>
              <p>Download <code>WinSW-x64.exe</code> from <a href="https://github.com/winsw/winsw/releases" target="_blank" rel="noopener noreferrer" className="text-primary">github.com/winsw/winsw/releases</a> and rename it to <code>AegisAI360Agent.exe</code>.</p>

              <h3>Step 3: Configure</h3>
              <p>Edit <code>AegisAI360Agent.xml</code> and set your server URL and device token:</p>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`<env name="AEGIS_SERVER_URL" value="https://your-server.com"/>
<env name="AEGIS_DEVICE_TOKEN" value="agt_your_token_here"/>`}</pre>

              <h3>Step 4: Build the Installer</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`# Requires NSIS 3.x installed
makensis installer.nsi

# Output: AegisAI360-Agent-Setup.exe`}</pre>

              <h3>Step 5: Install</h3>
              <p>Run <code>AegisAI360-Agent-Setup.exe</code> as Administrator. The installer will copy all files, register the Windows service, and start the agent automatically.</p>

              <h3>Agent Features</h3>
              <ul>
                <li>Registers with the SOC platform using a single-use device token</li>
                <li>Sends heartbeats every 30 seconds with system metrics</li>
                <li>Polls for commands every 5 seconds</li>
                <li>Supports <code>ping</code>, <code>run_system_scan</code>, and <code>terminal_exec</code> commands</li>
                <li>Enforces the same terminal command whitelist as the server</li>
                <li>Runs as a Windows service with auto-restart on failure</li>
              </ul>

              <h3>Uninstall</h3>
              <p>Use Windows Add/Remove Programs, or run <code>uninstall.exe</code> from the install directory. The uninstaller stops the service, removes it, and deletes all files.</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="registration">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Key className="w-5 h-5" />Registration Flow</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <h3>Step 1: Generate Device Token</h3>
              <p>Navigate to <strong>Deploy Agent</strong> in the sidebar and click "Generate New Token". Copy the token for use in step 2.</p>
              <h3>Step 2: Register Agent</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`POST /api/agent/register
Content-Type: application/json

{
  "token": "agt_your_device_token_here",
  "hostname": "workstation-01",
  "os": "Windows 11",
  "ip": "192.168.1.100"
}`}</pre>
              <h3>Step 3: Start Heartbeat Loop</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`POST /api/agent/heartbeat
Content-Type: application/json

{
  "agentId": 1,
  "token": "agt_your_device_token_here",
  "cpuUsage": 45,
  "ramUsage": 62,
  "ip": "192.168.1.100"
}`}</pre>
              <p>Send heartbeats every 30-60 seconds to maintain "online" status.</p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="commands">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Code className="w-5 h-5" />Command System</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <p>SOC analysts can send commands to agents from the dashboard. The agent polls for pending commands and reports results.</p>
              <h3>Available Commands</h3>
              <ul>
                <li><code>run_system_scan</code> - Full system security scan</li>
                <li><code>list_processes</code> - List running processes</li>
                <li><code>scan_directory</code> - Scan a specific directory for threats</li>
                <li><code>ping</code> - Network connectivity test</li>
                <li><code>kill_process</code> - Terminate a process (requires Professional plan)</li>
                <li><code>isolate_network</code> - Isolate endpoint from network (requires Professional plan)</li>
                <li><code>restore_network</code> - Restore network connectivity</li>
                <li><code>terminal_exec</code> - Remote terminal command execution</li>
              </ul>
              <h3>Polling for Commands</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`GET /api/agent/commands?agentId=1&token=agt_your_token

Response: [
  { "id": 5, "command": "run_system_scan", "params": null, "status": "pending" }
]`}</pre>
              <h3>Reporting Results</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`POST /api/agent/command-result
Content-Type: application/json

{
  "commandId": 5,
  "agentId": 1,
  "token": "agt_your_token",
  "status": "done",
  "result": "Scan complete. No threats found."
}`}</pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="terminal">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Terminal className="w-5 h-5" />Terminal Access</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <div className="flex items-center gap-2 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded mb-4 not-prose">
                <AlertTriangle className="w-4 h-4 text-yellow-500 shrink-0" />
                <span className="text-yellow-700 dark:text-yellow-400 text-xs">Terminal access requires Professional or Enterprise plan</span>
              </div>
              <h3>Allowed Commands</h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4>Linux</h4>
                  <ul>
                    <li><code>whoami</code></li>
                    <li><code>ifconfig</code></li>
                    <li><code>ip a</code></li>
                    <li><code>netstat</code></li>
                    <li><code>ss</code></li>
                    <li><code>ps aux</code></li>
                    <li><code>ls</code></li>
                    <li><code>uname -a</code></li>
                    <li><code>df -h</code></li>
                    <li><code>free -m</code></li>
                  </ul>
                </div>
                <div>
                  <h4>Windows</h4>
                  <ul>
                    <li><code>whoami</code></li>
                    <li><code>ipconfig</code></li>
                    <li><code>netstat</code></li>
                    <li><code>tasklist</code></li>
                    <li><code>dir</code></li>
                    <li><code>systeminfo</code></li>
                    <li><code>hostname</code></li>
                  </ul>
                </div>
              </div>
              <h3>Blocked Patterns</h3>
              <p>The following are always blocked: <code>rm</code>, <code>del</code>, <code>format</code>, <code>shutdown</code>, <code>reboot</code>, <code>sudo</code>, <code>chmod</code>, <code>wget</code>, <code>curl</code>, <code>kill</code>, <code>eval</code>, <code>exec</code></p>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="api">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Code className="w-5 h-5" />API Reference</CardTitle>
            </CardHeader>
            <CardContent className="prose dark:prose-invert max-w-none text-sm space-y-4">
              <h3>Agent Endpoints (No session required - uses device token)</h3>
              <table>
                <thead>
                  <tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
                </thead>
                <tbody>
                  <tr><td>POST</td><td>/api/agent/register</td><td>Register new agent with device token</td></tr>
                  <tr><td>POST</td><td>/api/agent/heartbeat</td><td>Send heartbeat with metrics</td></tr>
                  <tr><td>POST</td><td>/api/agent/logs</td><td>Ingest security events from agent</td></tr>
                  <tr><td>GET</td><td>/api/agent/commands</td><td>Poll for pending commands</td></tr>
                  <tr><td>POST</td><td>/api/agent/command-result</td><td>Report command execution result</td></tr>
                </tbody>
              </table>
              <h3>Dashboard Endpoints (Session required)</h3>
              <table>
                <thead>
                  <tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
                </thead>
                <tbody>
                  <tr><td>POST</td><td>/api/agent/device-token/create</td><td>Generate new device token</td></tr>
                  <tr><td>GET</td><td>/api/agent/list</td><td>List all agents for org</td></tr>
                  <tr><td>GET</td><td>/api/agent/:id</td><td>Get agent details</td></tr>
                  <tr><td>POST</td><td>/api/agent/send-command</td><td>Send command to agent</td></tr>
                  <tr><td>POST</td><td>/api/agent/terminal/execute</td><td>Execute terminal command</td></tr>
                </tbody>
              </table>
              <h3>Example Go Agent (Skeleton)</h3>
              <pre className="bg-muted p-3 rounded text-xs overflow-x-auto">{`package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "runtime"
    "time"
)

const baseURL = "https://aegisai360.com/api/agent"

type Agent struct {
    ID    int    \`json:"agentId"\`
    Token string \`json:"token"\`
}

func register(token, hostname string) (*Agent, error) {
    body, _ := json.Marshal(map[string]string{
        "token":    token,
        "hostname": hostname,
        "os":       runtime.GOOS,
    })
    resp, err := http.Post(baseURL+"/register", "application/json", bytes.NewReader(body))
    if err != nil { return nil, err }
    defer resp.Body.Close()
    var result struct { AgentId int \`json:"agentId"\` }
    json.NewDecoder(resp.Body).Decode(&result)
    return &Agent{ID: result.AgentId, Token: token}, nil
}

func (a *Agent) heartbeat() {
    body, _ := json.Marshal(map[string]interface{}{
        "agentId": a.ID, "token": a.Token,
        "cpuUsage": 25, "ramUsage": 50,
    })
    http.Post(baseURL+"/heartbeat", "application/json", bytes.NewReader(body))
}

func main() {
    token := os.Args[1]
    hostname, _ := os.Hostname()
    agent, err := register(token, hostname)
    if err != nil { fmt.Println("Registration failed:", err); return }
    fmt.Printf("Registered as agent %d\\n", agent.ID)
    for { agent.heartbeat(); time.Sleep(30 * time.Second) }
}`}</pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="plans">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Shield className="w-5 h-5" />Plan Feature Matrix</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b">
                      <th className="text-start py-2 pe-4">Feature</th>
                      <th className="py-2 px-4">Starter</th>
                      <th className="py-2 px-4">Professional</th>
                      <th className="py-2 px-4">Enterprise</th>
                    </tr>
                  </thead>
                  <tbody className="text-center">
                    <tr className="border-b"><td className="text-start py-2 pe-4">Max Agents</td><td>3</td><td>25</td><td>Unlimited</td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Logs/Day</td><td>500</td><td>5,000</td><td>50,000</td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Commands/Day</td><td>20</td><td>200</td><td>2,000</td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Threat Intel Queries</td><td>20</td><td>200</td><td>2,000</td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">File Scanning</td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Agent Downloads</td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Threat Intelligence</td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Network Isolation</td><td><Badge variant="secondary">No</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Process Kill</td><td><Badge variant="secondary">No</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr className="border-b"><td className="text-start py-2 pe-4">Terminal Access</td><td><Badge variant="secondary">No</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                    <tr><td className="text-start py-2 pe-4">Advanced Analytics</td><td><Badge variant="secondary">No</Badge></td><td><Badge>Yes</Badge></td><td><Badge>Yes</Badge></td></tr>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
