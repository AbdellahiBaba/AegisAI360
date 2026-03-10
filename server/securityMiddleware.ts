import type { Request, Response, NextFunction } from "express";
import { storage } from "./storage";

const suspiciousPatterns = [
  /(\b(union|select|insert|update|delete|drop|alter|exec|execute)\b.*\b(from|into|table|database|where)\b)/i,
  /(--|;|\/\*|\*\/|xp_|sp_)/,
  /(<script|<\/script|javascript:|on\w+\s*=)/i,
  /(\.\.\/|\.\.\\|%2e%2e|%252e)/i,
  /(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|gobuster|wfuzz)/i,
  /(\{|\}|\$\{|<%|%>|\$\()/,
];

const attackTypeMap: Record<string, string> = {
  sql: "SQL Injection Attempt",
  xss: "Cross-Site Scripting Attempt",
  traversal: "Path Traversal Attempt",
  scanner: "Automated Scanner Detected",
  injection: "Code Injection Attempt",
};

function classifyThreat(value: string, context: "url" | "body" | "header" = "body"): string | null {
  if (/(union|select|insert|update|delete|drop|alter|exec|execute)/i.test(value) && /(from|into|table|database|where)/i.test(value)) return "sql";
  if (context !== "header" && /(--|\/\*|\*\/|xp_|sp_)/.test(value)) return "sql";
  if (/(<script|<\/script|javascript:|on\w+\s*=)/i.test(value)) return "xss";
  if (/(\.\.\/|\.\.\\|%2e%2e|%252e)/i.test(value)) return "traversal";
  if (/(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|gobuster|wfuzz)/i.test(value)) return "scanner";
  if (/(\$\{|<%|%>|\$\()/.test(value) && value.length > 50) return "injection";
  return null;
}

function scanValue(value: unknown): string | null {
  if (typeof value === "string") {
    return classifyThreat(value);
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const threat = scanValue(item);
      if (threat) return threat;
    }
  }
  if (value && typeof value === "object") {
    for (const key of Object.keys(value as Record<string, unknown>)) {
      const threat = classifyThreat(key);
      if (threat) return threat;
      const valThreat = scanValue((value as Record<string, unknown>)[key]);
      if (valThreat) return valThreat;
    }
  }
  return null;
}

interface SecurityStats {
  blockedAttacks: number;
  rateLimitedIps: Set<string>;
  recentEvents: Array<{ timestamp: Date; type: string; ip: string; path: string }>;
}

const securityStats: SecurityStats = {
  blockedAttacks: 0,
  rateLimitedIps: new Set(),
  recentEvents: [],
};

function addSecurityEvent(type: string, ip: string, path: string) {
  securityStats.blockedAttacks++;
  securityStats.recentEvents.unshift({ timestamp: new Date(), type, ip, path });
  if (securityStats.recentEvents.length > 100) {
    securityStats.recentEvents = securityStats.recentEvents.slice(0, 100);
  }
}

const ipFailureTracker = new Map<string, { count: number; lastAttempt: number }>();
const IP_BLOCK_THRESHOLD = 50;
const IP_BLOCK_WINDOW = 15 * 60 * 1000;
const IP_BLOCK_DURATION = 30 * 60 * 1000;
const blockedIps = new Map<string, number>();

const EXEMPT_ROUTES = [
  "/api/login",
  "/api/register",
  "/api/user",
  "/api/logout",
  "/api/billing",
  "/api/plans",
  "/api/agent",
  "/api/ai",
  "/api/threat-intel",
  "/api/alerts",
  "/api/forensics",
  "/api/honeypot",
  "/api/trojan",
  "/api/payload",
  "/api/network-traffic",
  "/api/compliance",
  "/api/pentest",
  "/api/mobile-pentest",
  "/api/vulnerability",
  "/api/scan",
  "/api/hash",
  "/api/ssl",
  "/api/email-security",
  "/api/cve",
  "/api/dark-web",
  "/api/conversations",
  "/api/conversations/",
];

function isExemptRoute(path: string): boolean {
  return EXEMPT_ROUTES.some(r => path.startsWith(r));
}

export function intrusionDetectionMiddleware(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const fullUrl = req.originalUrl || req.url;

  const blockedAt = blockedIps.get(ip);
  if (blockedAt) {
    if (Date.now() - blockedAt > IP_BLOCK_DURATION) {
      blockedIps.delete(ip);
      ipFailureTracker.delete(ip);
    } else {
      return res.status(403).json({ error: "Access denied" });
    }
  }

  if (isExemptRoute(fullUrl.replace(/\?.*$/, ""))) {
    return next();
  }

  if ((req as any).user || (req as any).session?.passport?.user) {
    return next();
  }

  let threatType: string | null = null;

  try {
    threatType = classifyThreat(decodeURIComponent(fullUrl), "url");
  } catch {
    threatType = classifyThreat(fullUrl, "url");
  }

  if (!threatType) {
    const queryStr = JSON.stringify(req.query);
    threatType = classifyThreat(queryStr);
  }

  if (!threatType) {
    for (const [key, value] of Object.entries(req.headers)) {
      if (typeof value === "string" && key !== "cookie" && key !== "authorization") {
        threatType = classifyThreat(value, "header");
        if (threatType) break;
      }
    }
  }

  if (threatType) {
    const attackName = attackTypeMap[threatType] || "Suspicious Activity";
    addSecurityEvent(attackName, ip, fullUrl);

    const tracker = ipFailureTracker.get(ip) || { count: 0, lastAttempt: 0 };
    const now = Date.now();
    if (now - tracker.lastAttempt > IP_BLOCK_WINDOW) {
      tracker.count = 0;
    }
    tracker.count++;
    tracker.lastAttempt = now;
    ipFailureTracker.set(ip, tracker);

    if (tracker.count >= IP_BLOCK_THRESHOLD) {
      blockedIps.set(ip, now);
      console.log(`[SECURITY] Auto-blocked IP ${ip} for ${IP_BLOCK_DURATION / 60000}min after ${tracker.count} malicious requests`);
    }

    console.log(`[SECURITY] ${attackName} from ${ip}: ${fullUrl}`);
    return res.status(400).json({ error: "Request rejected" });
  }

  next();
}

export function trackRateLimitViolation(ip: string) {
  securityStats.rateLimitedIps.add(ip);
  addSecurityEvent("Rate Limit Exceeded", ip, "");
}

export function getSecurityStats() {
  const now = Date.now();
  for (const [ip, blockedAt] of blockedIps) {
    if (now - blockedAt > IP_BLOCK_DURATION) {
      blockedIps.delete(ip);
      ipFailureTracker.delete(ip);
    }
  }
  return {
    blockedAttacks: securityStats.blockedAttacks,
    rateLimitedIps: securityStats.rateLimitedIps.size,
    blockedIps: blockedIps.size,
    recentEvents: securityStats.recentEvents.slice(0, 20),
  };
}
