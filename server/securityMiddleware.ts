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
const IP_BLOCK_THRESHOLD = 20;
const IP_BLOCK_WINDOW = 15 * 60 * 1000;
const blockedIps = new Set<string>();

export function intrusionDetectionMiddleware(req: Request, res: Response, next: NextFunction) {
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  if (blockedIps.has(ip)) {
    return res.status(403).json({ error: "Access denied" });
  }

  let threatType: string | null = null;

  const fullUrl = req.originalUrl || req.url;
  try {
    threatType = classifyThreat(decodeURIComponent(fullUrl), "url");
  } catch {
    threatType = classifyThreat(fullUrl, "url");
  }

  if (!threatType && req.body) {
    threatType = scanValue(req.body);
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
      blockedIps.add(ip);
      console.log(`[SECURITY] Auto-blocked IP ${ip} after ${tracker.count} malicious requests`);
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
  return {
    blockedAttacks: securityStats.blockedAttacks,
    rateLimitedIps: securityStats.rateLimitedIps.size,
    blockedIps: blockedIps.size,
    recentEvents: securityStats.recentEvents.slice(0, 20),
  };
}
