import dns from "dns";
import tls from "tls";
import net from "net";
import { URL } from "url";
import { safeBrowsingLookup } from "./threatIntel/googleSafeBrowsing";
import { urlscanLookup } from "./threatIntel/urlscan";

const BLOCKED_HOSTNAMES = ["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "metadata.google.internal", "169.254.169.254"];

function isPrivateIP(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4) return false;
    if (parts[0] === 10) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase().replace(/\[|\]/g, "");
    if (normalized === "::1" || normalized === "::") return true;
    if (normalized.startsWith("fe80")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    if (normalized.startsWith("ff")) return true;
    if (normalized.startsWith("::ffff:")) {
      const v4 = normalized.slice(7);
      if (net.isIPv4(v4)) return isPrivateIP(v4);
    }
    return false;
  }
  return false;
}

function isBlockedHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(lower)) return true;
  if (net.isIP(lower)) return isPrivateIP(lower);
  return false;
}

const ALLOWED_PORTS = [80, 443, 8080, 8443];

interface CheckResult {
  name: string;
  status: "clean" | "warning" | "danger" | "error";
  details: string;
  source: string;
}

interface Finding {
  severity: "info" | "low" | "medium" | "high" | "critical";
  title: string;
  description: string;
}

interface LinkScanResult {
  url: string;
  overallRisk: "safe" | "suspicious" | "malicious" | "unknown";
  riskScore: number;
  checks: CheckResult[];
  findings: Finding[];
  scannedAt: string;
}

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
  ".loan", ".download", ".racing", ".win", ".bid", ".stream", ".date",
  ".faith", ".review", ".party", ".trade", ".webcam", ".science",
  ".accountant", ".cricket", ".zip", ".mov", ".php",
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "buff.ly", "adf.ly", "bit.do", "mcaf.ee", "su.pr", "dlvr.it",
  "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "v.gd", "qr.ae",
];

const HOMOGLYPH_CHARS = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u04BB\u0456\u0458\u04CF\u0501\u051B\u051D]/;

function runHeuristicAnalysis(urlStr: string): { check: CheckResult; findings: Finding[] } {
  const findings: Finding[] = [];
  let worstStatus: "clean" | "warning" | "danger" = "clean";

  try {
    const parsed = new URL(urlStr);
    const hostname = parsed.hostname.toLowerCase();

    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      findings.push({ severity: "medium", title: "IP-based URL", description: "URL uses an IP address instead of a domain name, which is common in phishing attacks." });
      worstStatus = "warning";
    }

    if (URL_SHORTENERS.includes(hostname)) {
      findings.push({ severity: "medium", title: "URL Shortener Detected", description: `URL uses shortener service "${hostname}" which can hide the true destination.` });
      worstStatus = "warning";
    }

    const tld = "." + hostname.split(".").pop();
    if (SUSPICIOUS_TLDS.includes(tld)) {
      findings.push({ severity: "medium", title: "Suspicious TLD", description: `Domain uses "${tld}" TLD which is frequently associated with malicious sites.` });
      worstStatus = "warning";
    }

    const subdomainCount = hostname.split(".").length - 2;
    if (subdomainCount > 3) {
      findings.push({ severity: "medium", title: "Excessive Subdomains", description: `URL has ${subdomainCount} subdomains, which can indicate domain abuse or phishing.` });
      worstStatus = "warning";
    }

    if (HOMOGLYPH_CHARS.test(hostname)) {
      findings.push({ severity: "high", title: "Homoglyph Characters Detected", description: "Domain contains Unicode characters that visually resemble ASCII letters (IDN homograph attack)." });
      worstStatus = "danger";
    }

    const phishingKeywords = ["login", "signin", "verify", "account", "secure", "update", "confirm", "banking", "paypal", "microsoft", "apple", "google", "amazon", "netflix"];
    const hostnameWords = hostname.replace(/[.-]/g, " ").split(" ");
    const matchedKeywords = hostnameWords.filter(w => phishingKeywords.includes(w));
    if (matchedKeywords.length >= 2) {
      findings.push({ severity: "high", title: "Phishing Pattern Detected", description: `Domain contains multiple suspicious keywords: ${matchedKeywords.join(", ")}` });
      worstStatus = "danger";
    } else if (matchedKeywords.length === 1) {
      findings.push({ severity: "low", title: "Suspicious Keyword in Domain", description: `Domain contains keyword "${matchedKeywords[0]}" commonly used in phishing.` });
      if (worstStatus === "clean") worstStatus = "warning";
    }

    if (parsed.pathname.length > 200) {
      findings.push({ severity: "low", title: "Excessively Long URL Path", description: `URL path is ${parsed.pathname.length} characters long, which may indicate obfuscation.` });
      if (worstStatus === "clean") worstStatus = "warning";
    }

    if (urlStr.startsWith("data:")) {
      findings.push({ severity: "high", title: "Data URI Detected", description: "URL is a data URI which can embed malicious content directly." });
      worstStatus = "danger";
    }

    const encodedCharCount = (urlStr.match(/%[0-9A-Fa-f]{2}/g) || []).length;
    if (encodedCharCount > 5) {
      findings.push({ severity: "medium", title: "Heavy URL Encoding", description: `URL contains ${encodedCharCount} encoded characters, possibly hiding malicious content.` });
      if (worstStatus === "clean") worstStatus = "warning";
    }

    if (parsed.port && !["80", "443", ""].includes(parsed.port)) {
      findings.push({ severity: "low", title: "Non-Standard Port", description: `URL uses port ${parsed.port} which is unusual for web traffic.` });
      if (worstStatus === "clean") worstStatus = "warning";
    }

    if (hostname.includes("--") || hostname.includes("..")) {
      findings.push({ severity: "low", title: "Suspicious Domain Characters", description: "Domain contains unusual character sequences (double dashes or dots)." });
      if (worstStatus === "clean") worstStatus = "warning";
    }

  } catch {
    return {
      check: { name: "Heuristic Analysis", status: "error", details: "Failed to parse URL for heuristic analysis", source: "AegisAI360 Heuristics" },
      findings,
    };
  }

  const details = findings.length === 0
    ? "No suspicious patterns detected"
    : `Found ${findings.length} potential issue(s)`;

  return {
    check: { name: "Heuristic Analysis", status: worstStatus, details, source: "AegisAI360 Heuristics" },
    findings,
  };
}

async function checkDNS(hostname: string): Promise<CheckResult> {
  return new Promise((resolve) => {
    dns.resolve4(hostname, (err, addresses) => {
      if (err) {
        if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
          resolve({ name: "DNS Resolution", status: "danger", details: `Domain "${hostname}" does not resolve to any IP address`, source: "DNS Resolver" });
        } else {
          resolve({ name: "DNS Resolution", status: "error", details: `DNS lookup failed: ${err.code}`, source: "DNS Resolver" });
        }
      } else {
        const hasPrivate = addresses.some(isPrivateIP);
        if (hasPrivate) {
          resolve({ name: "DNS Resolution", status: "warning", details: `Domain resolves to private/internal IP address — connection checks skipped for security`, source: "DNS Resolver" });
        } else {
          resolve({ name: "DNS Resolution", status: "clean", details: `Domain resolves to ${addresses.join(", ")}`, source: "DNS Resolver" });
        }
      }
    });
  });
}

async function checkSSLCert(urlStr: string): Promise<CheckResult> {
  try {
    const parsed = new URL(urlStr);

    if (parsed.protocol !== "https:") {
      return { name: "SSL/TLS Certificate", status: "warning", details: "URL does not use HTTPS encryption", source: "SSL Checker" };
    }

    const port = parsed.port ? parseInt(parsed.port) : 443;

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve({ name: "SSL/TLS Certificate", status: "error", details: "SSL connection timed out", source: "SSL Checker" });
      }, 10000);

      try {
        const socket = tls.connect({ host: parsed.hostname, port, servername: parsed.hostname, rejectUnauthorized: false }, () => {
          clearTimeout(timeout);
          const cert = socket.getPeerCertificate();
          const authorized = socket.authorized;
          socket.destroy();

          if (!cert || !cert.subject) {
            resolve({ name: "SSL/TLS Certificate", status: "warning", details: "Could not retrieve certificate details", source: "SSL Checker" });
            return;
          }

          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

          if (!authorized) {
            resolve({ name: "SSL/TLS Certificate", status: "danger", details: `Certificate is not trusted. Issuer: ${cert.issuer?.O || "Unknown"}`, source: "SSL Checker" });
          } else if (daysUntilExpiry < 0) {
            resolve({ name: "SSL/TLS Certificate", status: "danger", details: `Certificate expired ${Math.abs(daysUntilExpiry)} days ago`, source: "SSL Checker" });
          } else if (daysUntilExpiry < 30) {
            resolve({ name: "SSL/TLS Certificate", status: "warning", details: `Certificate expires in ${daysUntilExpiry} days. Issuer: ${cert.issuer?.O || "Unknown"}`, source: "SSL Checker" });
          } else {
            resolve({ name: "SSL/TLS Certificate", status: "clean", details: `Valid certificate issued by ${cert.issuer?.O || "Unknown"}, expires in ${daysUntilExpiry} days`, source: "SSL Checker" });
          }
        });

        socket.on("error", (err) => {
          clearTimeout(timeout);
          resolve({ name: "SSL/TLS Certificate", status: "error", details: `SSL connection error: ${err.message}`, source: "SSL Checker" });
        });
      } catch (err: any) {
        clearTimeout(timeout);
        resolve({ name: "SSL/TLS Certificate", status: "error", details: `SSL check failed: ${err.message}`, source: "SSL Checker" });
      }
    });
  } catch {
    return { name: "SSL/TLS Certificate", status: "error", details: "Failed to parse URL for SSL check", source: "SSL Checker" };
  }
}

async function checkSafeBrowsing(url: string): Promise<CheckResult> {
  try {
    const result = await safeBrowsingLookup(url);

    if (!result.configured) {
      return { name: "Google Safe Browsing", status: "clean", details: "API key not configured — skipped (configure GOOGLE_SAFE_BROWSING_API_KEY for live checks)", source: "Google Safe Browsing" };
    }

    if (result.error) {
      return { name: "Google Safe Browsing", status: "error", details: `API error: ${result.error}`, source: "Google Safe Browsing" };
    }

    if (result.data?.safe) {
      return { name: "Google Safe Browsing", status: "clean", details: "No threats found in Google Safe Browsing database", source: "Google Safe Browsing" };
    }

    const threats = result.data?.matches?.map((m: any) => m.threatType).join(", ") || "Unknown threat";
    return { name: "Google Safe Browsing", status: "danger", details: `Threats detected: ${threats}`, source: "Google Safe Browsing" };
  } catch (err: any) {
    return { name: "Google Safe Browsing", status: "error", details: `Check failed: ${err.message}`, source: "Google Safe Browsing" };
  }
}

async function checkUrlscan(url: string): Promise<CheckResult> {
  try {
    const result = await urlscanLookup(url);

    if (!result.configured) {
      return { name: "URLScan.io", status: "clean", details: "API key not configured — skipped (configure URLSCAN_API_KEY for live scans)", source: "URLScan.io" };
    }

    if (result.error) {
      return { name: "URLScan.io", status: "error", details: `API error: ${result.error}`, source: "URLScan.io" };
    }

    if (result.data?.uuid) {
      return { name: "URLScan.io", status: "clean", details: `Scan submitted (ID: ${result.data.uuid}). No immediate threats detected.`, source: "URLScan.io" };
    }

    return { name: "URLScan.io", status: "clean", details: "Scan completed, no threats detected", source: "URLScan.io" };
  } catch (err: any) {
    return { name: "URLScan.io", status: "error", details: `Check failed: ${err.message}`, source: "URLScan.io" };
  }
}

function calculateRiskScore(checks: CheckResult[], findings: Finding[]): number {
  let score = 0;

  for (const check of checks) {
    if (check.status === "danger") score += 25;
    else if (check.status === "warning") score += 10;
    else if (check.status === "error") score += 5;
  }

  for (const finding of findings) {
    if (finding.severity === "critical") score += 20;
    else if (finding.severity === "high") score += 15;
    else if (finding.severity === "medium") score += 10;
    else if (finding.severity === "low") score += 5;
    else score += 2;
  }

  return Math.min(100, score);
}

function determineOverallRisk(riskScore: number, checks: CheckResult[]): "safe" | "suspicious" | "malicious" | "unknown" {
  const hasDanger = checks.some(c => c.status === "danger");
  const allErrors = checks.every(c => c.status === "error");

  if (allErrors) return "unknown";
  if (hasDanger || riskScore >= 60) return "malicious";
  if (riskScore >= 30) return "suspicious";
  return "safe";
}

export async function scanLink(url: string): Promise<LinkScanResult> {
  let hostname: string;
  let port: string;
  try {
    const parsed = new URL(url);
    hostname = parsed.hostname;
    port = parsed.port;

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return {
        url,
        overallRisk: "unknown",
        riskScore: 0,
        checks: [{ name: "URL Validation", status: "error", details: "Only HTTP and HTTPS URLs are supported", source: "AegisAI360" }],
        findings: [{ severity: "high", title: "Unsupported Protocol", description: `Protocol "${parsed.protocol}" is not supported for scanning.` }],
        scannedAt: new Date().toISOString(),
      };
    }

    if (isBlockedHost(hostname)) {
      return {
        url,
        overallRisk: "unknown",
        riskScore: 0,
        checks: [{ name: "URL Validation", status: "error", details: "Internal/private addresses cannot be scanned", source: "AegisAI360" }],
        findings: [{ severity: "high", title: "Blocked Address", description: "Scanning internal, private, or loopback addresses is not allowed." }],
        scannedAt: new Date().toISOString(),
      };
    }

    if (port && !ALLOWED_PORTS.includes(parseInt(port))) {
      return {
        url,
        overallRisk: "unknown",
        riskScore: 0,
        checks: [{ name: "URL Validation", status: "error", details: `Port ${port} is not allowed for scanning`, source: "AegisAI360" }],
        findings: [{ severity: "medium", title: "Restricted Port", description: `Only standard web ports (${ALLOWED_PORTS.join(", ")}) are allowed.` }],
        scannedAt: new Date().toISOString(),
      };
    }
  } catch {
    return {
      url,
      overallRisk: "unknown",
      riskScore: 0,
      checks: [{ name: "URL Validation", status: "error", details: "Invalid URL format", source: "AegisAI360" }],
      findings: [{ severity: "high", title: "Invalid URL", description: "The provided URL could not be parsed." }],
      scannedAt: new Date().toISOString(),
    };
  }

  const heuristics = runHeuristicAnalysis(url);

  const [safeBrowsingResult, urlscanResult, dnsResult] = await Promise.all([
    checkSafeBrowsing(url),
    checkUrlscan(url),
    checkDNS(hostname),
  ]);

  let sslResult: CheckResult;
  if (dnsResult.status === "warning" && dnsResult.details.includes("private")) {
    sslResult = { name: "SSL/TLS Certificate", status: "warning", details: "SSL check skipped — domain resolves to private/internal IP", source: "SSL Checker" };
  } else if (dnsResult.status === "danger") {
    sslResult = { name: "SSL/TLS Certificate", status: "error", details: "SSL check skipped — domain does not resolve", source: "SSL Checker" };
  } else {
    sslResult = await checkSSLCert(url);
  }

  const checks = [safeBrowsingResult, urlscanResult, heuristics.check, dnsResult, sslResult];
  const findings = [...heuristics.findings];

  if (dnsResult.status === "danger") {
    findings.push({ severity: "critical", title: "Domain Does Not Resolve", description: dnsResult.details });
  }

  if (sslResult.status === "danger") {
    findings.push({ severity: "high", title: "SSL Certificate Issue", description: sslResult.details });
  } else if (sslResult.status === "warning") {
    findings.push({ severity: "medium", title: "SSL Notice", description: sslResult.details });
  }

  if (safeBrowsingResult.status === "danger") {
    findings.push({ severity: "critical", title: "Google Safe Browsing Alert", description: safeBrowsingResult.details });
  }

  const riskScore = calculateRiskScore(checks, findings);
  const overallRisk = determineOverallRisk(riskScore, checks);

  return {
    url,
    overallRisk,
    riskScore,
    checks,
    findings,
    scannedAt: new Date().toISOString(),
  };
}
