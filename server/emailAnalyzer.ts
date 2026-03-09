import { createHash } from "crypto";

export interface EmailHop {
  index: number;
  from: string;
  by: string;
  timestamp: string;
  delay: string;
  protocol: string;
}

export interface AuthResult {
  protocol: string;
  result: "pass" | "fail" | "neutral" | "none" | "softfail" | "temperror" | "permerror" | "unknown";
  details: string;
}

export interface PhishingIndicator {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  evidence: string;
}

export interface ExtractedIOC {
  type: "url" | "ip" | "email" | "hash" | "domain";
  value: string;
  context: string;
}

export interface EmailAnalysisResult {
  headers: Record<string, string>;
  hops: EmailHop[];
  authResults: AuthResult[];
  phishingIndicators: PhishingIndicator[];
  iocs: ExtractedIOC[];
  verdict: "clean" | "suspicious" | "likely_phishing" | "confirmed_phishing";
  confidenceScore: number;
  riskScore: number;
  summary: string;
  senderInfo: {
    from: string;
    replyTo: string;
    returnPath: string;
    displayName: string;
    domain: string;
    mismatch: boolean;
  };
  subject: string;
  totalHops: number;
  totalDelay: string;
}

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".club",
  ".work", ".link", ".click", ".icu", ".cam", ".rest", ".monster",
];

const URGENCY_KEYWORDS = [
  "urgent", "immediately", "action required", "verify your account",
  "suspend", "locked", "unauthorized", "confirm your identity",
  "click here", "act now", "limited time", "expire", "warning",
  "security alert", "unusual activity", "reset your password",
  "verify now", "update payment", "billing problem", "account compromised",
  "final notice", "last chance", "important notice",
];

const KNOWN_PHISHING_PATTERNS = [
  /paypa[l1]/i,
  /app[l1]e/i,
  /micr[o0]s[o0]ft/i,
  /g[o0]{2}g[l1]e/i,
  /amaz[o0]n/i,
  /netf[l1]ix/i,
  /faceb[o0]{2}k/i,
  /instag[r]am/i,
  /we[l1]{2}sfarg[o0]/i,
  /chase.*bank/i,
  /bank.*of.*america/i,
];

function parseHeaders(rawHeaders: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = rawHeaders.split(/\r?\n/);
  let currentKey = "";
  let currentValue = "";

  for (const line of lines) {
    if (/^\s/.test(line) && currentKey) {
      currentValue += " " + line.trim();
    } else {
      if (currentKey) {
        headers[currentKey.toLowerCase()] = currentValue;
      }
      const colonIdx = line.indexOf(":");
      if (colonIdx > 0) {
        currentKey = line.substring(0, colonIdx).trim();
        currentValue = line.substring(colonIdx + 1).trim();
      } else {
        currentKey = "";
        currentValue = "";
      }
    }
  }
  if (currentKey) {
    headers[currentKey.toLowerCase()] = currentValue;
  }
  return headers;
}

function parseReceivedHeaders(rawHeaders: string): EmailHop[] {
  const hops: EmailHop[] = [];
  const receivedRegex = new RegExp("^Received:\\s*(.*?)(?=^Received:|^[A-Z][a-zA-Z-]+:|$)", "gms");
  let match;

  while ((match = receivedRegex.exec(rawHeaders)) !== null) {
    const block = match[1].trim();

    const fromMatch = block.match(/from\s+(\S+)/i);
    const byMatch = block.match(/by\s+(\S+)/i);
    const withMatch = block.match(/with\s+(\S+)/i);
    const dateMatch = block.match(/;\s*(.+)$/m);

    hops.push({
      index: hops.length,
      from: fromMatch?.[1] || "unknown",
      by: byMatch?.[1] || "unknown",
      timestamp: dateMatch?.[1]?.trim() || "unknown",
      delay: "",
      protocol: withMatch?.[1] || "SMTP",
    });
  }

  for (let i = 0; i < hops.length - 1; i++) {
    try {
      const current = new Date(hops[i].timestamp);
      const next = new Date(hops[i + 1].timestamp);
      if (!isNaN(current.getTime()) && !isNaN(next.getTime())) {
        const diffMs = Math.abs(current.getTime() - next.getTime());
        const diffSec = Math.floor(diffMs / 1000);
        if (diffSec < 60) {
          hops[i].delay = `${diffSec}s`;
        } else if (diffSec < 3600) {
          hops[i].delay = `${Math.floor(diffSec / 60)}m ${diffSec % 60}s`;
        } else {
          hops[i].delay = `${Math.floor(diffSec / 3600)}h ${Math.floor((diffSec % 3600) / 60)}m`;
        }
      }
    } catch {
      hops[i].delay = "N/A";
    }
  }

  return hops.reverse();
}

function parseAuthResults(headers: Record<string, string>): AuthResult[] {
  const results: AuthResult[] = [];

  const authHeader = headers["authentication-results"] || "";

  const spfMatch = authHeader.match(/spf=(\w+)/i);
  if (spfMatch) {
    results.push({
      protocol: "SPF",
      result: normalizeAuthResult(spfMatch[1]),
      details: extractAuthDetails(authHeader, "spf"),
    });
  } else {
    const spfReceived = headers["received-spf"] || "";
    if (spfReceived) {
      const spfResult = spfReceived.match(/^(\w+)/);
      results.push({
        protocol: "SPF",
        result: normalizeAuthResult(spfResult?.[1] || "none"),
        details: spfReceived.substring(0, 200),
      });
    } else {
      results.push({ protocol: "SPF", result: "none", details: "No SPF record found" });
    }
  }

  const dkimMatch = authHeader.match(/dkim=(\w+)/i);
  if (dkimMatch) {
    results.push({
      protocol: "DKIM",
      result: normalizeAuthResult(dkimMatch[1]),
      details: extractAuthDetails(authHeader, "dkim"),
    });
  } else {
    const dkimSig = headers["dkim-signature"] || "";
    results.push({
      protocol: "DKIM",
      result: dkimSig ? "unknown" : "none",
      details: dkimSig ? "DKIM signature present but result unknown" : "No DKIM signature found",
    });
  }

  const dmarcMatch = authHeader.match(/dmarc=(\w+)/i);
  if (dmarcMatch) {
    results.push({
      protocol: "DMARC",
      result: normalizeAuthResult(dmarcMatch[1]),
      details: extractAuthDetails(authHeader, "dmarc"),
    });
  } else {
    results.push({ protocol: "DMARC", result: "none", details: "No DMARC result found" });
  }

  return results;
}

function normalizeAuthResult(result: string): AuthResult["result"] {
  const lower = result.toLowerCase();
  const validResults: AuthResult["result"][] = ["pass", "fail", "neutral", "none", "softfail", "temperror", "permerror"];
  return validResults.includes(lower as any) ? (lower as AuthResult["result"]) : "unknown";
}

function extractAuthDetails(authHeader: string, protocol: string): string {
  const regex = new RegExp(`${protocol}=\\w+[^;]*`, "i");
  const match = authHeader.match(regex);
  return match?.[0]?.trim() || `${protocol} result found`;
}

function extractSenderInfo(headers: Record<string, string>) {
  const from = headers["from"] || "";
  const replyTo = headers["reply-to"] || "";
  const returnPath = headers["return-path"] || "";

  const emailRegex = /<([^>]+)>|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/;
  const fromEmail = from.match(emailRegex)?.[1] || from.match(emailRegex)?.[2] || from;
  const displayNameMatch = from.match(/^"?([^"<]+)"?\s*</);
  const displayName = displayNameMatch?.[1]?.trim() || "";
  const domain = fromEmail.split("@")[1] || "";

  const replyToEmail = replyTo.match(emailRegex)?.[1] || replyTo.match(emailRegex)?.[2] || replyTo;
  const returnPathEmail = returnPath.match(emailRegex)?.[1] || returnPath.match(emailRegex)?.[2] || returnPath;

  const mismatch = !!(
    (replyTo && replyToEmail && fromEmail && replyToEmail.toLowerCase() !== fromEmail.toLowerCase()) ||
    (returnPath && returnPathEmail && fromEmail && returnPathEmail.split("@")[1]?.toLowerCase() !== domain.toLowerCase())
  );

  return {
    from: fromEmail,
    replyTo: replyToEmail || fromEmail,
    returnPath: returnPathEmail || fromEmail,
    displayName,
    domain,
    mismatch,
  };
}

function detectPhishingIndicators(
  headers: Record<string, string>,
  rawContent: string,
  senderInfo: ReturnType<typeof extractSenderInfo>,
  authResults: AuthResult[]
): PhishingIndicator[] {
  const indicators: PhishingIndicator[] = [];

  if (senderInfo.mismatch) {
    indicators.push({
      type: "sender_mismatch",
      severity: "high",
      description: "Reply-To or Return-Path does not match the From address",
      evidence: `From: ${senderInfo.from}, Reply-To: ${senderInfo.replyTo}, Return-Path: ${senderInfo.returnPath}`,
    });
  }

  if (senderInfo.displayName && senderInfo.from) {
    for (const pattern of KNOWN_PHISHING_PATTERNS) {
      if (pattern.test(senderInfo.displayName) && !pattern.test(senderInfo.domain)) {
        indicators.push({
          type: "display_name_deception",
          severity: "critical",
          description: `Display name impersonates a known brand but email domain doesn't match`,
          evidence: `Display: "${senderInfo.displayName}", Domain: ${senderInfo.domain}`,
        });
        break;
      }
    }
  }

  for (const tld of SUSPICIOUS_TLDS) {
    if (senderInfo.domain.endsWith(tld)) {
      indicators.push({
        type: "suspicious_tld",
        severity: "medium",
        description: `Sender uses a suspicious top-level domain (${tld})`,
        evidence: `Domain: ${senderInfo.domain}`,
      });
      break;
    }
  }

  const spfResult = authResults.find(a => a.protocol === "SPF");
  if (spfResult && (spfResult.result === "fail" || spfResult.result === "softfail")) {
    indicators.push({
      type: "spf_failure",
      severity: spfResult.result === "fail" ? "critical" : "high",
      description: `SPF authentication ${spfResult.result} - sender may be spoofing the domain`,
      evidence: spfResult.details,
    });
  }

  const dkimResult = authResults.find(a => a.protocol === "DKIM");
  if (dkimResult && dkimResult.result === "fail") {
    indicators.push({
      type: "dkim_failure",
      severity: "high",
      description: "DKIM signature verification failed - message may have been altered",
      evidence: dkimResult.details,
    });
  }

  const dmarcResult = authResults.find(a => a.protocol === "DMARC");
  if (dmarcResult && dmarcResult.result === "fail") {
    indicators.push({
      type: "dmarc_failure",
      severity: "critical",
      description: "DMARC authentication failed - strong indicator of spoofing",
      evidence: dmarcResult.details,
    });
  }

  const lowerContent = rawContent.toLowerCase();
  const foundUrgency: string[] = [];
  for (const keyword of URGENCY_KEYWORDS) {
    if (lowerContent.includes(keyword)) {
      foundUrgency.push(keyword);
    }
  }
  if (foundUrgency.length >= 2) {
    indicators.push({
      type: "urgency_language",
      severity: "medium",
      description: "Multiple urgency/pressure keywords detected",
      evidence: `Found: ${foundUrgency.slice(0, 5).join(", ")}`,
    });
  }

  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const urls = rawContent.match(urlRegex) || [];
  const shortenedDomains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"];
  for (const url of urls) {
    try {
      const urlObj = new URL(url);
      if (shortenedDomains.some(d => urlObj.hostname.includes(d))) {
        indicators.push({
          type: "shortened_url",
          severity: "medium",
          description: "Message contains shortened URLs that hide the true destination",
          evidence: url,
        });
        break;
      }
    } catch (err) { console.error("Error checking shortened URL:", err); }
  }

  const ipUrlRegex = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi;
  const ipUrls = rawContent.match(ipUrlRegex) || [];
  if (ipUrls.length > 0) {
    indicators.push({
      type: "ip_url",
      severity: "high",
      description: "Message contains URLs with raw IP addresses instead of domain names",
      evidence: ipUrls[0]!,
    });
  }

  const xMailer = headers["x-mailer"] || "";
  if (xMailer && /php|script|swiftmailer/i.test(xMailer)) {
    indicators.push({
      type: "suspicious_mailer",
      severity: "medium",
      description: "Email was sent using a scripted/automated mailer",
      evidence: `X-Mailer: ${xMailer}`,
    });
  }

  const contentType = headers["content-type"] || "";
  if (/\.exe|\.scr|\.bat|\.cmd|\.vbs|\.js|\.pif|\.com/i.test(rawContent)) {
    indicators.push({
      type: "dangerous_attachment",
      severity: "critical",
      description: "Email references potentially dangerous file types",
      evidence: "Executable or script file type detected in email content",
    });
  }

  if (/base64/i.test(contentType) && /text\/html/i.test(contentType)) {
    indicators.push({
      type: "encoded_html",
      severity: "low",
      description: "HTML content is Base64 encoded, which may hide phishing content",
      evidence: "Content-Type indicates Base64-encoded HTML",
    });
  }

  return indicators;
}

function extractIOCs(rawContent: string): ExtractedIOC[] {
  const iocs: ExtractedIOC[] = [];
  const seen = new Set<string>();

  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  const urls = rawContent.match(urlRegex) || [];
  for (const url of urls.slice(0, 50)) {
    const clean = url.replace(/[.,;:!?)]+$/, "");
    if (!seen.has(clean)) {
      seen.add(clean);
      iocs.push({ type: "url", value: clean, context: "Found in email content" });
    }
  }

  const ipRegex = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;
  let ipMatch;
  while ((ipMatch = ipRegex.exec(rawContent)) !== null) {
    const ip = ipMatch[1];
    if (!seen.has(ip) && !ip.startsWith("10.") && !ip.startsWith("127.") && !ip.startsWith("192.168.") && !ip.startsWith("0.")) {
      seen.add(ip);
      iocs.push({ type: "ip", value: ip, context: "IP address found in headers or body" });
    }
  }

  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const emails = rawContent.match(emailRegex) || [];
  for (const email of emails.slice(0, 20)) {
    if (!seen.has(email.toLowerCase())) {
      seen.add(email.toLowerCase());
      iocs.push({ type: "email", value: email, context: "Email address found in content" });
    }
  }

  const hashRegex = /\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g;
  let hashMatch;
  while ((hashMatch = hashRegex.exec(rawContent)) !== null) {
    const hash = hashMatch[1].toLowerCase();
    if (!seen.has(hash)) {
      seen.add(hash);
      const hashType = hash.length === 32 ? "MD5" : hash.length === 40 ? "SHA-1" : "SHA-256";
      iocs.push({ type: "hash", value: hash, context: `${hashType} hash found in content` });
    }
  }

  for (const url of urls.slice(0, 20)) {
    try {
      const domain = new URL(url).hostname;
      if (!seen.has(domain)) {
        seen.add(domain);
        iocs.push({ type: "domain", value: domain, context: "Domain extracted from URL" });
      }
    } catch (err) { console.error("Error parsing URL for IOC extraction:", err); }
  }

  return iocs;
}

function calculateVerdict(indicators: PhishingIndicator[], authResults: AuthResult[]): {
  verdict: EmailAnalysisResult["verdict"];
  confidenceScore: number;
  riskScore: number;
} {
  let riskScore = 0;

  for (const indicator of indicators) {
    switch (indicator.severity) {
      case "critical": riskScore += 30; break;
      case "high": riskScore += 20; break;
      case "medium": riskScore += 10; break;
      case "low": riskScore += 5; break;
      case "info": riskScore += 2; break;
    }
  }

  const spf = authResults.find(a => a.protocol === "SPF");
  const dkim = authResults.find(a => a.protocol === "DKIM");
  const dmarc = authResults.find(a => a.protocol === "DMARC");

  if (spf?.result === "pass") riskScore -= 10;
  if (dkim?.result === "pass") riskScore -= 10;
  if (dmarc?.result === "pass") riskScore -= 15;

  riskScore = Math.max(0, Math.min(100, riskScore));

  let verdict: EmailAnalysisResult["verdict"];
  let confidenceScore: number;

  if (riskScore >= 70) {
    verdict = "confirmed_phishing";
    confidenceScore = Math.min(95, 70 + riskScore * 0.25);
  } else if (riskScore >= 45) {
    verdict = "likely_phishing";
    confidenceScore = Math.min(85, 50 + riskScore * 0.3);
  } else if (riskScore >= 20) {
    verdict = "suspicious";
    confidenceScore = Math.min(75, 40 + riskScore * 0.4);
  } else {
    verdict = "clean";
    confidenceScore = Math.max(60, 90 - riskScore * 2);
  }

  return { verdict, confidenceScore: Math.round(confidenceScore), riskScore };
}

function generateSummary(
  verdict: EmailAnalysisResult["verdict"],
  indicators: PhishingIndicator[],
  authResults: AuthResult[],
  senderInfo: ReturnType<typeof extractSenderInfo>
): string {
  const parts: string[] = [];

  switch (verdict) {
    case "confirmed_phishing":
      parts.push("This email shows strong indicators of being a phishing attempt.");
      break;
    case "likely_phishing":
      parts.push("This email has multiple suspicious characteristics consistent with phishing.");
      break;
    case "suspicious":
      parts.push("This email has some suspicious elements that warrant caution.");
      break;
    case "clean":
      parts.push("This email appears to be legitimate based on the analyzed headers.");
      break;
  }

  const criticals = indicators.filter(i => i.severity === "critical");
  if (criticals.length > 0) {
    parts.push(`Critical findings: ${criticals.map(i => i.description).join("; ")}.`);
  }

  const authPassed = authResults.filter(a => a.result === "pass").map(a => a.protocol);
  const authFailed = authResults.filter(a => a.result === "fail" || a.result === "softfail").map(a => a.protocol);

  if (authPassed.length > 0) {
    parts.push(`Authentication passed: ${authPassed.join(", ")}.`);
  }
  if (authFailed.length > 0) {
    parts.push(`Authentication failed: ${authFailed.join(", ")}.`);
  }

  if (senderInfo.mismatch) {
    parts.push("Sender address mismatch detected between From, Reply-To, and/or Return-Path.");
  }

  return parts.join(" ");
}

export function analyzeEmail(rawContent: string): EmailAnalysisResult {
  const headers = parseHeaders(rawContent);
  const hops = parseReceivedHeaders(rawContent);
  const authResults = parseAuthResults(headers);
  const senderInfo = extractSenderInfo(headers);
  const phishingIndicators = detectPhishingIndicators(headers, rawContent, senderInfo, authResults);
  const iocs = extractIOCs(rawContent);
  const { verdict, confidenceScore, riskScore } = calculateVerdict(phishingIndicators, authResults);
  const summary = generateSummary(verdict, phishingIndicators, authResults, senderInfo);

  let totalDelay = "N/A";
  if (hops.length >= 2) {
    try {
      const first = new Date(hops[0].timestamp);
      const last = new Date(hops[hops.length - 1].timestamp);
      if (!isNaN(first.getTime()) && !isNaN(last.getTime())) {
        const diffSec = Math.abs(last.getTime() - first.getTime()) / 1000;
        if (diffSec < 60) totalDelay = `${Math.round(diffSec)}s`;
        else if (diffSec < 3600) totalDelay = `${Math.floor(diffSec / 60)}m ${Math.round(diffSec % 60)}s`;
        else totalDelay = `${Math.floor(diffSec / 3600)}h ${Math.floor((diffSec % 3600) / 60)}m`;
      }
    } catch (err) { console.error("Error calculating email hop delay:", err); }
  }

  return {
    headers,
    hops,
    authResults,
    phishingIndicators,
    iocs,
    verdict,
    confidenceScore,
    riskScore,
    summary,
    senderInfo,
    subject: headers["subject"] || "(no subject)",
    totalHops: hops.length,
    totalDelay,
  };
}
