import * as tls from "tls";
import * as https from "https";
import * as net from "net";
import { URL } from "url";

interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  fingerprint256: string;
  keySize: number;
  signatureAlgorithm: string;
  subjectAltNames: string[];
  isCA: boolean;
}

interface ChainCertificate {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  signatureAlgorithm: string;
  isCA: boolean;
  depth: number;
}

interface Finding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

interface SSLInspectionResult {
  domain: string;
  ip: string;
  port: number;
  grade: string;
  gradeColor: string;
  certificate: CertificateInfo;
  chain: ChainCertificate[];
  protocols: Record<string, boolean>;
  daysUntilExpiration: number;
  isExpired: boolean;
  isSelfSigned: boolean;
  hasHSTS: boolean;
  findings: Finding[];
  recommendations: string[];
  scannedAt: string;
}

function parseSubject(raw: any): Record<string, string> {
  if (!raw) return {};
  const result: Record<string, string> = {};
  if (typeof raw === "object") {
    for (const [key, value] of Object.entries(raw)) {
      result[key] = String(value);
    }
  }
  return result;
}

function extractSANs(cert: tls.PeerCertificate): string[] {
  if (!cert.subjectaltname) return [];
  return cert.subjectaltname.split(",").map(s => s.trim().replace(/^DNS:/, "").replace(/^IP Address:/, ""));
}

function getKeySize(cert: tls.PeerCertificate): number {
  const bits = (cert as any).bits;
  if (bits) return bits;
  const modulus = (cert as any).modulus;
  if (modulus && typeof modulus === "string") {
    return modulus.replace(/:/g, "").length * 4;
  }
  return 2048;
}

async function checkProtocol(domain: string, port: number, minVersion: string, maxVersion: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: domain,
        port,
        minVersion: minVersion as tls.SecureVersion,
        maxVersion: maxVersion as tls.SecureVersion,
        rejectUnauthorized: false,
        timeout: 5000,
      },
      () => {
        socket.destroy();
        resolve(true);
      }
    );
    socket.on("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

async function checkHSTS(domain: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = https.get(
      `https://${domain}`,
      { rejectUnauthorized: false, timeout: 5000 },
      (res) => {
        const hstsHeader = res.headers["strict-transport-security"];
        resolve(!!hstsHeader);
        res.resume();
      }
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
  });
}

function calculateGrade(findings: Finding[], protocols: Record<string, boolean>, daysUntilExpiration: number, hasHSTS: boolean, keySize: number): { grade: string; gradeColor: string } {
  let score = 100;

  const criticalCount = findings.filter(f => f.severity === "critical").length;
  const highCount = findings.filter(f => f.severity === "high").length;
  const mediumCount = findings.filter(f => f.severity === "medium").length;

  score -= criticalCount * 40;
  score -= highCount * 20;
  score -= mediumCount * 10;

  if (protocols["TLS 1.0"]) score -= 15;
  if (protocols["TLS 1.1"]) score -= 10;
  if (!protocols["TLS 1.3"]) score -= 5;

  if (!hasHSTS) score -= 5;
  if (keySize < 2048) score -= 20;

  if (daysUntilExpiration < 0) score = 0;
  else if (daysUntilExpiration < 7) score -= 30;
  else if (daysUntilExpiration < 30) score -= 15;

  score = Math.max(0, Math.min(100, score));

  let grade: string;
  let gradeColor: string;
  if (score >= 95) { grade = "A+"; gradeColor = "#22c55e"; }
  else if (score >= 90) { grade = "A"; gradeColor = "#22c55e"; }
  else if (score >= 80) { grade = "B"; gradeColor = "#84cc16"; }
  else if (score >= 70) { grade = "C"; gradeColor = "#eab308"; }
  else if (score >= 60) { grade = "D"; gradeColor = "#f97316"; }
  else { grade = "F"; gradeColor = "#ef4444"; }

  return { grade, gradeColor };
}

export async function inspectSSL(domain: string, port: number = 443): Promise<SSLInspectionResult> {
  const cleanDomain = domain.replace(/^https?:\/\//, "").split(/[:/]/)[0].trim();
  if (!cleanDomain) throw new Error("Invalid domain");

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: cleanDomain,
        port,
        rejectUnauthorized: false,
        timeout: 10000,
        servername: cleanDomain,
      },
      async () => {
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const protocol = socket.getProtocol();
          const remoteAddress = (socket as any).remoteAddress || socket.remoteAddress || "unknown";

          if (!cert || !cert.subject) {
            socket.destroy();
            return reject(new Error("Could not retrieve certificate"));
          }

          const keySize = getKeySize(cert);
          const sigAlg = (cert as any).sigalg || (cert as any).signatureAlgorithm || "unknown";
          const validFrom = new Date(cert.valid_from);
          const validTo = new Date(cert.valid_to);
          const now = new Date();
          const daysUntilExpiration = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
          const isExpired = daysUntilExpiration < 0;

          const subjectStr = Object.values(parseSubject(cert.subject)).join(", ");
          const issuerStr = Object.values(parseSubject(cert.issuer)).join(", ");
          const isSelfSigned = subjectStr === issuerStr;

          const chain: ChainCertificate[] = [];
          let currentCert: tls.DetailedPeerCertificate | undefined = cert as tls.DetailedPeerCertificate;
          let depth = 0;
          const seenSerials = new Set<string>();
          while (currentCert && depth < 10) {
            if (seenSerials.has(currentCert.serialNumber)) break;
            seenSerials.add(currentCert.serialNumber);
            chain.push({
              subject: Object.values(parseSubject(currentCert.subject)).join(", "),
              issuer: Object.values(parseSubject(currentCert.issuer)).join(", "),
              validFrom: currentCert.valid_from,
              validTo: currentCert.valid_to,
              signatureAlgorithm: (currentCert as any).sigalg || "unknown",
              isCA: depth > 0,
              depth,
            });
            currentCert = (currentCert as any).issuerCertificate;
            depth++;
          }

          const [tls10, tls11, tls12, tls13] = await Promise.all([
            checkProtocol(cleanDomain, port, "TLSv1", "TLSv1"),
            checkProtocol(cleanDomain, port, "TLSv1.1", "TLSv1.1"),
            checkProtocol(cleanDomain, port, "TLSv1.2", "TLSv1.2"),
            checkProtocol(cleanDomain, port, "TLSv1.3", "TLSv1.3"),
          ]);

          const protocols: Record<string, boolean> = {
            "TLS 1.0": tls10,
            "TLS 1.1": tls11,
            "TLS 1.2": tls12,
            "TLS 1.3": tls13,
          };

          const hasHSTS = await checkHSTS(cleanDomain);

          const findings: Finding[] = [];

          if (isExpired) {
            findings.push({
              id: "expired",
              title: "Certificate Expired",
              description: `Certificate expired ${Math.abs(daysUntilExpiration)} days ago on ${validTo.toISOString().split("T")[0]}`,
              severity: "critical",
            });
          } else if (daysUntilExpiration < 7) {
            findings.push({
              id: "expiring-soon",
              title: "Certificate Expiring Very Soon",
              description: `Certificate expires in ${daysUntilExpiration} day(s) on ${validTo.toISOString().split("T")[0]}`,
              severity: "high",
            });
          } else if (daysUntilExpiration < 30) {
            findings.push({
              id: "expiring-soon",
              title: "Certificate Expiring Soon",
              description: `Certificate expires in ${daysUntilExpiration} days on ${validTo.toISOString().split("T")[0]}`,
              severity: "medium",
            });
          }

          if (isSelfSigned) {
            findings.push({
              id: "self-signed",
              title: "Self-Signed Certificate",
              description: "Certificate is self-signed and not issued by a trusted Certificate Authority",
              severity: "high",
            });
          }

          if (keySize < 2048) {
            findings.push({
              id: "weak-key",
              title: "Weak Key Size",
              description: `Certificate uses a ${keySize}-bit key which is below the recommended minimum of 2048 bits`,
              severity: "high",
            });
          }

          if (sigAlg.toLowerCase().includes("sha1") || sigAlg.toLowerCase().includes("sha-1")) {
            findings.push({
              id: "sha1-signature",
              title: "SHA-1 Signature Algorithm",
              description: "Certificate uses deprecated SHA-1 signature algorithm which is vulnerable to collision attacks",
              severity: "high",
            });
          }

          if (tls10) {
            findings.push({
              id: "tls10",
              title: "TLS 1.0 Supported",
              description: "TLS 1.0 is deprecated and has known vulnerabilities (POODLE, BEAST)",
              severity: "medium",
            });
          }

          if (tls11) {
            findings.push({
              id: "tls11",
              title: "TLS 1.1 Supported",
              description: "TLS 1.1 is deprecated and should be disabled",
              severity: "medium",
            });
          }

          if (!tls13) {
            findings.push({
              id: "no-tls13",
              title: "TLS 1.3 Not Supported",
              description: "TLS 1.3 provides improved security and performance; consider enabling it",
              severity: "low",
            });
          }

          if (!hasHSTS) {
            findings.push({
              id: "no-hsts",
              title: "HSTS Not Configured",
              description: "HTTP Strict Transport Security header not found; site may be vulnerable to downgrade attacks",
              severity: "medium",
            });
          }

          if (!authorized && !isSelfSigned) {
            findings.push({
              id: "chain-invalid",
              title: "Certificate Chain Validation Failed",
              description: "The certificate chain could not be validated against trusted root certificates",
              severity: "high",
            });
          }

          const sans = extractSANs(cert);
          const wildcardSANs = sans.filter(s => s.startsWith("*."));
          if (wildcardSANs.length > 3) {
            findings.push({
              id: "wildcard-overuse",
              title: "Excessive Wildcard Usage",
              description: `Certificate contains ${wildcardSANs.length} wildcard entries which increases attack surface`,
              severity: "low",
            });
          }

          if (findings.length === 0) {
            findings.push({
              id: "all-clear",
              title: "No Issues Found",
              description: "Certificate configuration looks secure",
              severity: "info",
            });
          }

          const recommendations: string[] = [];
          if (isExpired) recommendations.push("Renew the SSL certificate immediately");
          if (daysUntilExpiration > 0 && daysUntilExpiration < 30) recommendations.push("Renew the SSL certificate before it expires");
          if (isSelfSigned) recommendations.push("Replace with a certificate from a trusted CA (e.g., Let's Encrypt)");
          if (keySize < 2048) recommendations.push("Upgrade to at least a 2048-bit RSA key or use ECDSA P-256");
          if (tls10) recommendations.push("Disable TLS 1.0 support");
          if (tls11) recommendations.push("Disable TLS 1.1 support");
          if (!tls13) recommendations.push("Enable TLS 1.3 support for improved performance and security");
          if (!hasHSTS) recommendations.push("Configure HSTS header with a long max-age value");
          if (sigAlg.toLowerCase().includes("sha1")) recommendations.push("Re-issue certificate with SHA-256 signature algorithm");

          const { grade, gradeColor } = calculateGrade(findings, protocols, daysUntilExpiration, hasHSTS, keySize);

          socket.destroy();

          resolve({
            domain: cleanDomain,
            ip: remoteAddress,
            port,
            grade,
            gradeColor,
            certificate: {
              subject: parseSubject(cert.subject),
              issuer: parseSubject(cert.issuer),
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              serialNumber: cert.serialNumber,
              fingerprint: cert.fingerprint,
              fingerprint256: cert.fingerprint256,
              keySize,
              signatureAlgorithm: sigAlg,
              subjectAltNames: sans,
              isCA: (cert as any).ca || false,
            },
            chain,
            protocols,
            daysUntilExpiration,
            isExpired,
            isSelfSigned,
            hasHSTS,
            findings,
            recommendations,
            scannedAt: new Date().toISOString(),
          });
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      }
    );

    socket.on("error", (err) => {
      socket.destroy();
      reject(new Error(`TLS connection failed: ${err.message}`));
    });

    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("Connection timed out"));
    });
  });
}
