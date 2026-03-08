import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import {
  Brain, Activity, ShieldCheck, Target, Siren, Globe,
  Monitor, Scan, Mail, Search, Key, Wifi,
  AlertTriangle, Terminal, Lock, Eye,
  Network, BarChart3, Bug, Crosshair, FileSearch,
  Fingerprint, Layers, Zap
} from "lucide-react";

const featureCategories = [
  {
    category: "Threat Detection & Intelligence",
    features: [
      {
        icon: Brain,
        title: "AI Threat Analysis",
        desc: "Advanced machine learning models analyze security events in real-time, providing expert-level threat assessment, behavioral pattern recognition, and actionable recommendations.",
        capabilities: ["Real-time event classification", "Behavioral anomaly detection", "Natural language threat queries", "Automated severity scoring"],
      },
      {
        icon: Activity,
        title: "Real-Time Monitoring",
        desc: "Live security event feeds via WebSocket connections with instant alerting, customizable dashboards, and complete situational awareness across your infrastructure.",
        capabilities: ["WebSocket live feeds", "Custom alert rules", "Severity-based filtering", "24/7 continuous monitoring"],
      },
      {
        icon: Target,
        title: "MITRE ATT&CK Mapping",
        desc: "Full tactical heatmap coverage across the MITRE ATT&CK framework. Track adversary techniques, measure detection gaps, and prioritize defensive improvements.",
        capabilities: ["Technique coverage heatmap", "Detection gap analysis", "Tactic-level scoring", "Framework alignment reports"],
      },
      {
        icon: Globe,
        title: "Threat Intelligence Feeds",
        desc: "Multi-source threat intelligence from AbuseIPDB, OTX AlienVault, MalwareBazaar, Google Safe Browsing, and URLScan with automated IOC correlation.",
        capabilities: ["5+ integrated threat feeds", "Automated IOC enrichment", "Threat scoring & correlation", "Bulk indicator import"],
      },
      {
        icon: Eye,
        title: "Dark Web Monitoring",
        desc: "Continuous surveillance of dark web marketplaces, forums, and paste sites for leaked credentials, exposed data, and threat actor mentions.",
        capabilities: ["Credential leak detection", "Brand mention tracking", "Data exposure alerts", "Threat actor monitoring"],
      },
      {
        icon: AlertTriangle,
        title: "Threat Simulation",
        desc: "Simulate ransomware, phishing, supply chain attacks, insider threats, and zero-day exploits to validate detection and response capabilities.",
        capabilities: ["Ransomware simulation", "Phishing campaign tests", "Supply chain scenarios", "MITRE-mapped exercises"],
      },
    ],
  },
  {
    category: "Offensive Security & Testing",
    features: [
      {
        icon: Scan,
        title: "Vulnerability Scanner",
        desc: "Comprehensive web application scanning with OWASP Top 10 mapping, CWE identification, CVSS risk scoring, and detailed remediation guidance.",
        capabilities: ["OWASP Top 10 coverage", "CWE ID mapping", "CVSS risk scoring", "Config-level remediation"],
      },
      {
        icon: Crosshair,
        title: "Mobile Penetration Testing",
        desc: "OWASP Mobile Top 10 compliance checks including insecure storage, authentication flaws, certificate pinning, and platform-specific security assessments.",
        capabilities: ["OWASP Mobile Top 10", "Permission risk analysis", "Certificate pinning checks", "iOS & Android coverage"],
      },
      {
        icon: Terminal,
        title: "Payload Generator",
        desc: "Generate security testing payloads for XSS, SQL injection, SSRF, command injection, and other common vulnerability classes to validate defenses.",
        capabilities: ["XSS payload variants", "SQLi test strings", "SSRF bypass payloads", "Encoding & obfuscation"],
      },
      {
        icon: Lock,
        title: "SSL/TLS Inspector",
        desc: "Certificate chain validation, protocol version analysis, cipher suite auditing, HSTS verification, and expiration monitoring for all domains.",
        capabilities: ["Certificate chain analysis", "Cipher suite grading", "Protocol version check", "Expiry monitoring"],
      },
      {
        icon: Key,
        title: "Password Auditor",
        desc: "Hash identification and cracking simulation, entropy analysis, password policy compliance checking, and organizational credential hygiene assessments.",
        capabilities: ["Hash type identification", "Dictionary attack testing", "Entropy calculation", "Policy compliance checks"],
      },
      {
        icon: Mail,
        title: "Email Security Analyzer",
        desc: "Comprehensive email header analysis with SPF/DKIM/DMARC validation, phishing indicator detection, and malicious attachment identification.",
        capabilities: ["SPF/DKIM/DMARC checks", "Header forgery detection", "Phishing scoring", "Attachment analysis"],
      },
    ],
  },
  {
    category: "Endpoint Protection",
    features: [
      {
        icon: Monitor,
        title: "Agent-Based EDR",
        desc: "Lightweight endpoint agents with real-time process monitoring, registry persistence detection, DLL sideloading checks, and PowerShell script analysis.",
        capabilities: ["Process watchlist (50+ signatures)", "Registry persistence monitoring", "DLL sideloading detection", "Encoded command detection"],
      },
      {
        icon: ShieldCheck,
        title: "Auto-Protect System",
        desc: "One-click protection activation across all endpoints with automated defense mode, real-time policy enforcement, and continuous threat scanning.",
        capabilities: ["One-click activation", "Auto defense mode", "Policy enforcement", "Continuous scanning"],
      },
      {
        icon: Zap,
        title: "Automated Response",
        desc: "Automated response playbooks execute countermeasures in milliseconds — IP blocking, asset isolation, file quarantine, and domain sinkholing.",
        capabilities: ["Sub-50ms response", "IP/domain blocking", "File quarantine", "Host isolation"],
      },
      {
        icon: Siren,
        title: "Incident Management",
        desc: "Structured incident workflow from detection to resolution with forensic timeline, evidence preservation, team assignment, and post-incident reporting.",
        capabilities: ["Kanban-style workflow", "Forensic timeline", "Team assignment", "Playbook integration"],
      },
    ],
  },
  {
    category: "Network Security",
    features: [
      {
        icon: Wifi,
        title: "Infrastructure Monitor",
        desc: "Real-time network infrastructure monitoring with bandwidth analysis, ARP spoofing detection, traffic anomaly alerts, and deep packet inspection.",
        capabilities: ["Bandwidth monitoring", "ARP spoof detection", "Traffic anomaly alerts", "Packet capture & analysis"],
      },
      {
        icon: Network,
        title: "Network Topology Map",
        desc: "Visual network asset inventory with risk assessment, connectivity mapping, and real-time status monitoring for all infrastructure components.",
        capabilities: ["Asset discovery", "Risk scoring", "Topology visualization", "Status monitoring"],
      },
    ],
  },
  {
    category: "Compliance & Reporting",
    features: [
      {
        icon: BarChart3,
        title: "Compliance Dashboard",
        desc: "Multi-framework compliance mapping for NIST CSF, ISO 27001, PCI-DSS, HIPAA, and SOC 2 with automated evidence collection and continuous gap analysis.",
        capabilities: ["5+ framework support", "Automated evidence collection", "Gap analysis reports", "Compliance scoring"],
      },
      {
        icon: Search,
        title: "CVE Database",
        desc: "Searchable vulnerability database with CVSS scoring, affected product tracking, exploit availability indicators, and automated patch priority recommendations.",
        capabilities: ["Full CVE search", "CVSS scoring", "Exploit tracking", "Patch prioritization"],
      },
      {
        icon: Bug,
        title: "Trojan Analyzer",
        desc: "Deep behavioral analysis with automated IOC extraction, MITRE ATT&CK heatmap visualization, threat actor attribution, and YARA/Sigma rule generation.",
        capabilities: ["IOC auto-extraction", "MITRE heatmap", "Threat actor attribution", "YARA/Sigma generation"],
      },
      {
        icon: FileSearch,
        title: "Forensic Timeline",
        desc: "Comprehensive audit logging and chronological event reconstruction for incident investigation, compliance auditing, and post-breach analysis.",
        capabilities: ["Chronological reconstruction", "Action-type filtering", "CSV export", "Tamper-proof logging"],
      },
    ],
  },
];

export default function FeaturesPage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-features-heading">
            {t("public.featuresTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <p className="text-lg text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.featuresSubtitle")}
          </p>
        </div>
      </section>

      {featureCategories.map((category) => (
        <section key={category.category} className="py-12 px-6 border-t border-border/30">
          <div className="max-w-6xl mx-auto">
            <div className="mb-8">
              <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{category.category}</span>
              <div className="h-px w-12 bg-primary/30 mt-2" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {category.features.map((feature) => {
                const Icon = feature.icon;
                return (
                  <Card key={feature.title} className="p-6" data-testid={`card-feature-${feature.title.toLowerCase().replace(/\s+/g, "-")}`}>
                    <div className="flex items-start gap-4">
                      <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                        <Icon className="w-5 h-5 text-primary" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <h3 className="text-sm font-semibold tracking-wide uppercase mb-2">
                          {feature.title}
                        </h3>
                        <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                          {feature.desc}
                        </p>
                        <div className="flex flex-wrap gap-2">
                          {feature.capabilities.map((cap) => (
                            <span
                              key={cap}
                              className="text-[10px] font-mono tracking-wider px-2 py-0.5 rounded-md border border-border/50 bg-muted/30 text-muted-foreground"
                            >
                              {cap}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </Card>
                );
              })}
            </div>
          </div>
        </section>
      ))}
    </PublicLayout>
  );
}
