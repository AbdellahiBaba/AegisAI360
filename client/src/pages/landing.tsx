import { useState, useEffect } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { MatrixRain } from "@/components/matrix-rain";
import { AegisLogo } from "@/components/logo";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Shield, Brain, Activity, Target, Bug, Database,
  Lock, Zap, Eye, ChevronRight, ArrowRight,
  Globe, Server, Cpu, Radio, BookOpen,
  Monitor, Scan, Mail, Search, Key, Wifi,
  AlertTriangle, FileSearch, Crosshair, Terminal,
  Network, ShieldCheck, Layers, Fingerprint,
  Download, BarChart3, CheckCircle2
} from "lucide-react";

function TypewriterText({ texts, className }: { texts: string[]; className?: string }) {
  const [currentTextIndex, setCurrentTextIndex] = useState(0);
  const [displayText, setDisplayText] = useState("");
  const [isDeleting, setIsDeleting] = useState(false);

  useEffect(() => {
    const currentFullText = texts[currentTextIndex];
    let timeout: NodeJS.Timeout;

    if (!isDeleting && displayText === currentFullText) {
      timeout = setTimeout(() => setIsDeleting(true), 2000);
    } else if (isDeleting && displayText === "") {
      setIsDeleting(false);
      setCurrentTextIndex((prev) => (prev + 1) % texts.length);
    } else {
      timeout = setTimeout(() => {
        setDisplayText(
          isDeleting
            ? currentFullText.substring(0, displayText.length - 1)
            : currentFullText.substring(0, displayText.length + 1)
        );
      }, isDeleting ? 30 : 70);
    }

    return () => clearTimeout(timeout);
  }, [displayText, isDeleting, currentTextIndex, texts]);

  return (
    <span className={className}>
      {displayText}
      <span className="animate-pulse text-primary">|</span>
    </span>
  );
}

function StatsCounter({ value, label }: { value: string; label: string }) {
  const [count, setCount] = useState(0);
  const target = parseInt(value.replace(/[^0-9]/g, ""));
  const suffix = value.replace(/[0-9]/g, "");

  useEffect(() => {
    let frame: number;
    const duration = 2000;
    const start = performance.now();

    function animate(now: number) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setCount(Math.floor(eased * target));
      if (progress < 1) frame = requestAnimationFrame(animate);
    }

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [target]);

  return (
    <div className="text-center">
      <div className="text-3xl md:text-4xl font-bold text-primary font-mono">
        {count.toLocaleString()}{suffix}
      </div>
      <div className="text-xs text-muted-foreground mt-1 tracking-wider uppercase">{label}</div>
    </div>
  );
}

const features = [
  { icon: Brain, titleKey: "landing.featureAiTitle", descKey: "landing.featureAiDesc" },
  { icon: Activity, titleKey: "landing.featureMonitorTitle", descKey: "landing.featureMonitorDesc" },
  { icon: Zap, titleKey: "landing.featureDefenseTitle", descKey: "landing.featureDefenseDesc" },
  { icon: Target, titleKey: "landing.featureMitreTitle", descKey: "landing.featureMitreDesc" },
  { icon: Bug, titleKey: "landing.featureIncidentTitle", descKey: "landing.featureIncidentDesc" },
  { icon: Database, titleKey: "landing.featureIntelTitle", descKey: "landing.featureIntelDesc" },
];

const platformCapabilities = [
  { icon: Monitor, title: "Agent-Based EDR", desc: "Deploy lightweight agents on endpoints for real-time process monitoring, registry persistence detection, and automated threat response." },
  { icon: ShieldCheck, title: "Auto-Protect", desc: "One-click protection activation across all endpoints with automated defense mode, policy enforcement, and continuous monitoring." },
  { icon: Bug, title: "Trojan Analysis", desc: "Deep behavioral analysis with IOC extraction, MITRE ATT&CK heatmap mapping, threat actor attribution, and YARA/Sigma rule generation." },
  { icon: Crosshair, title: "Mobile Pentesting", desc: "OWASP Mobile Top 10 compliance checks, permission analysis, certificate pinning verification, and platform-specific security assessments." },
  { icon: Lock, title: "SSL Inspector", desc: "Certificate chain validation, protocol version analysis, cipher suite auditing, and expiration monitoring for all your domains." },
  { icon: Eye, title: "Dark Web Monitor", desc: "Continuous dark web surveillance for leaked credentials, exposed data, and threat actor mentions targeting your organization." },
  { icon: Mail, title: "Email Analyzer", desc: "Header analysis, SPF/DKIM/DMARC validation, phishing detection, and malicious attachment scanning for suspicious emails." },
  { icon: Search, title: "CVE Database", desc: "Searchable vulnerability database with CVSS scoring, affected product tracking, and automated patch priority recommendations." },
  { icon: Key, title: "Password Auditor", desc: "Hash identification, dictionary attack simulation, entropy analysis, and organization-wide password policy compliance checking." },
  { icon: Wifi, title: "Network Monitor", desc: "Real-time infrastructure monitoring with bandwidth analysis, ARP spoofing detection, traffic anomaly alerts, and packet capture." },
  { icon: Database, title: "Threat Intelligence", desc: "Multi-source threat feeds from AbuseIPDB, OTX, MalwareBazaar, and URLScan with automated IOC correlation and enrichment." },
  { icon: BarChart3, title: "Compliance Dashboard", desc: "Framework mapping for NIST, ISO 27001, PCI-DSS, HIPAA, and SOC 2 with automated evidence collection and gap analysis." },
  { icon: Globe, title: "Honeypot System", desc: "Deploy decoy services to attract and analyze attacker behavior, capture TTPs, and generate actionable threat intelligence." },
  { icon: Terminal, title: "Payload Generator", desc: "Create security testing payloads for XSS, SQLi, SSRF, and command injection to validate your application defenses." },
  { icon: AlertTriangle, title: "Threat Simulation", desc: "Simulate ransomware, phishing, supply chain, and insider threat scenarios to test your detection and response capabilities." },
];

const howItWorks = [
  { step: "01", icon: Download, title: "Deploy Agent", desc: "Install the lightweight AegisAI360 agent on your endpoints. Supports Windows, Linux, and macOS." },
  { step: "02", icon: Scan, title: "Auto-Monitor", desc: "The agent continuously monitors processes, registry, network connections, and file system changes in real-time." },
  { step: "03", icon: AlertTriangle, title: "Detect Threats", desc: "AI-powered analysis identifies threats, maps to MITRE ATT&CK, and generates severity-scored alerts instantly." },
  { step: "04", icon: Zap, title: "Respond & Remediate", desc: "Automated playbooks execute countermeasures in milliseconds — block IPs, quarantine files, isolate hosts." },
];

const trustIndicators = [
  "MITRE ATT&CK Aligned",
  "NIST CSF Compliant",
  "ISO 27001 Ready",
  "SOC 2 Compatible",
  "PCI-DSS Mapped",
  "HIPAA Supportive",
  "OWASP Top 10 Coverage",
  "CIS Benchmarks",
];

export default function LandingPage() {
  const { t } = useTranslation();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <nav className="fixed top-0 start-0 end-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <Link href="/">
            <div className="cursor-pointer" data-testid="link-landing-home">
              <AegisLogo size={32} />
            </div>
          </Link>
          <div className="hidden md:flex items-center gap-6">
            <Link href="/features" className="text-xs tracking-wider uppercase text-muted-foreground hover:text-primary transition-colors" data-testid="link-features">
              {t("landing.navFeatures")}
            </Link>
            <Link href="/pricing" className="text-xs tracking-wider uppercase text-muted-foreground hover:text-primary transition-colors" data-testid="link-pricing">
              {t("landing.navPricing")}
            </Link>
            <Link href="/about" className="text-xs tracking-wider uppercase text-muted-foreground hover:text-primary transition-colors" data-testid="link-about">
              {t("landing.navAbout")}
            </Link>
          </div>
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <Link href="/auth">
              <Button size="sm" className="text-xs tracking-wider uppercase" data-testid="button-login">
                {t("landing.login")}
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      <section className="relative min-h-screen flex items-center justify-center overflow-hidden pt-14">
        <MatrixRain opacity={0.4} color="#d4af37" />
        <div className="absolute inset-0 bg-gradient-to-b from-background/30 via-background/60 to-background z-[1]" />
        <div className="relative z-[2] text-center px-4 max-w-5xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/30 bg-primary/5 mb-6">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse-glow" />
            <span className="text-[10px] font-mono tracking-wider text-primary uppercase">{t("landing.badge")}</span>
          </div>

          <h1 className="text-4xl sm:text-5xl md:text-7xl font-bold tracking-tight mb-4">
            {t("landing.heroTitle1")}
            <br />
            <span className="text-primary">{t("landing.heroTitle2")}</span>
          </h1>

          <div className="h-8 mb-6">
            <TypewriterText
              texts={[
                t("landing.typewriter1"),
                t("landing.typewriter2"),
                t("landing.typewriter3"),
                t("landing.typewriter4"),
              ]}
              className="text-sm md:text-base font-mono text-muted-foreground"
            />
          </div>

          <p className="text-sm md:text-base text-muted-foreground max-w-2xl mx-auto mb-8">
            {t("landing.heroDesc")}
          </p>

          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link href="/auth">
              <Button size="lg" className="text-sm tracking-wider uppercase gap-2" data-testid="button-hero-access">
                {t("landing.requestAccess")}
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link href="/features">
              <Button variant="outline" size="lg" className="text-sm tracking-wider uppercase gap-2" data-testid="button-hero-features">
                {t("landing.viewFeatures")}
                <ChevronRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>

          <div className="mt-16 grid grid-cols-2 md:grid-cols-4 gap-8">
            <StatsCounter value="2500000" label={t("landing.statThreats")} />
            <StatsCounter value="50" label={t("landing.statResponse")} />
            <StatsCounter value="9999" label={t("landing.statUptime")} />
            <StatsCounter value="150" label={t("landing.statOrgs")} />
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.featuresTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("landing.featuresDesc")}</p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature) => {
              const Icon = feature.icon;
              return (
                <div
                  key={feature.titleKey}
                  className="group p-6 rounded-md border border-border/50 bg-card/50 hover:border-primary/30 hover:bg-card transition-all duration-300"
                >
                  <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                    <Icon className="w-5 h-5 text-primary" />
                  </div>
                  <h3 className="text-sm font-semibold mb-2 tracking-wider uppercase">{t(feature.titleKey)}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{t(feature.descKey)}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">Complete Security Stack</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">Platform Capabilities</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              15+ integrated security tools covering endpoint protection, offensive security, network defense, compliance, and threat intelligence — all in one unified platform.
            </p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {platformCapabilities.map((cap) => {
              const Icon = cap.icon;
              return (
                <Card key={cap.title} className="p-5" data-testid={`card-capability-${cap.title.toLowerCase().replace(/\s+/g, "-")}`}>
                  <div className="flex items-start gap-3">
                    <div className="w-9 h-9 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                      <Icon className="w-4 h-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-xs font-semibold tracking-wider uppercase mb-1">{cap.title}</h3>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{cap.desc}</p>
                    </div>
                  </div>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">Getting Started</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">How It Works</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              From deployment to automated response in four simple steps.
            </p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {howItWorks.map((step) => {
              const Icon = step.icon;
              return (
                <div key={step.step} className="text-center" data-testid={`step-${step.step}`}>
                  <div className="relative mx-auto w-14 h-14 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                    <Icon className="w-6 h-6 text-primary" />
                    <span className="absolute -top-2 -right-2 text-[10px] font-mono font-bold text-primary bg-background border border-primary/30 rounded-full w-6 h-6 flex items-center justify-center">
                      {step.step}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold tracking-wider uppercase mb-2">{step.title}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{step.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">Compliance & Standards</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">Trusted by Security Teams</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              Built to meet the strictest security frameworks and compliance standards used by government and enterprise organizations.
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3">
            {trustIndicators.map((indicator) => (
              <div
                key={indicator}
                className="flex items-center gap-2 px-4 py-2 rounded-md border border-border/40 bg-card/30"
                data-testid={`badge-trust-${indicator.toLowerCase().replace(/\s+/g, "-")}`}
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-primary shrink-0" />
                <span className="text-xs font-mono tracking-wider">{indicator}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">{t("landing.capabilitiesTitle")}</h2>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { icon: Lock, text: t("landing.capFirewall") },
              { icon: Eye, text: t("landing.capHoneypot") },
              { icon: Globe, text: t("landing.capGeoBlock") },
              { icon: Server, text: t("landing.capForensics") },
              { icon: Cpu, text: t("landing.capPlaybooks") },
              { icon: Radio, text: t("landing.capWebsocket") },
              { icon: BookOpen, text: t("landing.capPolicies") },
              { icon: Shield, text: t("landing.capQuarantine") },
              { icon: Scan, text: "Vulnerability Scanner" },
              { icon: FileSearch, text: "Hash Analysis" },
              { icon: Network, text: "Traffic Analysis" },
              { icon: Fingerprint, text: "IOC Extraction" },
              { icon: Layers, text: "Kill Chain Mapping" },
              { icon: Crosshair, text: "Penetration Testing" },
              { icon: Mail, text: "Phishing Detection" },
              { icon: Key, text: "Credential Auditing" },
            ].map((cap) => {
              const Icon = cap.icon;
              return (
                <div key={cap.text} className="flex items-center gap-3 p-4 rounded-md border border-border/30 bg-card/30">
                  <Icon className="w-4 h-4 text-primary flex-shrink-0" />
                  <span className="text-xs tracking-wider">{cap.text}</span>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-4xl mx-auto text-center">
          <div className="p-8 md:p-12 rounded-md border border-primary/20 bg-gradient-to-b from-primary/5 to-transparent">
            <Shield className="w-12 h-12 text-primary mx-auto mb-6" />
            <h2 className="text-2xl md:text-3xl font-bold mb-4">{t("landing.ctaTitle")}</h2>
            <p className="text-muted-foreground mb-8 max-w-lg mx-auto">{t("landing.ctaDesc")}</p>
            <Link href="/auth">
              <Button size="lg" className="text-sm tracking-wider uppercase gap-2" data-testid="button-cta-access">
                {t("landing.ctaButton")}
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      <footer className="border-t border-border/30 py-12 px-4">
        <div className="max-w-6xl mx-auto">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div className="md:col-span-2">
              <AegisLogo size={28} />
              <p className="text-xs text-muted-foreground mt-3 max-w-sm leading-relaxed">
                {t("landing.footerDesc")}
              </p>
            </div>
            <div>
              <h4 className="text-[10px] font-semibold tracking-[0.3em] uppercase text-muted-foreground mb-3">{t("landing.footerPlatform")}</h4>
              <div className="space-y-2">
                <Link href="/features" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-features">{t("landing.navFeatures")}</Link>
                <Link href="/pricing" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-pricing">{t("landing.navPricing")}</Link>
                <Link href="/about" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-about">{t("landing.navAbout")}</Link>
              </div>
            </div>
            <div>
              <h4 className="text-[10px] font-semibold tracking-[0.3em] uppercase text-muted-foreground mb-3">{t("landing.footerLegal")}</h4>
              <div className="space-y-2">
                <Link href="/privacy" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-privacy">{t("landing.privacyPolicy")}</Link>
                <Link href="/terms" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-terms">{t("landing.termsOfService")}</Link>
                <Link href="/refund" className="block text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-refund">{t("landing.refundPolicy")}</Link>
              </div>
            </div>
          </div>
          <div className="border-t border-border/30 pt-6 flex flex-col sm:flex-row items-center justify-between gap-4">
            <span className="text-[10px] text-muted-foreground font-mono">{t("landing.copyright")}</span>
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse-glow" />
              <span className="text-[10px] text-muted-foreground font-mono tracking-wider">{t("landing.allSystemsOperational")}</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
