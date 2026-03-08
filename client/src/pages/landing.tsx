import { useState, useEffect } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { MatrixRain } from "@/components/matrix-rain";
import { AegisLogo } from "@/components/logo";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { CyberStats } from "@/components/cyber-stats";
import { CyberAttackFlow } from "@/components/cyber-attack-flow";
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

function CyberShieldPulse() {
  return (
    <div className="relative w-40 h-40 md:w-52 md:h-52 mx-auto mb-8" data-testid="cyber-shield-pulse">
      <svg viewBox="0 0 200 200" className="w-full h-full">
        <defs>
          <linearGradient id="shieldBodyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.6" />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0.1" />
          </linearGradient>
          <filter id="shieldGlowFilter">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <circle cx="100" cy="100" r="85" fill="none" stroke="hsl(var(--primary))" strokeWidth="0.5" opacity="0.1">
          <animate attributeName="r" values="75;90;75" dur="4s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.15;0.05;0.15" dur="4s" repeatCount="indefinite" />
        </circle>
        <circle cx="100" cy="100" r="70" fill="none" stroke="hsl(var(--primary))" strokeWidth="0.5" opacity="0.15">
          <animate attributeName="r" values="60;75;60" dur="3.5s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.2;0.05;0.2" dur="3.5s" repeatCount="indefinite" />
        </circle>
        <circle cx="100" cy="100" r="55" fill="none" stroke="hsl(var(--primary))" strokeWidth="0.8" opacity="0.2">
          <animate attributeName="r" values="50;60;50" dur="3s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.25;0.08;0.25" dur="3s" repeatCount="indefinite" />
        </circle>

        <g filter="url(#shieldGlowFilter)">
          <path
            d="M100 45 L135 65 L135 110 Q135 140 100 160 Q65 140 65 110 L65 65 Z"
            fill="url(#shieldBodyGrad)"
            stroke="hsl(var(--primary))"
            strokeWidth="1.5"
          />
        </g>

        <path
          d="M100 45 L135 65 L135 110 Q135 140 100 160 Q65 140 65 110 L65 65 Z"
          fill="none"
          stroke="hsl(var(--primary))"
          strokeWidth="2"
          strokeDasharray="8 4"
          opacity="0.6"
        >
          <animate attributeName="stroke-dashoffset" values="0;-24" dur="3s" repeatCount="indefinite" />
        </path>

        <path d="M92 100 L98 108 L112 90" fill="none" stroke="hsl(var(--primary))" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" opacity="0.9" />

        {[0, 60, 120, 180, 240, 300].map((angle) => {
          const rad = (angle * Math.PI) / 180;
          const startR = 88;
          const x = 100 + startR * Math.cos(rad);
          const y = 100 + startR * Math.sin(rad);
          return (
            <circle key={angle} cx={x} cy={y} r="1.5" fill="hsl(var(--primary))" opacity="0.4">
              <animate
                attributeName="r"
                values="1;2.5;1"
                dur={`${2 + (angle % 3) * 0.5}s`}
                repeatCount="indefinite"
                begin={`${angle * 0.01}s`}
              />
              <animate
                attributeName="opacity"
                values="0.6;0.1;0.6"
                dur={`${2 + (angle % 3) * 0.5}s`}
                repeatCount="indefinite"
                begin={`${angle * 0.01}s`}
              />
              <animateMotion
                dur={`${3 + (angle % 2)}s`}
                repeatCount="indefinite"
                path={`M0,0 L${(100 - x) * 0.6},${(100 - y) * 0.6}`}
              />
            </circle>
          );
        })}
      </svg>
    </div>
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
  { icon: Monitor, titleKey: "landing.capAgentEdr", descKey: "landing.capAgentEdrDesc" },
  { icon: ShieldCheck, titleKey: "landing.capAutoProtect", descKey: "landing.capAutoProtectDesc" },
  { icon: Bug, titleKey: "landing.capTrojanAnalysis", descKey: "landing.capTrojanAnalysisDesc" },
  { icon: Crosshair, titleKey: "landing.capMobilePentest", descKey: "landing.capMobilePentestDesc" },
  { icon: Lock, titleKey: "landing.capSslInspector", descKey: "landing.capSslInspectorDesc" },
  { icon: Eye, titleKey: "landing.capDarkWebMonitor", descKey: "landing.capDarkWebMonitorDesc" },
  { icon: Mail, titleKey: "landing.capEmailAnalyzer", descKey: "landing.capEmailAnalyzerDesc" },
  { icon: Search, titleKey: "landing.capCveDatabase", descKey: "landing.capCveDatabaseDesc" },
  { icon: Key, titleKey: "landing.capPasswordAuditor", descKey: "landing.capPasswordAuditorDesc" },
  { icon: Wifi, titleKey: "landing.capNetworkMonitor", descKey: "landing.capNetworkMonitorDesc" },
  { icon: Database, titleKey: "landing.capThreatIntel", descKey: "landing.capThreatIntelDesc" },
  { icon: BarChart3, titleKey: "landing.capComplianceDash", descKey: "landing.capComplianceDashDesc" },
  { icon: Globe, titleKey: "landing.capHoneypotSystem", descKey: "landing.capHoneypotSystemDesc" },
  { icon: Terminal, titleKey: "landing.capPayloadGen", descKey: "landing.capPayloadGenDesc" },
  { icon: AlertTriangle, titleKey: "landing.capThreatSim", descKey: "landing.capThreatSimDesc" },
];

const howItWorks = [
  { step: "01", icon: Download, titleKey: "landing.howDeployTitle", descKey: "landing.howDeployDesc" },
  { step: "02", icon: Scan, titleKey: "landing.howMonitorTitle", descKey: "landing.howMonitorDesc" },
  { step: "03", icon: AlertTriangle, titleKey: "landing.howDetectTitle", descKey: "landing.howDetectDesc" },
  { step: "04", icon: Zap, titleKey: "landing.howRespondTitle", descKey: "landing.howRespondDesc" },
];

const trustIndicatorKeys = [
  "landing.trustMitre",
  "landing.trustNist",
  "landing.trustIso",
  "landing.trustSoc",
  "landing.trustPci",
  "landing.trustHipaa",
  "landing.trustOwasp",
  "landing.trustCis",
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
            <Link href="/guide" className="text-xs tracking-wider uppercase text-muted-foreground hover:text-primary transition-colors" data-testid="link-guide">
              {t("public.navGuide")}
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
          <CyberShieldPulse />

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
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("landing.liveMetricsLabel")}</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">{t("landing.liveMetricsTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("landing.liveMetricsDesc")}</p>
          </div>
          <CyberStats />
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("landing.killChainLabel")}</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">{t("landing.killChainTitle")}</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">{t("landing.killChainDesc")}</p>
          </div>
          <CyberAttackFlow />
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("landing.capSectionLabel")}</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">{t("landing.capSectionTitle")}</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              {t("landing.capSectionDesc")}
            </p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {platformCapabilities.map((cap) => {
              const Icon = cap.icon;
              return (
                <Card key={cap.titleKey} className="p-5" data-testid={`card-capability-${cap.titleKey}`}>
                  <div className="flex items-start gap-3">
                    <div className="w-9 h-9 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                      <Icon className="w-4 h-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-xs font-semibold tracking-wider uppercase mb-1">{t(cap.titleKey)}</h3>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{t(cap.descKey)}</p>
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
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("landing.howSectionLabel")}</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">{t("landing.howSectionTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              {t("landing.howSectionDesc")}
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
                  <h3 className="text-sm font-semibold tracking-wider uppercase mb-2">{t(step.titleKey)}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{t(step.descKey)}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      <section className="relative py-24 px-4 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("landing.trustSectionLabel")}</span>
            <h2 className="text-3xl md:text-4xl font-bold mt-3 mb-4">{t("landing.trustSectionTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              {t("landing.trustSectionDesc")}
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-3">
            {trustIndicatorKeys.map((key) => (
              <div
                key={key}
                className="flex items-center gap-2 px-4 py-2 rounded-md border border-border/40 bg-card/30"
                data-testid={`badge-trust-${key}`}
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-primary shrink-0" />
                <span className="text-xs font-mono tracking-wider">{t(key)}</span>
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
              { icon: Lock, textKey: "landing.capFirewall" },
              { icon: Eye, textKey: "landing.capHoneypot" },
              { icon: Globe, textKey: "landing.capGeoBlock" },
              { icon: Server, textKey: "landing.capForensics" },
              { icon: Cpu, textKey: "landing.capPlaybooks" },
              { icon: Radio, textKey: "landing.capWebsocket" },
              { icon: BookOpen, textKey: "landing.capPolicies" },
              { icon: Shield, textKey: "landing.capQuarantine" },
              { icon: Scan, textKey: "landing.capVulnScanner" },
              { icon: FileSearch, textKey: "landing.capHashAnalysis" },
              { icon: Network, textKey: "landing.capTrafficAnalysis" },
              { icon: Fingerprint, textKey: "landing.capIocExtraction" },
              { icon: Layers, textKey: "landing.capKillChain" },
              { icon: Crosshair, textKey: "landing.capPentest" },
              { icon: Mail, textKey: "landing.capPhishing" },
              { icon: Key, textKey: "landing.capCredAudit" },
            ].map((cap) => {
              const Icon = cap.icon;
              return (
                <div key={cap.textKey} className="flex items-center gap-3 p-4 rounded-md border border-border/30 bg-card/30">
                  <Icon className="w-4 h-4 text-primary flex-shrink-0" />
                  <span className="text-xs tracking-wider">{t(cap.textKey)}</span>
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
