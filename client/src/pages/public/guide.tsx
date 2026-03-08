import { useState } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CyberTerminal } from "@/components/cyber-terminal";
import { CyberNetwork } from "@/components/cyber-network";
import {
  Shield, Brain, Activity, Target, Bug, Lock, Zap, Eye,
  Monitor, Scan, Mail, Search, Key, Wifi, Database,
  BarChart3, Globe, Terminal, AlertTriangle, Crosshair,
  Download, UserPlus, Settings, LayoutDashboard,
  ChevronDown, ChevronRight, ArrowRight,
  Layers, Radio, Server, Cpu
} from "lucide-react";

const gettingStartedSteps = [
  { icon: UserPlus, stepKey: "1", titleKey: "guide.step1Title", descKey: "guide.step1Desc" },
  { icon: Download, stepKey: "2", titleKey: "guide.step2Title", descKey: "guide.step2Desc" },
  { icon: Settings, stepKey: "3", titleKey: "guide.step3Title", descKey: "guide.step3Desc" },
  { icon: LayoutDashboard, stepKey: "4", titleKey: "guide.step4Title", descKey: "guide.step4Desc" },
];

const tools = [
  { icon: LayoutDashboard, titleKey: "guide.toolDashboard", descKey: "guide.toolDashboardDesc", caps: ["guide.toolDashboardCap1", "guide.toolDashboardCap2", "guide.toolDashboardCap3"], link: "/" },
  { icon: Brain, titleKey: "guide.toolAiAnalysis", descKey: "guide.toolAiAnalysisDesc", caps: ["guide.toolAiAnalysisCap1", "guide.toolAiAnalysisCap2", "guide.toolAiAnalysisCap3"], link: "/ai-analysis" },
  { icon: Database, titleKey: "guide.toolThreatIntel", descKey: "guide.toolThreatIntelDesc", caps: ["guide.toolThreatIntelCap1", "guide.toolThreatIntelCap2", "guide.toolThreatIntelCap3"], link: "/threat-intel" },
  { icon: Scan, titleKey: "guide.toolScanner", descKey: "guide.toolScannerDesc", caps: ["guide.toolScannerCap1", "guide.toolScannerCap2", "guide.toolScannerCap3"], link: "/scanner" },
  { icon: Crosshair, titleKey: "guide.toolMobilePentest", descKey: "guide.toolMobilePentestDesc", caps: ["guide.toolMobilePentestCap1", "guide.toolMobilePentestCap2", "guide.toolMobilePentestCap3"], link: "/mobile-pentest" },
  { icon: Bug, titleKey: "guide.toolTrojanAnalyzer", descKey: "guide.toolTrojanAnalyzerDesc", caps: ["guide.toolTrojanAnalyzerCap1", "guide.toolTrojanAnalyzerCap2", "guide.toolTrojanAnalyzerCap3"], link: "/trojan-analyzer" },
  { icon: AlertTriangle, titleKey: "guide.toolThreatSim", descKey: "guide.toolThreatSimDesc", caps: ["guide.toolThreatSimCap1", "guide.toolThreatSimCap2", "guide.toolThreatSimCap3"], link: "/threat-simulation" },
  { icon: Lock, titleKey: "guide.toolSslInspector", descKey: "guide.toolSslInspectorDesc", caps: ["guide.toolSslInspectorCap1", "guide.toolSslInspectorCap2", "guide.toolSslInspectorCap3"], link: "/ssl-inspector" },
  { icon: Mail, titleKey: "guide.toolEmailAnalyzer", descKey: "guide.toolEmailAnalyzerDesc", caps: ["guide.toolEmailAnalyzerCap1", "guide.toolEmailAnalyzerCap2", "guide.toolEmailAnalyzerCap3"], link: "/email-analyzer" },
  { icon: Key, titleKey: "guide.toolPasswordAuditor", descKey: "guide.toolPasswordAuditorDesc", caps: ["guide.toolPasswordAuditorCap1", "guide.toolPasswordAuditorCap2", "guide.toolPasswordAuditorCap3"], link: "/password-auditor" },
  { icon: BarChart3, titleKey: "guide.toolCompliance", descKey: "guide.toolComplianceDesc", caps: ["guide.toolComplianceCap1", "guide.toolComplianceCap2", "guide.toolComplianceCap3"], link: "/compliance" },
  { icon: Wifi, titleKey: "guide.toolNetworkMonitor", descKey: "guide.toolNetworkMonitorDesc", caps: ["guide.toolNetworkMonitorCap1", "guide.toolNetworkMonitorCap2", "guide.toolNetworkMonitorCap3"], link: "/network-monitor" },
];

const deploySteps = [
  { icon: Download, titleKey: "guide.deployStep1" },
  { icon: Shield, titleKey: "guide.deployStep2" },
  { icon: Terminal, titleKey: "guide.deployStep3" },
  { icon: Zap, titleKey: "guide.deployStep4" },
  { icon: Monitor, titleKey: "guide.deployStep5" },
];

const architectureLayers = [
  { icon: Monitor, titleKey: "guide.archEndpoint", descKey: "guide.archEndpointDesc", color: "text-cyan-400" },
  { icon: Globe, titleKey: "guide.archNetwork", descKey: "guide.archNetworkDesc", color: "text-blue-400" },
  { icon: Brain, titleKey: "guide.archIntelligence", descKey: "guide.archIntelligenceDesc", color: "text-purple-400" },
  { icon: Zap, titleKey: "guide.archResponse", descKey: "guide.archResponseDesc", color: "text-amber-400" },
];

const faqItems = [
  { qKey: "guide.faq1Q", aKey: "guide.faq1A" },
  { qKey: "guide.faq2Q", aKey: "guide.faq2A" },
  { qKey: "guide.faq3Q", aKey: "guide.faq3A" },
  { qKey: "guide.faq4Q", aKey: "guide.faq4A" },
  { qKey: "guide.faq5Q", aKey: "guide.faq5A" },
];

function FaqItem({ qKey, aKey }: { qKey: string; aKey: string }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-border/40 rounded-md" data-testid={`faq-item-${qKey}`}>
      <button
        className="w-full flex items-center justify-between gap-4 p-4 text-start hover-elevate"
        onClick={() => setOpen(!open)}
        data-testid={`button-faq-${qKey}`}
      >
        <span className="text-sm font-medium">{t(qKey)}</span>
        {open ? <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4">
          <p className="text-xs text-muted-foreground leading-relaxed">{t(aKey)}</p>
        </div>
      )}
    </div>
  );
}

export default function GuidePage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-primary/30 bg-primary/5 mb-6">
            <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="text-[10px] font-mono tracking-wider text-primary uppercase">{t("guide.badge")}</span>
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4" data-testid="text-guide-heading">
            {t("guide.heroTitle")}
          </h1>
          <p className="text-base text-muted-foreground max-w-2xl mx-auto">
            {t("guide.heroSubtitle")}
          </p>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("guide.gettingStartedLabel")}</span>
            <h2 className="text-3xl font-bold mt-3 mb-4">{t("guide.gettingStartedTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("guide.gettingStartedDesc")}</p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            {gettingStartedSteps.map((step) => {
              const Icon = step.icon;
              return (
                <div key={step.stepKey} className="text-center" data-testid={`guide-step-${step.stepKey}`}>
                  <div className="relative mx-auto w-14 h-14 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                    <Icon className="w-6 h-6 text-primary" />
                    <span className="absolute -top-2 -right-2 text-[10px] font-mono font-bold text-primary bg-background border border-primary/30 rounded-full w-6 h-6 flex items-center justify-center">
                      {step.stepKey}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold tracking-wider uppercase mb-2">{t(step.titleKey)}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{t(step.descKey)}</p>
                </div>
              );
            })}
          </div>
          <div className="max-w-3xl mx-auto">
            <CyberTerminal />
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("guide.toolShowcaseLabel")}</span>
            <h2 className="text-3xl font-bold mt-3 mb-4">{t("guide.toolShowcaseTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("guide.toolShowcaseDesc")}</p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {tools.map((tool) => {
              const Icon = tool.icon;
              return (
                <Card key={tool.titleKey} className="p-5" data-testid={`guide-tool-${tool.titleKey}`}>
                  <div className="flex items-start gap-3 mb-3">
                    <div className="w-9 h-9 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                      <Icon className="w-4 h-4 text-primary" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="text-xs font-semibold tracking-wider uppercase mb-1">{t(tool.titleKey)}</h3>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{t(tool.descKey)}</p>
                    </div>
                  </div>
                  <ul className="space-y-1 mb-3">
                    {tool.caps.map((capKey) => (
                      <li key={capKey} className="flex items-center gap-2 text-[11px] text-muted-foreground">
                        <div className="w-1 h-1 rounded-full bg-primary shrink-0" />
                        {t(capKey)}
                      </li>
                    ))}
                  </ul>
                  <Link href={tool.link}>
                    <Button variant="outline" size="sm" className="w-full text-[11px] tracking-wider uppercase gap-1" data-testid={`button-try-${tool.titleKey}`}>
                      {t("guide.tryIt")}
                      <ArrowRight className="w-3 h-3" />
                    </Button>
                  </Link>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("guide.deployLabel")}</span>
            <h2 className="text-3xl font-bold mt-3 mb-4">{t("guide.deployTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("guide.deployDesc")}</p>
          </div>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 mb-12">
            {deploySteps.map((step, idx) => {
              const Icon = step.icon;
              return (
                <div key={step.titleKey} className="flex items-center gap-3" data-testid={`deploy-step-${idx}`}>
                  <div className="flex flex-col items-center gap-2">
                    <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center">
                      <Icon className="w-5 h-5 text-primary" />
                    </div>
                    <span className="text-[10px] font-mono text-muted-foreground text-center max-w-[100px]">{t(step.titleKey)}</span>
                  </div>
                  {idx < deploySteps.length - 1 && (
                    <div className="hidden sm:block">
                      <ArrowRight className="w-4 h-4 text-primary/40" />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="max-w-3xl mx-auto">
            <CyberNetwork />
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("guide.archLabel")}</span>
            <h2 className="text-3xl font-bold mt-3 mb-4">{t("guide.archTitle")}</h2>
            <p className="text-muted-foreground max-w-xl mx-auto">{t("guide.archDesc")}</p>
          </div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {architectureLayers.map((layer, idx) => {
              const Icon = layer.icon;
              return (
                <Card key={layer.titleKey} className="p-5 text-center" data-testid={`arch-layer-${idx}`}>
                  <div className="mx-auto w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-3">
                    <Icon className={`w-5 h-5 ${layer.color}`} />
                  </div>
                  <h3 className="text-xs font-semibold tracking-wider uppercase mb-2">{t(layer.titleKey)}</h3>
                  <p className="text-[11px] text-muted-foreground leading-relaxed">{t(layer.descKey)}</p>
                  {idx < architectureLayers.length - 1 && (
                    <div className="hidden lg:flex justify-center mt-3">
                      <ChevronDown className="w-4 h-4 text-primary/40" />
                    </div>
                  )}
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-3xl mx-auto">
          <div className="text-center mb-12">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("guide.faqLabel")}</span>
            <h2 className="text-3xl font-bold mt-3 mb-4">{t("guide.faqTitle")}</h2>
          </div>
          <div className="space-y-3">
            {faqItems.map((item) => (
              <FaqItem key={item.qKey} qKey={item.qKey} aKey={item.aKey} />
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-4xl mx-auto text-center">
          <div className="p-8 md:p-12 rounded-md border border-primary/20 bg-gradient-to-b from-primary/5 to-transparent">
            <Shield className="w-12 h-12 text-primary mx-auto mb-6" />
            <h2 className="text-2xl md:text-3xl font-bold mb-4">{t("guide.ctaTitle")}</h2>
            <p className="text-muted-foreground mb-8 max-w-lg mx-auto">{t("guide.ctaDesc")}</p>
            <Link href="/auth">
              <Button size="lg" className="text-sm tracking-wider uppercase gap-2" data-testid="button-guide-cta">
                {t("guide.ctaButton")}
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
