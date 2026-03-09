import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { CyberRadar } from "@/components/cyber-network";
import { CyberStats } from "@/components/cyber-stats";
import { CyberAttackFlow } from "@/components/cyber-attack-flow";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Brain, Activity, ShieldCheck, Target, Siren, Globe,
  Monitor, Scan, Mail, Search, Key, Wifi,
  AlertTriangle, Terminal, Lock, Eye,
  Network, BarChart3, Bug, Crosshair, FileSearch,
  Fingerprint, Layers, Zap
} from "lucide-react";

const featureCategories = [
  {
    categoryKey: "feat.catThreatDetection",
    features: [
      { icon: Brain, titleKey: "feat.aiThreatTitle", descKey: "feat.aiThreatDesc", capKeys: ["feat.aiThreatC1", "feat.aiThreatC2", "feat.aiThreatC3", "feat.aiThreatC4"] },
      { icon: Activity, titleKey: "feat.realtimeTitle", descKey: "feat.realtimeDesc", capKeys: ["feat.realtimeC1", "feat.realtimeC2", "feat.realtimeC3", "feat.realtimeC4"] },
      { icon: Target, titleKey: "feat.mitreTitle", descKey: "feat.mitreDesc", capKeys: ["feat.mitreC1", "feat.mitreC2", "feat.mitreC3", "feat.mitreC4"] },
      { icon: Globe, titleKey: "feat.intelTitle", descKey: "feat.intelDesc", capKeys: ["feat.intelC1", "feat.intelC2", "feat.intelC3", "feat.intelC4"] },
      { icon: Eye, titleKey: "feat.darkwebTitle", descKey: "feat.darkwebDesc", capKeys: ["feat.darkwebC1", "feat.darkwebC2", "feat.darkwebC3", "feat.darkwebC4"] },
      { icon: AlertTriangle, titleKey: "feat.simTitle", descKey: "feat.simDesc", capKeys: ["feat.simC1", "feat.simC2", "feat.simC3", "feat.simC4"] },
    ],
  },
  {
    categoryKey: "feat.catOffensiveSec",
    features: [
      { icon: Scan, titleKey: "feat.vulnScanTitle", descKey: "feat.vulnScanDesc", capKeys: ["feat.vulnScanC1", "feat.vulnScanC2", "feat.vulnScanC3", "feat.vulnScanC4"] },
      { icon: Crosshair, titleKey: "feat.mobilePentestTitle", descKey: "feat.mobilePentestDesc", capKeys: ["feat.mobilePentestC1", "feat.mobilePentestC2", "feat.mobilePentestC3", "feat.mobilePentestC4"] },
      { icon: Terminal, titleKey: "feat.payloadTitle", descKey: "feat.payloadDesc", capKeys: ["feat.payloadC1", "feat.payloadC2", "feat.payloadC3", "feat.payloadC4"] },
      { icon: Lock, titleKey: "feat.sslTitle", descKey: "feat.sslDesc", capKeys: ["feat.sslC1", "feat.sslC2", "feat.sslC3", "feat.sslC4"] },
      { icon: Key, titleKey: "feat.passwordTitle", descKey: "feat.passwordDesc", capKeys: ["feat.passwordC1", "feat.passwordC2", "feat.passwordC3", "feat.passwordC4"] },
      { icon: Mail, titleKey: "feat.emailTitle", descKey: "feat.emailDesc", capKeys: ["feat.emailC1", "feat.emailC2", "feat.emailC3", "feat.emailC4"] },
    ],
  },
  {
    categoryKey: "feat.catEndpointProt",
    features: [
      { icon: Monitor, titleKey: "feat.edrTitle", descKey: "feat.edrDesc", capKeys: ["feat.edrC1", "feat.edrC2", "feat.edrC3", "feat.edrC4"] },
      { icon: ShieldCheck, titleKey: "feat.autoProtTitle", descKey: "feat.autoProtDesc", capKeys: ["feat.autoProtC1", "feat.autoProtC2", "feat.autoProtC3", "feat.autoProtC4"] },
      { icon: Zap, titleKey: "feat.autoRespTitle", descKey: "feat.autoRespDesc", capKeys: ["feat.autoRespC1", "feat.autoRespC2", "feat.autoRespC3", "feat.autoRespC4"] },
      { icon: Siren, titleKey: "feat.incidentTitle", descKey: "feat.incidentDesc", capKeys: ["feat.incidentC1", "feat.incidentC2", "feat.incidentC3", "feat.incidentC4"] },
    ],
  },
  {
    categoryKey: "feat.catNetworkSec",
    features: [
      { icon: Wifi, titleKey: "feat.infraTitle", descKey: "feat.infraDesc", capKeys: ["feat.infraC1", "feat.infraC2", "feat.infraC3", "feat.infraC4"] },
      { icon: Network, titleKey: "feat.topoTitle", descKey: "feat.topoDesc", capKeys: ["feat.topoC1", "feat.topoC2", "feat.topoC3", "feat.topoC4"] },
    ],
  },
  {
    categoryKey: "feat.catComplianceRep",
    features: [
      { icon: BarChart3, titleKey: "feat.complianceTitle", descKey: "feat.complianceDesc", capKeys: ["feat.complianceC1", "feat.complianceC2", "feat.complianceC3", "feat.complianceC4"] },
      { icon: Search, titleKey: "feat.cveTitle", descKey: "feat.cveDesc", capKeys: ["feat.cveC1", "feat.cveC2", "feat.cveC3", "feat.cveC4"] },
      { icon: Bug, titleKey: "feat.trojanTitle", descKey: "feat.trojanDesc", capKeys: ["feat.trojanC1", "feat.trojanC2", "feat.trojanC3", "feat.trojanC4"] },
      { icon: FileSearch, titleKey: "feat.forensicTitle", descKey: "feat.forensicDesc", capKeys: ["feat.forensicC1", "feat.forensicC2", "feat.forensicC3", "feat.forensicC4"] },
    ],
  },
];

export default function FeaturesPage() {
  useDocumentTitle("Features");
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

      {featureCategories.map((category, catIndex) => (
        <section key={category.categoryKey}>
          <div className="py-12 px-6 border-t border-border/30">
            <div className="max-w-6xl mx-auto">
              <div className="mb-8">
                <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t(category.categoryKey)}</span>
                <div className="h-px w-12 bg-primary/30 mt-2" />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                {category.features.map((feature) => {
                  const Icon = feature.icon;
                  return (
                    <Card key={feature.titleKey} className="p-6" data-testid={`card-feature-${feature.titleKey.replace("feat.", "")}`}>
                      <div className="flex items-start gap-4">
                        <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                          <Icon className="w-5 h-5 text-primary" />
                        </div>
                        <div className="min-w-0 flex-1">
                          <h3 className="text-sm font-semibold tracking-wide uppercase mb-2">
                            {t(feature.titleKey)}
                          </h3>
                          <p className="text-xs text-muted-foreground leading-relaxed mb-3">
                            {t(feature.descKey)}
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {feature.capKeys.map((capKey) => (
                              <span
                                key={capKey}
                                className="text-[10px] font-mono tracking-wider px-2 py-0.5 rounded-md border border-border/50 bg-muted/30 text-muted-foreground"
                              >
                                {t(capKey)}
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
          </div>
          {catIndex === 0 && (
            <>
              <div className="py-12 px-6 border-t border-border/30">
                <div className="max-w-md mx-auto">
                  <div className="text-center mb-6">
                    <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("feat.radarLabel")}</span>
                    <h3 className="text-lg font-bold mt-2">{t("feat.radarTitle")}</h3>
                    <p className="text-xs text-muted-foreground mt-1">{t("feat.radarDesc")}</p>
                  </div>
                  <CyberRadar />
                </div>
              </div>
              <div className="py-12 px-6 border-t border-border/30">
                <div className="max-w-6xl mx-auto">
                  <div className="text-center mb-6">
                    <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("feat.statsLabel")}</span>
                    <h3 className="text-lg font-bold mt-2">{t("feat.statsTitle")}</h3>
                    <p className="text-xs text-muted-foreground mt-1">{t("feat.statsDesc")}</p>
                  </div>
                  <CyberStats />
                </div>
              </div>
            </>
          )}
          {catIndex === 1 && (
            <div className="py-12 px-6 border-t border-border/30">
              <div className="max-w-5xl mx-auto">
                <div className="text-center mb-6">
                  <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("feat.killChainLabel")}</span>
                  <h3 className="text-lg font-bold mt-2">{t("feat.killChainTitle")}</h3>
                  <p className="text-xs text-muted-foreground mt-1">{t("feat.killChainDesc")}</p>
                </div>
                <CyberAttackFlow />
              </div>
            </div>
          )}
        </section>
      ))}
    </PublicLayout>
  );
}
