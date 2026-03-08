import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Check, X } from "lucide-react";

const plans = [
  {
    nameKey: "pricingStarter",
    priceKey: "pricingStarterPrice",
    descKey: "pricingStarterDesc",
    features: [
      { textKey: "pricing.s5users", included: true },
      { textKey: "pricing.sEventMon", included: true },
      { textKey: "pricing.sBasicAlerts", included: true },
      { textKey: "pricing.sEmailNotif", included: true },
      { textKey: "pricing.s7dayRet", included: true },
      { textKey: "pricing.sVulnScan", included: true },
      { textKey: "pricing.sHashTools", included: true },
      { textKey: "pricing.sCommunity", included: true },
      { textKey: "pricing.sAiThreat", included: false },
      { textKey: "pricing.sAutoDefense", included: false },
      { textKey: "pricing.sMitre", included: false },
      { textKey: "pricing.sThreatIntel", included: false },
      { textKey: "pricing.sEndpointAgent", included: false },
      { textKey: "pricing.sDarkWeb", included: false },
      { textKey: "pricing.sCompDash", included: false },
      { textKey: "pricing.sThreatSim", included: false },
    ],
  },
  {
    nameKey: "pricingPro",
    priceKey: "pricingProPrice",
    descKey: "pricingProDesc",
    popular: true,
    features: [
      { textKey: "pricing.p25users", included: true },
      { textKey: "pricing.sEventMon", included: true },
      { textKey: "pricing.pAdvAlerts", included: true },
      { textKey: "pricing.pEmailWebhook", included: true },
      { textKey: "pricing.p30dayRet", included: true },
      { textKey: "pricing.pVulnOwasp", included: true },
      { textKey: "pricing.sHashTools", included: true },
      { textKey: "pricing.pPriority", included: true },
      { textKey: "pricing.sAiThreat", included: true },
      { textKey: "pricing.sAutoDefense", included: true },
      { textKey: "pricing.sMitre", included: true },
      { textKey: "pricing.sThreatIntel", included: true },
      { textKey: "pricing.pEndpoint10", included: true },
      { textKey: "pricing.pSslInsp", included: true },
      { textKey: "pricing.pEmailAnalyzer", included: true },
      { textKey: "pricing.pMobilePentest", included: true },
      { textKey: "pricing.sDarkWeb", included: false },
      { textKey: "pricing.sCompDash", included: false },
      { textKey: "pricing.sThreatSim", included: false },
      { textKey: "pricing.pTrojanIoc", included: false },
    ],
  },
  {
    nameKey: "pricingEnterprise",
    priceKey: "pricingEnterprisePrice",
    descKey: "pricingEnterpriseDesc",
    features: [
      { textKey: "pricing.eUnlimitedUsers", included: true },
      { textKey: "pricing.sEventMon", included: true },
      { textKey: "pricing.eCustomAlerts", included: true },
      { textKey: "pricing.eAllNotif", included: true },
      { textKey: "pricing.e1yrRet", included: true },
      { textKey: "pricing.eFullVuln", included: true },
      { textKey: "pricing.sHashTools", included: true },
      { textKey: "pricing.eDedicated", included: true },
      { textKey: "pricing.eFullAi", included: true },
      { textKey: "pricing.eCustomPlaybooks", included: true },
      { textKey: "pricing.sMitre", included: true },
      { textKey: "pricing.ePremiumIntel", included: true },
      { textKey: "pricing.eUnlimitedAgents", included: true },
      { textKey: "pricing.pSslInsp", included: true },
      { textKey: "pricing.pEmailAnalyzer", included: true },
      { textKey: "pricing.pMobilePentest", included: true },
      { textKey: "pricing.sDarkWeb", included: true },
      { textKey: "pricing.eCompDash5", included: true },
      { textKey: "pricing.eThreatSimEngine", included: true },
      { textKey: "pricing.eTrojanFull", included: true },
      { textKey: "pricing.ePayloadGen", included: true },
      { textKey: "pricing.eHoneypot", included: true },
      { textKey: "pricing.eNetTraffic", included: true },
      { textKey: "pricing.eCveAccess", included: true },
      { textKey: "pricing.eOnPrem", included: true },
    ],
  },
];

const featureComparison = [
  { featureKey: "pricing.compUsers", starterKey: "pricing.val5", proKey: "pricing.val25", enterpriseKey: "pricing.valUnlimited" },
  { featureKey: "pricing.compRetention", starterKey: "pricing.val7days", proKey: "pricing.val30days", enterpriseKey: "pricing.val1year" },
  { featureKey: "pricing.compAgents", starterKey: "pricing.valNa", proKey: "pricing.val10", enterpriseKey: "pricing.valUnlimited" },
  { featureKey: "pricing.compAi", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valFull" },
  { featureKey: "pricing.compAutoDefense", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valCustom" },
  { featureKey: "pricing.compMitre", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compIntel", starterKey: "pricing.valNa", proKey: "pricing.valBasic", enterpriseKey: "pricing.valPremium" },
  { featureKey: "pricing.compVuln", starterKey: "pricing.valBasic", proKey: "pricing.valOwaspMapped", enterpriseKey: "pricing.valFullSuite" },
  { featureKey: "pricing.compSsl", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compEmail", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compMobile", starterKey: "pricing.valNa", proKey: "pricing.valIncluded", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compDarkWeb", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compCompliance", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.val5Frameworks" },
  { featureKey: "pricing.compThreatSim", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compTrojan", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.valFull" },
  { featureKey: "pricing.compHoneypot", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compPayload", starterKey: "pricing.valNa", proKey: "pricing.valNa", enterpriseKey: "pricing.valIncluded" },
  { featureKey: "pricing.compSupport", starterKey: "pricing.valCommunity", proKey: "pricing.valPriority", enterpriseKey: "pricing.valDedicatedSla" },
];

export default function PricingPage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-pricing-heading">
            {t("public.pricingTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <p className="text-lg text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.pricingSubtitle")}
          </p>
        </div>
      </section>

      <section className="py-16 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {plans.map((plan) => (
              <Card
                key={plan.nameKey}
                className={`p-6 flex flex-col ${plan.popular ? "border-primary/50 ring-1 ring-primary/20" : ""}`}
                data-testid={`card-plan-${plan.nameKey}`}
              >
                {plan.popular && (
                  <span className="text-[10px] font-semibold tracking-widest uppercase text-primary mb-4">
                    {t("public.pricingMostPopular")}
                  </span>
                )}
                <h3 className="text-lg font-bold tracking-wide">{t(`public.${plan.nameKey}`)}</h3>
                <div className="flex items-baseline gap-1 mt-3 mb-2">
                  <span className="text-3xl font-bold text-primary">{t(`public.${plan.priceKey}`)}</span>
                  <span className="text-sm text-muted-foreground">{t("public.pricingPerMonth")}</span>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed mb-6">{t(`public.${plan.descKey}`)}</p>
                <ul className="flex flex-col gap-2 mb-8 flex-1">
                  {plan.features.map((f) => (
                    <li key={f.textKey} className="flex items-start gap-2 text-xs">
                      {f.included ? (
                        <Check className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
                      ) : (
                        <X className="w-3.5 h-3.5 text-muted-foreground/40 mt-0.5 shrink-0" />
                      )}
                      <span className={f.included ? "text-muted-foreground" : "text-muted-foreground/40"}>
                        {t(f.textKey)}
                      </span>
                    </li>
                  ))}
                </ul>
                <Link href="/auth">
                  <Button
                    className="w-full"
                    variant={plan.popular ? "default" : "outline"}
                    data-testid={`button-get-started-${plan.nameKey}`}
                  >
                    {t("public.pricingCta")}
                  </Button>
                </Link>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-10">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">{t("pricing.detailedBreakdown")}</span>
            <h2 className="text-2xl font-bold mt-3 mb-2">{t("pricing.featureComparison")}</h2>
            <p className="text-sm text-muted-foreground">{t("pricing.comparisonDesc")}</p>
          </div>
          <Card className="overflow-x-auto">
            <table className="w-full min-w-[600px] text-xs" data-testid="table-feature-comparison">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-start py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">{t("pricing.colFeature")}</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">{t("pricing.colStarter")}</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-primary">{t("pricing.colProfessional")}</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">{t("pricing.colEnterprise")}</th>
                </tr>
              </thead>
              <tbody>
                {featureComparison.map((row, idx) => (
                  <tr key={row.featureKey} className={idx % 2 === 0 ? "bg-muted/20" : ""}>
                    <td className="py-2.5 px-4 font-medium">{t(row.featureKey)}</td>
                    <td className="py-2.5 px-4 text-center text-muted-foreground">{t(row.starterKey)}</td>
                    <td className="py-2.5 px-4 text-center">{t(row.proKey)}</td>
                    <td className="py-2.5 px-4 text-center">{t(row.enterpriseKey)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      </section>
    </PublicLayout>
  );
}
