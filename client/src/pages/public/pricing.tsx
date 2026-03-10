import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Check, X } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const plans = [
  {
    nameKey: "pricingStarter",
    priceKey: "pricingStarterPrice",
    descKey: "pricingStarterDesc",
    features: [
      { text: "5 endpoint agents", included: true },
      { text: "1,000 logs/day", included: true },
      { text: "50 commands/day", included: true },
      { text: "10 threat intel queries/day", included: true },
      { text: "File scanning", included: true },
      { text: "Agent downloads", included: true },
      { text: "Security event monitoring", included: true },
      { text: "Basic alert rules", included: true },
      { text: "Email notifications", included: true },
      { text: "7-day event retention", included: true },
      { text: "Vulnerability scanner", included: true },
      { text: "Hash tools & password analyzer", included: true },
      { text: "Community support", included: true },
      { text: "AI threat analysis", included: false },
      { text: "Automated defense playbooks", included: false },
      { text: "MITRE ATT&CK heatmap", included: false },
      { text: "Threat intelligence feeds", included: false },
      { text: "Dark web monitoring", included: false },
      { text: "Compliance dashboard", included: false },
      { text: "Threat simulation", included: false },
    ],
  },
  {
    nameKey: "pricingPro",
    priceKey: "pricingProPrice",
    descKey: "pricingProDesc",
    popular: true,
    features: [
      { text: "25 endpoint agents", included: true },
      { text: "10,000 logs/day", included: true },
      { text: "200 commands/day", included: true },
      { text: "100 threat intel queries/day", included: true },
      { text: "File scanning", included: true },
      { text: "Agent downloads", included: true },
      { text: "Threat intelligence APIs", included: true },
      { text: "Network isolation", included: true },
      { text: "Process management", included: true },
      { text: "Remote terminal access", included: true },
      { text: "Advanced alert rules", included: true },
      { text: "Email & webhook notifications", included: true },
      { text: "30-day event retention", included: true },
      { text: "Vulnerability scanner + OWASP mapping", included: true },
      { text: "Hash tools & password analyzer", included: true },
      { text: "AI threat analysis", included: true },
      { text: "Automated defense playbooks", included: true },
      { text: "MITRE ATT&CK heatmap", included: true },
      { text: "Threat intelligence feeds", included: true },
      { text: "SSL/TLS inspector", included: true },
      { text: "Email security analyzer", included: true },
      { text: "Mobile penetration testing", included: true },
      { text: "Priority support", included: true },
      { text: "Dark web monitoring", included: false },
      { text: "Compliance dashboard", included: false },
      { text: "Threat simulation", included: false },
      { text: "Trojan analyzer with IOC extraction", included: false },
    ],
  },
  {
    nameKey: "pricingEnterprise",
    priceKey: "pricingEnterprisePrice",
    descKey: "pricingEnterpriseDesc",
    features: [
      { text: "100 endpoint agents", included: true },
      { text: "100,000 logs/day", included: true },
      { text: "1,000 commands/day", included: true },
      { text: "500 threat intel queries/day", included: true },
      { text: "File scanning", included: true },
      { text: "Agent downloads", included: true },
      { text: "Threat intelligence APIs", included: true },
      { text: "Network isolation", included: true },
      { text: "Process management", included: true },
      { text: "Remote terminal access", included: true },
      { text: "Advanced analytics & AI", included: true },
      { text: "AegisAI360 Agent", included: true },
      { text: "Custom alert rules & workflows", included: true },
      { text: "All notification channels", included: true },
      { text: "1-year event retention", included: true },
      { text: "Full vulnerability scanner suite", included: true },
      { text: "Hash tools & password analyzer", included: true },
      { text: "Full AI threat analysis", included: true },
      { text: "Custom automated playbooks", included: true },
      { text: "MITRE ATT&CK heatmap", included: true },
      { text: "Premium threat intelligence", included: true },
      { text: "SSL/TLS inspector", included: true },
      { text: "Email security analyzer", included: true },
      { text: "Mobile penetration testing", included: true },
      { text: "Dark web monitoring", included: true },
      { text: "Compliance dashboard (NIST, ISO, PCI, HIPAA, SOC 2)", included: true },
      { text: "Threat simulation engine", included: true },
      { text: "Trojan analyzer with IOC extraction & MITRE heatmap", included: true },
      { text: "Payload generator", included: true },
      { text: "Honeypot deployment", included: true },
      { text: "Network traffic analysis", included: true },
      { text: "CVE database access", included: true },
      { text: "Dedicated support + SLA", included: true },
      { text: "On-premise deployment option", included: true },
    ],
  },
];

const featureComparison = [
  { feature: "Endpoint agents", starter: "5", pro: "25", enterprise: "100" },
  { feature: "Logs/day", starter: "1,000", pro: "10,000", enterprise: "100,000" },
  { feature: "Commands/day", starter: "50", pro: "200", enterprise: "1,000" },
  { feature: "Threat intel queries/day", starter: "10", pro: "100", enterprise: "500" },
  { feature: "Event retention", starter: "7 days", pro: "30 days", enterprise: "1 year" },
  { feature: "File scanning", starter: "Included", pro: "Included", enterprise: "Included" },
  { feature: "Agent downloads", starter: "Included", pro: "Included", enterprise: "Included" },
  { feature: "Vulnerability scanner", starter: "Basic", pro: "OWASP mapped", enterprise: "Full suite" },
  { feature: "Hash tools & password analyzer", starter: "Included", pro: "Included", enterprise: "Included" },
  { feature: "AI threat analysis", starter: "--", pro: "Included", enterprise: "Full" },
  { feature: "Automated defense playbooks", starter: "--", pro: "Included", enterprise: "Custom" },
  { feature: "MITRE ATT&CK heatmap", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "Threat intelligence feeds", starter: "--", pro: "Basic", enterprise: "Premium" },
  { feature: "Network isolation", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "Process management", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "Remote terminal access", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "SSL/TLS inspector", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "Email security analyzer", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "Mobile penetration testing", starter: "--", pro: "Included", enterprise: "Included" },
  { feature: "AegisAI360 Agent", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Advanced analytics & AI", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Dark web monitoring", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Compliance dashboard", starter: "--", pro: "--", enterprise: "5 frameworks" },
  { feature: "Threat simulation engine", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Trojan analyzer + IOC extraction", starter: "--", pro: "--", enterprise: "Full" },
  { feature: "Honeypot deployment", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Payload generator", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Network traffic analysis", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "CVE database access", starter: "--", pro: "--", enterprise: "Included" },
  { feature: "Support", starter: "Community", pro: "Priority", enterprise: "Dedicated + SLA" },
];

export default function PricingPage() {
  useDocumentTitle("Pricing");
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
                    <li key={f.text} className="flex items-start gap-2 text-xs">
                      {f.included ? (
                        <Check className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
                      ) : (
                        <X className="w-3.5 h-3.5 text-muted-foreground/40 mt-0.5 shrink-0" />
                      )}
                      <span className={f.included ? "text-muted-foreground" : "text-muted-foreground/40"}>
                        {f.text}
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
                  <th className="text-start py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Feature</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Starter</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-primary">Professional</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                {featureComparison.map((row, idx) => (
                  <tr key={row.feature} className={idx % 2 === 0 ? "bg-muted/20" : ""}>
                    <td className="py-2.5 px-4 font-medium">{row.feature}</td>
                    <td className={`py-2.5 px-4 text-center ${row.starter === "--" ? "text-muted-foreground/40" : "text-muted-foreground"}`}>{row.starter}</td>
                    <td className={`py-2.5 px-4 text-center ${row.pro === "--" ? "text-muted-foreground/40" : ""}`}>{row.pro}</td>
                    <td className={`py-2.5 px-4 text-center ${row.enterprise === "--" ? "text-muted-foreground/40" : ""}`}>{row.enterprise}</td>
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
