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
      { text: "Up to 5 users", included: true },
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
      { text: "Endpoint agent deployment", included: false },
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
      { text: "Up to 25 users", included: true },
      { text: "Security event monitoring", included: true },
      { text: "Advanced alert rules", included: true },
      { text: "Email & webhook notifications", included: true },
      { text: "30-day event retention", included: true },
      { text: "Vulnerability scanner + OWASP mapping", included: true },
      { text: "Hash tools & password analyzer", included: true },
      { text: "Priority support", included: true },
      { text: "AI threat analysis", included: true },
      { text: "Automated defense playbooks", included: true },
      { text: "MITRE ATT&CK heatmap", included: true },
      { text: "Threat intelligence feeds", included: true },
      { text: "Endpoint agent deployment (10 agents)", included: true },
      { text: "SSL/TLS inspector", included: true },
      { text: "Email security analyzer", included: true },
      { text: "Mobile penetration testing", included: true },
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
      { text: "Unlimited users", included: true },
      { text: "Security event monitoring", included: true },
      { text: "Custom alert rules & workflows", included: true },
      { text: "All notification channels", included: true },
      { text: "1-year event retention", included: true },
      { text: "Full vulnerability scanner suite", included: true },
      { text: "Hash tools & password analyzer", included: true },
      { text: "Dedicated support + SLA", included: true },
      { text: "Full AI threat analysis", included: true },
      { text: "Custom automated playbooks", included: true },
      { text: "MITRE ATT&CK heatmap", included: true },
      { text: "Premium threat intelligence", included: true },
      { text: "Unlimited endpoint agents", included: true },
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
      { text: "On-premise deployment option", included: true },
    ],
  },
];

const featureComparison = [
  { feature: "Users", starter: "5", pro: "25", enterprise: "Unlimited" },
  { feature: "Event Retention", starter: "7 days", pro: "30 days", enterprise: "1 year" },
  { feature: "Endpoint Agents", starter: "---", pro: "10", enterprise: "Unlimited" },
  { feature: "AI Analysis", starter: "---", pro: "Included", enterprise: "Full" },
  { feature: "Automated Defense", starter: "---", pro: "Included", enterprise: "Custom" },
  { feature: "MITRE ATT&CK", starter: "---", pro: "Included", enterprise: "Included" },
  { feature: "Threat Intel Feeds", starter: "---", pro: "Basic", enterprise: "Premium" },
  { feature: "Vulnerability Scanner", starter: "Basic", pro: "OWASP Mapped", enterprise: "Full Suite" },
  { feature: "SSL Inspector", starter: "---", pro: "Included", enterprise: "Included" },
  { feature: "Email Analyzer", starter: "---", pro: "Included", enterprise: "Included" },
  { feature: "Mobile Pentest", starter: "---", pro: "Included", enterprise: "Included" },
  { feature: "Dark Web Monitor", starter: "---", pro: "---", enterprise: "Included" },
  { feature: "Compliance Dashboard", starter: "---", pro: "---", enterprise: "5 Frameworks" },
  { feature: "Threat Simulation", starter: "---", pro: "---", enterprise: "Included" },
  { feature: "Trojan Analyzer", starter: "---", pro: "---", enterprise: "Full" },
  { feature: "Honeypot System", starter: "---", pro: "---", enterprise: "Included" },
  { feature: "Payload Generator", starter: "---", pro: "---", enterprise: "Included" },
  { feature: "Support", starter: "Community", pro: "Priority", enterprise: "Dedicated + SLA" },
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
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">Detailed Breakdown</span>
            <h2 className="text-2xl font-bold mt-3 mb-2">Feature Comparison</h2>
            <p className="text-sm text-muted-foreground">See exactly what's included in each plan</p>
          </div>
          <Card className="overflow-auto">
            <table className="w-full text-xs" data-testid="table-feature-comparison">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Feature</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Starter</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-primary">Professional</th>
                  <th className="text-center py-3 px-4 font-semibold tracking-wider uppercase text-muted-foreground">Enterprise</th>
                </tr>
              </thead>
              <tbody>
                {featureComparison.map((row, idx) => (
                  <tr key={row.feature} className={idx % 2 === 0 ? "bg-muted/20" : ""}>
                    <td className="py-2.5 px-4 font-medium">{row.feature}</td>
                    <td className="py-2.5 px-4 text-center text-muted-foreground">{row.starter}</td>
                    <td className="py-2.5 px-4 text-center">{row.pro}</td>
                    <td className="py-2.5 px-4 text-center">{row.enterprise}</td>
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
