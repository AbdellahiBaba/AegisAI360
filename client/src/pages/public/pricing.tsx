import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Check } from "lucide-react";

const plans = [
  {
    nameKey: "pricingStarter",
    priceKey: "pricingStarterPrice",
    descKey: "pricingStarterDesc",
    featureKeys: ["pricingStarterF1", "pricingStarterF2", "pricingStarterF3", "pricingStarterF4", "pricingStarterF5"],
  },
  {
    nameKey: "pricingPro",
    priceKey: "pricingProPrice",
    descKey: "pricingProDesc",
    featureKeys: ["pricingProF1", "pricingProF2", "pricingProF3", "pricingProF4", "pricingProF5", "pricingProF6"],
    popular: true,
  },
  {
    nameKey: "pricingEnterprise",
    priceKey: "pricingEnterprisePrice",
    descKey: "pricingEnterpriseDesc",
    featureKeys: ["pricingEnterpriseF1", "pricingEnterpriseF2", "pricingEnterpriseF3", "pricingEnterpriseF4", "pricingEnterpriseF5", "pricingEnterpriseF6", "pricingEnterpriseF7"],
  },
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
                <ul className="flex flex-col gap-2.5 mb-8 flex-1">
                  {plan.featureKeys.map((fk) => (
                    <li key={fk} className="flex items-start gap-2 text-xs">
                      <Check className="w-3.5 h-3.5 text-primary mt-0.5 shrink-0" />
                      <span className="text-muted-foreground">{t(`public.${fk}`)}</span>
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
    </PublicLayout>
  );
}
