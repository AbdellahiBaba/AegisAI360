import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Brain, Activity, ShieldCheck, Target, Siren, Globe } from "lucide-react";

const featureKeys = [
  { icon: Brain, key: "Ai" },
  { icon: Activity, key: "Monitor" },
  { icon: ShieldCheck, key: "Defense" },
  { icon: Target, key: "Mitre" },
  { icon: Siren, key: "Incident" },
  { icon: Globe, key: "Intel" },
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

      <section className="py-16 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {featureKeys.map(({ icon: Icon, key }) => (
              <Card key={key} className="p-6" data-testid={`card-feature-${key.toLowerCase()}`}>
                <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mb-4">
                  <Icon className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-sm font-semibold tracking-wide uppercase mb-3">
                  {t(`landing.feature${key}Title`)}
                </h3>
                <p className="text-xs text-muted-foreground leading-relaxed">
                  {t(`landing.feature${key}Desc`)}
                </p>
              </Card>
            ))}
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
