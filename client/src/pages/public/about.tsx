import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Shield, Lightbulb, Award, Scale } from "lucide-react";

const valueIcons = [Shield, Lightbulb, Award, Scale];
const valueKeys = ["Protection", "Innovation", "Excellence", "Integrity"];

export default function AboutPage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-about-heading">
            {t("public.aboutTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <h2 className="text-xl font-semibold mb-4">{t("public.aboutMission")}</h2>
          <p className="text-base text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.aboutMissionText")}
          </p>
        </div>
      </section>

      <section className="py-16 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
            {valueKeys.map((key, idx) => {
              const Icon = valueIcons[idx];
              return (
                <Card key={key} className="p-6 text-center" data-testid={`card-value-${key.toLowerCase()}`}>
                  <div className="w-12 h-12 rounded-md bg-primary/10 flex items-center justify-center mx-auto mb-4">
                    <Icon className="w-6 h-6 text-primary" />
                  </div>
                  <h3 className="text-sm font-semibold tracking-wide uppercase mb-2">
                    {t(`public.aboutValue${key}`)}
                  </h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {t(`public.aboutValue${key}Desc`)}
                  </p>
                </Card>
              );
            })}
          </div>
        </div>
      </section>

      <section className="py-16 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-2xl font-bold tracking-wide mb-6">{t("public.aboutTeamTitle")}</h2>
          <div className="h-px w-16 bg-primary/40 mx-auto mb-8" />
          <p className="text-muted-foreground leading-relaxed">
            {t("public.aboutTeamDesc")}
          </p>
        </div>
      </section>
    </PublicLayout>
  );
}
