import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Shield, Lightbulb, Award, Scale, Building2, MapPin } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const valueIcons = [Shield, Lightbulb, Award, Scale];
const valueKeys = ["Protection", "Innovation", "Excellence", "Integrity"];

export default function AboutPage() {
  useDocumentTitle("About");
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

      <section className="py-16 px-6 border-t border-border/30">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-10">
            <span className="text-[10px] font-mono tracking-[0.3em] uppercase text-primary">Corporate Information</span>
            <h2 className="text-2xl font-bold mt-3 mb-2">Company Details</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="p-6 flex items-start gap-4" data-testid="card-company-entity">
              <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                <Building2 className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h3 className="text-sm font-semibold tracking-wide uppercase mb-1">Business Entity</h3>
                <p className="text-base font-bold text-primary">FAHADERA LLC</p>
                <p className="text-xs text-muted-foreground mt-1">Registered Limited Liability Company</p>
                <p className="text-xs text-muted-foreground">State of Delaware, United States</p>
              </div>
            </Card>
            <Card className="p-6 flex items-start gap-4" data-testid="card-company-address">
              <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center shrink-0">
                <MapPin className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h3 className="text-sm font-semibold tracking-wide uppercase mb-1">Registered Address</h3>
                <p className="text-sm font-medium">8 The Green Suite B</p>
                <p className="text-sm text-muted-foreground">Dover, Delaware</p>
                <p className="text-sm text-muted-foreground">United States of America</p>
              </div>
            </Card>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
