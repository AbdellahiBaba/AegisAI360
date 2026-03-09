import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const sectionKeys = ["Collect", "Use", "Security", "Retention", "ThirdParty", "Rights", "Contact"];

export default function PrivacyPage() {
  useDocumentTitle("Privacy Policy");
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto">
          <h1 className="text-4xl font-bold tracking-tight mb-4 text-center" data-testid="text-privacy-heading">
            {t("public.privacyTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-6" />
          <p className="text-sm text-muted-foreground text-center mb-16">
            {t("public.privacyIntro")}
          </p>

          <div className="flex flex-col gap-10">
            {sectionKeys.map((key) => (
              <div key={key}>
                <h2 className="text-lg font-semibold mb-3">{t(`public.privacy${key}Title`)}</h2>
                <p className="text-sm text-muted-foreground leading-relaxed">{t(`public.privacy${key}Text`)}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
