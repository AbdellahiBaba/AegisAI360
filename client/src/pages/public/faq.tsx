import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";

const faqKeys = [
  "whatIs",
  "howWorks",
  "whoFor",
  "freeTrial",
  "pricingPlans",
  "cancelAnytime",
  "installAgent",
  "agentRequirements",
  "dataSecurity",
  "dataLocation",
  "gdprCompliant",
  "apiIntegrations",
  "complianceFrameworks",
  "supportChannels",
  "uptime",
  "customPlaybooks",
  "threatIntelFeeds",
  "onPremise",
];

export default function FaqPage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-faq-heading">
            {t("public.faqTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <p className="text-base text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.faqSubtitle")}
          </p>
        </div>
      </section>

      <section className="pb-20 px-6">
        <div className="max-w-3xl mx-auto">
          <Accordion type="multiple" className="space-y-2">
            {faqKeys.map((key, idx) => (
              <AccordionItem key={key} value={key} data-testid={`faq-item-${key}`}>
                <AccordionTrigger className="text-sm font-medium text-left">
                  {t(`public.faq_${key}_q`)}
                </AccordionTrigger>
                <AccordionContent className="text-sm text-muted-foreground leading-relaxed">
                  {t(`public.faq_${key}_a`)}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      </section>
    </PublicLayout>
  );
}
