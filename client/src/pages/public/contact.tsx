import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Mail, Clock, MapPin, Globe } from "lucide-react";
import { SiGithub, SiLinkedin, SiX } from "react-icons/si";
import { useState } from "react";
import { useToast } from "@/hooks/use-toast";

export default function ContactPage() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setSubmitting(true);
    setTimeout(() => {
      setSubmitting(false);
      toast({
        title: t("public.contactSubmitted"),
        description: t("public.contactSubmittedDesc"),
      });
      (e.target as HTMLFormElement).reset();
    }, 1000);
  };

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-contact-heading">
            {t("public.contactTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <p className="text-base text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.contactSubtitle")}
          </p>
        </div>
      </section>

      <section className="pb-20 px-6">
        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-5 gap-8">
          <div className="lg:col-span-3">
            <Card className="p-6">
              <h2 className="text-lg font-semibold mb-6">{t("public.contactFormTitle")}</h2>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="contact-name">{t("public.contactName")}</Label>
                    <Input id="contact-name" required placeholder={t("public.contactNamePlaceholder")} data-testid="input-contact-name" />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="contact-email">{t("public.contactEmail")}</Label>
                    <Input id="contact-email" type="email" required placeholder={t("public.contactEmailPlaceholder")} data-testid="input-contact-email" />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contact-subject">{t("public.contactSubject")}</Label>
                  <Select required>
                    <SelectTrigger data-testid="select-contact-subject">
                      <SelectValue placeholder={t("public.contactSubjectPlaceholder")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="general">{t("public.contactSubjectGeneral")}</SelectItem>
                      <SelectItem value="sales">{t("public.contactSubjectSales")}</SelectItem>
                      <SelectItem value="support">{t("public.contactSubjectSupport")}</SelectItem>
                      <SelectItem value="partnership">{t("public.contactSubjectPartnership")}</SelectItem>
                      <SelectItem value="security">{t("public.contactSubjectSecurity")}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="contact-message">{t("public.contactMessage")}</Label>
                  <Textarea id="contact-message" required rows={6} placeholder={t("public.contactMessagePlaceholder")} data-testid="input-contact-message" />
                </div>
                <Button type="submit" disabled={submitting} data-testid="button-contact-submit">
                  {submitting ? t("common.processing") : t("public.contactSend")}
                </Button>
              </form>
            </Card>
          </div>

          <div className="lg:col-span-2 space-y-6">
            <Card className="p-6">
              <h3 className="text-sm font-semibold uppercase tracking-wide mb-4">{t("public.contactInfoTitle")}</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <Mail className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium">{t("public.contactEmailGeneral")}</p>
                    <p className="text-xs text-muted-foreground">info@aegisai360.com</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Mail className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium">{t("public.contactEmailSales")}</p>
                    <p className="text-xs text-muted-foreground">sales@aegisai360.com</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <Mail className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <div>
                    <p className="text-sm font-medium">{t("public.contactEmailSupport")}</p>
                    <p className="text-xs text-muted-foreground">support@aegisai360.com</p>
                  </div>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h3 className="text-sm font-semibold uppercase tracking-wide mb-4">{t("public.contactOffice")}</h3>
              <div className="space-y-4">
                <div className="flex items-start gap-3">
                  <MapPin className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <p className="text-sm text-muted-foreground">{t("public.contactLocation")}</p>
                </div>
                <div className="flex items-start gap-3">
                  <Clock className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <p className="text-sm text-muted-foreground">{t("public.contactHours")}</p>
                </div>
                <div className="flex items-start gap-3">
                  <Globe className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <p className="text-sm text-muted-foreground">{t("public.contactTimezone")}</p>
                </div>
              </div>
            </Card>

            <Card className="p-6">
              <h3 className="text-sm font-semibold uppercase tracking-wide mb-4">{t("public.contactSocial")}</h3>
              <div className="flex items-center gap-3">
                <Button variant="outline" size="icon" data-testid="link-social-github">
                  <SiGithub className="w-4 h-4" />
                </Button>
                <Button variant="outline" size="icon" data-testid="link-social-linkedin">
                  <SiLinkedin className="w-4 h-4" />
                </Button>
                <Button variant="outline" size="icon" data-testid="link-social-x">
                  <SiX className="w-4 h-4" />
                </Button>
              </div>
            </Card>
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
