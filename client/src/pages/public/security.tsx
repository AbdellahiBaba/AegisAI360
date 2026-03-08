import { useTranslation } from "react-i18next";
import { PublicLayout } from "@/components/public-layout";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Lock, Server, Bug, CheckCircle } from "lucide-react";

const certifications = [
  { key: "nist", label: "NIST CSF" },
  { key: "iso27001", label: "ISO 27001" },
  { key: "soc2", label: "SOC 2 Type II" },
  { key: "gdpr", label: "GDPR" },
  { key: "pciDss", label: "PCI-DSS" },
  { key: "hipaa", label: "HIPAA" },
];

export default function SecurityPage() {
  const { t } = useTranslation();

  return (
    <PublicLayout>
      <section className="py-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-6" data-testid="text-security-heading">
            {t("public.securityTitle")}
          </h1>
          <div className="h-px w-24 bg-primary/40 mx-auto mb-8" />
          <p className="text-base text-muted-foreground leading-relaxed max-w-3xl mx-auto">
            {t("public.securitySubtitle")}
          </p>
        </div>
      </section>

      <section className="pb-16 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="p-6" data-testid="card-security-overview">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">{t("public.securityOverviewTitle")}</h2>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed">
                {t("public.securityOverviewText")}
              </p>
            </Card>

            <Card className="p-6" data-testid="card-security-encryption">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Lock className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">{t("public.securityEncryptionTitle")}</h2>
              </div>
              <ul className="space-y-3">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityEncryptionTransit")}</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityEncryptionRest")}</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityEncryptionKeys")}</span>
                </li>
              </ul>
            </Card>

            <Card className="p-6" data-testid="card-security-infrastructure">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Server className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">{t("public.securityInfraTitle")}</h2>
              </div>
              <ul className="space-y-3">
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityInfraRedundancy")}</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityInfraMonitoring")}</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityInfraBackups")}</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle className="w-4 h-4 text-primary mt-0.5 shrink-0" />
                  <span className="text-sm text-muted-foreground">{t("public.securityInfraDDoS")}</span>
                </li>
              </ul>
            </Card>

            <Card className="p-6" data-testid="card-security-disclosure">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-md bg-primary/10 flex items-center justify-center">
                  <Bug className="w-5 h-5 text-primary" />
                </div>
                <h2 className="text-lg font-semibold">{t("public.securityDisclosureTitle")}</h2>
              </div>
              <p className="text-sm text-muted-foreground leading-relaxed mb-3">
                {t("public.securityDisclosureText")}
              </p>
              <p className="text-sm text-muted-foreground">
                {t("public.securityDisclosureEmail")}
              </p>
            </Card>
          </div>
        </div>
      </section>

      <section className="pb-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-2xl font-bold tracking-wide mb-6">{t("public.securityCertTitle")}</h2>
          <div className="h-px w-16 bg-primary/40 mx-auto mb-8" />
          <p className="text-sm text-muted-foreground mb-8 max-w-2xl mx-auto">
            {t("public.securityCertSubtitle")}
          </p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            {certifications.map((cert) => (
              <Badge key={cert.key} variant="outline" className="text-sm py-1.5 px-4" data-testid={`badge-cert-${cert.key}`}>
                <Shield className="w-3.5 h-3.5 mr-1.5" />
                {cert.label}
              </Badge>
            ))}
          </div>
        </div>
      </section>
    </PublicLayout>
  );
}
