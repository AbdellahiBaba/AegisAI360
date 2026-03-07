import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import { CreditCard, Zap, Shield, Crown, Check, ExternalLink, Loader2 } from "lucide-react";
import { useMemo } from "react";

interface BillingStatus {
  plan: string;
  maxUsers: number;
  stripeCustomerId: string | null;
  stripeSubscriptionId: string | null;
}

interface StripeProduct {
  id: string;
  name: string;
  description: string;
  metadata: any;
  price_id: string;
  unit_amount: number;
  currency: string;
  recurring: any;
}

const planMeta: Record<string, { features: string[]; icon: React.ElementType; popular?: boolean }> = {
  starter: {
    features: ["Up to 5 users", "Core SOC dashboard", "Basic alerting", "Security events monitoring", "Email support"],
    icon: Shield,
  },
  professional: {
    features: ["Up to 25 users", "AI-powered analysis", "ATT&CK heatmap", "Forensic timeline", "Honeypot monitoring", "Response playbooks", "Priority support"],
    icon: Zap,
    popular: true,
  },
  enterprise: {
    features: ["Unlimited users", "Priority AI processing", "Advanced honeypot", "Custom playbooks", "Audit compliance", "Quarantine management", "Dedicated support", "SLA guarantee"],
    icon: Crown,
  },
};

export default function Billing() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const { data: billingStatus, isLoading } = useQuery<BillingStatus>({
    queryKey: ["/api/billing/status"],
  });

  const { data: stripeProducts } = useQuery<StripeProduct[]>({
    queryKey: ["/api/billing/products"],
  });

  const productsByTier = useMemo(() => {
    const map: Record<string, { priceId: string; amount: number; name: string }> = {};
    if (stripeProducts) {
      for (const p of stripeProducts) {
        const meta = typeof p.metadata === 'string' ? JSON.parse(p.metadata) : p.metadata;
        const tier = meta?.plan || p.name?.toLowerCase();
        if (tier) {
          map[tier] = { priceId: p.price_id, amount: p.unit_amount, name: p.name };
        }
      }
    }
    return map;
  }, [stripeProducts]);

  const checkoutMutation = useMutation({
    mutationFn: async (priceId: string) => {
      const res = await apiRequest("POST", "/api/billing/create-checkout", { priceId });
      return res.json();
    },
    onSuccess: (data: { url: string }) => {
      if (data.url) window.location.href = data.url;
    },
  });

  const portalMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/portal");
      return res.json();
    },
    onSuccess: (data: { url: string }) => {
      if (data.url) window.location.href = data.url;
    },
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => <Card key={i}><CardContent className="p-6"><Skeleton className="h-[300px] w-full" /></CardContent></Card>)}
        </div>
      </div>
    );
  }

  const isSuperAdmin = user?.isSuperAdmin === true;
  const currentPlan = isSuperAdmin ? "enterprise" : (billingStatus?.plan || "starter");
  const tiers = ["starter", "professional", "enterprise"];

  if (isSuperAdmin) {
    return (
      <div className="p-4 md:p-6 space-y-6">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">{t("billing.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("billing.subtitle")}</p>
        </div>
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-lg bg-severity-critical/10">
                <Crown className="w-8 h-8 text-severity-critical" />
              </div>
              <div>
                <h2 className="text-lg font-bold tracking-wider uppercase" data-testid="text-admin-plan">Platform Administrator</h2>
                <p className="text-sm text-muted-foreground">Full unrestricted access to all platform features. No billing plan required.</p>
                <div className="flex flex-wrap gap-2 mt-3">
                  <Badge className="bg-severity-critical text-white border-0 text-[10px]">SUPER ADMIN</Badge>
                  <Badge variant="secondary" className="text-[10px]">Unlimited Users</Badge>
                  <Badge variant="secondary" className="text-[10px]">All Features</Badge>
                  <Badge variant="secondary" className="text-[10px]">No Restrictions</Badge>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {tiers.map((tier) => {
            const meta = planMeta[tier];
            const TierIcon = meta?.icon || Shield;
            return (
              <Card key={tier} className="relative overflow-hidden">
                <CardHeader className="pb-2">
                  <div className="flex items-center gap-2">
                    <TierIcon className="w-5 h-5 text-primary" />
                    <CardTitle className="text-sm uppercase tracking-wider">{tier}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <ul className="space-y-1.5">
                    {meta?.features.map((f, i) => (
                      <li key={i} className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Check className="w-3 h-3 text-primary flex-shrink-0" />
                        {f}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-6">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase">{t("billing.title")}</h1>
        <p className="text-xs text-muted-foreground">{t("billing.subtitle")}</p>
      </div>

      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <CreditCard className="w-5 h-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-bold">{t("billing.currentPlanLabel")}: <span className="text-primary capitalize" data-testid="text-current-plan">{currentPlan}</span></p>
                <p className="text-xs text-muted-foreground">
                  {billingStatus?.maxUsers === -1 ? t("billing.unlimited") : billingStatus?.maxUsers} {t("billing.users")}
                  {billingStatus?.stripeSubscriptionId ? ` · ${t("billing.activeSubscription")}` : ` · ${t("billing.noActiveSubscription")}`}
                </p>
              </div>
            </div>
            {isAdmin && billingStatus?.stripeCustomerId && (
              <Button
                variant="secondary"
                size="sm"
                onClick={() => portalMutation.mutate()}
                disabled={portalMutation.isPending}
                data-testid="button-manage-billing"
              >
                {portalMutation.isPending ? <Loader2 className="w-4 h-4 me-1 animate-spin" /> : <ExternalLink className="w-4 h-4 me-1" />}
                {t("billing.manageBilling")}
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {tiers.map((tier) => {
          const meta = planMeta[tier];
          if (!meta) return null;
          const isCurrent = currentPlan === tier;
          const PlanIcon = meta.icon;
          const product = productsByTier[tier];
          const displayPrice = product ? `$${(product.amount / 100).toFixed(0)}` : tier === "starter" ? "$9" : tier === "professional" ? "$29" : "$79";

          return (
            <Card
              key={tier}
              className={`relative ${meta.popular ? "border-primary ring-1 ring-primary/20" : ""} ${isCurrent ? "border-status-online" : ""}`}
              data-testid={`plan-card-${tier}`}
            >
              {meta.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <Badge className="bg-primary text-primary-foreground text-[10px]">{t("billing.mostPopular")}</Badge>
                </div>
              )}
              <CardHeader className="pb-2 pt-6">
                <div className="flex items-center gap-2">
                  <PlanIcon className="w-5 h-5 text-primary" />
                  <CardTitle className="text-base font-bold capitalize">{tier}</CardTitle>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  {tier === "starter" ? t("billing.starterDesc") :
                   tier === "professional" ? t("billing.professionalDesc") :
                   t("billing.enterpriseDesc")}
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-baseline gap-1">
                  <span className="text-3xl font-bold font-mono">{displayPrice}</span>
                  <span className="text-sm text-muted-foreground">{t("billing.perMonth")}</span>
                </div>
                <div className="space-y-2">
                  {meta.features.map((f) => (
                    <div key={f} className="flex items-center gap-2">
                      <Check className="w-3.5 h-3.5 text-status-online flex-shrink-0" />
                      <span className="text-xs">{f}</span>
                    </div>
                  ))}
                </div>
                {isAdmin && (
                  <Button
                    className="w-full"
                    variant={isCurrent ? "secondary" : meta.popular ? "default" : "secondary"}
                    disabled={isCurrent || checkoutMutation.isPending || (!product && !isCurrent)}
                    onClick={() => {
                      if (product?.priceId && !isCurrent) {
                        checkoutMutation.mutate(product.priceId);
                      }
                    }}
                    data-testid={`button-select-${tier}`}
                  >
                    {isCurrent ? t("common.currentPlan") :
                     checkoutMutation.isPending ? <><Loader2 className="w-4 h-4 me-1 animate-spin" />{t("common.processing")}</> :
                     !product ? t("common.loading") : t("common.upgrade")}
                  </Button>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
