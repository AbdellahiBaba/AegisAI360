import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import { useToast } from "@/hooks/use-toast";
import {
  CreditCard, Zap, Shield, Crown, Check, ExternalLink,
  Loader2, AlertTriangle, Clock, Rocket, FlaskConical, ArrowRight,
} from "lucide-react";
import { useMemo, useEffect, useState } from "react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface BillingStatus {
  plan: string;
  maxUsers: number;
  stripeCustomerId: string | null;
  stripeSubscriptionId: string | null;
  subscriptionStatus: string;
  subscriptionExpiresAt: string | null;
  trialUsed: boolean;
  trialStartedAt: string | null;
  planId: number | null;
  planDetails: any;
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
    features: [
      "5 endpoint agents",
      "1,000 logs/day",
      "50 commands/day",
      "10 threat intel queries/day",
      "File scanning",
      "Agent downloads",
      "Security event monitoring",
      "Basic alert rules",
      "Email notifications",
      "7-day event retention",
      "Vulnerability scanner",
      "Hash tools & password analyzer",
      "Community support",
    ],
    icon: Shield,
  },
  professional: {
    features: [
      "25 endpoint agents",
      "10,000 logs/day",
      "200 commands/day",
      "100 threat intel queries/day",
      "File scanning",
      "Agent downloads",
      "Threat intelligence APIs",
      "Network isolation",
      "Process management",
      "Remote terminal access",
      "Advanced alert rules",
      "Email & webhook notifications",
      "30-day event retention",
      "Vulnerability scanner + OWASP mapping",
      "Hash tools & password analyzer",
      "AI threat analysis",
      "Automated defense playbooks",
      "MITRE ATT&CK heatmap",
      "Threat intelligence feeds",
      "SSL/TLS inspector",
      "Email security analyzer",
      "Mobile penetration testing",
      "Priority support",
    ],
    icon: Zap,
    popular: true,
  },
  enterprise: {
    features: [
      "100 endpoint agents",
      "100,000 logs/day",
      "1,000 commands/day",
      "500 threat intel queries/day",
      "File scanning",
      "Agent downloads",
      "Threat intelligence APIs",
      "Network isolation",
      "Process management",
      "Remote terminal access",
      "Advanced analytics & AI",
      "AegisAI360 Agent",
      "Custom alert rules & workflows",
      "All notification channels",
      "1-year event retention",
      "Full vulnerability scanner suite",
      "Hash tools & password analyzer",
      "Full AI threat analysis",
      "Custom automated playbooks",
      "MITRE ATT&CK heatmap",
      "Premium threat intelligence",
      "SSL/TLS inspector",
      "Email security analyzer",
      "Mobile penetration testing",
      "Dark web monitoring",
      "Compliance dashboard (NIST, ISO, PCI, HIPAA, SOC 2)",
      "Threat simulation engine",
      "Trojan analyzer with IOC extraction & MITRE heatmap",
      "Payload generator",
      "Honeypot deployment",
      "Network traffic analysis",
      "CVE database access",
      "Dedicated support + SLA",
      "On-premise deployment option",
    ],
    icon: Crown,
  },
};

function useCountdown(targetDate: string | null) {
  const [remaining, setRemaining] = useState<number>(0);
  useEffect(() => {
    if (!targetDate) return;
    const update = () => {
      const diff = new Date(targetDate).getTime() - Date.now();
      setRemaining(Math.max(0, diff));
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [targetDate]);
  const hours = Math.floor(remaining / 3600000);
  const mins = Math.floor((remaining % 3600000) / 60000);
  const secs = Math.floor((remaining % 60000) / 1000);
  const pct = targetDate
    ? Math.max(0, Math.min(100, (remaining / (24 * 3600000)) * 100))
    : 0;
  return { remaining, hours, mins, secs, pct, expired: remaining === 0 };
}

function TrialCountdownCard({ expiresAt, onUpgrade }: { expiresAt: string; onUpgrade: () => void }) {
  const { hours, mins, secs, pct, expired } = useCountdown(expiresAt);
  if (expired) {
    return (
      <div className="flex items-start gap-3 p-4 rounded-lg border border-red-500/50 bg-red-500/10" data-testid="banner-trial-expired">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="text-sm font-semibold text-red-400">Your free trial has ended</p>
          <p className="text-xs text-muted-foreground mt-0.5">All agents have been automatically disconnected. Subscribe to restore access.</p>
        </div>
        <Button size="sm" onClick={onUpgrade} data-testid="button-upgrade-after-trial">
          <ArrowRight className="w-4 h-4 me-1" /> Subscribe now
        </Button>
      </div>
    );
  }
  return (
    <div className="p-4 rounded-lg border border-amber-500/50 bg-amber-500/8 space-y-3" data-testid="card-trial-countdown">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <FlaskConical className="w-5 h-5 text-amber-400" />
          <span className="text-sm font-semibold text-amber-400">Free trial active</span>
          <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/30 text-[9px] uppercase">24h</Badge>
        </div>
        <Button size="sm" variant="outline" onClick={onUpgrade} data-testid="button-upgrade-from-trial">
          Upgrade before trial ends <ArrowRight className="w-3 h-3 ms-1" />
        </Button>
      </div>
      <div className="flex items-center gap-4">
        {[
          { label: "Hours", value: String(hours).padStart(2, "0") },
          { label: "Minutes", value: String(mins).padStart(2, "0") },
          { label: "Seconds", value: String(secs).padStart(2, "0") },
        ].map(({ label, value }) => (
          <div key={label} className="text-center">
            <div className="text-2xl font-mono font-bold tabular-nums text-amber-300" data-testid={`text-trial-${label.toLowerCase()}`}>
              {value}
            </div>
            <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div>
          </div>
        ))}
        <div className="flex-1">
          <div className="h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-amber-500 transition-all duration-1000"
              style={{ width: `${pct}%` }}
              data-testid="bar-trial-progress"
            />
          </div>
          <p className="text-[9px] text-muted-foreground mt-1">
            Trial ends {new Date(expiresAt).toLocaleString()}
          </p>
        </div>
      </div>
    </div>
  );
}

export default function Billing() {
  useDocumentTitle("Billing | AegisAI360");
  const { t } = useTranslation();
  const { user } = useAuth();
  const { toast } = useToast();
  const isAdmin = user?.role === "admin";

  const { data: billingStatus, isLoading } = useQuery<BillingStatus>({
    queryKey: ["/api/billing/status"],
  });

  const { data: stripeProducts } = useQuery<StripeProduct[]>({
    queryKey: ["/api/billing/products"],
  });

  const { data: billingConfig } = useQuery<{ publishableKey: string; liveMode: boolean }>({
    queryKey: ["/api/billing/config"],
  });

  const productsByTier = useMemo(() => {
    const map: Record<string, { priceId: string; amount: number; name: string }> = {};
    if (stripeProducts) {
      for (const p of stripeProducts) {
        const meta = typeof p.metadata === "string" ? JSON.parse(p.metadata) : p.metadata;
        const tier = meta?.plan || p.name?.toLowerCase();
        if (tier) map[tier] = { priceId: p.price_id, amount: p.unit_amount, name: p.name };
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

  const trialMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/start-trial", {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/billing/status"] });
      toast({ title: "Free trial started! You have 24 hours of full Professional access." });
    },
    onError: (err: any) => {
      toast({ title: "Could not start trial", description: err.message, variant: "destructive" });
    },
  });

  const scrollToPlans = () => {
    document.getElementById("plan-cards")?.scrollIntoView({ behavior: "smooth" });
  };

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
  const isTrialing = billingStatus?.subscriptionStatus === "trialing";
  const isActive = billingStatus?.subscriptionStatus === "active";
  const trialUsed = billingStatus?.trialUsed ?? false;
  const trialExpired = trialUsed && !isTrialing && !isActive && billingStatus?.subscriptionStatus !== "inactive";
  const showTrialOffer = !trialUsed && !isActive && !isTrialing && !isSuperAdmin;

  if (isSuperAdmin) {
    return (
      <div className="p-4 md:p-6 space-y-6">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">{t("billing.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("billing.subtitle")}</p>
        </div>
        {billingConfig && !billingConfig.liveMode && (
          <div className="flex items-center gap-3 p-4 rounded-lg border border-amber-500/50 bg-amber-500/10" data-testid="banner-sandbox-mode">
            <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-600 dark:text-amber-400">Stripe Test Mode Active</p>
              <p className="text-xs text-muted-foreground">Payments are in sandbox/test mode.</p>
            </div>
          </div>
        )}
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

      {billingConfig && !billingConfig.liveMode && (
        <div className="flex items-center gap-3 p-4 rounded-lg border border-amber-500/50 bg-amber-500/10" data-testid="banner-sandbox-mode">
          <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />
          <div>
            <p className="text-sm font-semibold text-amber-600 dark:text-amber-400">Stripe Test Mode Active</p>
            <p className="text-xs text-muted-foreground">Payments are in sandbox/test mode. Configure production Stripe keys to enable live payments.</p>
          </div>
        </div>
      )}

      {/* Trial countdown or expired banner */}
      {isTrialing && billingStatus?.subscriptionExpiresAt && (
        <TrialCountdownCard expiresAt={billingStatus.subscriptionExpiresAt} onUpgrade={scrollToPlans} />
      )}
      {trialExpired && (
        <TrialCountdownCard expiresAt={billingStatus?.subscriptionExpiresAt ?? new Date(0).toISOString()} onUpgrade={scrollToPlans} />
      )}

      {/* Free trial offer — only for orgs that haven't used it */}
      {showTrialOffer && (
        <Card className="border-2 border-amber-500/40 bg-gradient-to-br from-amber-500/5 to-transparent" data-testid="card-trial-offer">
          <CardContent className="p-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4">
              <div className="p-3 rounded-xl bg-amber-500/15">
                <Rocket className="w-7 h-7 text-amber-400" />
              </div>
              <div className="flex-1 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-bold text-base">Try AegisAI360 free for 24 hours</h3>
                  <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/30 text-[10px] uppercase">No credit card required</Badge>
                </div>
                <p className="text-sm text-muted-foreground">
                  Get full Professional plan access — all agents, threat intel, remote terminal, AI analysis, and more. One trial per organization.
                </p>
                <div className="flex flex-wrap gap-3 pt-1">
                  {["25 agents", "All features unlocked", "AI threat analysis", "Remote terminal"].map((f) => (
                    <span key={f} className="flex items-center gap-1 text-xs text-muted-foreground">
                      <Check className="w-3 h-3 text-amber-400" /> {f}
                    </span>
                  ))}
                </div>
              </div>
              <Button
                size="lg"
                className="bg-amber-500 hover:bg-amber-600 text-black font-bold shrink-0 gap-2"
                onClick={() => trialMutation.mutate()}
                disabled={trialMutation.isPending}
                data-testid="button-start-trial"
              >
                {trialMutation.isPending
                  ? <><Loader2 className="w-4 h-4 animate-spin" /> Starting...</>
                  : <><FlaskConical className="w-4 h-4" /> Start Free Trial</>
                }
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Current subscription status card */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <CreditCard className="w-5 h-5 text-primary" />
              </div>
              <div>
                <p className="text-sm font-bold">
                  {t("billing.currentPlanLabel")}:{" "}
                  <span className="text-primary capitalize" data-testid="text-current-plan">{currentPlan}</span>
                  {isTrialing && (
                    <Badge className="ms-2 bg-amber-500/20 text-amber-300 border-amber-500/30 text-[9px] uppercase">Trial</Badge>
                  )}
                </p>
                <p className="text-xs text-muted-foreground">
                  {billingStatus?.maxUsers === -1 ? t("billing.unlimited") : billingStatus?.maxUsers} {t("billing.users")}
                  {billingStatus?.stripeSubscriptionId
                    ? ` · ${t("billing.activeSubscription")}`
                    : isTrialing
                    ? ` · Trial active`
                    : ` · ${t("billing.noActiveSubscription")}`}
                  {billingStatus?.subscriptionExpiresAt && !isTrialing && (
                    <span className="ms-1">· Renews {new Date(billingStatus.subscriptionExpiresAt).toLocaleDateString()}</span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
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
          </div>
        </CardContent>
      </Card>

      {/* Plan cards */}
      <div id="plan-cards" className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {tiers.map((tier) => {
          const meta = planMeta[tier];
          if (!meta) return null;
          const isCurrent = currentPlan === tier && !isTrialing;
          const PlanIcon = meta.icon;
          const product = productsByTier[tier];
          const displayPrice = product
            ? `$${(product.amount / 100).toFixed(0)}`
            : tier === "starter" ? "$29" : tier === "professional" ? "$99" : "$299";

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
              {isTrialing && tier === "professional" && (
                <div className="absolute -top-3 right-4">
                  <Badge className="bg-amber-500 text-black text-[10px]">Currently trialing</Badge>
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
                    {checkoutMutation.isPending
                      ? <><Loader2 className="w-4 h-4 me-1 animate-spin" />{t("common.processing")}</>
                      : isCurrent
                      ? t("common.currentPlan")
                      : isTrialing
                      ? "Subscribe now"
                      : !product
                      ? t("common.loading")
                      : t("common.upgrade")}
                  </Button>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Trial already used notice */}
      {trialUsed && !isTrialing && !isActive && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-border/40 bg-muted/30 text-sm text-muted-foreground" data-testid="banner-trial-used">
          <Clock className="w-4 h-4 shrink-0" />
          Your organization has used its free trial. Subscribe to a plan above to continue.
        </div>
      )}
    </div>
  );
}
