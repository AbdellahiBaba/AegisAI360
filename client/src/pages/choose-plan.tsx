import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useLocation } from "wouter";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Loader2, Check, Shield, Zap, Crown, LogOut, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function ChoosePlan() {
  useDocumentTitle("Choose Plan");
  const { t } = useTranslation();
  const { user, logoutMutation } = useAuth();
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const { data: plans, isLoading, isError, refetch } = useQuery<any[]>({
    queryKey: ["/api/plans"],
    retry: 3,
    retryDelay: 1000,
  });

  const { data: billingConfig } = useQuery<{ publishableKey: string; liveMode: boolean }>({
    queryKey: ["/api/billing/config"],
  });

  const checkoutMutation = useMutation({
    mutationFn: async ({ planName, priceId }: { planName: string; priceId?: string }) => {
      const res = await apiRequest("POST", "/api/billing/create-checkout", { planName, priceId });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Checkout failed");
      return data;
    },
    onSuccess: (data) => {
      if (data.url) window.location.href = data.url;
      else toast({ title: "Error", description: "No checkout URL received. Please try again.", variant: "destructive" });
    },
    onError: (error: any) => {
      toast({ title: "Checkout Error", description: error?.message || "Failed to start checkout. Please try again.", variant: "destructive" });
    },
  });

  const planIcons: Record<string, any> = { starter: Shield, professional: Zap, enterprise: Crown };
  const planColors: Record<string, string> = { starter: "border-blue-500/30", professional: "border-purple-500/30 ring-2 ring-purple-500/20", enterprise: "border-amber-500/30" };

  const getFeatureList = (plan: any) => {
    const features: string[] = [];
    features.push(`${plan.maxAgents} endpoint agents`);
    features.push(`${plan.maxLogsPerDay.toLocaleString()} logs/day`);
    features.push(`${plan.maxCommandsPerDay} commands/day`);
    features.push(`${plan.maxThreatIntelQueries} threat intel queries/day`);
    if (plan.allowFileScan) features.push("File scanning");
    if (plan.allowEndpointDownload) features.push("Agent downloads");
    if (plan.allowThreatIntel) features.push("Threat intelligence APIs");
    if (plan.allowNetworkIsolation) features.push("Network isolation");
    if (plan.allowProcessKill) features.push("Process management");
    if (plan.allowTerminalAccess) features.push("Remote terminal access");
    if (plan.allowAdvancedAnalytics) features.push("Advanced analytics & AI");
    if (plan.allowAegisAgent) features.push("AegisAI360 Agent");

    if (plan.name === "starter") {
      features.push("Security event monitoring", "Basic alert rules", "Email notifications", "7-day event retention", "Vulnerability scanner", "Hash tools & password analyzer", "Community support");
    } else if (plan.name === "professional") {
      features.push("Advanced alert rules", "Email & webhook notifications", "30-day event retention", "Vulnerability scanner + OWASP mapping", "Hash tools & password analyzer", "AI threat analysis", "Automated defense playbooks", "MITRE ATT&CK heatmap", "Threat intelligence feeds", "SSL/TLS inspector", "Email security analyzer", "Mobile penetration testing", "Priority support");
    } else if (plan.name === "enterprise") {
      features.push("Custom alert rules & workflows", "All notification channels", "1-year event retention", "Full vulnerability scanner suite", "Hash tools & password analyzer", "Full AI threat analysis", "Custom automated playbooks", "MITRE ATT&CK heatmap", "Premium threat intelligence", "SSL/TLS inspector", "Email security analyzer", "Mobile penetration testing", "Dark web monitoring", "Compliance dashboard (NIST, ISO, PCI, HIPAA, SOC 2)", "Threat simulation engine", "Trojan analyzer with IOC extraction & MITRE heatmap", "Payload generator", "Honeypot deployment", "Network traffic analysis", "CVE database access", "Dedicated support + SLA", "On-premise deployment option");
    }
    return features;
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-background" data-testid="loading-plans">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (isError || (!isLoading && (!plans || plans.length === 0))) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen bg-background gap-4" data-testid="error-plans">
        <p className="text-muted-foreground">Failed to load plans. Please try again.</p>
        <Button onClick={() => refetch()} data-testid="button-retry-plans">Retry</Button>
        <Button variant="ghost" onClick={() => logoutMutation.mutate()} data-testid="button-logout-error">
          <LogOut className="w-4 h-4 me-2" />
          Logout
        </Button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto">
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold" data-testid="text-choose-plan-title">Choose Your Plan</h1>
            <p className="text-muted-foreground mt-2">Select a plan to access the AegisAI360 SOC platform</p>
          </div>
          <Button variant="ghost" onClick={() => logoutMutation.mutate()} data-testid="button-logout-plan">
            <LogOut className="w-4 h-4 me-2" />
            Logout
          </Button>
        </div>

        {billingConfig && !billingConfig.liveMode && (
          <div className="flex items-center gap-3 p-4 rounded-lg border border-amber-500/50 bg-amber-500/10 mb-2" data-testid="banner-sandbox-mode">
            <AlertTriangle className="w-5 h-5 text-amber-500 shrink-0" />
            <div>
              <p className="text-sm font-semibold text-amber-600 dark:text-amber-400">Stripe Test Mode Active</p>
              <p className="text-xs text-muted-foreground">Payments are in sandbox/test mode. No real charges will be made. To enable live payments, configure production Stripe keys in your deployment settings.</p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plans?.map((plan: any) => {
            const Icon = planIcons[plan.name] || Shield;
            return (
              <Card key={plan.id} className={`relative ${planColors[plan.name] || ""}`} data-testid={`card-plan-${plan.name}`}>
                {plan.name === "professional" && (
                  <Badge className="absolute -top-3 start-1/2 -translate-x-1/2 bg-purple-600" data-testid="badge-recommended">Recommended</Badge>
                )}
                <CardHeader className="text-center">
                  <Icon className="w-10 h-10 mx-auto mb-2 text-primary" />
                  <CardTitle className="capitalize text-xl">{plan.name}</CardTitle>
                  <CardDescription>
                    <span className="text-3xl font-bold text-foreground">${(plan.price / 100).toFixed(0)}</span>
                    <span className="text-muted-foreground">/mo</span>
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2 mb-6">
                    {getFeatureList(plan).map((feature: string, i: number) => (
                      <li key={i} className="flex items-center gap-2 text-sm">
                        <Check className="w-4 h-4 text-green-500 shrink-0" />
                        <span>{feature}</span>
                      </li>
                    ))}
                  </ul>
                  <Button
                    className="w-full"
                    variant={plan.name === "professional" ? "default" : "outline"}
                    disabled={checkoutMutation.isPending}
                    onClick={() => {
                      checkoutMutation.mutate({ planName: plan.name });
                    }}
                    data-testid={`button-subscribe-${plan.name}`}
                  >
                    {checkoutMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : `Subscribe to ${plan.name}`}
                  </Button>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>
    </div>
  );
}
