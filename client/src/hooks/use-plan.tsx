import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";

export interface PlanDetails {
  name: string;
  price: number;
  maxAgents: number;
  maxLogsPerDay: number;
  maxCommandsPerDay: number;
  maxThreatIntelQueries: number;
  allowNetworkIsolation: boolean;
  allowProcessKill: boolean;
  allowFileScan: boolean;
  allowEndpointDownload: boolean;
  allowTerminalAccess: boolean;
  allowThreatIntel: boolean;
  allowAdvancedAnalytics: boolean;
  allowAegisAgent: boolean;
}

interface BillingStatus {
  plan: string;
  planDetails: PlanDetails | null;
  subscriptionStatus: string;
  stripeSubscriptionId: string | null;
  planId: number | null;
}

const ALL_FEATURES_PLAN: PlanDetails = {
  name: "enterprise",
  price: 0,
  maxAgents: 999,
  maxLogsPerDay: 999999,
  maxCommandsPerDay: 99999,
  maxThreatIntelQueries: 99999,
  allowNetworkIsolation: true,
  allowProcessKill: true,
  allowFileScan: true,
  allowEndpointDownload: true,
  allowTerminalAccess: true,
  allowThreatIntel: true,
  allowAdvancedAnalytics: true,
  allowAegisAgent: true,
};

export function usePlan() {
  const { user } = useAuth();

  const { data: billingStatus, isLoading } = useQuery<BillingStatus>({
    queryKey: ["/api/billing/status"],
    enabled: !!user && !user.isSuperAdmin,
  });

  if (user?.isSuperAdmin) {
    return {
      plan: ALL_FEATURES_PLAN,
      planName: "enterprise",
      isLoading: false,
      hasFeature: (_feature: string) => true,
    };
  }

  const plan = billingStatus?.planDetails || null;

  const hasFeature = (feature: string): boolean => {
    if (user?.isSuperAdmin) return true;
    if (!plan) return false;
    return !!(plan as any)[feature];
  };

  return {
    plan,
    planName: plan?.name || billingStatus?.plan || "starter",
    isLoading,
    hasFeature,
  };
}
