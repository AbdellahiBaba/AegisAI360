import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { AppSidebar } from "@/components/app-sidebar";
import { ThemeProvider } from "@/components/theme-provider";
import { AuthProvider, useAuth } from "@/hooks/use-auth";
import { NotificationBell } from "@/components/notification-bell";
import { LanguageSwitcher } from "@/components/language-switcher";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import NotFound from "@/pages/not-found";
import Dashboard from "@/pages/dashboard";
import Alerts from "@/pages/alerts";
import Incidents from "@/pages/incidents";
import ThreatIntel from "@/pages/threat-intel";
import AiAnalysis from "@/pages/ai-analysis";
import Policies from "@/pages/policies";
import AuthPage from "@/pages/auth";
import NetworkMap from "@/pages/network-map";
import AttackMap from "@/pages/attack-map";
import Forensics from "@/pages/forensics";
import Honeypot from "@/pages/honeypot";
import Quarantine from "@/pages/quarantine";
import Playbooks from "@/pages/playbooks";
import SettingsPage from "@/pages/settings";
import Billing from "@/pages/billing";
import Firewall from "@/pages/firewall";
import AlertRules from "@/pages/alert-rules";
import SuperAdmin from "@/pages/super-admin";

function AppRouter() {
  return (
    <Switch>
      <Route path="/" component={Dashboard} />
      <Route path="/alerts" component={Alerts} />
      <Route path="/incidents" component={Incidents} />
      <Route path="/threat-intel" component={ThreatIntel} />
      <Route path="/ai-analysis" component={AiAnalysis} />
      <Route path="/policies" component={Policies} />
      <Route path="/network-map" component={NetworkMap} />
      <Route path="/attack-map" component={AttackMap} />
      <Route path="/forensics" component={Forensics} />
      <Route path="/honeypot" component={Honeypot} />
      <Route path="/quarantine" component={Quarantine} />
      <Route path="/playbooks" component={Playbooks} />
      <Route path="/settings" component={SettingsPage} />
      <Route path="/billing" component={Billing} />
      <Route path="/firewall" component={Firewall} />
      <Route path="/alert-rules" component={AlertRules} />
      <Route path="/super-admin" component={SuperAdmin} />
      <Route component={NotFound} />
    </Switch>
  );
}

function AppLayout() {
  const { t } = useTranslation();
  const style = {
    "--sidebar-width": "15rem",
    "--sidebar-width-icon": "3rem",
  };

  return (
    <SidebarProvider style={style as React.CSSProperties}>
      <div className="flex h-screen w-full">
        <AppSidebar />
        <div className="flex flex-col flex-1 min-w-0">
          <header className="flex items-center justify-between gap-2 px-4 py-1.5 border-b h-10">
            <div className="flex items-center gap-3">
              <SidebarTrigger data-testid="button-sidebar-toggle" />
              <div className="hidden sm:flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-status-online animate-pulse-glow" />
                <span className="text-[9px] font-mono text-muted-foreground tracking-[0.3em] uppercase">
                  {t("common.liveOperations")}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <LanguageSwitcher />
              <NotificationBell />
            </div>
          </header>
          <main className="flex-1 overflow-auto tactical-grid">
            <AppRouter />
          </main>
        </div>
      </div>
    </SidebarProvider>
  );
}

function AuthenticatedApp() {
  const { t } = useTranslation();
  const { user, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-screen bg-background">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
          <span className="text-xs font-mono text-muted-foreground tracking-wider uppercase">
            {t("common.initializing")}
          </span>
        </div>
      </div>
    );
  }

  if (!user) return <AuthPage />;
  return <AppLayout />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <AuthProvider>
            <AuthenticatedApp />
          </AuthProvider>
          <Toaster />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
