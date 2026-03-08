import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import {
  LayoutDashboard, ShieldAlert, Bug, Brain, Database,
  Network, Target, Clock, Radio, Lock, BookOpen, FileText,
  Settings, CreditCard, LogOut, User, Shield, Bell, Flame, Radar, LifeBuoy, Server, Key,
  Monitor, Download, Terminal, Activity, ScanSearch, Smartphone, Eye, ShieldCheck,
  Mail, KeyRound, ShieldBan, FileSearch, CalendarClock, Zap,
} from "lucide-react";
import {
  Sidebar, SidebarContent, SidebarGroup, SidebarGroupContent,
  SidebarGroupLabel, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
  SidebarHeader, SidebarFooter,
} from "@/components/ui/sidebar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { AegisLogo } from "@/components/logo";

interface NavItem {
  title: string;
  testId: string;
  url: string;
  icon: React.ElementType;
}

function NavGroup({ label, items, location }: { label: string; items: NavItem[]; location: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel className="text-[9px] tracking-[0.3em] uppercase text-muted-foreground/60 font-semibold px-3">
        {label}
      </SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.testId}>
              <SidebarMenuButton
                asChild
                data-active={location === item.url}
                className="data-[active=true]:bg-primary/10 data-[active=true]:text-primary data-[active=true]:font-semibold h-8"
              >
                <Link href={item.url} data-testid={`link-${item.testId}`}>
                  <item.icon className="w-4 h-4" />
                  <span className="text-xs">{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

export function AppSidebar() {
  const [location] = useLocation();
  const { user, logoutMutation } = useAuth();
  const { t } = useTranslation();

  const isSuperAdmin = user?.isSuperAdmin === true;

  const commandItems: NavItem[] = [
    { title: t("sidebar.protectionCenter"), testId: "protection-center", url: "/protection-center", icon: Shield },
    { title: t("sidebar.dashboard"), testId: "dashboard", url: "/", icon: LayoutDashboard },
    { title: t("sidebar.aiAnalysis"), testId: "ai-analysis", url: "/ai-analysis", icon: Brain },
  ];

  const detectItems: NavItem[] = [
    { title: t("sidebar.securityEvents"), testId: "security-events", url: "/alerts", icon: ShieldAlert },
    { title: t("sidebar.attackHeatmap"), testId: "att&ck-heatmap", url: "/attack-map", icon: Target },
    { title: t("sidebar.scanner"), testId: "scanner", url: "/scanner", icon: Radar },
    { title: t("sidebar.networkMonitor"), testId: "network-monitor", url: "/network-monitor", icon: Server },
    { title: t("sidebar.honeypot"), testId: "honeypot", url: "/honeypot", icon: Radio },
    { title: t("sidebar.alertRules"), testId: "alert-rules", url: "/alert-rules", icon: Bell },
    { title: t("sidebar.hashTools"), testId: "hash-tools", url: "/hash-tools", icon: Key },
    { title: "Traffic Analysis", testId: "traffic-analysis", url: "/traffic-analysis", icon: Activity },
    { title: "Network Security", testId: "network-security", url: "/network-security", icon: ScanSearch },
    { title: "Payload Generator", testId: "payload-generator", url: "/payload-generator", icon: Terminal },
    { title: "Trojan Analyzer", testId: "trojan-analyzer", url: "/trojan-analyzer", icon: Bug },
    { title: "Mobile Pentest", testId: "mobile-pentest", url: "/mobile-pentest", icon: Smartphone },
    { title: "SSL Inspector", testId: "ssl-inspector", url: "/ssl-inspector", icon: ShieldBan },
    { title: "Email Analyzer", testId: "email-analyzer", url: "/email-analyzer", icon: Mail },
    { title: "Password Auditor", testId: "password-auditor", url: "/password-auditor", icon: KeyRound },
    { title: "Scheduled Scans", testId: "scheduled-scans", url: "/scheduled-scans", icon: CalendarClock },
    { title: "Threat Simulation", testId: "threat-simulation", url: "/threat-simulation", icon: Zap },
  ];

  const respondItems: NavItem[] = [
    { title: t("sidebar.incidents"), testId: "incidents", url: "/incidents", icon: Bug },
    { title: t("sidebar.quarantine"), testId: "quarantine", url: "/quarantine", icon: Lock },
    { title: t("sidebar.playbooks"), testId: "playbooks", url: "/playbooks", icon: BookOpen },
    { title: t("sidebar.firewall"), testId: "firewall", url: "/firewall", icon: Flame },
    { title: t("sidebar.policies"), testId: "policies", url: "/policies", icon: FileText },
    { title: "Compliance", testId: "compliance", url: "/compliance", icon: ShieldCheck },
  ];

  const endpointItems: NavItem[] = [
    { title: "Endpoints", testId: "endpoints", url: "/endpoints", icon: Monitor },
    { title: "Deploy Agent", testId: "download-agent", url: "/download-agent", icon: Download },
  ];

  const intelItems: NavItem[] = [
    { title: t("sidebar.threatIntel"), testId: "threat-intel", url: "/threat-intel", icon: Database },
    { title: t("sidebar.networkMap"), testId: "network-map", url: "/network-map", icon: Network },
    { title: t("sidebar.forensicTimeline"), testId: "forensic-timeline", url: "/forensics", icon: Clock },
    { title: "Dark Web Monitor", testId: "dark-web-monitor", url: "/dark-web-monitor", icon: Eye },
    { title: "CVE Database", testId: "cve-database", url: "/cve-database", icon: FileSearch },
  ];

  const adminItems: NavItem[] = [
    { title: t("sidebar.settings"), testId: "settings", url: "/settings", icon: Settings },
    { title: t("sidebar.billing"), testId: "billing", url: "/billing", icon: CreditCard },
    { title: t("sidebar.support"), testId: "support", url: "/support", icon: LifeBuoy },
    { title: "Agent Docs", testId: "docs-agent", url: "/docs/agent", icon: BookOpen },
  ];

  const fullAdminItems = [
    ...adminItems,
    ...(isSuperAdmin ? [{ title: t("sidebar.superAdmin"), testId: "super-admin", url: "/super-admin", icon: Shield }] : []),
  ];

  return (
    <Sidebar>
      <SidebarHeader className="p-3 border-b border-border/50">
        <Link href="/">
          <div className="cursor-pointer" data-testid="link-home">
            <AegisLogo size={32} />
          </div>
        </Link>
      </SidebarHeader>

      <SidebarContent className="py-1">
        <NavGroup label={t("sidebar.command")} items={commandItems} location={location} />
        <NavGroup label={t("sidebar.detect")} items={detectItems} location={location} />
        <NavGroup label={t("sidebar.respond")} items={respondItems} location={location} />
        <NavGroup label="ENDPOINTS" items={endpointItems} location={location} />
        <NavGroup label={t("sidebar.intel")} items={intelItems} location={location} />
        <NavGroup label={t("sidebar.admin")} items={fullAdminItems} location={location} />
      </SidebarContent>

      <SidebarFooter className="p-3 space-y-2 border-t border-border/50">
        <div className="flex items-center gap-2 p-2 rounded-md bg-sidebar-accent/50">
          <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20">
            <User className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[11px] font-medium truncate font-mono" data-testid="text-username">{user?.username}</p>
            <div className="flex items-center gap-1">
              <Badge variant="secondary" className="text-[8px] px-1 py-0 h-3.5">
                {user?.role || "user"}
              </Badge>
              {isSuperAdmin && (
                <Badge className="text-[8px] px-1 py-0 h-3.5 bg-severity-high text-white border-0">
                  ADMIN
                </Badge>
              )}
            </div>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 flex-shrink-0"
            onClick={() => logoutMutation.mutate()}
            data-testid="button-logout"
          >
            <LogOut className="w-3.5 h-3.5" />
          </Button>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-status-online animate-pulse-glow" />
          <span className="text-[10px] text-muted-foreground font-mono">{t("common.operational")}</span>
          <Badge variant="secondary" className="ml-auto text-[9px] font-mono">{t("common.version")}</Badge>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
