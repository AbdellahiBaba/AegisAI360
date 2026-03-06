import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import {
  LayoutDashboard, ShieldAlert, Bug, Brain, Database,
  Network, Target, Clock, Radio, Lock, BookOpen, FileText,
  Settings, CreditCard, LogOut, User, Shield, Bell, Flame,
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
  url: string;
  icon: React.ElementType;
}

const commandItems: NavItem[] = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "AI Analysis", url: "/ai-analysis", icon: Brain },
];

const detectItems: NavItem[] = [
  { title: "Security Events", url: "/alerts", icon: ShieldAlert },
  { title: "ATT&CK Heatmap", url: "/attack-map", icon: Target },
  { title: "Honeypot", url: "/honeypot", icon: Radio },
  { title: "Alert Rules", url: "/alert-rules", icon: Bell },
];

const respondItems: NavItem[] = [
  { title: "Incidents", url: "/incidents", icon: Bug },
  { title: "Quarantine", url: "/quarantine", icon: Lock },
  { title: "Playbooks", url: "/playbooks", icon: BookOpen },
  { title: "Firewall", url: "/firewall", icon: Flame },
  { title: "Policies", url: "/policies", icon: FileText },
];

const intelItems: NavItem[] = [
  { title: "Threat Intel", url: "/threat-intel", icon: Database },
  { title: "Network Map", url: "/network-map", icon: Network },
  { title: "Forensic Timeline", url: "/forensics", icon: Clock },
];

const adminItems: NavItem[] = [
  { title: "Settings", url: "/settings", icon: Settings },
  { title: "Billing", url: "/billing", icon: CreditCard },
];

function NavGroup({ label, items, location }: { label: string; items: NavItem[]; location: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel className="text-[9px] tracking-[0.3em] uppercase text-muted-foreground/60 font-semibold px-3">
        {label}
      </SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                asChild
                data-active={location === item.url}
                className="data-[active=true]:bg-primary/10 data-[active=true]:text-primary data-[active=true]:font-semibold h-8"
              >
                <Link href={item.url} data-testid={`link-${item.title.toLowerCase().replace(/\s+/g, '-')}`}>
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

  const isSuperAdmin = user?.isSuperAdmin === true;

  const fullAdminItems = [
    ...adminItems,
    ...(isSuperAdmin ? [{ title: "Super Admin", url: "/super-admin", icon: Shield }] : []),
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
        <NavGroup label="Command" items={commandItems} location={location} />
        <NavGroup label="Detect" items={detectItems} location={location} />
        <NavGroup label="Respond" items={respondItems} location={location} />
        <NavGroup label="Intel" items={intelItems} location={location} />
        <NavGroup label="Admin" items={fullAdminItems} location={location} />
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
                {user?.role || "operator"}
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
          <span className="text-[10px] text-muted-foreground font-mono">OPERATIONAL</span>
          <Badge variant="secondary" className="ml-auto text-[9px] font-mono">v3.0</Badge>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
