import { useLocation, Link } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import {
  Shield, LayoutDashboard, ShieldAlert, Bug, Database, Brain, FileText,
  Network, Target, Clock, Radio, Lock, BookOpen, Settings, CreditCard, LogOut, User,
} from "lucide-react";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
} from "@/components/ui/sidebar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

const operationsItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Security Events", url: "/alerts", icon: ShieldAlert },
  { title: "Incidents", url: "/incidents", icon: Bug },
  { title: "AI Analysis", url: "/ai-analysis", icon: Brain },
];

const detectionItems = [
  { title: "Threat Intel", url: "/threat-intel", icon: Database },
  { title: "Network Map", url: "/network-map", icon: Network },
  { title: "ATT&CK Heatmap", url: "/attack-map", icon: Target },
  { title: "Honeypot", url: "/honeypot", icon: Radio },
];

const responseItems = [
  { title: "Quarantine", url: "/quarantine", icon: Lock },
  { title: "Playbooks", url: "/playbooks", icon: BookOpen },
  { title: "Policies", url: "/policies", icon: FileText },
  { title: "Forensic Timeline", url: "/forensics", icon: Clock },
];

const adminItems = [
  { title: "Settings", url: "/settings", icon: Settings, roles: ["admin", "analyst", "auditor", "readonly"] },
  { title: "Billing", url: "/billing", icon: CreditCard, roles: ["admin"] },
];

const planColors: Record<string, string> = {
  starter: "bg-severity-info text-white",
  professional: "bg-primary text-primary-foreground",
  enterprise: "bg-severity-high text-white",
};

function NavGroup({ label, items, location }: { label: string; items: typeof operationsItems; location: string }) {
  return (
    <SidebarGroup>
      <SidebarGroupLabel className="text-[10px] tracking-widest uppercase">{label}</SidebarGroupLabel>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                asChild
                data-active={location === item.url}
                className="data-[active=true]:bg-sidebar-accent"
              >
                <Link href={item.url} data-testid={`link-${item.title.toLowerCase().replace(/\s+/g, '-')}`}>
                  <item.icon className="w-4 h-4" />
                  <span>{item.title}</span>
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

  const userRole = user?.role || "readonly";
  const filteredAdminItems = adminItems.filter((item) => !item.roles || item.roles.includes(userRole));

  return (
    <Sidebar>
      <SidebarHeader className="p-4">
        <Link href="/">
          <div className="flex items-center gap-2 cursor-pointer" data-testid="link-home">
            <div className="flex items-center justify-center w-9 h-9 rounded-md bg-primary">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <div className="flex flex-col">
              <span className="text-sm font-bold tracking-wider">AEGIS<span className="text-primary">AI</span></span>
              <span className="text-[10px] text-muted-foreground tracking-widest uppercase">Command Center</span>
            </div>
          </div>
        </Link>
      </SidebarHeader>

      <SidebarContent>
        <NavGroup label="Operations" items={operationsItems} location={location} />
        <NavGroup label="Detection" items={detectionItems} location={location} />
        <NavGroup label="Response" items={responseItems} location={location} />
        {filteredAdminItems.length > 0 && (
          <NavGroup label="Admin" items={filteredAdminItems} location={location} />
        )}
      </SidebarContent>

      <SidebarFooter className="p-4 space-y-3">
        <div className="flex items-center gap-2 p-2 rounded-md bg-sidebar-accent/50">
          <div className="flex items-center justify-center w-7 h-7 rounded-full bg-primary/20">
            <User className="w-3.5 h-3.5 text-primary" />
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium truncate" data-testid="text-username">{user?.username}</p>
            <div className="flex items-center gap-1.5">
              <Badge className={`text-[8px] ${planColors[userRole === "admin" ? "professional" : "starter"]} px-1 py-0`}>
                {userRole}
              </Badge>
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
          <div className="w-2 h-2 rounded-full bg-status-online animate-pulse-glow" />
          <span className="text-xs text-muted-foreground">System Online</span>
          <Badge variant="secondary" className="ml-auto text-[10px]">v2.0</Badge>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
