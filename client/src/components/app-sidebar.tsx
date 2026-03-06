import { useLocation, Link } from "wouter";
import { Shield, LayoutDashboard, ShieldAlert, Bug, Database, Brain, FileText } from "lucide-react";
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

const navItems = [
  { title: "Dashboard", url: "/", icon: LayoutDashboard },
  { title: "Security Events", url: "/alerts", icon: ShieldAlert },
  { title: "Incidents", url: "/incidents", icon: Bug },
  { title: "Threat Intel", url: "/threat-intel", icon: Database },
  { title: "AI Analysis", url: "/ai-analysis", icon: Brain },
  { title: "Policies", url: "/policies", icon: FileText },
];

export function AppSidebar() {
  const [location] = useLocation();

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
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] tracking-widest uppercase">Operations</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
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
      </SidebarContent>
      <SidebarFooter className="p-4">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-status-online animate-pulse-glow" />
          <span className="text-xs text-muted-foreground">System Online</span>
          <Badge variant="secondary" className="ml-auto text-[10px]">v1.0</Badge>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
