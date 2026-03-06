import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useAuth } from "@/hooks/use-auth";
import { useToast } from "@/hooks/use-toast";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import type { SupportTicket } from "@shared/schema";
import {
  Shield,
  Building2,
  Users,
  Activity,
  Server,
  Clock,
  Cpu,
  HardDrive,
  ShieldAlert,
  Ban,
  CheckCircle,
  Lock,
  AlertTriangle,
  LifeBuoy,
  MessageSquare,
  Send,
  Wifi,
  ArrowLeft,
  Wrench,
  UserCog,
  Key,
  Settings,
  Flame,
  LayoutDashboard,
} from "lucide-react";

interface PlatformStats {
  totalOrgs: number;
  totalUsers: number;
  totalEvents: number;
}

interface AdminOrganization {
  id: number;
  name: string;
  slug: string;
  plan: string;
  suspended: boolean;
  userCount: number;
  createdAt: string;
}

interface AdminUser {
  id: string;
  username: string;
  role: string;
  isSuperAdmin: boolean;
  organizationName: string | null;
}

interface SystemHealth {
  uptime: number;
  memory: { used: number; total: number; percentage: number };
  load: number[];
  nodeVersion: string;
}

interface SecurityStats {
  blockedAttacks: number;
  rateLimitedIps: number;
  blockedIps: number;
  recentEvents: Array<{
    timestamp: string;
    type: string;
    ip: string;
    path: string;
  }>;
}

interface AuditEntry {
  id: number;
  action: string;
  userId: string | null;
  targetType: string | null;
  targetId: string | null;
  details: string | null;
  createdAt: string;
}

const planColors: Record<string, string> = {
  starter: "bg-muted text-muted-foreground",
  professional: "bg-blue-500/20 text-blue-400",
  enterprise: "bg-purple-500/20 text-purple-400",
};

function formatUptime(seconds: number) {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function SuperAdmin() {
  const { t } = useTranslation();
  const { user } = useAuth();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("overview");

  if (!user?.isSuperAdmin) {
    return (
      <div className="flex items-center justify-center h-full" data-testid="access-denied">
        <Card className="max-w-md w-full">
          <CardContent className="p-8 text-center space-y-4">
            <ShieldAlert className="w-12 h-12 text-severity-critical mx-auto" />
            <h2 className="text-lg font-semibold tracking-wide uppercase">{t("superAdmin.accessDenied")}</h2>
            <p className="text-sm text-muted-foreground">
              {t("superAdmin.noPrivileges")}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-severity-critical" />
          <h1 className="text-lg font-semibold tracking-wide uppercase">{t("superAdmin.platformAdmin")}</h1>
        </div>
        <Badge variant="destructive" className="text-[10px] uppercase tracking-wider">
          {t("superAdmin.superAdminBadge")}
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList data-testid="tabs-admin">
          <TabsTrigger value="overview" data-testid="tab-overview">{t("superAdmin.overview")}</TabsTrigger>
          <TabsTrigger value="organizations" data-testid="tab-organizations">{t("superAdmin.organizations")}</TabsTrigger>
          <TabsTrigger value="users" data-testid="tab-users">{t("superAdmin.users")}</TabsTrigger>
          <TabsTrigger value="system" data-testid="tab-system">{t("superAdmin.system")}</TabsTrigger>
          <TabsTrigger value="security" data-testid="tab-security">{t("superAdmin.security", "Security")}</TabsTrigger>
          <TabsTrigger value="support" data-testid="tab-support"><LifeBuoy className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />{t("sidebar.support")}</TabsTrigger>
          <TabsTrigger value="audit" data-testid="tab-audit">{t("superAdmin.auditLog")}</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4 mt-4">
          <PlatformOverview />
        </TabsContent>

        <TabsContent value="organizations" className="mt-4">
          <OrganizationsTable />
        </TabsContent>

        <TabsContent value="users" className="mt-4">
          <UsersTable />
        </TabsContent>

        <TabsContent value="system" className="mt-4">
          <SystemHealthCard />
        </TabsContent>

        <TabsContent value="security" className="mt-4">
          <SecurityPanel />
        </TabsContent>

        <TabsContent value="support" className="mt-4">
          <SupportPanel />
        </TabsContent>

        <TabsContent value="audit" className="mt-4">
          <AuditLogFeed />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function PlatformOverview() {
  const { t } = useTranslation();
  const { data: stats, isLoading } = useQuery<PlatformStats>({
    queryKey: ["/api/admin/platform-stats"],
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
    );
  }

  const cards = [
    { label: t("superAdmin.totalOrganizations"), value: stats?.totalOrgs ?? 0, icon: Building2 },
    { label: t("superAdmin.totalUsers"), value: stats?.totalUsers ?? 0, icon: Users },
    { label: t("superAdmin.totalEvents"), value: stats?.totalEvents ?? 0, icon: Activity },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {cards.map((card) => (
        <Card key={card.label}>
          <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
            <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
              {card.label}
            </CardTitle>
            <card.icon className="w-4 h-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold font-mono" data-testid={`stat-${card.label.toLowerCase().replace(/\s/g, "-")}`}>
              {card.value.toLocaleString()}
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function OrganizationsTable() {
  const { t } = useTranslation();
  const { toast } = useToast();

  const { data: orgs, isLoading } = useQuery<AdminOrganization[]>({
    queryKey: ["/api/admin/organizations"],
  });

  const suspendMutation = useMutation({
    mutationFn: async ({ id, suspended }: { id: number; suspended: boolean }) => {
      await apiRequest("POST", `/api/admin/organizations/${id}/suspend`, { suspended });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/organizations"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/platform-stats"] });
      toast({ title: t("superAdmin.orgStatusUpdated") });
    },
  });

  const changePlanMutation = useMutation({
    mutationFn: async ({ id, plan }: { id: number; plan: string }) => {
      await apiRequest("POST", `/api/admin/organizations/${id}/change-plan`, { plan });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/organizations"] });
      toast({ title: t("superAdmin.orgPlanUpdated") });
    },
  });

  if (isLoading) {
    return <Skeleton className="h-[400px] w-full" />;
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="text-sm tracking-wider uppercase">{t("superAdmin.organizations")}</CardTitle>
        <Badge variant="secondary" className="font-mono text-xs">{orgs?.length ?? 0}</Badge>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[calc(100vh-300px)]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("common.name")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.plan")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.userCount")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("common.status")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("common.actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(orgs || []).map((org) => (
                <TableRow key={org.id} data-testid={`org-row-${org.id}`}>
                  <TableCell className="text-xs font-mono">{org.name}</TableCell>
                  <TableCell>
                    <Badge className={`${planColors[org.plan] || planColors.starter} text-[9px] uppercase`}>
                      {org.plan}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs font-mono">{org.userCount}</TableCell>
                  <TableCell>
                    {org.suspended ? (
                      <Badge variant="destructive" className="text-[9px] uppercase">{t("superAdmin.suspended")}</Badge>
                    ) : (
                      <Badge className="bg-status-online/20 text-status-online text-[9px] uppercase">{t("common.active")}</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Button
                        size="sm"
                        variant={org.suspended ? "default" : "destructive"}
                        onClick={() => suspendMutation.mutate({ id: org.id, suspended: !org.suspended })}
                        disabled={suspendMutation.isPending}
                        data-testid={`button-toggle-suspend-${org.id}`}
                      >
                        {org.suspended ? (
                          <><CheckCircle className="w-3 h-3 me-1" /> {t("superAdmin.activate")}</>
                        ) : (
                          <><Ban className="w-3 h-3 me-1" /> {t("superAdmin.suspend")}</>
                        )}
                      </Button>
                      <Select
                        value={org.plan}
                        onValueChange={(plan) => changePlanMutation.mutate({ id: org.id, plan })}
                      >
                        <SelectTrigger className="w-[130px]" data-testid={`select-plan-${org.id}`}>
                          <SelectValue placeholder={t("superAdmin.changePlan")} />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="starter">{t("superAdmin.starter")}</SelectItem>
                          <SelectItem value="professional">{t("superAdmin.professional")}</SelectItem>
                          <SelectItem value="enterprise">{t("superAdmin.enterprise")}</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {(!orgs || orgs.length === 0) && (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground py-8">
                    {t("superAdmin.noOrganizations")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function UsersTable() {
  const { t } = useTranslation();
  const { data: users, isLoading } = useQuery<AdminUser[]>({
    queryKey: ["/api/admin/users"],
  });

  if (isLoading) {
    return <Skeleton className="h-[400px] w-full" />;
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="text-sm tracking-wider uppercase">{t("superAdmin.users")}</CardTitle>
        <Badge variant="secondary" className="font-mono text-xs">{users?.length ?? 0}</Badge>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[calc(100vh-300px)]">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.username")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.organization")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.role")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("superAdmin.superAdminBadge")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users || []).map((u, idx) => (
                <TableRow key={u.id} data-testid={`user-row-${idx}`}>
                  <TableCell className="text-xs font-mono">{u.username}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{u.organizationName || t("common.noData")}</TableCell>
                  <TableCell>
                    <Badge variant="secondary" className="text-[9px] uppercase">{u.role}</Badge>
                  </TableCell>
                  <TableCell>
                    {u.isSuperAdmin ? (
                      <Badge variant="destructive" className="text-[9px] uppercase">{t("superAdmin.superAdminBadge")}</Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">--</span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {(!users || users.length === 0) && (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-sm text-muted-foreground py-8">
                    {t("superAdmin.noUsers")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function SystemHealthCard() {
  const { t } = useTranslation();
  const { data: health, isLoading } = useQuery<SystemHealth>({
    queryKey: ["/api/admin/system-health"],
    refetchInterval: 30000,
  });

  if (isLoading) {
    return <Skeleton className="h-[300px] w-full" />;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
            {t("superAdmin.uptime")}
          </CardTitle>
          <Clock className="w-4 h-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-xl font-bold font-mono" data-testid="stat-uptime">
            {health ? formatUptime(health.uptime) : t("common.noData")}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
            {t("superAdmin.memoryUsage")}
          </CardTitle>
          <HardDrive className="w-4 h-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-xl font-bold font-mono" data-testid="stat-memory">
            {health ? `${health.memory.percentage.toFixed(1)}%` : t("common.noData")}
          </div>
          <p className="text-[10px] text-muted-foreground font-mono mt-1">
            {health ? `${(health.memory.used / 1024 / 1024).toFixed(0)}MB / ${(health.memory.total / 1024 / 1024).toFixed(0)}MB` : ""}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
            {t("superAdmin.systemLoad")}
          </CardTitle>
          <Cpu className="w-4 h-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-xl font-bold font-mono" data-testid="stat-load">
            {health?.load ? health.load.map((l) => l.toFixed(2)).join(" / ") : t("common.noData")}
          </div>
          <p className="text-[10px] text-muted-foreground mt-1">{t("superAdmin.loadIntervals")}</p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
            {t("superAdmin.nodeVersion")}
          </CardTitle>
          <Server className="w-4 h-4 text-muted-foreground" />
        </CardHeader>
        <CardContent>
          <div className="text-xl font-bold font-mono" data-testid="stat-node-version">
            {health?.nodeVersion ?? t("common.noData")}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function AuditLogFeed() {
  const { t } = useTranslation();
  const { data: logs, isLoading } = useQuery<AuditEntry[]>({
    queryKey: ["/api/admin/audit-log"],
  });

  if (isLoading) {
    return <Skeleton className="h-[400px] w-full" />;
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
        <CardTitle className="text-sm tracking-wider uppercase">{t("superAdmin.auditLog")}</CardTitle>
        <Badge variant="secondary" className="font-mono text-xs">{logs?.length ?? 0} {t("common.entries")}</Badge>
      </CardHeader>
      <CardContent className="p-0">
        <ScrollArea className="h-[calc(100vh-300px)]">
          <div className="divide-y">
            {(logs || []).map((entry) => (
              <div key={entry.id} className="px-4 py-3 space-y-1" data-testid={`audit-entry-${entry.id}`}>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-xs font-mono font-medium">{entry.action}</span>
                  <span className="text-[10px] text-muted-foreground font-mono">
                    {formatDate(entry.createdAt)}
                  </span>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {entry.userId && (
                    <Badge variant="secondary" className="text-[9px]">{t("superAdmin.user")}: {entry.userId}</Badge>
                  )}
                  {entry.targetType && (
                    <Badge variant="outline" className="text-[9px]">
                      {entry.targetType}{entry.targetId ? `: ${entry.targetId}` : ""}
                    </Badge>
                  )}
                </div>
                {entry.details && (
                  <p className="text-[10px] text-muted-foreground">{entry.details}</p>
                )}
              </div>
            ))}
            {(!logs || logs.length === 0) && (
              <div className="text-center text-sm text-muted-foreground py-12">{t("superAdmin.noAuditEntries")}</div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

function SecurityPanel() {
  const { t } = useTranslation();
  const { data: stats, isLoading } = useQuery<SecurityStats>({
    queryKey: ["/api/admin/security-stats"],
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-28" />
        ))}
      </div>
    );
  }

  const secCards = [
    {
      label: t("superAdmin.blockedAttacks", "Blocked Attacks"),
      value: stats?.blockedAttacks ?? 0,
      icon: ShieldAlert,
      color: "text-severity-critical",
    },
    {
      label: t("superAdmin.rateLimitedIPs", "Rate-Limited IPs"),
      value: stats?.rateLimitedIps ?? 0,
      icon: Ban,
      color: "text-amber-500",
    },
    {
      label: t("superAdmin.blockedIPs", "Blocked IPs"),
      value: stats?.blockedIps ?? 0,
      icon: Lock,
      color: "text-red-500",
    },
  ];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {secCards.map((card) => (
          <Card key={card.label}>
            <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
              <CardTitle className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
                {card.label}
              </CardTitle>
              <card.icon className={`w-4 h-4 ${card.color}`} />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono" data-testid={`security-stat-${card.label.toLowerCase().replace(/\s/g, "-")}`}>
                {card.value.toLocaleString()}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs uppercase tracking-wider flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            {t("superAdmin.recentSecurityEvents", "Recent Security Events")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-450px)]">
            <div className="divide-y">
              {(stats?.recentEvents || []).map((event, idx) => (
                <div key={idx} className="px-4 py-3 space-y-1" data-testid={`security-event-${idx}`}>
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <Badge variant="destructive" className="text-[9px] uppercase tracking-wider">
                      {event.type}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[10px] text-muted-foreground font-mono">
                    <span>IP: {event.ip}</span>
                    {event.path && <span className="truncate max-w-[300px]">{event.path}</span>}
                  </div>
                </div>
              ))}
              {(!stats?.recentEvents || stats.recentEvents.length === 0) && (
                <div className="flex flex-col items-center gap-2 py-12">
                  <CheckCircle className="w-8 h-8 text-emerald-500" />
                  <span className="text-sm text-muted-foreground">{t("superAdmin.noSecurityEvents", "No security events detected")}</span>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}

function SupportPanel() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [selectedTicket, setSelectedTicket] = useState<SupportTicket | null>(null);
  const [statusFilter, setStatusFilter] = useState("all");
  const [replyContent, setReplyContent] = useState("");

  const { data: tickets, isLoading } = useQuery<SupportTicket[]>({
    queryKey: ["/api/admin/support/tickets"],
    refetchInterval: 10000,
  });

  const updateMutation = useMutation({
    mutationFn: async ({ id, data }: { id: number; data: any }) => {
      const res = await apiRequest("PATCH", `/api/admin/support/tickets/${id}`, data);
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: t("support.ticketUpdated") });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/support/tickets"] });
      if (selectedTicket) setSelectedTicket(data);
    },
  });

  const replyMutation = useMutation({
    mutationFn: async ({ id, content }: { id: number; content: string }) => {
      const res = await apiRequest("POST", `/api/admin/support/tickets/${id}/messages`, { content });
      return res.json();
    },
    onSuccess: (data) => {
      setReplyContent("");
      queryClient.invalidateQueries({ queryKey: ["/api/admin/support/tickets"] });
      if (selectedTicket) setSelectedTicket(data);
    },
  });

  const remoteMutation = useMutation({
    mutationFn: async ({ id, active }: { id: number; active: boolean }) => {
      const res = await apiRequest("POST", `/api/admin/support/tickets/${id}/remote-session`, { active });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/support/tickets"] });
      if (selectedTicket) setSelectedTicket(data);
    },
  });

  const actionMutation = useMutation({
    mutationFn: async ({ id, actionType, details }: { id: number; actionType: string; details: string }) => {
      const res = await apiRequest("POST", `/api/admin/support/tickets/${id}/take-action`, { actionType, details });
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("support.actionExecuted") });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/support/tickets"] });
    },
  });

  if (selectedTicket) {
    const messages = Array.isArray(selectedTicket.messages) ? (selectedTicket.messages as any[]) : [];
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" onClick={() => setSelectedTicket(null)} data-testid="button-back-admin">
            <ArrowLeft className="w-4 h-4 ltr:mr-1 rtl:ml-1" />
            {t("support.back")}
          </Button>
          <div className="flex-1">
            <h3 className="text-sm font-semibold">{selectedTicket.subject}</h3>
            <p className="text-[10px] text-muted-foreground">
              Org #{selectedTicket.organizationId} | User: {selectedTicket.userId}
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card className="md:col-span-2">
            <CardHeader className="py-3 px-4">
              <CardTitle className="text-xs flex items-center gap-2">
                <MessageSquare className="w-3.5 h-3.5" />
                {t("support.messages")}
              </CardTitle>
            </CardHeader>
            <CardContent className="px-4 pb-4">
              <div className="space-y-3 max-h-[350px] overflow-y-auto mb-4">
                {messages.map((msg: any, i: number) => (
                  <div key={i} className={`flex ${msg.role === "user" ? "justify-start" : msg.role === "admin" ? "justify-end" : "justify-center"}`} data-testid={`admin-message-${i}`}>
                    <div className={`max-w-[80%] rounded-lg p-3 text-xs ${
                      msg.role === "user" ? "bg-muted" : msg.role === "admin" ? "bg-primary/10 border border-primary/20" : "bg-yellow-500/10 text-yellow-400 italic"
                    }`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-semibold text-[10px]">
                          {msg.role === "user" ? "Customer" : msg.role === "admin" ? "Admin" : "System"}
                        </span>
                        <span className="text-[9px] text-muted-foreground">{new Date(msg.timestamp).toLocaleString()}</span>
                      </div>
                      <p>{msg.content}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <Textarea
                  value={replyContent}
                  onChange={(e) => setReplyContent(e.target.value)}
                  placeholder={t("support.typeMessage")}
                  className="text-xs min-h-[60px]"
                  data-testid="input-admin-reply"
                />
                <Button
                  size="sm"
                  onClick={() => replyContent.trim() && replyMutation.mutate({ id: selectedTicket.id, content: replyContent.trim() })}
                  disabled={replyMutation.isPending || !replyContent.trim()}
                  data-testid="button-admin-send"
                >
                  <Send className="w-3.5 h-3.5" />
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-xs">{t("support.changeStatus")}</CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-2">
                <Select value={selectedTicket.status} onValueChange={(status) => updateMutation.mutate({ id: selectedTicket.id, data: { status } })}>
                  <SelectTrigger className="text-xs" data-testid="select-ticket-status">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Open</SelectItem>
                    <SelectItem value="in_progress">In Progress</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                    <SelectItem value="closed">Closed</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={selectedTicket.priority} onValueChange={(priority) => updateMutation.mutate({ id: selectedTicket.id, data: { priority } })}>
                  <SelectTrigger className="text-xs" data-testid="select-ticket-priority">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">{t("common.low")}</SelectItem>
                    <SelectItem value="medium">{t("common.medium")}</SelectItem>
                    <SelectItem value="high">{t("common.high")}</SelectItem>
                    <SelectItem value="critical">{t("common.critical")}</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  variant="outline"
                  size="sm"
                  className="w-full text-xs"
                  onClick={() => updateMutation.mutate({ id: selectedTicket.id, data: { assignedTo: "admin" } })}
                  data-testid="button-assign-to-me"
                >
                  <UserCog className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
                  {t("support.assignToMe")}
                </Button>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-xs flex items-center gap-2">
                  <Wifi className="w-3.5 h-3.5" />
                  Remote Session
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-2">
                {selectedTicket.remoteSessionRequested ? (
                  <>
                    <Badge className={`text-[10px] w-full justify-center py-1 ${selectedTicket.remoteSessionActive ? "bg-green-500/20 text-green-400" : "bg-yellow-500/20 text-yellow-400"}`}>
                      {selectedTicket.remoteSessionActive ? t("support.remoteActive") : t("support.remotePending")}
                    </Badge>
                    {selectedTicket.remoteSessionActive ? (
                      <Button
                        variant="destructive"
                        size="sm"
                        className="w-full text-xs"
                        onClick={() => remoteMutation.mutate({ id: selectedTicket.id, active: false })}
                        data-testid="button-end-remote"
                      >
                        {t("support.endRemote")}
                      </Button>
                    ) : (
                      <Button
                        size="sm"
                        className="w-full text-xs"
                        onClick={() => remoteMutation.mutate({ id: selectedTicket.id, active: true })}
                        data-testid="button-start-remote"
                      >
                        {t("support.startRemote")}
                      </Button>
                    )}
                  </>
                ) : (
                  <p className="text-[10px] text-muted-foreground text-center py-2">No remote session requested</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-xs flex items-center gap-2">
                  <Wrench className="w-3.5 h-3.5" />
                  {t("support.takeAction")}
                </CardTitle>
              </CardHeader>
              <CardContent className="px-4 pb-4 space-y-1.5">
                {[
                  { type: "view_dashboard", label: t("support.viewDashboard"), icon: LayoutDashboard },
                  { type: "modify_firewall", label: t("support.modifyFirewall"), icon: Flame },
                  { type: "manage_settings", label: t("support.manageSettings"), icon: Settings },
                  { type: "reset_password", label: t("support.resetPassword"), icon: Key },
                ].map((action) => (
                  <Button
                    key={action.type}
                    variant="outline"
                    size="sm"
                    className="w-full text-xs justify-start"
                    onClick={() => actionMutation.mutate({ id: selectedTicket.id, actionType: action.type, details: `On behalf of org #${selectedTicket.organizationId}` })}
                    disabled={actionMutation.isPending}
                    data-testid={`button-action-${action.type}`}
                  >
                    <action.icon className="w-3.5 h-3.5 ltr:mr-2 rtl:ml-2" />
                    {action.label}
                  </Button>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    );
  }

  const filtered = (tickets || []).filter(t => statusFilter === "all" || t.status === statusFilter);
  const statusCounts = {
    open: (tickets || []).filter(t => t.status === "open").length,
    in_progress: (tickets || []).filter(t => t.status === "in_progress").length,
    resolved: (tickets || []).filter(t => t.status === "resolved").length,
  };

  if (isLoading) return <Skeleton className="h-[400px] w-full" />;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <Card className="cursor-pointer hover:bg-muted/30 transition-colors" onClick={() => setStatusFilter("open")}>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-blue-500/10"><Clock className="w-4 h-4 text-blue-400" /></div>
            <div>
              <p className="text-lg font-bold" data-testid="admin-open-count">{statusCounts.open}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.openTickets")}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="cursor-pointer hover:bg-muted/30 transition-colors" onClick={() => setStatusFilter("in_progress")}>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-yellow-500/10"><AlertTriangle className="w-4 h-4 text-yellow-400" /></div>
            <div>
              <p className="text-lg font-bold" data-testid="admin-progress-count">{statusCounts.in_progress}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.inProgressTickets")}</p>
            </div>
          </CardContent>
        </Card>
        <Card className="cursor-pointer hover:bg-muted/30 transition-colors" onClick={() => setStatusFilter("resolved")}>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-green-500/10"><CheckCircle className="w-4 h-4 text-green-400" /></div>
            <div>
              <p className="text-lg font-bold" data-testid="admin-resolved-count">{statusCounts.resolved}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.resolvedTickets")}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2 space-y-0 pb-2">
          <CardTitle className="text-sm tracking-wider uppercase flex items-center gap-2">
            <LifeBuoy className="w-4 h-4" />
            {t("support.allTickets")}
          </CardTitle>
          <div className="flex items-center gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[130px] text-xs" data-testid="select-status-filter">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">{t("common.all")}</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
                <SelectItem value="closed">Closed</SelectItem>
              </SelectContent>
            </Select>
            <Badge variant="secondary" className="font-mono text-xs">{filtered.length}</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-400px)]">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider">ID</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Subject</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Org</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("common.status")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Priority</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Category</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Remote</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("common.time")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((ticket) => (
                  <TableRow
                    key={ticket.id}
                    className="cursor-pointer hover:bg-muted/30"
                    onClick={() => setSelectedTicket(ticket)}
                    data-testid={`admin-ticket-row-${ticket.id}`}
                  >
                    <TableCell className="text-xs font-mono">#{ticket.id}</TableCell>
                    <TableCell className="text-xs max-w-[200px] truncate">{ticket.subject}</TableCell>
                    <TableCell className="text-xs font-mono">#{ticket.organizationId}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[9px] ${
                        ticket.status === "open" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
                        : ticket.status === "in_progress" ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                        : ticket.status === "resolved" ? "bg-green-500/20 text-green-400 border-green-500/30"
                        : "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"
                      }`}>{ticket.status.replace("_", " ").toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className={`text-[9px] ${
                        ticket.priority === "critical" ? "bg-red-500/20 text-red-400 border-red-500/30"
                        : ticket.priority === "high" ? "bg-orange-500/20 text-orange-400 border-orange-500/30"
                        : ticket.priority === "medium" ? "bg-blue-500/20 text-blue-400 border-blue-500/30"
                        : "bg-zinc-500/20 text-zinc-400 border-zinc-500/30"
                      }`}>{ticket.priority.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell className="text-xs">{ticket.category}</TableCell>
                    <TableCell>
                      {ticket.remoteSessionActive ? (
                        <Badge className="text-[9px] bg-green-500/20 text-green-400"><Wifi className="w-3 h-3 ltr:mr-1 rtl:ml-1" />Live</Badge>
                      ) : ticket.remoteSessionRequested ? (
                        <Badge className="text-[9px] bg-yellow-500/20 text-yellow-400">Requested</Badge>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">--</span>
                      )}
                    </TableCell>
                    <TableCell className="text-[10px] text-muted-foreground font-mono whitespace-nowrap">
                      {formatDate(ticket.createdAt as unknown as string)}
                    </TableCell>
                  </TableRow>
                ))}
                {filtered.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} className="text-center text-sm text-muted-foreground py-12">
                      {t("support.noTicketsAdmin")}
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
