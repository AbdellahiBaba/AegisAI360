import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Building2, Users, UserPlus, Copy, Shield, Zap, Play, Loader2,
  ShieldCheck, ShieldAlert, ShieldOff, Trash2, Clock, KeyRound,
  Bell, Webhook, Mail, Plus, Send, Power, X, Key, RotateCcw, Ban, Check, Monitor, AlertTriangle,
  FileText, History, Search, Download, Calendar,
} from "lucide-react";
import type { Organization, Invite, NotificationChannel, ApiKey, SessionMetadata, AuditLog, ScheduledReport, LoginHistory } from "@shared/schema";
import { useState, useEffect, useMemo } from "react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const roleColors: Record<string, string> = {
  admin: "bg-severity-critical text-white",
  analyst: "bg-primary text-white",
  auditor: "bg-severity-medium text-black",
  readonly: "bg-muted text-muted-foreground",
};

export default function SettingsPage() {
  useDocumentTitle("Settings");
  const { t } = useTranslation();
  const { toast } = useToast();
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const { data: org, isLoading: orgLoading } = useQuery<Organization>({ queryKey: ["/api/organization"] });
  const { data: orgUsers } = useQuery<{ id: string; username: string; role: string }[]>({ queryKey: ["/api/organization/users"] });
  const { data: invites } = useQuery<Invite[]>({ queryKey: ["/api/invites"], enabled: isAdmin });
  const { data: defenseData } = useQuery<{ defenseMode: string }>({ queryKey: ["/api/settings/defense-mode"] });
  const { data: scenarios } = useQuery<{ id: string; name: string; description: string }[]>({ queryKey: ["/api/simulate/scenarios"] });
  const [runningScenario, setRunningScenario] = useState<string | null>(null);

  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [twoFASetup, setTwoFASetup] = useState<{ secret: string; qrCode: string } | null>(null);
  const [totpVerifyCode, setTotpVerifyCode] = useState("");

  const { data: apiKeysData } = useQuery<ApiKey[]>({ queryKey: ["/api/api-keys"], enabled: isAdmin });
  const [showCreateKeyDialog, setShowCreateKeyDialog] = useState(false);
  const [newKeyRevealed, setNewKeyRevealed] = useState<string | null>(null);
  const [rotatedKeyRevealed, setRotatedKeyRevealed] = useState<{ rawKey: string; oldKeyId: number; gracePeriodEnds: string } | null>(null);

  const createApiKeyForm = useForm({
    defaultValues: { name: "", description: "", expiresAt: "", permissions: "ingest" },
  });

  const createApiKeyMutation = useMutation({
    mutationFn: async (data: { name: string; description?: string; expiresAt?: string; permissions?: string }) => {
      const payload: any = { name: data.name, permissions: data.permissions || "ingest" };
      if (data.description) payload.description = data.description;
      if (data.expiresAt) payload.expiresAt = new Date(data.expiresAt).toISOString();
      const res = await apiRequest("POST", "/api/api-keys", payload);
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      setNewKeyRevealed(data.rawKey);
      createApiKeyForm.reset();
      toast({ title: "API Key Created" });
    },
    onError: () => {
      toast({ title: "Failed to create API key", variant: "destructive" });
    },
  });

  const revokeApiKeyMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("POST", `/api/api-keys/${id}/revoke`, {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API Key Revoked" });
    },
  });

  const rotateApiKeyMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("POST", `/api/api-keys/${id}/rotate`, {});
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      setRotatedKeyRevealed({ rawKey: data.rawKey, oldKeyId: data.oldKeyId, gracePeriodEnds: data.gracePeriodEnds });
      toast({ title: "API Key Rotated", description: "Old key will remain valid for 24 hours" });
    },
    onError: () => {
      toast({ title: "Failed to rotate API key", variant: "destructive" });
    },
  });

  const deleteApiKeyMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("DELETE", `/api/api-keys/${id}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/api-keys"] });
      toast({ title: "API Key Deleted" });
    },
  });

  const getKeyStatus = (key: ApiKey): { label: string; variant: "default" | "secondary" | "destructive" | "outline" } => {
    if (key.revokedAt) return { label: "Revoked", variant: "destructive" };
    if (key.expiresAt && new Date(key.expiresAt) < new Date()) return { label: "Expired", variant: "destructive" };
    return { label: "Active", variant: "default" };
  };

  const setup2FAMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/2fa/setup", {});
      return res.json();
    },
    onSuccess: (data: { secret: string; qrCode: string }) => {
      setTwoFASetup(data);
    },
    onError: (error: Error) => {
      toast({ title: "2FA Setup Failed", description: error.message, variant: "destructive" });
    },
  });

  const enable2FAMutation = useMutation({
    mutationFn: async (code: string) => {
      const res = await apiRequest("POST", "/api/auth/2fa/enable", { code });
      return res.json();
    },
    onSuccess: () => {
      setTwoFASetup(null);
      setTotpVerifyCode("");
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      toast({ title: "Two-Factor Authentication Enabled", description: "Your account is now secured with 2FA" });
    },
    onError: (error: Error) => {
      toast({ title: "Verification Failed", description: error.message, variant: "destructive" });
    },
  });

  const disable2FAMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/2fa/disable", {});
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      toast({ title: "Two-Factor Authentication Disabled" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to Disable 2FA", description: error.message, variant: "destructive" });
    },
  });

  const { data: channels } = useQuery<NotificationChannel[]>({
    queryKey: ["/api/settings/notification-channels"],
    enabled: isAdmin,
  });

  const [showAddChannel, setShowAddChannel] = useState(false);
  const [newChannelType, setNewChannelType] = useState<"webhook" | "email">("webhook");
  const [newChannelName, setNewChannelName] = useState("");
  const [newChannelUrl, setNewChannelUrl] = useState("");
  const [newChannelSecret, setNewChannelSecret] = useState("");
  const [newChannelRecipients, setNewChannelRecipients] = useState("");
  const [testingChannelId, setTestingChannelId] = useState<number | null>(null);

  const createChannelMutation = useMutation({
    mutationFn: async () => {
      const config = newChannelType === "webhook"
        ? { url: newChannelUrl, secret: newChannelSecret || undefined }
        : { recipients: newChannelRecipients };
      const res = await apiRequest("POST", "/api/settings/notification-channels", {
        name: newChannelName,
        type: newChannelType,
        config,
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/notification-channels"] });
      setShowAddChannel(false);
      setNewChannelName("");
      setNewChannelUrl("");
      setNewChannelSecret("");
      setNewChannelRecipients("");
      toast({ title: "Notification channel created" });
    },
    onError: () => {
      toast({ title: "Failed to create channel", variant: "destructive" });
    },
  });

  const toggleChannelMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/settings/notification-channels/${id}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/notification-channels"] });
    },
  });

  const deleteChannelMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("DELETE", `/api/settings/notification-channels/${id}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/notification-channels"] });
      toast({ title: "Channel deleted" });
    },
  });

  const testChannelMutation = useMutation({
    mutationFn: async (id: number) => {
      setTestingChannelId(id);
      const res = await apiRequest("POST", `/api/settings/notification-channels/${id}/test`);
      return res.json();
    },
    onSuccess: (data) => {
      setTestingChannelId(null);
      if (data.success) {
        queryClient.invalidateQueries({ queryKey: ["/api/settings/notification-channels"] });
        toast({ title: "Test notification sent successfully" });
      } else {
        toast({ title: "Test failed", description: data.error, variant: "destructive" });
      }
    },
    onError: () => {
      setTestingChannelId(null);
      toast({ title: "Test failed", variant: "destructive" });
    },
  });

  const { data: retentionData } = useQuery<{ logRetentionDays: number; auditRetentionDays: number }>({
    queryKey: ["/api/settings/retention"],
  });

  const [logDays, setLogDays] = useState<number | "">(90);
  const [auditDays, setAuditDays] = useState<number | "">(365);
  const [retentionInitialized, setRetentionInitialized] = useState(false);

  useEffect(() => {
    if (retentionData && !retentionInitialized) {
      setLogDays(retentionData.logRetentionDays);
      setAuditDays(retentionData.auditRetentionDays);
      setRetentionInitialized(true);
    }
  }, [retentionData, retentionInitialized]);

  const updateRetentionMutation = useMutation({
    mutationFn: async (data: { logRetentionDays: number; auditRetentionDays: number }) => {
      const res = await apiRequest("PATCH", "/api/settings/retention", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/retention"] });
      toast({ title: t("settings.retentionUpdated") });
    },
    onError: () => {
      toast({ title: t("settings.retentionUpdateFailed"), variant: "destructive" });
    },
  });

  const runCleanupMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/settings/retention/run-now", {});
      return res.json();
    },
    onSuccess: (data) => {
      const stats = data.stats;
      const total = (stats?.deletedEvents || 0) + (stats?.deletedAuditLogs || 0) + (stats?.deletedHoneypot || 0) + (stats?.deletedCaptures || 0) + (stats?.deletedCommands || 0);
      toast({ title: t("settings.cleanupComplete"), description: `${total} records removed` });
    },
    onError: () => {
      toast({ title: t("settings.cleanupFailed"), variant: "destructive" });
    },
  });

  type SessionWithCurrent = SessionMetadata & { isCurrent: boolean };
  const { data: sessions, isLoading: sessionsLoading } = useQuery<SessionWithCurrent[]>({
    queryKey: ["/api/auth/sessions"],
  });

  const revokeSessionMutation = useMutation({
    mutationFn: async (sessionId: string) => {
      const res = await apiRequest("DELETE", `/api/auth/sessions/${sessionId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/sessions"] });
      toast({ title: "Session revoked" });
    },
    onError: () => {
      toast({ title: "Failed to revoke session", variant: "destructive" });
    },
  });

  const revokeAllSessionsMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/auth/sessions/revoke-all", {});
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/auth/sessions"] });
      toast({ title: "All other sessions revoked", description: `${data.revokedCount} session(s) revoked` });
    },
    onError: () => {
      toast({ title: "Failed to revoke sessions", variant: "destructive" });
    },
  });

  const orgForm = useForm({ defaultValues: { name: org?.name || "" } });

  const updateOrgMutation = useMutation({
    mutationFn: async (data: { name: string }) => {
      const res = await apiRequest("PATCH", "/api/organization", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/organization"] });
      toast({ title: t("settings.orgUpdated") });
    },
  });

  const inviteForm = useForm({ defaultValues: { role: "analyst", email: "" } });

  const createInviteMutation = useMutation({
    mutationFn: async (data: { role: string; email?: string }) => {
      const res = await apiRequest("POST", "/api/invites", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/invites"] });
      inviteForm.reset();
      toast({ title: t("settings.inviteCreated") });
    },
  });

  const updateRoleMutation = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: string }) => {
      const res = await apiRequest("PATCH", `/api/organization/users/${userId}/role`, { role });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/organization/users"] });
      toast({ title: t("settings.roleUpdated") });
    },
  });

  const updateDefenseModeMutation = useMutation({
    mutationFn: async (defenseMode: string) => {
      const res = await apiRequest("PATCH", "/api/settings/defense-mode", { defenseMode });
      return res.json();
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/defense-mode"] });
      toast({ title: t("settings.defenseModeUpdated"), description: data.defenseMode });
    },
  });

  const simulateMutation = useMutation({
    mutationFn: async (scenario: string) => {
      setRunningScenario(scenario);
      const res = await apiRequest("POST", `/api/simulate/${scenario}`, {});
      return res.json();
    },
    onSuccess: (data) => {
      toast({ title: t("settings.simulationStarted"), description: data.scenario });
      setTimeout(() => {
        setRunningScenario(null);
        queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
        queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
        toast({ title: t("settings.simulationComplete") });
      }, 5000);
    },
    onError: () => {
      setRunningScenario(null);
      toast({ title: t("settings.simulationFailed"), variant: "destructive" });
    },
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (userId: string) => {
      const res = await apiRequest("DELETE", `/api/organization/users/${userId}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/organization/users"] });
      setDeleteConfirmUserId(null);
      toast({ title: "User removed from organization" });
    },
    onError: (error: Error) => {
      toast({ title: "Failed to remove user", description: error.message, variant: "destructive" });
    },
  });

  const [deleteConfirmUserId, setDeleteConfirmUserId] = useState<string | null>(null);

  const { data: auditLogs, isLoading: auditLogsLoading } = useQuery<AuditLog[]>({
    queryKey: ["/api/audit-logs"],
    enabled: isAdmin,
  });
  const [auditSearch, setAuditSearch] = useState("");
  const [auditActionFilter, setAuditActionFilter] = useState<string>("all");

  const filteredAuditLogs = useMemo(() => {
    if (!auditLogs) return [];
    let filtered = auditLogs;
    if (auditActionFilter !== "all") {
      filtered = filtered.filter(l => l.action === auditActionFilter);
    }
    if (auditSearch) {
      const q = auditSearch.toLowerCase();
      filtered = filtered.filter(l =>
        l.action.toLowerCase().includes(q) ||
        (l.details && l.details.toLowerCase().includes(q)) ||
        (l.userId && l.userId.toLowerCase().includes(q)) ||
        (l.targetType && l.targetType.toLowerCase().includes(q))
      );
    }
    return filtered;
  }, [auditLogs, auditSearch, auditActionFilter]);

  const auditActions = useMemo(() => {
    if (!auditLogs) return [];
    return [...new Set(auditLogs.map(l => l.action))].sort();
  }, [auditLogs]);

  const exportAuditCsv = () => {
    if (!filteredAuditLogs.length) return;
    const headers = ["ID", "Action", "User ID", "Target Type", "Target ID", "Details", "IP Address", "Timestamp"];
    const rows = filteredAuditLogs.map(l => [
      l.id, l.action, l.userId || "", l.targetType || "", l.targetId || "",
      l.details || "", l.ipAddress || "",
      l.createdAt ? new Date(l.createdAt).toISOString() : "",
    ]);
    const safeCsv = (v: string | number) => {
      let s = String(v);
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
      return `"${s.replace(/"/g, '""')}"`;
    };
    const csv = [headers.join(","), ...rows.map(r => r.map(safeCsv).join(","))].join("\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const { data: loginHistoryData, isLoading: loginHistoryLoading } = useQuery<LoginHistory[]>({
    queryKey: ["/api/login-history"],
    enabled: isAdmin,
  });

  const { data: scheduledReportsData } = useQuery<ScheduledReport[]>({
    queryKey: ["/api/scheduled-reports"],
    enabled: isAdmin,
  });

  const [showCreateReport, setShowCreateReport] = useState(false);
  const [newReportType, setNewReportType] = useState("executive_summary");
  const [newReportFrequency, setNewReportFrequency] = useState("weekly");
  const [newReportRecipients, setNewReportRecipients] = useState("");

  const createReportMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/scheduled-reports", {
        reportType: newReportType,
        frequency: newReportFrequency,
        recipients: newReportRecipients,
      });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-reports"] });
      setShowCreateReport(false);
      setNewReportRecipients("");
      toast({ title: "Scheduled report created" });
    },
    onError: () => {
      toast({ title: "Failed to create report", variant: "destructive" });
    },
  });

  const toggleReportMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/scheduled-reports/${id}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-reports"] });
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("DELETE", `/api/scheduled-reports/${id}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-reports"] });
      toast({ title: "Report schedule deleted" });
    },
  });

  const copyInviteCode = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(code);
    setTimeout(() => setCopiedCode(null), 2000);
    toast({ title: t("settings.inviteCodeCopied") });
  };

  if (orgLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[300px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase">{t("settings.title")}</h1>
        <p className="text-xs text-muted-foreground">{t("settings.subtitle")}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Building2 className="w-4 h-4 text-primary" />{t("settings.orgDetails")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{t("settings.plan")}</span>
                <Badge variant="secondary" className="text-xs capitalize" data-testid="text-org-plan">{org?.plan}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{t("settings.maxUsers")}</span>
                <span className="text-xs font-mono" data-testid="text-max-users">{org?.maxUsers}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-muted-foreground">{t("settings.currentUsers")}</span>
                <span className="text-xs font-mono" data-testid="text-current-users">{orgUsers?.length || 0}</span>
              </div>
              {isAdmin && (
                <Form {...orgForm}>
                  <form onSubmit={orgForm.handleSubmit((d) => updateOrgMutation.mutate(d))} className="flex gap-2 mt-3">
                    <FormField control={orgForm.control} name="name" render={({ field }) => (
                      <FormItem className="flex-1"><FormControl>
                        <Input {...field} placeholder={t("settings.orgName")} defaultValue={org?.name} data-testid="input-org-name" />
                      </FormControl></FormItem>
                    )} />
                    <Button type="submit" size="sm" disabled={updateOrgMutation.isPending} data-testid="button-update-org">{t("common.save")}</Button>
                  </form>
                </Form>
              )}
            </div>
          </CardContent>
        </Card>

        {isAdmin && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
                <UserPlus className="w-4 h-4 text-primary" />{t("settings.inviteTeamMember")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Form {...inviteForm}>
                <form onSubmit={inviteForm.handleSubmit((d) => createInviteMutation.mutate(d))} className="space-y-3">
                  <FormField control={inviteForm.control} name="email" render={({ field }) => (
                    <FormItem><FormLabel>{t("settings.emailOptional")}</FormLabel><FormControl>
                      <Input {...field} placeholder={t("settings.emailPlaceholder")} data-testid="input-invite-email" />
                    </FormControl></FormItem>
                  )} />
                  <FormField control={inviteForm.control} name="role" render={({ field }) => (
                    <FormItem><FormLabel>{t("settings.role")}</FormLabel><FormControl>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <SelectTrigger data-testid="select-invite-role"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="admin">{t("settings.admin")}</SelectItem>
                          <SelectItem value="analyst">{t("settings.analyst")}</SelectItem>
                          <SelectItem value="auditor">{t("settings.auditor")}</SelectItem>
                          <SelectItem value="readonly">{t("settings.readOnly")}</SelectItem>
                        </SelectContent>
                      </Select>
                    </FormControl></FormItem>
                  )} />
                  <Button type="submit" className="w-full" disabled={createInviteMutation.isPending} data-testid="button-create-invite">
                    {createInviteMutation.isPending ? t("common.creating") : t("settings.generateInvite")}
                  </Button>
                </form>
              </Form>
            </CardContent>
          </Card>
        )}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-primary" />Two-Factor Authentication
          </CardTitle>
        </CardHeader>
        <CardContent>
          {user?.totpEnabled ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-5 h-5 text-green-500" />
                <div>
                  <p className="text-sm font-medium" data-testid="text-2fa-enabled">2FA is enabled</p>
                  <p className="text-xs text-muted-foreground">Your account is protected with an authenticator app</p>
                </div>
              </div>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => disable2FAMutation.mutate()}
                disabled={disable2FAMutation.isPending}
                data-testid="button-disable-2fa"
              >
                {disable2FAMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : null}
                Disable 2FA
              </Button>
            </div>
          ) : twoFASetup ? (
            <div className="space-y-4">
              <p className="text-xs text-muted-foreground">Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
              <div className="flex justify-center">
                <img src={twoFASetup.qrCode} alt="2FA QR Code" className="w-48 h-48 rounded border" data-testid="img-2fa-qrcode" />
              </div>
              <div className="bg-muted p-2 rounded">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Manual Entry Key</p>
                <code className="text-xs font-mono break-all select-all" data-testid="text-2fa-secret">{twoFASetup.secret}</code>
              </div>
              <div className="space-y-2">
                <label className="text-[10px] uppercase tracking-wider text-muted-foreground">Verification Code</label>
                <Input
                  value={totpVerifyCode}
                  onChange={(e) => setTotpVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  className="font-mono text-center text-lg tracking-[0.3em]"
                  data-testid="input-2fa-verify"
                />
              </div>
              <div className="flex gap-2">
                <Button
                  onClick={() => enable2FAMutation.mutate(totpVerifyCode)}
                  disabled={totpVerifyCode.length !== 6 || enable2FAMutation.isPending}
                  className="flex-1"
                  data-testid="button-enable-2fa"
                >
                  {enable2FAMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : null}
                  Enable 2FA
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => { setTwoFASetup(null); setTotpVerifyCode(""); }}
                  data-testid="button-cancel-2fa-setup"
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <ShieldOff className="w-5 h-5 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium" data-testid="text-2fa-disabled">2FA is not enabled</p>
                  <p className="text-xs text-muted-foreground">Add an extra layer of security to your account</p>
                </div>
              </div>
              <Button
                onClick={() => setup2FAMutation.mutate()}
                disabled={setup2FAMutation.isPending}
                data-testid="button-setup-2fa"
              >
                {setup2FAMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : null}
                Set Up 2FA
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center justify-between gap-2 flex-wrap">
            <span className="flex items-center gap-2">
              <Monitor className="w-4 h-4 text-primary" />Active Sessions
            </span>
            {sessions && sessions.length > 1 && (
              <Button
                variant="destructive"
                size="sm"
                onClick={() => revokeAllSessionsMutation.mutate()}
                disabled={revokeAllSessionsMutation.isPending}
                data-testid="button-revoke-all-sessions"
              >
                {revokeAllSessionsMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin me-1" /> : <AlertTriangle className="w-3 h-3 me-1" />}
                Revoke All Other Sessions
              </Button>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {sessionsLoading ? (
            <div className="p-4"><Skeleton className="h-20 w-full" /></div>
          ) : sessions && sessions.length > 0 ? (
            <div className="overflow-x-auto"><Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider">Device / Browser</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">IP Address</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Last Active</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => {
                  const ua = session.userAgent || "Unknown";
                  const browser = ua.includes("Firefox") ? "Firefox"
                    : ua.includes("Edg") ? "Edge"
                    : ua.includes("Chrome") ? "Chrome"
                    : ua.includes("Safari") ? "Safari"
                    : "Unknown Browser";
                  const os = ua.includes("Windows") ? "Windows"
                    : ua.includes("Mac") ? "macOS"
                    : ua.includes("Linux") ? "Linux"
                    : ua.includes("Android") ? "Android"
                    : ua.includes("iPhone") ? "iOS"
                    : "Unknown OS";
                  return (
                    <TableRow key={session.sessionId} data-testid={`session-row-${session.id}`}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <Monitor className="w-4 h-4 text-muted-foreground" />
                          <div>
                            <span className="text-xs font-medium" data-testid={`text-session-browser-${session.id}`}>{browser} on {os}</span>
                            {session.isCurrent && (
                              <Badge variant="default" className="ms-2 text-[9px]">Current</Badge>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs font-mono text-muted-foreground" data-testid={`text-session-ip-${session.id}`}>{session.ipAddress || "Unknown"}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs text-muted-foreground" data-testid={`text-session-active-${session.id}`}>
                          {new Date(session.lastActive).toLocaleString()}
                        </span>
                      </TableCell>
                      <TableCell>
                        {!session.isCurrent && (
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => revokeSessionMutation.mutate(session.sessionId)}
                            disabled={revokeSessionMutation.isPending}
                            data-testid={`button-revoke-session-${session.id}`}
                          >
                            <Trash2 className="w-4 h-4 text-destructive" />
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table></div>
          ) : (
            <div className="p-4 text-center text-xs text-muted-foreground">No active sessions found</div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <Users className="w-4 h-4 text-primary" />{t("settings.teamMembers")}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto"><Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("settings.username")}</TableHead>
                <TableHead className="text-[10px] uppercase tracking-wider">{t("settings.role")}</TableHead>
                {isAdmin && <TableHead className="text-[10px] uppercase tracking-wider">{t("common.actions")}</TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {orgUsers?.map((u) => (
                <TableRow key={u.id} data-testid={`user-row-${u.id}`}>
                  <TableCell>
                    <span className="text-xs font-mono" data-testid={`user-name-${u.id}`}>{u.username}</span>
                    {u.id === user?.id && <Badge variant="secondary" className="ms-2 text-[10px]">{t("common.you")}</Badge>}
                  </TableCell>
                  <TableCell>
                    <Badge className={`text-[10px] ${roleColors[u.role] || roleColors.readonly}`}>{u.role}</Badge>
                  </TableCell>
                  {isAdmin && (
                    <TableCell>
                      <div className="flex items-center gap-1">
                        {u.id !== user?.id && (
                          <Select
                            value={u.role}
                            onValueChange={(role) => updateRoleMutation.mutate({ userId: u.id, role })}
                          >
                            <SelectTrigger className="w-28 h-7 text-[10px]" data-testid={`select-role-${u.id}`}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="admin">{t("settings.admin")}</SelectItem>
                              <SelectItem value="analyst">{t("settings.analyst")}</SelectItem>
                              <SelectItem value="auditor">{t("settings.auditor")}</SelectItem>
                              <SelectItem value="readonly">{t("settings.readOnly")}</SelectItem>
                            </SelectContent>
                          </Select>
                        )}
                        {u.id !== user?.id && (
                          deleteConfirmUserId === u.id ? (
                            <div className="flex items-center gap-1">
                              <Button
                                size="sm"
                                variant="destructive"
                                className="h-7 text-[10px]"
                                onClick={() => deleteUserMutation.mutate(u.id)}
                                disabled={deleteUserMutation.isPending}
                                data-testid={`button-confirm-delete-user-${u.id}`}
                              >
                                {deleteUserMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : "Confirm"}
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 text-[10px]"
                                onClick={() => setDeleteConfirmUserId(null)}
                                data-testid={`button-cancel-delete-user-${u.id}`}
                              >
                                Cancel
                              </Button>
                            </div>
                          ) : (
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-7 w-7"
                              onClick={() => setDeleteConfirmUserId(u.id)}
                              data-testid={`button-delete-user-${u.id}`}
                            >
                              <Trash2 className="w-3 h-3 text-destructive" />
                            </Button>
                          )
                        )}
                      </div>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table></div>
        </CardContent>
      </Card>

      {isAdmin && invites && invites.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />{t("settings.activeInvites")}
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto"><Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("settings.code")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("settings.role")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("common.status")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("settings.expires")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("common.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {invites.map((invite) => (
                  <TableRow key={invite.id} data-testid={`invite-row-${invite.id}`}>
                    <TableCell>
                      <span className="text-xs font-mono">{invite.code.slice(0, 8)}...</span>
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-[10px] ${roleColors[invite.role] || roleColors.readonly}`}>{invite.role}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={invite.used ? "secondary" : "default"} className="text-[10px]">
                        {invite.used ? t("common.used") : t("common.pending")}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {new Date(invite.expiresAt).toLocaleDateString()}
                      </span>
                    </TableCell>
                    <TableCell>
                      {!invite.used && (
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2"
                          onClick={() => copyInviteCode(invite.code)}
                          data-testid={`button-copy-invite-${invite.id}`}
                        >
                          <Copy className="w-3 h-3 me-1" />
                          {copiedCode === invite.code ? t("common.copied") : t("common.copy")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table></div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Zap className="w-4 h-4 text-primary" />{t("settings.defenseMode")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">{t("settings.defenseModeDescription")}</p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {[
                { mode: "auto", icon: ShieldCheck, label: t("settings.autoMode"), desc: t("settings.autoModeDesc"), color: "border-green-500/50" },
                { mode: "semi-auto", icon: ShieldAlert, label: t("settings.semiAutoMode"), desc: t("settings.semiAutoModeDesc"), color: "border-yellow-500/50" },
                { mode: "manual", icon: ShieldOff, label: t("settings.manualMode"), desc: t("settings.manualModeDesc"), color: "border-red-500/50" },
              ].map(({ mode, icon: ModeIcon, label, desc, color }) => (
                <button
                  key={mode}
                  onClick={() => updateDefenseModeMutation.mutate(mode)}
                  disabled={updateDefenseModeMutation.isPending}
                  data-testid={`button-defense-${mode}`}
                  className={`p-4 rounded-lg border-2 text-start transition-all ${
                    defenseData?.defenseMode === mode
                      ? `${color} bg-primary/5`
                      : "border-border hover:border-primary/30"
                  }`}
                >
                  <div className="flex items-center gap-2 mb-2">
                    <ModeIcon className={`w-5 h-5 ${defenseData?.defenseMode === mode ? "text-primary" : "text-muted-foreground"}`} />
                    <span className="text-sm font-semibold">{label}</span>
                    {defenseData?.defenseMode === mode && (
                      <Badge className="text-[9px] ms-auto">{t("common.active")}</Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-muted-foreground">{desc}</p>
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Play className="w-4 h-4 text-primary" />{t("settings.threatSimulator")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">{t("settings.simulatorDescription")}</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {scenarios?.map((scenario) => (
                <Card key={scenario.id} className="overflow-hidden">
                  <CardContent className="p-4">
                    <h3 className="text-xs font-semibold mb-1" data-testid={`text-scenario-${scenario.id}`}>{scenario.name}</h3>
                    <p className="text-[10px] text-muted-foreground mb-3 line-clamp-2">{scenario.description}</p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="w-full text-xs"
                      disabled={!!runningScenario}
                      onClick={() => simulateMutation.mutate(scenario.id)}
                      data-testid={`button-simulate-${scenario.id}`}
                    >
                      {runningScenario === scenario.id ? (
                        <><Loader2 className="w-3 h-3 me-1.5 animate-spin" />{t("settings.simulating")}</>
                      ) : (
                        <><Play className="w-3 h-3 me-1.5" />{t("settings.runSimulation")}</>
                      )}
                    </Button>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center flex-wrap gap-2">
              <Bell className="w-4 h-4 text-primary" />Notification Channels
              <Button
                size="sm"
                variant="outline"
                className="ms-auto text-xs"
                onClick={() => setShowAddChannel(!showAddChannel)}
                data-testid="button-add-channel"
              >
                {showAddChannel ? <X className="w-3 h-3 me-1" /> : <Plus className="w-3 h-3 me-1" />}
                {showAddChannel ? "Cancel" : "Add Channel"}
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">
              Configure webhook or email channels to receive alert notifications outside the dashboard.
            </p>

            {showAddChannel && (
              <Card className="mb-4">
                <CardContent className="p-4 space-y-3">
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant={newChannelType === "webhook" ? "default" : "outline"}
                      onClick={() => setNewChannelType("webhook")}
                      data-testid="button-type-webhook"
                    >
                      <Webhook className="w-3 h-3 me-1" />Webhook
                    </Button>
                    <Button
                      size="sm"
                      variant={newChannelType === "email" ? "default" : "outline"}
                      onClick={() => setNewChannelType("email")}
                      data-testid="button-type-email"
                    >
                      <Mail className="w-3 h-3 me-1" />Email
                    </Button>
                  </div>
                  <div>
                    <label className="text-xs font-medium">Channel Name</label>
                    <Input
                      value={newChannelName}
                      onChange={(e) => setNewChannelName(e.target.value)}
                      placeholder="e.g. Slack Alerts, Security Team Email"
                      data-testid="input-channel-name"
                    />
                  </div>
                  {newChannelType === "webhook" ? (
                    <>
                      <div>
                        <label className="text-xs font-medium">Webhook URL</label>
                        <Input
                          value={newChannelUrl}
                          onChange={(e) => setNewChannelUrl(e.target.value)}
                          placeholder="https://hooks.slack.com/services/..."
                          data-testid="input-channel-url"
                        />
                      </div>
                      <div>
                        <label className="text-xs font-medium">Secret (optional, for HMAC signature)</label>
                        <Input
                          value={newChannelSecret}
                          onChange={(e) => setNewChannelSecret(e.target.value)}
                          placeholder="Optional signing secret"
                          data-testid="input-channel-secret"
                        />
                      </div>
                    </>
                  ) : (
                    <div>
                      <label className="text-xs font-medium">Recipients (comma-separated)</label>
                      <Input
                        value={newChannelRecipients}
                        onChange={(e) => setNewChannelRecipients(e.target.value)}
                        placeholder="admin@company.com, soc@company.com"
                        data-testid="input-channel-recipients"
                      />
                      <p className="text-[10px] text-muted-foreground mt-1">
                        Requires SMTP configuration (SMTP_HOST, SMTP_USER, SMTP_PASS env vars)
                      </p>
                    </div>
                  )}
                  <Button
                    onClick={() => createChannelMutation.mutate()}
                    disabled={createChannelMutation.isPending || !newChannelName || (newChannelType === "webhook" ? !newChannelUrl : !newChannelRecipients)}
                    data-testid="button-save-channel"
                  >
                    {createChannelMutation.isPending && <Loader2 className="w-3 h-3 me-1.5 animate-spin" />}
                    Create Channel
                  </Button>
                </CardContent>
              </Card>
            )}

            {channels && channels.length > 0 ? (
              <div className="overflow-x-auto"><Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-[10px] uppercase tracking-wider">Name</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Type</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Status</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Last Used</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {channels.map((ch) => (
                    <TableRow key={ch.id} data-testid={`channel-row-${ch.id}`}>
                      <TableCell>
                        <span className="text-xs font-medium" data-testid={`text-channel-name-${ch.id}`}>{ch.name}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">
                          {ch.type === "webhook" ? <Webhook className="w-3 h-3 me-1" /> : <Mail className="w-3 h-3 me-1" />}
                          {ch.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={ch.enabled}
                          onCheckedChange={(enabled) => toggleChannelMutation.mutate({ id: ch.id, enabled })}
                          data-testid={`switch-channel-${ch.id}`}
                        />
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {ch.lastUsed ? new Date(ch.lastUsed).toLocaleString() : "Never"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1">
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => testChannelMutation.mutate(ch.id)}
                            disabled={testingChannelId === ch.id}
                            data-testid={`button-test-channel-${ch.id}`}
                          >
                            {testingChannelId === ch.id ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            onClick={() => deleteChannelMutation.mutate(ch.id)}
                            data-testid={`button-delete-channel-${ch.id}`}
                          >
                            <Trash2 className="w-3 h-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table></div>
            ) : (
              <div className="text-center py-6 text-xs text-muted-foreground">
                No notification channels configured. Add a webhook or email channel to receive alerts.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <Trash2 className="w-4 h-4 text-primary" />{t("settings.dataRetention")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">{t("settings.dataRetentionDescription")}</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
              <div className="space-y-2">
                <label className="text-xs font-medium" htmlFor="logRetentionDays">{t("settings.logRetentionDays")}</label>
                <Input
                  id="logRetentionDays"
                  type="number"
                  min={7}
                  max={3650}
                  value={logDays}
                  onChange={(e) => setLogDays(e.target.value ? parseInt(e.target.value) : "")}
                  data-testid="input-log-retention-days"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-medium" htmlFor="auditRetentionDays">{t("settings.auditRetentionDays")}</label>
                <Input
                  id="auditRetentionDays"
                  type="number"
                  min={30}
                  max={3650}
                  value={auditDays}
                  onChange={(e) => setAuditDays(e.target.value ? parseInt(e.target.value) : "")}
                  data-testid="input-audit-retention-days"
                />
              </div>
            </div>
            <div className="space-y-1 mb-4">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>{t("settings.honeypotRetention")}</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>{t("settings.packetCaptureRetention")}</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3 h-3" />
                <span>{t("settings.commandRetention")}</span>
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => {
                  if (typeof logDays === "number" && typeof auditDays === "number") {
                    updateRetentionMutation.mutate({ logRetentionDays: logDays, auditRetentionDays: auditDays });
                  }
                }}
                disabled={updateRetentionMutation.isPending || logDays === "" || auditDays === ""}
                data-testid="button-save-retention"
              >
                {updateRetentionMutation.isPending ? <Loader2 className="w-3 h-3 me-1.5 animate-spin" /> : null}
                {t("common.save")}
              </Button>
              <Button
                variant="outline"
                onClick={() => runCleanupMutation.mutate()}
                disabled={runCleanupMutation.isPending}
                data-testid="button-run-cleanup"
              >
                {runCleanupMutation.isPending ? <Loader2 className="w-3 h-3 me-1.5 animate-spin" /> : <Trash2 className="w-3 h-3 me-1.5" />}
                {t("settings.runCleanupNow")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center justify-between gap-2 flex-wrap">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-primary" />
                API Keys
              </div>
              <Button
                size="sm"
                onClick={() => { setShowCreateKeyDialog(true); setNewKeyRevealed(null); }}
                data-testid="button-create-api-key"
              >
                <Plus className="w-3 h-3 me-1.5" />
                Create Key
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">
              Manage API keys for the ingestion pipeline. Keys can be rotated with a 24-hour grace period.
            </p>

            {newKeyRevealed && (
              <Card className="mb-4 border-green-500/50">
                <CardContent className="p-4">
                  <div className="flex items-start gap-2">
                    <Check className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-semibold text-green-600 dark:text-green-400 mb-1">New API Key Created</p>
                      <p className="text-[10px] text-muted-foreground mb-2">Copy this key now. It will not be shown again.</p>
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-[10px] font-mono bg-muted px-2 py-1 rounded break-all" data-testid="text-new-api-key">{newKeyRevealed}</code>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => { navigator.clipboard.writeText(newKeyRevealed); toast({ title: "Key copied to clipboard" }); }}
                          data-testid="button-copy-new-key"
                        >
                          <Copy className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                    <Button size="sm" variant="ghost" onClick={() => setNewKeyRevealed(null)} data-testid="button-dismiss-new-key">
                      <X className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {rotatedKeyRevealed && (
              <Card className="mb-4 border-blue-500/50">
                <CardContent className="p-4">
                  <div className="flex items-start gap-2">
                    <RotateCcw className="w-4 h-4 text-blue-500 mt-0.5 shrink-0" />
                    <div className="min-w-0 flex-1">
                      <p className="text-xs font-semibold text-blue-600 dark:text-blue-400 mb-1">Key Rotated Successfully</p>
                      <p className="text-[10px] text-muted-foreground mb-2">
                        Old key (#{rotatedKeyRevealed.oldKeyId}) will remain valid until {new Date(rotatedKeyRevealed.gracePeriodEnds).toLocaleString()}.
                      </p>
                      <div className="flex items-center gap-2 flex-wrap">
                        <code className="text-[10px] font-mono bg-muted px-2 py-1 rounded break-all" data-testid="text-rotated-api-key">{rotatedKeyRevealed.rawKey}</code>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => { navigator.clipboard.writeText(rotatedKeyRevealed.rawKey); toast({ title: "Key copied to clipboard" }); }}
                          data-testid="button-copy-rotated-key"
                        >
                          <Copy className="w-3 h-3" />
                        </Button>
                      </div>
                    </div>
                    <Button size="sm" variant="ghost" onClick={() => setRotatedKeyRevealed(null)} data-testid="button-dismiss-rotated-key">
                      <X className="w-3 h-3" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {apiKeysData && apiKeysData.length > 0 ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="text-[10px] uppercase tracking-wider">Name</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Prefix</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Status</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Last Used</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Expires</TableHead>
                      <TableHead className="text-[10px] uppercase tracking-wider">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {apiKeysData.map((key) => {
                      const status = getKeyStatus(key);
                      return (
                        <TableRow key={key.id} data-testid={`api-key-row-${key.id}`}>
                          <TableCell>
                            <div>
                              <span className="text-xs font-medium" data-testid={`text-key-name-${key.id}`}>{key.name}</span>
                              {key.description && (
                                <p className="text-[10px] text-muted-foreground">{key.description}</p>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <code className="text-[10px] font-mono bg-muted px-1.5 py-0.5 rounded" data-testid={`text-key-prefix-${key.id}`}>{key.keyPrefix}...</code>
                          </TableCell>
                          <TableCell>
                            <Badge variant={status.variant} className="text-[10px]" data-testid={`badge-key-status-${key.id}`}>
                              {status.label}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <span className="text-[10px] text-muted-foreground font-mono" data-testid={`text-key-lastused-${key.id}`}>
                              {key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : "Never"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <span className="text-[10px] text-muted-foreground font-mono" data-testid={`text-key-expires-${key.id}`}>
                              {key.expiresAt ? new Date(key.expiresAt).toLocaleDateString() : "Never"}
                            </span>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1">
                              {!key.revokedAt && !(key.expiresAt && new Date(key.expiresAt) < new Date()) && (
                                <>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => rotateApiKeyMutation.mutate(key.id)}
                                    disabled={rotateApiKeyMutation.isPending}
                                    data-testid={`button-rotate-key-${key.id}`}
                                  >
                                    <RotateCcw className="w-3 h-3" />
                                  </Button>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => revokeApiKeyMutation.mutate(key.id)}
                                    disabled={revokeApiKeyMutation.isPending}
                                    data-testid={`button-revoke-key-${key.id}`}
                                  >
                                    <Ban className="w-3 h-3" />
                                  </Button>
                                </>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => deleteApiKeyMutation.mutate(key.id)}
                                disabled={deleteApiKeyMutation.isPending}
                                data-testid={`button-delete-key-${key.id}`}
                              >
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground text-center py-6" data-testid="text-no-api-keys">
                No API keys yet. Create one to start ingesting security events.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center justify-between gap-2 flex-wrap">
              <span className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-primary" />Scheduled Reports
              </span>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => setShowCreateReport(!showCreateReport)}
                data-testid="button-add-report"
              >
                {showCreateReport ? <X className="w-3 h-3 me-1" /> : <Plus className="w-3 h-3 me-1" />}
                {showCreateReport ? "Cancel" : "Add Report"}
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground mb-4">
              Schedule automated security reports to be delivered via email.
            </p>

            {showCreateReport && (
              <Card className="mb-4">
                <CardContent className="p-4 space-y-3">
                  <div>
                    <label className="text-xs font-medium">Report Type</label>
                    <Select value={newReportType} onValueChange={setNewReportType}>
                      <SelectTrigger data-testid="select-report-type"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="executive_summary">Executive Summary</SelectItem>
                        <SelectItem value="compliance">Compliance Report</SelectItem>
                        <SelectItem value="incidents">Incident Report</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs font-medium">Frequency</label>
                    <Select value={newReportFrequency} onValueChange={setNewReportFrequency}>
                      <SelectTrigger data-testid="select-report-frequency"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="daily">Daily</SelectItem>
                        <SelectItem value="weekly">Weekly</SelectItem>
                        <SelectItem value="monthly">Monthly</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs font-medium">Recipients (comma-separated emails)</label>
                    <Input
                      value={newReportRecipients}
                      onChange={(e) => setNewReportRecipients(e.target.value)}
                      placeholder="admin@company.com, ciso@company.com"
                      data-testid="input-report-recipients"
                    />
                  </div>
                  <Button
                    onClick={() => createReportMutation.mutate()}
                    disabled={createReportMutation.isPending || !newReportRecipients}
                    data-testid="button-save-report"
                  >
                    {createReportMutation.isPending && <Loader2 className="w-3 h-3 me-1.5 animate-spin" />}
                    Create Schedule
                  </Button>
                </CardContent>
              </Card>
            )}

            {scheduledReportsData && scheduledReportsData.length > 0 ? (
              <div className="overflow-x-auto"><Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-[10px] uppercase tracking-wider">Type</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Frequency</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Recipients</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Next Run</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Enabled</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {scheduledReportsData.map((report) => (
                    <TableRow key={report.id} data-testid={`report-row-${report.id}`}>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px] capitalize" data-testid={`text-report-type-${report.id}`}>
                          {report.reportType.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs capitalize">{report.frequency}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground font-mono">{report.recipients}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {new Date(report.nextRun).toLocaleDateString()}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={report.enabled}
                          onCheckedChange={(enabled) => toggleReportMutation.mutate({ id: report.id, enabled })}
                          data-testid={`switch-report-${report.id}`}
                        />
                      </TableCell>
                      <TableCell>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteReportMutation.mutate(report.id)}
                          data-testid={`button-delete-report-${report.id}`}
                        >
                          <Trash2 className="w-3 h-3" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table></div>
            ) : (
              <div className="text-center py-6 text-xs text-muted-foreground">
                No scheduled reports. Create one to receive automated security summaries.
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center justify-between gap-2 flex-wrap">
              <span className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-primary" />Audit Log
              </span>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={exportAuditCsv}
                disabled={!filteredAuditLogs.length}
                data-testid="button-export-audit-csv"
              >
                <Download className="w-3 h-3 me-1" />Export CSV
              </Button>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2 mb-4">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute start-2.5 top-2.5 w-3 h-3 text-muted-foreground" />
                <Input
                  placeholder="Search audit logs..."
                  value={auditSearch}
                  onChange={(e) => setAuditSearch(e.target.value)}
                  className="ps-8 h-8 text-xs"
                  data-testid="input-audit-search"
                />
              </div>
              <Select value={auditActionFilter} onValueChange={setAuditActionFilter}>
                <SelectTrigger className="w-48 h-8 text-xs" data-testid="select-audit-action-filter">
                  <SelectValue placeholder="Filter by action" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Actions</SelectItem>
                  {auditActions.map(action => (
                    <SelectItem key={action} value={action}>{action.replace(/_/g, " ")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {auditLogsLoading ? (
              <Skeleton className="h-40 w-full" />
            ) : filteredAuditLogs.length > 0 ? (
              <div className="overflow-x-auto max-h-[400px] overflow-y-auto"><Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-[10px] uppercase tracking-wider">Action</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Target</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Details</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Timestamp</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAuditLogs.slice(0, 50).map((log) => (
                    <TableRow key={log.id} data-testid={`audit-row-${log.id}`}>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px]" data-testid={`text-audit-action-${log.id}`}>
                          {log.action.replace(/_/g, " ")}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground">
                          {log.targetType && <span className="font-medium">{log.targetType}</span>}
                          {log.targetId && <span className="font-mono ms-1">#{log.targetId.slice(0, 8)}</span>}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground line-clamp-1">{log.details || "-"}</span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {log.createdAt ? new Date(log.createdAt).toLocaleString() : "-"}
                        </span>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table></div>
            ) : (
              <div className="text-center py-6 text-xs text-muted-foreground">
                {auditSearch || auditActionFilter !== "all" ? "No matching audit logs found." : "No audit logs yet."}
              </div>
            )}
            {filteredAuditLogs.length > 50 && (
              <p className="text-[10px] text-muted-foreground text-center mt-2">
                Showing 50 of {filteredAuditLogs.length} entries. Export CSV for full data.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {isAdmin && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <History className="w-4 h-4 text-primary" />Login History
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            {loginHistoryLoading ? (
              <div className="p-4"><Skeleton className="h-20 w-full" /></div>
            ) : loginHistoryData && loginHistoryData.length > 0 ? (
              <div className="overflow-x-auto max-h-[400px] overflow-y-auto"><Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-[10px] uppercase tracking-wider">Action</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">User</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">IP Address</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Browser</TableHead>
                    <TableHead className="text-[10px] uppercase tracking-wider">Time</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loginHistoryData.map((entry) => {
                    const ua = entry.userAgent || "";
                    const browser = ua.includes("Firefox") ? "Firefox"
                      : ua.includes("Edg") ? "Edge"
                      : ua.includes("Chrome") ? "Chrome"
                      : ua.includes("Safari") ? "Safari"
                      : ua ? "Other" : "-";
                    const actionColors: Record<string, string> = {
                      login_success: "text-green-500",
                      login_failed: "text-destructive",
                      logout: "text-muted-foreground",
                      session_revoked: "text-yellow-500",
                    };
                    return (
                      <TableRow key={entry.id} data-testid={`login-history-row-${entry.id}`}>
                        <TableCell>
                          <span className={`text-[10px] font-medium capitalize ${actionColors[entry.action] || ""}`} data-testid={`text-login-action-${entry.id}`}>
                            {entry.action.replace(/_/g, " ")}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="text-[10px] font-mono text-muted-foreground">{entry.userId ? entry.userId.slice(0, 8) + "..." : "-"}</span>
                        </TableCell>
                        <TableCell>
                          <span className="text-[10px] font-mono text-muted-foreground">{entry.ipAddress || "-"}</span>
                        </TableCell>
                        <TableCell>
                          <span className="text-[10px] text-muted-foreground">{browser}</span>
                        </TableCell>
                        <TableCell>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            {entry.createdAt ? new Date(entry.createdAt).toLocaleString() : "-"}
                          </span>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table></div>
            ) : (
              <div className="p-4 text-center text-xs text-muted-foreground">No login history recorded yet.</div>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog open={showCreateKeyDialog} onOpenChange={(open) => { setShowCreateKeyDialog(open); if (!open) setNewKeyRevealed(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="w-4 h-4" />
              Create API Key
            </DialogTitle>
          </DialogHeader>
          <Form {...createApiKeyForm}>
            <form onSubmit={createApiKeyForm.handleSubmit((d) => createApiKeyMutation.mutate(d))} className="space-y-4">
              <FormField control={createApiKeyForm.control} name="name" render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="e.g. Production SIEM" data-testid="input-key-name" />
                  </FormControl>
                </FormItem>
              )} />
              <FormField control={createApiKeyForm.control} name="description" render={({ field }) => (
                <FormItem>
                  <FormLabel>Description (optional)</FormLabel>
                  <FormControl>
                    <Input {...field} placeholder="e.g. Used by Splunk forwarder" data-testid="input-key-description" />
                  </FormControl>
                </FormItem>
              )} />
              <FormField control={createApiKeyForm.control} name="expiresAt" render={({ field }) => (
                <FormItem>
                  <FormLabel>Expiration Date (optional)</FormLabel>
                  <FormControl>
                    <Input {...field} type="date" data-testid="input-key-expires" />
                  </FormControl>
                </FormItem>
              )} />
              <FormField control={createApiKeyForm.control} name="permissions" render={({ field }) => (
                <FormItem>
                  <FormLabel>Permissions</FormLabel>
                  <FormControl>
                    <Select onValueChange={field.onChange} value={field.value}>
                      <SelectTrigger data-testid="select-key-permissions"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ingest">Ingest Only</SelectItem>
                        <SelectItem value="read">Read Only</SelectItem>
                        <SelectItem value="full">Full Access</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl>
                </FormItem>
              )} />
              <Button type="submit" className="w-full" disabled={createApiKeyMutation.isPending} data-testid="button-submit-create-key">
                {createApiKeyMutation.isPending ? <Loader2 className="w-3 h-3 me-1.5 animate-spin" /> : <Key className="w-3 h-3 me-1.5" />}
                Create API Key
              </Button>
            </form>
          </Form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
