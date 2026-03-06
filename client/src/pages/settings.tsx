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
import {
  Building2, Users, UserPlus, Copy, Shield, Zap, Play, Loader2,
  ShieldCheck, ShieldAlert, ShieldOff,
} from "lucide-react";
import type { Organization, Invite } from "@shared/schema";
import { useState } from "react";

const roleColors: Record<string, string> = {
  admin: "bg-severity-critical text-white",
  analyst: "bg-primary text-white",
  auditor: "bg-severity-medium text-black",
  readonly: "bg-muted text-muted-foreground",
};

export default function SettingsPage() {
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
            <Users className="w-4 h-4 text-primary" />{t("settings.teamMembers")}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
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
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
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
            <Table>
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
            </Table>
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
    </div>
  );
}
