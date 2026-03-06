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
import { Building2, Users, UserPlus, Copy, Shield, Settings as SettingsIcon } from "lucide-react";
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
    </div>
  );
}
