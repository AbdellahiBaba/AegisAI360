import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { BookOpen, Plus, Zap, AlertTriangle, Clock, Bot, History, FlaskConical, Loader2 } from "lucide-react";
import type { ResponsePlaybook } from "@shared/schema";
import { useState } from "react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function Playbooks() {
  useDocumentTitle("Playbooks");
  const { t } = useTranslation();
  const { toast } = useToast();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [historyPlaybook, setHistoryPlaybook] = useState<ResponsePlaybook | null>(null);
  const { data: playbooks, isLoading } = useQuery<ResponsePlaybook[]>({ queryKey: ["/api/playbooks"] });

  const { data: historyData } = useQuery<any[]>({
    queryKey: ["/api/playbooks", historyPlaybook?.id, "history"],
    enabled: !!historyPlaybook,
  });

  const form = useForm({
    defaultValues: { name: "", description: "", triggerConditions: "", actions: "", enabled: true },
  });

  const addMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/playbooks", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
      setShowAddDialog(false);
      form.reset();
      toast({ title: t("playbooks.playbookCreated") });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, ...data }: { id: number; enabled?: boolean; autoTriggerEnabled?: boolean; triggerSeverity?: string; cooldownMinutes?: number }) => {
      const res = await apiRequest("PATCH", `/api/playbooks/${id}`, data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
    },
  });

  const enabledCount = playbooks?.filter((p) => p.enabled).length || 0;
  const autoCount = playbooks?.filter((p) => p.autoTriggerEnabled).length || 0;

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid gap-3"><Skeleton className="h-[400px] w-full" /></div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">{t("playbooks.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("playbooks.subtitle")}</p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-playbook"><Plus className="w-4 h-4 me-1" />{t("playbooks.newPlaybook")}</Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader><DialogTitle>{t("playbooks.createPlaybook")}</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit((d) => addMutation.mutate(d))} className="space-y-3">
                <FormField control={form.control} name="name" render={({ field }) => (
                  <FormItem><FormLabel>{t("common.name")}</FormLabel><FormControl><Input {...field} data-testid="input-playbook-name" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="description" render={({ field }) => (
                  <FormItem><FormLabel>{t("common.description")}</FormLabel><FormControl><Textarea {...field} rows={2} data-testid="input-playbook-description" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="triggerConditions" render={({ field }) => (
                  <FormItem><FormLabel>{t("playbooks.triggerConditions")}</FormLabel><FormControl><Input {...field} placeholder={t("playbooks.triggerPlaceholder")} data-testid="input-playbook-trigger" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="actions" render={({ field }) => (
                  <FormItem><FormLabel>{t("playbooks.actionsLabel")}</FormLabel><FormControl><Input {...field} placeholder={t("playbooks.actionsPlaceholder")} data-testid="input-playbook-actions" /></FormControl></FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={addMutation.isPending} data-testid="button-submit-playbook">
                  {addMutation.isPending ? t("common.creating") : t("playbooks.createPlaybook")}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("playbooks.totalPlaybooks")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-playbooks">{playbooks?.length || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("playbooks.active")}</span>
          <p className="text-2xl font-bold font-mono text-status-online mt-1" data-testid="stat-active-playbooks">{enabledCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Auto-Trigger</span>
          <p className="text-2xl font-bold font-mono text-amber-500 mt-1" data-testid="stat-auto-playbooks">{autoCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("playbooks.disabled")}</span>
          <p className="text-2xl font-bold font-mono text-muted-foreground mt-1" data-testid="stat-disabled-playbooks">{(playbooks?.length || 0) - enabledCount}</p>
        </CardContent></Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {playbooks?.map((playbook) => (
          <Card key={playbook.id} className={`border ${playbook.enabled ? "border-status-online/30" : "border-border"}`} data-testid={`playbook-card-${playbook.id}`}>
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded ${playbook.enabled ? "bg-status-online/10" : "bg-muted"}`}>
                    <BookOpen className={`w-4 h-4 ${playbook.enabled ? "text-status-online" : "text-muted-foreground"}`} />
                  </div>
                  <div>
                    <CardTitle className="text-sm font-bold" data-testid={`playbook-name-${playbook.id}`}>{playbook.name}</CardTitle>
                    <p className="text-[10px] text-muted-foreground mt-0.5">{playbook.description}</p>
                  </div>
                </div>
                <Switch
                  checked={playbook.enabled}
                  onCheckedChange={(enabled) => toggleMutation.mutate({ id: playbook.id, enabled })}
                  data-testid={`switch-playbook-${playbook.id}`}
                />
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {playbook.triggerConditions && (
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{t("playbooks.triggerConditions")}</span>
                  <div className="mt-1 p-2 rounded bg-muted/50 font-mono text-[11px] text-foreground">
                    <AlertTriangle className="w-3 h-3 inline me-1 text-severity-medium" />
                    {playbook.triggerConditions}
                  </div>
                </div>
              )}
              {playbook.actions && (
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">{t("playbooks.responseActions")}</span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {playbook.actions.split(",").map((action, i) => (
                      <Badge key={i} variant="secondary" className="text-[10px] font-mono">
                        <Zap className="w-3 h-3 me-0.5" />{action.trim().replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              <div className="border-t pt-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Bot className="w-4 h-4 text-amber-500" />
                    <span className="text-xs font-medium">Auto-Trigger</span>
                  </div>
                  <Switch
                    checked={playbook.autoTriggerEnabled}
                    onCheckedChange={(auto) => toggleMutation.mutate({ id: playbook.id, autoTriggerEnabled: auto })}
                    disabled={!playbook.enabled}
                    data-testid={`switch-auto-${playbook.id}`}
                  />
                </div>

                {playbook.autoTriggerEnabled && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-[10px] text-muted-foreground">Min Severity</span>
                      <Select
                        value={playbook.triggerSeverity || "critical"}
                        onValueChange={(val) => toggleMutation.mutate({ id: playbook.id, triggerSeverity: val })}
                      >
                        <SelectTrigger className="h-7 text-xs mt-1" data-testid={`select-severity-${playbook.id}`}>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="critical">Critical</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground">Cooldown (min)</span>
                      <Input
                        type="number"
                        className="h-7 text-xs mt-1"
                        value={playbook.cooldownMinutes || 30}
                        onChange={(e) => toggleMutation.mutate({ id: playbook.id, cooldownMinutes: parseInt(e.target.value) || 30 })}
                        data-testid={`input-cooldown-${playbook.id}`}
                      />
                    </div>
                  </div>
                )}

                {playbook.lastAutoRunAt && (
                  <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    Last auto-run: {new Date(playbook.lastAutoRunAt).toLocaleString()}
                  </div>
                )}
              </div>

              <div className="flex gap-2 pt-1">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs h-7"
                  onClick={() => setHistoryPlaybook(playbook)}
                  data-testid={`button-history-${playbook.id}`}
                >
                  <History className="w-3 h-3 me-1" />
                  History
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs h-7"
                  onClick={() => toast({ title: `Test run for "${playbook.name}" simulated`, description: "No destructive actions were executed." })}
                  data-testid={`button-test-${playbook.id}`}
                >
                  <FlaskConical className="w-3 h-3 me-1" />
                  Test Run
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Sheet open={!!historyPlaybook} onOpenChange={(open) => !open && setHistoryPlaybook(null)}>
        <SheetContent className="w-[400px] sm:w-[500px]">
          <SheetHeader>
            <SheetTitle>Execution History: {historyPlaybook?.name}</SheetTitle>
          </SheetHeader>
          <div className="mt-4 space-y-2 max-h-[calc(100vh-120px)] overflow-y-auto">
            {!historyData?.length ? (
              <p className="text-sm text-muted-foreground text-center py-8">No execution history yet.</p>
            ) : (
              historyData.map((entry: any) => (
                <Card key={entry.id} data-testid={`history-entry-${entry.id}`}>
                  <CardContent className="p-3 space-y-1">
                    <div className="flex items-center justify-between">
                      <Badge variant={entry.status === "completed" ? "default" : entry.status === "pending" ? "secondary" : "destructive"} className="text-[10px]">
                        {entry.status}
                      </Badge>
                      <span className="text-[10px] text-muted-foreground">{new Date(entry.createdAt).toLocaleString()}</span>
                    </div>
                    <p className="text-xs font-medium">{entry.actionType?.replace(/_/g, " ")}</p>
                    <p className="text-[10px] text-muted-foreground">{entry.details}</p>
                    {entry.executedBy && (
                      <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                        <Bot className="w-3 h-3" />
                        {entry.executedBy}
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
