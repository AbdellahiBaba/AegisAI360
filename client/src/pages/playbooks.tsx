import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { BookOpen, Plus, Zap, Play, AlertTriangle, CheckCircle } from "lucide-react";
import type { ResponsePlaybook } from "@shared/schema";
import { useState } from "react";

export default function Playbooks() {
  const { toast } = useToast();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const { data: playbooks, isLoading } = useQuery<ResponsePlaybook[]>({ queryKey: ["/api/playbooks"] });

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
      toast({ title: "Playbook created" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/playbooks/${id}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/playbooks"] });
    },
  });

  const enabledCount = playbooks?.filter((p) => p.enabled).length || 0;
  const disabledCount = playbooks?.filter((p) => !p.enabled).length || 0;

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
          <h1 className="text-lg font-bold tracking-wider uppercase">Response Playbooks</h1>
          <p className="text-xs text-muted-foreground">Automated incident response procedures</p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-playbook"><Plus className="w-4 h-4 mr-1" />New Playbook</Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader><DialogTitle>Create Playbook</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit((d) => addMutation.mutate(d))} className="space-y-3">
                <FormField control={form.control} name="name" render={({ field }) => (
                  <FormItem><FormLabel>Name</FormLabel><FormControl><Input {...field} data-testid="input-playbook-name" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="description" render={({ field }) => (
                  <FormItem><FormLabel>Description</FormLabel><FormControl><Textarea {...field} rows={2} data-testid="input-playbook-description" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="triggerConditions" render={({ field }) => (
                  <FormItem><FormLabel>Trigger Conditions</FormLabel><FormControl><Input {...field} placeholder="e.g. severity=critical AND eventType=malware" data-testid="input-playbook-trigger" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="actions" render={({ field }) => (
                  <FormItem><FormLabel>Actions (comma-separated)</FormLabel><FormControl><Input {...field} placeholder="e.g. isolate_host,block_ip,notify_team" data-testid="input-playbook-actions" /></FormControl></FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={addMutation.isPending} data-testid="button-submit-playbook">
                  {addMutation.isPending ? "Creating..." : "Create Playbook"}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Total Playbooks</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-playbooks">{playbooks?.length || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Active</span>
          <p className="text-2xl font-bold font-mono text-status-online mt-1" data-testid="stat-active-playbooks">{enabledCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Disabled</span>
          <p className="text-2xl font-bold font-mono text-muted-foreground mt-1" data-testid="stat-disabled-playbooks">{disabledCount}</p>
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
            <CardContent>
              {playbook.triggerConditions && (
                <div className="mb-2">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Trigger Conditions</span>
                  <div className="mt-1 p-2 rounded bg-muted/50 font-mono text-[11px] text-foreground">
                    <AlertTriangle className="w-3 h-3 inline mr-1 text-severity-medium" />
                    {playbook.triggerConditions}
                  </div>
                </div>
              )}
              {playbook.actions && (
                <div>
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Response Actions</span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {playbook.actions.split(",").map((action, i) => (
                      <Badge key={i} variant="secondary" className="text-[10px] font-mono">
                        <Zap className="w-3 h-3 mr-0.5" />{action.trim().replace(/_/g, " ")}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
