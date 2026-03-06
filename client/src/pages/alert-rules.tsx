import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Shield, Plus, Trash2, Zap, Clock, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { AlertRule } from "@shared/schema";

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
};

const FIELDS = ["event_type", "severity", "source", "source_ip", "description", "technique_id"];
const OPERATORS = ["equals", "contains", "in", "severity_gte", "not_equals"];
const ACTION_TYPES = ["create_incident", "notify", "block_source"];

interface ConditionRow {
  field: string;
  operator: string;
  value: string;
}

function formatDate(dateStr: string | null) {
  if (!dateStr) return "Never";
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function parseConditions(conditionsStr: string): ConditionRow[] {
  try {
    const parsed = JSON.parse(conditionsStr);
    if (Array.isArray(parsed)) return parsed;
    return [];
  } catch {
    return [];
  }
}

function summarizeConditions(conditionsStr: string): string {
  const conditions = parseConditions(conditionsStr);
  if (conditions.length === 0) return "No conditions";
  return conditions
    .map((c) => `${c.field} ${c.operator} "${c.value}"`)
    .join(" AND ");
}

function parseActions(actionsStr: string): string[] {
  try {
    const parsed = JSON.parse(actionsStr);
    if (Array.isArray(parsed)) return parsed.map((a: { type: string }) => a.type);
    return [];
  } catch {
    return [];
  }
}

export default function AlertRules() {
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [conditions, setConditions] = useState<ConditionRow[]>([
    { field: "event_type", operator: "equals", value: "" },
  ]);
  const [selectedActions, setSelectedActions] = useState<string[]>([]);
  const { toast } = useToast();

  const { data: rules, isLoading } = useQuery<AlertRule[]>({
    queryKey: ["/api/alert-rules"],
    refetchInterval: 15000,
  });

  const createRule = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/alert-rules", {
        name,
        severity,
        conditions: JSON.stringify(conditions),
        actions: JSON.stringify(selectedActions.map((t) => ({ type: t }))),
        enabled: true,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: "Alert rule created" });
      resetForm();
      setCreateOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create rule", description: err.message, variant: "destructive" });
    },
  });

  const toggleRule = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/alert-rules/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: "Rule updated" });
    },
  });

  const deleteRule = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/alert-rules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: "Rule deleted" });
    },
  });

  function resetForm() {
    setName("");
    setSeverity("medium");
    setConditions([{ field: "event_type", operator: "equals", value: "" }]);
    setSelectedActions([]);
  }

  function addCondition() {
    setConditions([...conditions, { field: "event_type", operator: "equals", value: "" }]);
  }

  function removeCondition(index: number) {
    setConditions(conditions.filter((_, i) => i !== index));
  }

  function updateCondition(index: number, key: keyof ConditionRow, val: string) {
    const updated = [...conditions];
    updated[index] = { ...updated[index], [key]: val };
    setConditions(updated);
  }

  function toggleAction(actionType: string) {
    setSelectedActions((prev) =>
      prev.includes(actionType) ? prev.filter((a) => a !== actionType) : [...prev, actionType]
    );
  }

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-[600px] w-full" />
      </div>
    );
  }

  const rulesList = rules || [];

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-lg font-semibold tracking-wide uppercase" data-testid="text-page-title">
          Alert Rules
        </h1>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="font-mono text-xs" data-testid="text-rules-count">
            {rulesList.length} rules
          </Badge>
          <Button size="sm" onClick={() => setCreateOpen(true)} data-testid="button-create-rule">
            <Plus className="w-3 h-3 mr-1" />
            CREATE RULE
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[1fr_90px_1fr_80px_100px_70px_50px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span>NAME</span>
                <span>SEVERITY</span>
                <span>CONDITIONS</span>
                <span>TRIGGERS</span>
                <span>LAST TRIGGERED</span>
                <span>STATUS</span>
                <span></span>
              </div>
              {rulesList.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-muted-foreground" data-testid="text-empty-state">
                  <AlertTriangle className="w-10 h-10 mb-3 opacity-40" />
                  <p className="text-sm uppercase tracking-wider font-medium">No Alert Rules Configured</p>
                  <p className="text-xs mt-1">Create your first rule to start automated threat detection</p>
                </div>
              ) : (
                rulesList.map((rule) => (
                  <div
                    key={rule.id}
                    className="grid grid-cols-[1fr_90px_1fr_80px_100px_70px_50px] gap-2 px-4 py-2.5 border-b last:border-0 items-center"
                    data-testid={`rule-row-${rule.id}`}
                  >
                    <div className="min-w-0">
                      <p className="text-xs font-medium truncate" data-testid={`text-rule-name-${rule.id}`}>
                        {rule.name}
                      </p>
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {parseActions(rule.actions).map((a) => (
                          <Badge key={a} variant="outline" className="text-[8px] uppercase">
                            {a.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <Badge
                      className={`${severityClasses[rule.severity]} text-[9px] uppercase w-fit`}
                      data-testid={`badge-severity-${rule.id}`}
                    >
                      {rule.severity}
                    </Badge>
                    <p className="text-[10px] text-muted-foreground truncate font-mono" data-testid={`text-conditions-${rule.id}`}>
                      {summarizeConditions(rule.conditions)}
                    </p>
                    <div className="flex items-center gap-1">
                      <Zap className="w-3 h-3 text-muted-foreground" />
                      <span className="text-xs font-mono" data-testid={`text-trigger-count-${rule.id}`}>
                        {rule.triggerCount}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-muted-foreground" />
                      <span className="text-[10px] text-muted-foreground font-mono" data-testid={`text-last-triggered-${rule.id}`}>
                        {formatDate(rule.lastTriggered as unknown as string | null)}
                      </span>
                    </div>
                    <Switch
                      checked={rule.enabled}
                      onCheckedChange={(checked) => toggleRule.mutate({ id: rule.id, enabled: checked })}
                      data-testid={`switch-enabled-${rule.id}`}
                    />
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => deleteRule.mutate(rule.id)}
                      data-testid={`button-delete-rule-${rule.id}`}
                    >
                      <Trash2 className="w-3.5 h-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle className="text-sm tracking-wider uppercase flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Create Alert Rule
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 mt-2">
            <div className="space-y-1">
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Rule Name</Label>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Critical Brute Force Detection"
                data-testid="input-rule-name"
              />
            </div>

            <div className="space-y-1">
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</Label>
              <Select value={severity} onValueChange={setSeverity}>
                <SelectTrigger data-testid="select-rule-severity">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Conditions</Label>
                <Button size="sm" variant="outline" onClick={addCondition} data-testid="button-add-condition">
                  <Plus className="w-3 h-3 mr-1" />
                  ADD
                </Button>
              </div>
              {conditions.map((cond, i) => (
                <div key={i} className="flex gap-2 items-center flex-wrap">
                  <Select value={cond.field} onValueChange={(v) => updateCondition(i, "field", v)}>
                    <SelectTrigger className="w-[130px]" data-testid={`select-condition-field-${i}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {FIELDS.map((f) => (
                        <SelectItem key={f} value={f}>
                          {f.replace(/_/g, " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={cond.operator} onValueChange={(v) => updateCondition(i, "operator", v)}>
                    <SelectTrigger className="w-[120px]" data-testid={`select-condition-operator-${i}`}>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {OPERATORS.map((o) => (
                        <SelectItem key={o} value={o}>
                          {o.replace(/_/g, " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    className="flex-1 min-w-[100px]"
                    value={cond.value}
                    onChange={(e) => updateCondition(i, "value", e.target.value)}
                    placeholder="Value"
                    data-testid={`input-condition-value-${i}`}
                  />
                  {conditions.length > 1 && (
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => removeCondition(i)}
                      data-testid={`button-remove-condition-${i}`}
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <Label className="text-[10px] uppercase tracking-wider text-muted-foreground">Actions</Label>
              <div className="flex gap-4 flex-wrap">
                {ACTION_TYPES.map((actionType) => (
                  <label key={actionType} className="flex items-center gap-2 cursor-pointer">
                    <Checkbox
                      checked={selectedActions.includes(actionType)}
                      onCheckedChange={() => toggleAction(actionType)}
                      data-testid={`checkbox-action-${actionType}`}
                    />
                    <span className="text-xs uppercase tracking-wider">
                      {actionType.replace(/_/g, " ")}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="secondary" onClick={() => setCreateOpen(false)} data-testid="button-cancel-create">
              Cancel
            </Button>
            <Button
              onClick={() => createRule.mutate()}
              disabled={!name.trim() || conditions.some((c) => !c.value.trim()) || createRule.isPending}
              data-testid="button-submit-rule"
            >
              {createRule.isPending ? "Creating..." : "CREATE RULE"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
