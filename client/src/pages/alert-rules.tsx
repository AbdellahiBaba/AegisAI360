import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Shield, Plus, Trash2, Zap, Clock, AlertTriangle, X, Check } from "lucide-react";
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
  if (!dateStr) return "";
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
  const conds = parseConditions(conditionsStr);
  if (conds.length === 0) return "";
  return conds
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
  const { t } = useTranslation();
  const [createOpen, setCreateOpen] = useState(false);
  const [ruleName, setRuleName] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [conditionRows, setConditionRows] = useState<ConditionRow[]>([
    { field: "event_type", operator: "equals", value: "" },
  ]);
  const [selectedActions, setSelectedActions] = useState<string[]>(["create_incident"]);
  const { toast } = useToast();

  const actionTypeLabels: Record<string, string> = {
    create_incident: t("alertRules.createIncidentAction"),
    notify: t("alertRules.notifyAction"),
    block_source: t("alertRules.blockSourceAction"),
  };

  const { data: rules, isLoading } = useQuery<AlertRule[]>({
    queryKey: ["/api/alert-rules"],
    refetchInterval: 15000,
  });

  const createRule = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/alert-rules", {
        name: ruleName,
        severity,
        conditions: JSON.stringify(conditionRows),
        actions: JSON.stringify(selectedActions.map((act) => ({ type: act }))),
        enabled: true,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: t("alertRules.ruleCreated") });
      resetForm();
      setCreateOpen(false);
    },
    onError: (err: Error) => {
      toast({ title: t("alertRules.ruleCreateFailed"), description: err.message, variant: "destructive" });
    },
  });

  const toggleRule = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/alert-rules/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: t("alertRules.ruleUpdated") });
    },
  });

  const deleteRule = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/alert-rules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/alert-rules"] });
      toast({ title: t("alertRules.ruleDeleted") });
    },
  });

  function resetForm() {
    setRuleName("");
    setSeverity("medium");
    setConditionRows([{ field: "event_type", operator: "equals", value: "" }]);
    setSelectedActions(["create_incident"]);
  }

  function addCondition() {
    setConditionRows([...conditionRows, { field: "event_type", operator: "equals", value: "" }]);
  }

  function removeCondition(index: number) {
    setConditionRows(conditionRows.filter((_, i) => i !== index));
  }

  function updateCondition(index: number, key: keyof ConditionRow, val: string) {
    const updated = [...conditionRows];
    updated[index] = { ...updated[index], [key]: val };
    setConditionRows(updated);
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
          {t("alertRules.title")}
        </h1>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="font-mono text-xs" data-testid="text-rules-count">
            {rulesList.length} {t("common.rules")}
          </Badge>
          <Button size="sm" onClick={() => setCreateOpen(true)} data-testid="button-create-rule">
            <Plus className="w-3 h-3 me-1" />
            {t("alertRules.createRule")}
          </Button>
        </div>
      </div>

      {createOpen && (
        <Card data-testid="create-rule-form">
          <CardContent className="p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
                <Shield className="w-4 h-4" />
                {t("alertRules.createAlertRule")}
              </h2>
              <Button size="icon" variant="ghost" onClick={() => { setCreateOpen(false); resetForm(); }}>
                <X className="w-4 h-4" />
              </Button>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-muted-foreground block">{t("alertRules.ruleName")}</label>
              <Input
                value={ruleName}
                onChange={(e) => setRuleName(e.target.value)}
                placeholder={t("alertRules.ruleNamePlaceholder")}
                data-testid="input-rule-name"
              />
            </div>

            <div className="space-y-1">
              <label className="text-[10px] uppercase tracking-wider text-muted-foreground block">{t("common.severity")}</label>
              <div className="flex gap-2 flex-wrap">
                {["critical", "high", "medium", "low"].map((sev) => (
                  <Button
                    key={sev}
                    size="sm"
                    variant={severity === sev ? "default" : "outline"}
                    className="h-7 text-[10px] uppercase"
                    onClick={() => setSeverity(sev)}
                    data-testid={`button-severity-${sev}`}
                  >
                    {t(`common.${sev}`)}
                  </Button>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <label className="text-[10px] uppercase tracking-wider text-muted-foreground">{t("alertRules.conditions")}</label>
                <Button size="sm" variant="outline" onClick={addCondition} data-testid="button-add-condition">
                  <Plus className="w-3 h-3 me-1" />
                  {t("alertRules.add")}
                </Button>
              </div>
              {conditionRows.map((cond, i) => (
                <div key={i} className="flex gap-2 items-center flex-wrap">
                  <select
                    value={cond.field}
                    onChange={(e) => updateCondition(i, "field", e.target.value)}
                    className="h-9 rounded-md border border-input bg-background px-2 text-xs"
                    data-testid={`select-condition-field-${i}`}
                  >
                    {FIELDS.map((f) => (
                      <option key={f} value={f}>{f.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                  <select
                    value={cond.operator}
                    onChange={(e) => updateCondition(i, "operator", e.target.value)}
                    className="h-9 rounded-md border border-input bg-background px-2 text-xs"
                    data-testid={`select-condition-operator-${i}`}
                  >
                    {OPERATORS.map((o) => (
                      <option key={o} value={o}>{o.replace(/_/g, " ")}</option>
                    ))}
                  </select>
                  <Input
                    className="flex-1 min-w-[100px]"
                    value={cond.value}
                    onChange={(e) => updateCondition(i, "value", e.target.value)}
                    placeholder={t("common.value")}
                    data-testid={`input-condition-value-${i}`}
                  />
                  {conditionRows.length > 1 && (
                    <Button size="icon" variant="ghost" onClick={() => removeCondition(i)} data-testid={`button-remove-condition-${i}`}>
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  )}
                </div>
              ))}
            </div>

            <div className="space-y-2">
              <label className="text-[10px] uppercase tracking-wider text-muted-foreground block">{t("alertRules.actionsLabel")}</label>
              <div className="flex gap-2 flex-wrap">
                {ACTION_TYPES.map((actionType) => (
                  <Button
                    key={actionType}
                    size="sm"
                    variant={selectedActions.includes(actionType) ? "default" : "outline"}
                    className="h-7 text-[10px] uppercase"
                    onClick={() => toggleAction(actionType)}
                    data-testid={`button-action-${actionType}`}
                  >
                    {selectedActions.includes(actionType) && <Check className="w-3 h-3 me-1" />}
                    {actionTypeLabels[actionType] || actionType.replace(/_/g, " ")}
                  </Button>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t">
              <Button variant="secondary" onClick={() => { setCreateOpen(false); resetForm(); }} data-testid="button-cancel-create">
                {t("common.cancel")}
              </Button>
              <Button
                onClick={() => createRule.mutate()}
                disabled={!ruleName.trim() || conditionRows.some((c) => !c.value.trim()) || createRule.isPending}
                data-testid="button-submit-rule"
              >
                {createRule.isPending ? t("common.creating") : t("alertRules.createRule")}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="p-0">
          <div className="overflow-auto max-h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[1fr_90px_1fr_80px_100px_70px_50px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span>{t("common.name")}</span>
                <span>{t("common.severity")}</span>
                <span>{t("alertRules.conditions")}</span>
                <span>{t("alertRules.triggers")}</span>
                <span>{t("alertRules.lastTriggered")}</span>
                <span>{t("common.status")}</span>
                <span></span>
              </div>
              {rulesList.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-20 text-muted-foreground" data-testid="text-empty-state">
                  <AlertTriangle className="w-10 h-10 mb-3 opacity-40" />
                  <p className="text-sm uppercase tracking-wider font-medium">{t("alertRules.noRulesConfigured")}</p>
                  <p className="text-xs mt-1">{t("alertRules.noRulesDescription")}</p>
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
                            {actionTypeLabels[a] || a.replace(/_/g, " ")}
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
                      {summarizeConditions(rule.conditions) || t("alertRules.noConditions")}
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
                        {formatDate(rule.lastTriggered as unknown as string | null) || t("common.never")}
                      </span>
                    </div>
                    <Button
                      size="sm"
                      variant={rule.enabled ? "default" : "outline"}
                      className="h-6 text-[9px] px-2"
                      onClick={() => toggleRule.mutate({ id: rule.id, enabled: !rule.enabled })}
                      data-testid={`switch-enabled-${rule.id}`}
                    >
                      {rule.enabled ? t("common.active") : t("common.inactive")}
                    </Button>
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
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
