import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Search, Plus, Shield, Trash2, ShieldOff } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { FirewallRule } from "@shared/schema";

const ruleTypeLabels: Record<string, string> = {
  ip_block: "IP Block",
  domain_block: "Domain Block",
  port_block: "Port Block",
  cidr_block: "CIDR Block",
};

const ruleTypeBadgeClasses: Record<string, string> = {
  ip_block: "bg-severity-critical/20 text-severity-critical",
  domain_block: "bg-severity-high/20 text-severity-high",
  port_block: "bg-severity-medium/20 text-severity-medium",
  cidr_block: "bg-severity-info/20 text-severity-info",
};

function formatDate(dateStr: string | null) {
  if (!dateStr) return "Never";
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function Firewall() {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newRuleType, setNewRuleType] = useState("ip_block");
  const [newValue, setNewValue] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newExpiration, setNewExpiration] = useState("");
  const { toast } = useToast();

  const { data: rules, isLoading } = useQuery<FirewallRule[]>({
    queryKey: ["/api/firewall"],
    refetchInterval: 15000,
  });

  const createRule = useMutation({
    mutationFn: async (body: { ruleType: string; value: string; action: string; reason?: string; expiresAt?: string }) => {
      await apiRequest("POST", "/api/firewall", body);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: "Firewall rule created" });
      resetDialog();
    },
    onError: (err: Error) => {
      toast({ title: "Failed to create rule", description: err.message, variant: "destructive" });
    },
  });

  const toggleRule = useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      await apiRequest("PATCH", `/api/firewall/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: "Rule status updated" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to update rule", description: err.message, variant: "destructive" });
    },
  });

  const deleteRule = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("DELETE", `/api/firewall/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/firewall"] });
      toast({ title: "Firewall rule deleted" });
    },
    onError: (err: Error) => {
      toast({ title: "Failed to delete rule", description: err.message, variant: "destructive" });
    },
  });

  function resetDialog() {
    setDialogOpen(false);
    setNewRuleType("ip_block");
    setNewValue("");
    setNewReason("");
    setNewExpiration("");
  }

  function handleCreateRule() {
    if (!newValue.trim()) {
      toast({ title: "Value is required", variant: "destructive" });
      return;
    }
    const body: { ruleType: string; value: string; action: string; reason?: string; expiresAt?: string } = {
      ruleType: newRuleType,
      value: newValue.trim(),
      action: "block",
    };
    if (newReason.trim()) body.reason = newReason.trim();
    if (newExpiration) body.expiresAt = new Date(newExpiration).toISOString();
    createRule.mutate(body);
  }

  const filtered = (rules || []).filter((rule) => {
    const matchesSearch =
      search === "" ||
      rule.value.toLowerCase().includes(search.toLowerCase()) ||
      rule.reason?.toLowerCase().includes(search.toLowerCase()) ||
      rule.ruleType.toLowerCase().includes(search.toLowerCase());
    const matchesType = typeFilter === "all" || rule.ruleType === typeFilter;
    return matchesSearch && matchesType;
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-10 w-full" />
        <Skeleton className="h-[600px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <Shield className="w-5 h-5 text-muted-foreground" />
          <h1 className="text-lg font-semibold tracking-wider uppercase">Firewall Rules</h1>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge variant="secondary" className="font-mono text-xs" data-testid="text-rule-count">
            {filtered.length} rules
          </Badge>
          <Button
            onClick={() => setDialogOpen(true)}
            data-testid="button-add-rule"
          >
            <Plus className="w-4 h-4 mr-1" />
            Add Rule
          </Button>
        </div>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search rules..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-rules"
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-[160px]" data-testid="select-type-filter">
            <SelectValue placeholder="Rule Type" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Types</SelectItem>
            <SelectItem value="ip_block">IP Block</SelectItem>
            <SelectItem value="domain_block">Domain Block</SelectItem>
            <SelectItem value="port_block">Port Block</SelectItem>
            <SelectItem value="cidr_block">CIDR Block</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[1fr_100px_80px_120px_120px_80px_60px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span>Value</span>
                <span>Type</span>
                <span>Action</span>
                <span>Reason</span>
                <span>Expires</span>
                <span>Status</span>
                <span>Actions</span>
              </div>
              {filtered.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-muted-foreground" data-testid="text-empty-state">
                  <ShieldOff className="w-10 h-10 mb-3 opacity-40" />
                  <p className="text-sm font-medium tracking-wider uppercase">No Firewall Rules</p>
                  <p className="text-xs mt-1">Add a rule to begin protecting your network perimeter</p>
                </div>
              ) : (
                filtered.map((rule) => (
                  <div
                    key={rule.id}
                    className="grid grid-cols-[1fr_100px_80px_120px_120px_80px_60px] gap-2 px-4 py-2.5 border-b last:border-0 items-center"
                    data-testid={`rule-row-${rule.id}`}
                  >
                    <span className="text-xs font-mono truncate" data-testid={`text-rule-value-${rule.id}`}>
                      {rule.value}
                    </span>
                    <Badge className={`${ruleTypeBadgeClasses[rule.ruleType] || ""} text-[9px] uppercase w-fit`}>
                      {ruleTypeLabels[rule.ruleType] || rule.ruleType}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground uppercase font-mono">{rule.action}</span>
                    <span className="text-[10px] text-muted-foreground truncate">{rule.reason || "—"}</span>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      {formatDate(rule.expiresAt as unknown as string | null)}
                    </span>
                    <div className="flex items-center gap-1.5">
                      <Switch
                        checked={rule.status === "active"}
                        onCheckedChange={(checked) =>
                          toggleRule.mutate({ id: rule.id, status: checked ? "active" : "disabled" })
                        }
                        data-testid={`switch-toggle-rule-${rule.id}`}
                      />
                      <span className="text-[9px] uppercase tracking-wider text-muted-foreground">
                        {rule.status === "active" ? "On" : "Off"}
                      </span>
                    </div>
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => deleteRule.mutate(rule.id)}
                      data-testid={`button-delete-rule-${rule.id}`}
                    >
                      <Trash2 className="w-3.5 h-3.5 text-destructive" />
                    </Button>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="text-sm tracking-wider uppercase">Add Firewall Rule</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-2">
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">Rule Type</Label>
              <Select value={newRuleType} onValueChange={setNewRuleType}>
                <SelectTrigger data-testid="select-new-rule-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip_block">IP Block</SelectItem>
                  <SelectItem value="domain_block">Domain Block</SelectItem>
                  <SelectItem value="port_block">Port Block</SelectItem>
                  <SelectItem value="cidr_block">CIDR Block</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">Value</Label>
              <Input
                placeholder={
                  newRuleType === "ip_block" ? "192.168.1.100" :
                  newRuleType === "domain_block" ? "malicious-domain.com" :
                  newRuleType === "port_block" ? "4444" :
                  "10.0.0.0/8"
                }
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
                data-testid="input-new-rule-value"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">Reason (Optional)</Label>
              <Input
                placeholder="Suspicious activity detected..."
                value={newReason}
                onChange={(e) => setNewReason(e.target.value)}
                data-testid="input-new-rule-reason"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-xs uppercase tracking-wider text-muted-foreground">Expiration (Optional)</Label>
              <Input
                type="datetime-local"
                value={newExpiration}
                onChange={(e) => setNewExpiration(e.target.value)}
                data-testid="input-new-rule-expiration"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="secondary" onClick={resetDialog} data-testid="button-cancel-add-rule">
              Cancel
            </Button>
            <Button
              onClick={handleCreateRule}
              disabled={createRule.isPending}
              data-testid="button-submit-add-rule"
            >
              {createRule.isPending ? "Creating..." : "Create Rule"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
