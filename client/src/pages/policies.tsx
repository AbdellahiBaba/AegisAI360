import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Plus, Shield, Eye, Lock, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { SecurityPolicy } from "@shared/schema";

const tierConfig: Record<string, { label: string; icon: React.ElementType; className: string }> = {
  observe: { label: "Observe", icon: Eye, className: "bg-severity-info text-white" },
  protect: { label: "Protect", icon: Shield, className: "bg-severity-low text-white" },
  lockdown: { label: "Lockdown", icon: Lock, className: "bg-severity-high text-white" },
  critical: { label: "Critical Infrastructure", icon: AlertTriangle, className: "bg-severity-critical text-white" },
};

export default function Policies() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [tier, setTier] = useState("observe");
  const { toast } = useToast();

  const { data: policies, isLoading } = useQuery<SecurityPolicy[]>({
    queryKey: ["/api/security-policies"],
  });

  const createPolicy = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/security-policies", { name, description, tier, enabled: true });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-policies"] });
      toast({ title: "Policy created" });
      setDialogOpen(false);
      setName("");
      setDescription("");
      setTier("observe");
    },
  });

  const togglePolicy = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      await apiRequest("PATCH", `/api/security-policies/${id}`, { enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-policies"] });
    },
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-10 w-full" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-32" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-lg font-semibold tracking-wide">Security Policies</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-create-policy">
              <Plus className="w-4 h-4 mr-1" />
              New Policy
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Security Policy</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div className="space-y-2">
                <Label>Policy Name</Label>
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Block Unsigned Binaries" data-testid="input-policy-name" />
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the policy..." data-testid="input-policy-description" />
              </div>
              <div className="space-y-2">
                <Label>Policy Tier</Label>
                <Select value={tier} onValueChange={setTier}>
                  <SelectTrigger data-testid="select-policy-tier"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="observe">Observe</SelectItem>
                    <SelectItem value="protect">Protect</SelectItem>
                    <SelectItem value="lockdown">Lockdown</SelectItem>
                    <SelectItem value="critical">Critical Infrastructure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                onClick={() => createPolicy.mutate()}
                disabled={!name || !description || createPolicy.isPending}
                className="w-full"
                data-testid="button-submit-policy"
              >
                {createPolicy.isPending ? "Creating..." : "Create Policy"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {(policies?.length ?? 0) === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No policies configured. Create one to get started.
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {policies?.map((policy) => {
            const config = tierConfig[policy.tier] || tierConfig.observe;
            const TierIcon = config.icon;
            return (
              <Card key={policy.id} className={!policy.enabled ? "opacity-60" : ""} data-testid={`card-policy-${policy.id}`}>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0">
                      <div className="p-1.5 rounded-md bg-primary/10 flex-shrink-0">
                        <TierIcon className="w-4 h-4 text-primary" />
                      </div>
                      <CardTitle className="text-sm font-medium truncate">{policy.name}</CardTitle>
                    </div>
                    <Switch
                      checked={policy.enabled}
                      onCheckedChange={(checked) => togglePolicy.mutate({ id: policy.id, enabled: checked })}
                      data-testid={`switch-policy-${policy.id}`}
                    />
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{policy.description}</p>
                  <Badge className={`${config.className} text-[9px] uppercase`}>
                    {config.label}
                  </Badge>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
