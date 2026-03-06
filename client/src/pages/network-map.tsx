import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Monitor, Server, Shield, Wifi, HardDrive, Plus, AlertTriangle } from "lucide-react";
import type { Asset } from "@shared/schema";
import { useState } from "react";

const typeIcons: Record<string, React.ElementType> = {
  server: Server,
  workstation: Monitor,
  firewall: Shield,
  network: Wifi,
  appliance: HardDrive,
};

const statusColors: Record<string, string> = {
  online: "bg-status-online",
  offline: "bg-status-offline",
  isolated: "bg-severity-critical",
  maintenance: "bg-severity-medium",
};

function getRiskColor(score: number) {
  if (score >= 70) return "text-severity-critical";
  if (score >= 40) return "text-severity-high";
  if (score >= 20) return "text-severity-medium";
  return "text-status-online";
}

function getRiskBg(score: number) {
  if (score >= 70) return "bg-severity-critical/10 border-severity-critical/30";
  if (score >= 40) return "bg-severity-high/10 border-severity-high/30";
  if (score >= 20) return "bg-severity-medium/10 border-severity-medium/30";
  return "bg-status-online/10 border-status-online/30";
}

function AssetNode({ asset }: { asset: Asset }) {
  const Icon = typeIcons[asset.type] || HardDrive;
  return (
    <Card className={`border ${getRiskBg(asset.riskScore)} transition-all hover:scale-105`} data-testid={`asset-card-${asset.id}`}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-md bg-muted">
              <Icon className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="text-sm font-bold font-mono" data-testid={`asset-name-${asset.id}`}>{asset.name}</p>
              <p className="text-[10px] text-muted-foreground font-mono">{asset.ipAddress}</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${statusColors[asset.status] || statusColors.offline}`} />
            <span className="text-[10px] text-muted-foreground capitalize">{asset.status}</span>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Badge variant="secondary" className="text-[10px]">{asset.type}</Badge>
            {asset.os && <span className="text-[10px] text-muted-foreground">{asset.os}</span>}
          </div>
          <div className={`text-sm font-bold font-mono ${getRiskColor(asset.riskScore)}`} data-testid={`asset-risk-${asset.id}`}>
            {asset.riskScore}
          </div>
        </div>
        <div className="mt-2">
          <div className="w-full h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${asset.riskScore >= 70 ? "bg-severity-critical" : asset.riskScore >= 40 ? "bg-severity-high" : asset.riskScore >= 20 ? "bg-severity-medium" : "bg-status-online"}`}
              style={{ width: `${asset.riskScore}%` }}
            />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export default function NetworkMap() {
  const { toast } = useToast();
  const [showAddDialog, setShowAddDialog] = useState(false);
  const { data: assets, isLoading } = useQuery<Asset[]>({ queryKey: ["/api/assets"] });

  const form = useForm({
    defaultValues: { name: "", type: "server", ipAddress: "", os: "", status: "online", riskScore: 0 },
  });

  const addMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await apiRequest("POST", "/api/assets", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/assets"] });
      setShowAddDialog(false);
      form.reset();
      toast({ title: "Asset added" });
    },
  });

  const highRiskAssets = assets?.filter((a) => a.riskScore >= 60) || [];
  const onlineCount = assets?.filter((a) => a.status === "online").length || 0;
  const isolatedCount = assets?.filter((a) => a.status === "isolated").length || 0;
  const avgRisk = assets?.length ? Math.round(assets.reduce((s, a) => s + a.riskScore, 0) / assets.length) : 0;

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map((i) => <Card key={i}><CardContent className="p-4"><Skeleton className="h-16 w-full" /></CardContent></Card>)}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase">Network Map</h1>
          <p className="text-xs text-muted-foreground">Asset inventory and risk assessment</p>
        </div>
        <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-add-asset"><Plus className="w-4 h-4 mr-1" />Add Asset</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader><DialogTitle>Add Asset</DialogTitle></DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit((d) => addMutation.mutate({ ...d, riskScore: Number(d.riskScore) }))} className="space-y-3">
                <FormField control={form.control} name="name" render={({ field }) => (
                  <FormItem><FormLabel>Name</FormLabel><FormControl><Input {...field} data-testid="input-asset-name" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="type" render={({ field }) => (
                  <FormItem><FormLabel>Type</FormLabel><FormControl>
                    <Select onValueChange={field.onChange} value={field.value}>
                      <SelectTrigger data-testid="select-asset-type"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="server">Server</SelectItem>
                        <SelectItem value="workstation">Workstation</SelectItem>
                        <SelectItem value="firewall">Firewall</SelectItem>
                        <SelectItem value="network">Network</SelectItem>
                        <SelectItem value="appliance">Appliance</SelectItem>
                      </SelectContent>
                    </Select>
                  </FormControl></FormItem>
                )} />
                <FormField control={form.control} name="ipAddress" render={({ field }) => (
                  <FormItem><FormLabel>IP Address</FormLabel><FormControl><Input {...field} data-testid="input-asset-ip" /></FormControl></FormItem>
                )} />
                <FormField control={form.control} name="os" render={({ field }) => (
                  <FormItem><FormLabel>OS</FormLabel><FormControl><Input {...field} data-testid="input-asset-os" /></FormControl></FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={addMutation.isPending} data-testid="button-submit-asset">
                  {addMutation.isPending ? "Adding..." : "Add Asset"}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Total Assets</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-assets">{assets?.length || 0}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Online</span>
          <p className="text-2xl font-bold font-mono text-status-online mt-1" data-testid="stat-online">{onlineCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Isolated</span>
          <p className="text-2xl font-bold font-mono text-severity-critical mt-1" data-testid="stat-isolated">{isolatedCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">Avg Risk</span>
          <p className={`text-2xl font-bold font-mono mt-1 ${getRiskColor(avgRisk)}`} data-testid="stat-avg-risk">{avgRisk}</p>
        </CardContent></Card>
      </div>

      {highRiskAssets.length > 0 && (
        <Card className="border-severity-critical/30 bg-severity-critical/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-severity-critical" />High Risk Assets
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {highRiskAssets.map((a) => (
                <Badge key={a.id} variant="destructive" className="text-xs font-mono">{a.name} ({a.riskScore})</Badge>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {assets?.map((asset) => <AssetNode key={asset.id} asset={asset} />)}
      </div>
    </div>
  );
}
