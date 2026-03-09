import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useForm } from "react-hook-form";
import { Form, FormControl, FormField, FormItem, FormLabel } from "@/components/ui/form";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { CalendarClock, Plus, Trash2, Network, ShieldCheck, Eye, Lock } from "lucide-react";
import type { ScheduledScan } from "@shared/schema";
import { useState } from "react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const scanTypeLabels: Record<string, string> = {
  network_scan: "Network Scan",
  vulnerability_scan: "Vulnerability Scan",
  dark_web_check: "Dark Web Check",
  ssl_check: "SSL Check",
};

const scanTypeIcons: Record<string, React.ElementType> = {
  network_scan: Network,
  vulnerability_scan: ShieldCheck,
  dark_web_check: Eye,
  ssl_check: Lock,
};

const frequencyLabels: Record<string, string> = {
  daily: "Daily",
  weekly: "Weekly",
  monthly: "Monthly",
};

export default function ScheduledScansPage() {
  useDocumentTitle("Scheduled Scans");
  const { toast } = useToast();
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data: scans, isLoading } = useQuery<ScheduledScan[]>({
    queryKey: ["/api/scheduled-scans"],
  });

  const form = useForm({
    defaultValues: {
      scanType: "network_scan",
      target: "",
      frequency: "daily",
    },
  });

  const createMutation = useMutation({
    mutationFn: async (data: { scanType: string; target: string; frequency: string }) => {
      const res = await apiRequest("POST", "/api/scheduled-scans", data);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      form.reset();
      setDialogOpen(false);
      toast({ title: "Scheduled scan created" });
    },
    onError: () => {
      toast({ title: "Failed to create scheduled scan", variant: "destructive" });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: number; enabled: boolean }) => {
      const res = await apiRequest("PATCH", `/api/scheduled-scans/${id}`, { enabled });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiRequest("DELETE", `/api/scheduled-scans/${id}`);
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/scheduled-scans"] });
      toast({ title: "Scheduled scan deleted" });
    },
  });

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-[400px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h1 className="text-lg font-bold tracking-wider uppercase" data-testid="text-page-title">Scheduled Scans</h1>
          <p className="text-xs text-muted-foreground">Configure recurring automated security scans</p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button data-testid="button-create-scan">
              <Plus className="w-4 h-4 me-1.5" />
              New Scheduled Scan
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Scheduled Scan</DialogTitle>
            </DialogHeader>
            <Form {...form}>
              <form onSubmit={form.handleSubmit((d) => createMutation.mutate(d))} className="space-y-4">
                <FormField control={form.control} name="scanType" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Scan Type</FormLabel>
                    <FormControl>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <SelectTrigger data-testid="select-scan-type"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="network_scan">Network Scan</SelectItem>
                          <SelectItem value="vulnerability_scan">Vulnerability Scan</SelectItem>
                          <SelectItem value="dark_web_check">Dark Web Check</SelectItem>
                          <SelectItem value="ssl_check">SSL Check</SelectItem>
                        </SelectContent>
                      </Select>
                    </FormControl>
                  </FormItem>
                )} />
                <FormField control={form.control} name="target" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Target</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="e.g., 192.168.1.0/24 or example.com" data-testid="input-scan-target" />
                    </FormControl>
                  </FormItem>
                )} />
                <FormField control={form.control} name="frequency" render={({ field }) => (
                  <FormItem>
                    <FormLabel>Frequency</FormLabel>
                    <FormControl>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <SelectTrigger data-testid="select-scan-frequency"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="daily">Daily</SelectItem>
                          <SelectItem value="weekly">Weekly</SelectItem>
                          <SelectItem value="monthly">Monthly</SelectItem>
                        </SelectContent>
                      </Select>
                    </FormControl>
                  </FormItem>
                )} />
                <Button type="submit" className="w-full" disabled={createMutation.isPending} data-testid="button-submit-scan">
                  {createMutation.isPending ? "Creating..." : "Create Scheduled Scan"}
                </Button>
              </form>
            </Form>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Total Scans</p>
            <p className="text-2xl font-bold" data-testid="text-total-scans">{scans?.length || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Active</p>
            <p className="text-2xl font-bold text-green-500" data-testid="text-active-scans">{scans?.filter(s => s.enabled).length || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Paused</p>
            <p className="text-2xl font-bold text-muted-foreground" data-testid="text-paused-scans">{scans?.filter(s => !s.enabled).length || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <p className="text-xs text-muted-foreground">Scan Types</p>
            <p className="text-2xl font-bold" data-testid="text-scan-types">{new Set(scans?.map(s => s.scanType)).size || 0}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <CalendarClock className="w-4 h-4 text-primary" />
            Scheduled Scans
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {(!scans || scans.length === 0) ? (
            <div className="p-8 text-center">
              <CalendarClock className="w-10 h-10 mx-auto mb-3 text-muted-foreground/50" />
              <p className="text-sm text-muted-foreground">No scheduled scans configured</p>
              <p className="text-xs text-muted-foreground mt-1">Create your first scheduled scan to automate security checks</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider">Type</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Target</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Frequency</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Next Run</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Last Run</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Last Result</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Enabled</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan) => {
                  const ScanIcon = scanTypeIcons[scan.scanType] || Network;
                  return (
                    <TableRow key={scan.id} data-testid={`row-scan-${scan.id}`}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <ScanIcon className="w-3.5 h-3.5 text-muted-foreground" />
                          <span className="text-xs">{scanTypeLabels[scan.scanType] || scan.scanType}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs font-mono" data-testid={`text-target-${scan.id}`}>{scan.target}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">
                          {frequencyLabels[scan.frequency] || scan.frequency}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-[11px] text-muted-foreground font-mono">
                          {scan.nextRun ? new Date(scan.nextRun).toLocaleString() : "-"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[11px] text-muted-foreground font-mono">
                          {scan.lastRun ? new Date(scan.lastRun).toLocaleString() : "Never"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <span className="text-[11px] text-muted-foreground max-w-[200px] truncate block">
                          {scan.lastResult || "-"}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Switch
                          checked={scan.enabled}
                          onCheckedChange={(enabled) => toggleMutation.mutate({ id: scan.id, enabled })}
                          data-testid={`switch-scan-${scan.id}`}
                        />
                      </TableCell>
                      <TableCell>
                        <Button
                          size="icon"
                          variant="ghost"
                          onClick={() => deleteMutation.mutate(scan.id)}
                          disabled={deleteMutation.isPending}
                          data-testid={`button-delete-scan-${scan.id}`}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
