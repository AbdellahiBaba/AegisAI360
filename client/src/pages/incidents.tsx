import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Plus, Clock, User, ShieldBan, Loader2, Play, FileDown, Download } from "lucide-react";
import { generateIncidentReportPDF } from "@/lib/reportGenerator";
import { exportToCsv } from "@/lib/csvExport";
import { useToast } from "@/hooks/use-toast";
import type { Incident, ResponsePlaybook } from "@shared/schema";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
};

const statusClasses: Record<string, string> = {
  open: "bg-severity-critical/20 text-severity-critical",
  investigating: "bg-severity-medium/20 text-severity-medium",
  contained: "bg-severity-low/20 text-severity-low",
  resolved: "bg-status-online/20 text-status-online",
  closed: "bg-muted text-muted-foreground",
};

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

export default function Incidents() {
  useDocumentTitle("Incidents");
  const { t } = useTranslation();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [assignee, setAssignee] = useState("");
  const { toast } = useToast();

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: playbooks } = useQuery<ResponsePlaybook[]>({
    queryKey: ["/api/playbooks"],
  });

  const executePlaybook = useMutation({
    mutationFn: async ({ playbookId, context }: { playbookId: number; context: Record<string, any> }) => {
      const res = await apiRequest("POST", "/api/response/execute-playbook", { playbookId, context });
      return res.json();
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: t("incidents.playbookExecuted"), description: t("incidents.stepsCompleted", { count: data.results?.length || 0 }) });
    },
    onError: (err: Error) => {
      toast({ title: t("incidents.playbookFailed"), description: err.message, variant: "destructive" });
    },
  });

  const createIncident = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/incidents", { title, description, severity, assignee: assignee || undefined });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: t("incidents.incidentCreated") });
      setDialogOpen(false);
      setTitle("");
      setDescription("");
      setSeverity("medium");
      setAssignee("");
    },
  });

  const updateStatus = useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      await apiRequest("PATCH", `/api/incidents/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: t("incidents.incidentUpdated") });
    },
  });

  const statusOrder = ["open", "investigating", "contained", "resolved", "closed"];

  const getNextStatus = (current: string) => {
    const idx = statusOrder.indexOf(current);
    if (idx < statusOrder.length - 1) return statusOrder[idx + 1];
    return null;
  };

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-10 w-full" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2, 3, 4].map((i) => <Skeleton key={i} className="h-40" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h1 className="text-lg font-semibold tracking-wide">{t("incidents.title")}</h1>
        <div className="flex gap-2 flex-wrap">
          {incidents && incidents.length > 0 && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  exportToCsv(
                    "incidents",
                    ["ID", "Title", "Description", "Severity", "Status", "Assignee", "Created At"],
                    incidents.map((inc) => [
                      inc.id,
                      inc.title,
                      inc.description,
                      inc.severity,
                      inc.status,
                      inc.assignee || "",
                      inc.createdAt ? new Date(inc.createdAt as unknown as string).toISOString() : "",
                    ])
                  );
                }}
                data-testid="button-export-csv"
              >
                <Download className="w-4 h-4 me-1" />
                {t("common.exportCsv", "Export CSV")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => generateIncidentReportPDF(incidents as any)}
                data-testid="button-generate-pdf-report"
              >
                <FileDown className="w-4 h-4 me-1" />
                {t("incidents.generateReport", "Generate PDF Report")}
              </Button>
            </>
          )}
          <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm" data-testid="button-create-incident">
                <Plus className="w-4 h-4 me-1" />
                {t("incidents.newIncident")}
              </Button>
            </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t("incidents.createIncident")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div className="space-y-2">
                <Label>{t("incidents.incidentTitle")}</Label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder={t("incidents.incidentTitlePlaceholder")} data-testid="input-incident-title" />
              </div>
              <div className="space-y-2">
                <Label>{t("incidents.incidentDescription")}</Label>
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder={t("incidents.incidentDescriptionPlaceholder")} data-testid="input-incident-description" />
              </div>
              <div className="space-y-2">
                <Label>{t("common.severity")}</Label>
                <Select value={severity} onValueChange={setSeverity}>
                  <SelectTrigger data-testid="select-incident-severity"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">{t("common.critical")}</SelectItem>
                    <SelectItem value="high">{t("common.high")}</SelectItem>
                    <SelectItem value="medium">{t("common.medium")}</SelectItem>
                    <SelectItem value="low">{t("common.low")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>{t("incidents.assignee")}</Label>
                <Input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder={t("incidents.assigneePlaceholder")} data-testid="input-incident-assignee" />
              </div>
              <Button
                onClick={() => createIncident.mutate()}
                disabled={!title || !description || createIncident.isPending}
                className="w-full"
                data-testid="button-submit-incident"
              >
                {createIncident.isPending ? t("common.creating") : t("incidents.createIncident")}
              </Button>
            </div>
          </DialogContent>
          </Dialog>
        </div>
      </div>

      {(incidents?.length ?? 0) === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            {t("incidents.noIncidents")}
          </CardContent>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {incidents?.map((incident) => {
            const nextStatus = getNextStatus(incident.status);
            return (
              <Card key={incident.id} data-testid={`card-incident-${incident.id}`}>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-sm font-medium leading-snug">{incident.title}</CardTitle>
                    <div className="flex gap-1.5 flex-shrink-0 flex-wrap">
                      <Badge className={`${severityClasses[incident.severity]} text-[9px] uppercase`}>
                        {incident.severity}
                      </Badge>
                      <Badge className={`${statusClasses[incident.status]} text-[9px] uppercase`}>
                        {incident.status}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{incident.description}</p>
                  <div className="flex items-center gap-4 text-[10px] text-muted-foreground mb-3 flex-wrap">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDate(incident.createdAt as unknown as string)}
                    </div>
                    {incident.assignee && (
                      <div className="flex items-center gap-1">
                        <User className="w-3 h-3" />
                        {incident.assignee}
                      </div>
                    )}
                  </div>
                  <div className="flex gap-2 flex-wrap">
                    {nextStatus && (
                      <Button
                        size="sm"
                        variant="secondary"
                        onClick={() => updateStatus.mutate({ id: incident.id, status: nextStatus })}
                        disabled={updateStatus.isPending}
                        data-testid={`button-advance-${incident.id}`}
                      >
                        {t("incidents.moveTo", { status: nextStatus })}
                      </Button>
                    )}
                    {playbooks && playbooks.filter(p => p.enabled).length > 0 && incident.status !== "closed" && incident.status !== "resolved" && (
                      <Select onValueChange={(pbId) => {
                        if (window.confirm(t("incidents.executePlaybookConfirm"))) {
                          executePlaybook.mutate({ playbookId: parseInt(pbId), context: {} });
                        }
                      }}>
                        <SelectTrigger className="h-8 w-full sm:w-[160px] text-xs" data-testid={`select-playbook-${incident.id}`}>
                          <Play className="w-3 h-3 me-1" />
                          <SelectValue placeholder={t("incidents.runPlaybook")} />
                        </SelectTrigger>
                        <SelectContent>
                          {playbooks.filter(p => p.enabled).map(pb => (
                            <SelectItem key={pb.id} value={String(pb.id)}>{pb.name}</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
