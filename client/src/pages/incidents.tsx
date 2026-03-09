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
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { queryClient, apiRequest } from "@/lib/queryClient";
import {
  Plus, Clock, User, Loader2, Play, FileDown, Download,
  MessageSquare, ArrowRight, Settings, ChevronRight,
  Send, AlertTriangle,
} from "lucide-react";
import { generateIncidentReportPDF } from "@/lib/reportGenerator";
import { exportToCsv } from "@/lib/csvExport";
import { useToast } from "@/hooks/use-toast";
import type { Incident, ResponsePlaybook, IncidentNote, SecurityEvent } from "@shared/schema";
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

function formatDateFull(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short", day: "numeric", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function NoteIcon({ noteType }: { noteType: string }) {
  switch (noteType) {
    case "status_change":
      return <ArrowRight className="w-3.5 h-3.5 text-blue-500" />;
    case "action":
      return <Play className="w-3.5 h-3.5 text-orange-500" />;
    case "system":
      return <Settings className="w-3.5 h-3.5 text-muted-foreground" />;
    default:
      return <MessageSquare className="w-3.5 h-3.5 text-foreground" />;
  }
}

function IncidentTimeline({ incidentId }: { incidentId: number }) {
  const [commentText, setCommentText] = useState("");
  const { toast } = useToast();

  const { data: notes, isLoading } = useQuery<IncidentNote[]>({
    queryKey: ["/api/incidents", incidentId, "notes"],
    queryFn: async () => {
      const res = await fetch(`/api/incidents/${incidentId}/notes`, { credentials: "include" });
      if (!res.ok) throw new Error("Failed to fetch notes");
      return res.json();
    },
  });

  const addNote = useMutation({
    mutationFn: async (content: string) => {
      const res = await apiRequest("POST", `/api/incidents/${incidentId}/notes`, { content });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", incidentId, "notes"] });
      setCommentText("");
    },
    onError: (err: Error) => {
      toast({ title: "Failed to add note", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="space-y-3 py-4">
        {[1, 2, 3].map(i => <Skeleton key={i} className="h-12 w-full" />)}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Timeline</h3>

      {(!notes || notes.length === 0) ? (
        <p className="text-xs text-muted-foreground py-4 text-center">No timeline entries yet</p>
      ) : (
        <div className="space-y-0">
          {notes.map((note, idx) => (
            <div key={note.id} className="flex gap-3 relative" data-testid={`timeline-entry-${note.id}`}>
              <div className="flex flex-col items-center">
                <div className="flex items-center justify-center w-7 h-7 rounded-full bg-muted flex-shrink-0">
                  <NoteIcon noteType={note.noteType} />
                </div>
                {idx < notes.length - 1 && (
                  <div className="w-px flex-1 bg-border min-h-[16px]" />
                )}
              </div>
              <div className="pb-4 flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-medium">{note.userName || "System"}</span>
                  <Badge variant="outline" className="text-[9px] capitalize">{note.noteType.replace("_", " ")}</Badge>
                  <span className="text-[10px] text-muted-foreground">{formatDateFull(note.createdAt as unknown as string)}</span>
                </div>
                {note.noteType === "status_change" ? (
                  <div className="mt-1 flex items-center gap-1.5 text-xs">
                    {(() => {
                      const match = note.content.match(/from "(.+)" to "(.+)"/);
                      if (match) {
                        return (
                          <>
                            <Badge className={`${statusClasses[match[1]] || "bg-muted text-muted-foreground"} text-[9px] uppercase`}>{match[1]}</Badge>
                            <ArrowRight className="w-3 h-3 text-muted-foreground" />
                            <Badge className={`${statusClasses[match[2]] || "bg-muted text-muted-foreground"} text-[9px] uppercase`}>{match[2]}</Badge>
                          </>
                        );
                      }
                      return <span className="text-muted-foreground">{note.content}</span>;
                    })()}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground mt-1">{note.content}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        <Input
          placeholder="Add a comment..."
          value={commentText}
          onChange={(e) => setCommentText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && commentText.trim() && !addNote.isPending) {
              addNote.mutate(commentText.trim());
            }
          }}
          className="flex-1"
          data-testid={`input-comment-${incidentId}`}
        />
        <Button
          size="icon"
          onClick={() => {
            if (commentText.trim()) addNote.mutate(commentText.trim());
          }}
          disabled={!commentText.trim() || addNote.isPending}
          data-testid={`button-send-comment-${incidentId}`}
        >
          {addNote.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        </Button>
      </div>
    </div>
  );
}

function LinkedEvents({ incident }: { incident: Incident }) {
  const { data: events } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/security-events"],
  });

  const linkedEvents = events?.filter(e => {
    if (!e.description || !incident.title) return false;
    const titleWords = incident.title.toLowerCase().split(/\s+/).filter(w => w.length > 3);
    const descLower = e.description.toLowerCase();
    return titleWords.some(w => descLower.includes(w));
  }).slice(0, 5);

  if (!linkedEvents || linkedEvents.length === 0) return null;

  return (
    <div className="space-y-2">
      <h3 className="text-sm font-medium">Related Security Events</h3>
      <div className="space-y-1.5">
        {linkedEvents.map(evt => (
          <div key={evt.id} className="flex items-center gap-2 p-2 rounded-md bg-muted/50 text-xs" data-testid={`linked-event-${evt.id}`}>
            <AlertTriangle className="w-3 h-3 flex-shrink-0 text-muted-foreground" />
            <span className="flex-1 truncate">{evt.description}</span>
            <Badge className={`${severityClasses[evt.severity]} text-[9px] uppercase`}>{evt.severity}</Badge>
            <span className="text-muted-foreground text-[10px] flex-shrink-0">{formatDate(evt.createdAt as unknown as string)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Incidents() {
  useDocumentTitle("Incidents");
  const { t } = useTranslation();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [assignee, setAssignee] = useState("");
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const { toast } = useToast();

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const { data: playbooks } = useQuery<ResponsePlaybook[]>({
    queryKey: ["/api/playbooks"],
  });

  const executePlaybook = useMutation({
    mutationFn: async ({ playbookId, incidentId, context }: { playbookId: number; incidentId: number; context: Record<string, any> }) => {
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
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", variables.id, "notes"] });
      toast({ title: t("incidents.incidentUpdated") });
      if (selectedIncident && selectedIncident.id === variables.id) {
        setSelectedIncident({ ...selectedIncident, status: variables.status });
      }
    },
  });

  const updateAssignee = useMutation({
    mutationFn: async ({ id, assignee }: { id: number; assignee: string }) => {
      await apiRequest("PATCH", `/api/incidents/${id}`, { assignee });
    },
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      queryClient.invalidateQueries({ queryKey: ["/api/incidents", variables.id, "notes"] });
      if (selectedIncident && selectedIncident.id === variables.id) {
        setSelectedIncident({ ...selectedIncident, assignee: variables.assignee });
      }
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
              <Card
                key={incident.id}
                className="hover-elevate cursor-pointer"
                data-testid={`card-incident-${incident.id}`}
                onClick={() => setSelectedIncident(incident)}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-sm font-medium leading-snug">{incident.title}</CardTitle>
                    <div className="flex gap-1.5 flex-shrink-0 flex-wrap items-center">
                      <Badge className={`${severityClasses[incident.severity]} text-[9px] uppercase`}>
                        {incident.severity}
                      </Badge>
                      <Badge className={`${statusClasses[incident.status]} text-[9px] uppercase`}>
                        {incident.status}
                      </Badge>
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
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
                  <div className="flex gap-2 flex-wrap" onClick={(e) => e.stopPropagation()}>
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
                          executePlaybook.mutate({ playbookId: parseInt(pbId), incidentId: incident.id, context: {} });
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

      <Sheet open={!!selectedIncident} onOpenChange={(open) => { if (!open) setSelectedIncident(null); }}>
        <SheetContent className="w-full sm:max-w-lg p-0 flex flex-col">
          {selectedIncident && (
            <>
              <SheetHeader className="p-4 pb-0">
                <SheetTitle className="text-base leading-snug pr-6">{selectedIncident.title}</SheetTitle>
              </SheetHeader>
              <ScrollArea className="flex-1">
                <div className="p-4 space-y-4">
                  <div className="flex gap-1.5 flex-wrap">
                    <Badge className={`${severityClasses[selectedIncident.severity]} text-[9px] uppercase`}>
                      {selectedIncident.severity}
                    </Badge>
                    <Badge className={`${statusClasses[selectedIncident.status]} text-[9px] uppercase`}>
                      {selectedIncident.status}
                    </Badge>
                  </div>

                  <p className="text-sm text-muted-foreground" data-testid="text-incident-description">{selectedIncident.description}</p>

                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Created</span>
                      <p className="font-medium">{formatDateFull(selectedIncident.createdAt as unknown as string)}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Updated</span>
                      <p className="font-medium">{formatDateFull(selectedIncident.updatedAt as unknown as string)}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Assignee</span>
                      <p className="font-medium">{selectedIncident.assignee || "Unassigned"}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">ID</span>
                      <p className="font-medium">INC-{selectedIncident.id}</p>
                    </div>
                  </div>

                  <div className="flex gap-2 flex-wrap">
                    {(() => {
                      const nextStatus = getNextStatus(selectedIncident.status);
                      if (!nextStatus) return null;
                      return (
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => updateStatus.mutate({ id: selectedIncident.id, status: nextStatus })}
                          disabled={updateStatus.isPending}
                          data-testid="button-advance-detail"
                        >
                          <ArrowRight className="w-3 h-3 me-1" />
                          {t("incidents.moveTo", { status: nextStatus })}
                        </Button>
                      );
                    })()}
                    <Select
                      value={selectedIncident.status}
                      onValueChange={(status) => updateStatus.mutate({ id: selectedIncident.id, status })}
                    >
                      <SelectTrigger className="w-[140px]" data-testid="select-status-detail">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {statusOrder.map(s => (
                          <SelectItem key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator />

                  <LinkedEvents incident={selectedIncident} />

                  <Separator />

                  <IncidentTimeline incidentId={selectedIncident.id} />
                </div>
              </ScrollArea>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
