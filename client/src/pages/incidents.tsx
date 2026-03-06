import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
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
import { Plus, Clock, User } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { Incident } from "@shared/schema";

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
  const [dialogOpen, setDialogOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [assignee, setAssignee] = useState("");
  const { toast } = useToast();

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["/api/incidents"],
  });

  const createIncident = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/incidents", { title, description, severity, assignee: assignee || undefined });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/incidents"] });
      toast({ title: "Incident created" });
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
      toast({ title: "Incident updated" });
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
        <h1 className="text-lg font-semibold tracking-wide">Incidents</h1>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-create-incident">
              <Plus className="w-4 h-4 mr-1" />
              New Incident
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Incident</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div className="space-y-2">
                <Label>Title</Label>
                <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Incident title" data-testid="input-incident-title" />
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Describe the incident..." data-testid="input-incident-description" />
              </div>
              <div className="space-y-2">
                <Label>Severity</Label>
                <Select value={severity} onValueChange={setSeverity}>
                  <SelectTrigger data-testid="select-incident-severity"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Assignee</Label>
                <Input value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="Assign to..." data-testid="input-incident-assignee" />
              </div>
              <Button
                onClick={() => createIncident.mutate()}
                disabled={!title || !description || createIncident.isPending}
                className="w-full"
                data-testid="button-submit-incident"
              >
                {createIncident.isPending ? "Creating..." : "Create Incident"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {(incidents?.length ?? 0) === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No incidents reported. Use the button above to create one.
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
                  {nextStatus && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => updateStatus.mutate({ id: incident.id, status: nextStatus })}
                      disabled={updateStatus.isPending}
                      data-testid={`button-advance-${incident.id}`}
                    >
                      Move to {nextStatus}
                    </Button>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
