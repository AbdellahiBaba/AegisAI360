import { useQuery, useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { Search, Filter, Clock, Globe, Server, ArrowRight } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import type { SecurityEvent } from "@shared/schema";

const severityClasses: Record<string, string> = {
  critical: "bg-severity-critical text-white",
  high: "bg-severity-high text-white",
  medium: "bg-severity-medium text-black",
  low: "bg-severity-low text-white",
  info: "bg-severity-info text-white",
};

const statusClasses: Record<string, string> = {
  new: "bg-severity-critical/20 text-severity-critical",
  investigating: "bg-severity-medium/20 text-severity-medium",
  resolved: "bg-status-online/20 text-status-online",
  dismissed: "bg-muted text-muted-foreground",
};

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function Alerts() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const { toast } = useToast();

  const { data: events, isLoading } = useQuery<SecurityEvent[]>({
    queryKey: ["/api/security-events"],
    refetchInterval: 15000,
  });

  const updateStatus = useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      await apiRequest("PATCH", `/api/security-events/${id}`, { status });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/security-events"] });
      toast({ title: "Event status updated" });
    },
  });

  const filtered = (events || []).filter((event) => {
    const matchesSearch =
      search === "" ||
      event.description.toLowerCase().includes(search.toLowerCase()) ||
      event.sourceIp?.toLowerCase().includes(search.toLowerCase()) ||
      event.eventType.toLowerCase().includes(search.toLowerCase());
    const matchesSeverity = severityFilter === "all" || event.severity === severityFilter;
    const matchesStatus = statusFilter === "all" || event.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
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
        <h1 className="text-lg font-semibold tracking-wide">Security Events</h1>
        <Badge variant="secondary" className="font-mono text-xs">{filtered.length} events</Badge>
      </div>

      <div className="flex gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search events..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
            data-testid="input-search-events"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]" data-testid="select-severity-filter">
            <Filter className="w-3 h-3 mr-1" />
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[140px]" data-testid="select-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Status</SelectItem>
            <SelectItem value="new">New</SelectItem>
            <SelectItem value="investigating">Investigating</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
            <SelectItem value="dismissed">Dismissed</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardContent className="p-0">
          <ScrollArea className="h-[calc(100vh-230px)]">
            <div className="min-w-[600px]">
              <div className="grid grid-cols-[1fr_100px_120px_100px_80px_80px] gap-2 px-4 py-2 border-b text-[10px] text-muted-foreground uppercase tracking-wider font-medium sticky top-0 bg-card z-10">
                <span>Description</span>
                <span>Type</span>
                <span>Source</span>
                <span>Severity</span>
                <span>Status</span>
                <span>Time</span>
              </div>
              {filtered.length === 0 ? (
                <div className="text-center text-sm text-muted-foreground py-12">No events found</div>
              ) : (
                filtered.map((event) => (
                  <div
                    key={event.id}
                    className="grid grid-cols-[1fr_100px_120px_100px_80px_80px] gap-2 px-4 py-2.5 border-b last:border-0 hover-elevate cursor-pointer items-center"
                    onClick={() => setSelectedEvent(event)}
                    data-testid={`event-row-${event.id}`}
                  >
                    <div className="min-w-0">
                      <p className="text-xs truncate">{event.description}</p>
                      <p className="text-[10px] text-muted-foreground font-mono mt-0.5">
                        {event.sourceIp || "N/A"} {event.destinationIp ? `→ ${event.destinationIp}` : ""}
                      </p>
                    </div>
                    <span className="text-[10px] text-muted-foreground capitalize font-mono">{event.eventType.replace(/_/g, " ")}</span>
                    <span className="text-[10px] text-muted-foreground">{event.source}</span>
                    <Badge className={`${severityClasses[event.severity]} text-[9px] uppercase w-fit`}>
                      {event.severity}
                    </Badge>
                    <Badge className={`${statusClasses[event.status]} text-[9px] uppercase w-fit`}>
                      {event.status}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground font-mono">
                      {formatDate(event.createdAt as unknown as string)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      <Sheet open={!!selectedEvent} onOpenChange={() => setSelectedEvent(null)}>
        <SheetContent className="w-[400px] sm:w-[500px]">
          {selectedEvent && (
            <>
              <SheetHeader>
                <SheetTitle className="text-sm tracking-wider uppercase">Event Details</SheetTitle>
              </SheetHeader>
              <div className="space-y-4 mt-4">
                <div className="flex gap-2 flex-wrap">
                  <Badge className={`${severityClasses[selectedEvent.severity]} text-[10px] uppercase`}>
                    {selectedEvent.severity}
                  </Badge>
                  <Badge className={`${statusClasses[selectedEvent.status]} text-[10px] uppercase`}>
                    {selectedEvent.status}
                  </Badge>
                </div>
                <p className="text-sm">{selectedEvent.description}</p>
                <div className="space-y-3">
                  <DetailRow icon={Server} label="Event Type" value={selectedEvent.eventType.replace(/_/g, " ")} />
                  <DetailRow icon={Globe} label="Source IP" value={selectedEvent.sourceIp || "N/A"} />
                  <DetailRow icon={ArrowRight} label="Dest IP" value={selectedEvent.destinationIp || "N/A"} />
                  <DetailRow icon={Server} label="Port" value={selectedEvent.port?.toString() || "N/A"} />
                  <DetailRow icon={Server} label="Protocol" value={selectedEvent.protocol || "N/A"} />
                  <DetailRow icon={Server} label="Source" value={selectedEvent.source} />
                  <DetailRow icon={Clock} label="Time" value={formatDate(selectedEvent.createdAt as unknown as string)} />
                </div>
                <div className="flex gap-2 mt-6 flex-wrap">
                  {selectedEvent.status === "new" && (
                    <Button
                      size="sm"
                      onClick={() => {
                        updateStatus.mutate({ id: selectedEvent.id, status: "investigating" });
                        setSelectedEvent({ ...selectedEvent, status: "investigating" });
                      }}
                      data-testid="button-investigate-event"
                    >
                      Investigate
                    </Button>
                  )}
                  {selectedEvent.status !== "resolved" && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        updateStatus.mutate({ id: selectedEvent.id, status: "resolved" });
                        setSelectedEvent({ ...selectedEvent, status: "resolved" });
                      }}
                      data-testid="button-resolve-event"
                    >
                      Resolve
                    </Button>
                  )}
                  {selectedEvent.status !== "dismissed" && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => {
                        updateStatus.mutate({ id: selectedEvent.id, status: "dismissed" });
                        setSelectedEvent({ ...selectedEvent, status: "dismissed" });
                      }}
                      data-testid="button-dismiss-event"
                    >
                      Dismiss
                    </Button>
                  )}
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function DetailRow({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3">
      <Icon className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
      <span className="text-xs text-muted-foreground w-20 flex-shrink-0">{label}</span>
      <span className="text-xs font-mono">{value}</span>
    </div>
  );
}
