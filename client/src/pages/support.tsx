import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { SupportTicket } from "@shared/schema";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Loader2, Plus, MessageSquare, Send, Wifi, ArrowLeft, TicketCheck, Clock, AlertTriangle, CheckCircle } from "lucide-react";

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    open: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    in_progress: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    resolved: "bg-green-500/20 text-green-400 border-green-500/30",
    closed: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[status] || ""}`} data-testid={`badge-status-${status}`}>
      {status.replace("_", " ").toUpperCase()}
    </Badge>
  );
}

function PriorityBadge({ priority }: { priority: string }) {
  const colors: Record<string, string> = {
    low: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
    medium: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${colors[priority] || ""}`} data-testid={`badge-priority-${priority}`}>
      {priority.toUpperCase()}
    </Badge>
  );
}

function TicketDetail({ ticket, onBack }: { ticket: SupportTicket; onBack: () => void }) {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [message, setMessage] = useState("");

  const ticketQuery = useQuery<SupportTicket>({
    queryKey: ["/api/support/tickets", ticket.id],
    refetchInterval: 5000,
  });

  const current = ticketQuery.data || ticket;
  const messages = Array.isArray(current.messages) ? (current.messages as any[]) : [];

  const sendMutation = useMutation({
    mutationFn: async (content: string) => {
      const res = await apiRequest("POST", `/api/support/tickets/${current.id}/messages`, { content });
      return res.json();
    },
    onSuccess: () => {
      setMessage("");
      queryClient.invalidateQueries({ queryKey: ["/api/support/tickets"] });
    },
    onError: () => toast({ title: t("support.messageFailed"), variant: "destructive" }),
  });

  const remoteRequestMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", `/api/support/tickets/${current.id}/request-remote`);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("support.remoteRequested") });
      queryClient.invalidateQueries({ queryKey: ["/api/support/tickets"] });
    },
    onError: () => toast({ title: t("support.remoteRequestFailed"), variant: "destructive" }),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" onClick={onBack} data-testid="button-back">
          <ArrowLeft className="w-4 h-4 ltr:mr-1 rtl:ml-1" />
          {t("support.back")}
        </Button>
        <div className="flex-1">
          <h3 className="text-sm font-semibold" data-testid="text-ticket-subject">{current.subject}</h3>
          <div className="flex gap-2 mt-1">
            <StatusBadge status={current.status} />
            <PriorityBadge priority={current.priority} />
            <Badge variant="outline" className="text-[10px]">{current.category}</Badge>
          </div>
        </div>
        {!current.remoteSessionRequested && current.status !== "closed" && current.status !== "resolved" && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => remoteRequestMutation.mutate()}
            disabled={remoteRequestMutation.isPending}
            data-testid="button-request-remote"
          >
            <Wifi className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
            {t("support.requestRemote")}
          </Button>
        )}
        {current.remoteSessionRequested && (
          <Badge className={`text-[10px] ${current.remoteSessionActive ? "bg-green-500/20 text-green-400" : "bg-yellow-500/20 text-yellow-400"}`}>
            <Wifi className="w-3 h-3 ltr:mr-1 rtl:ml-1" />
            {current.remoteSessionActive ? t("support.remoteActive") : t("support.remotePending")}
          </Badge>
        )}
      </div>

      <Card>
        <CardContent className="p-4">
          <p className="text-xs text-muted-foreground mb-2" data-testid="text-ticket-description">{current.description}</p>
          <p className="text-[10px] text-muted-foreground">
            {t("support.created")}: {new Date(current.createdAt).toLocaleString()}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="py-3 px-4">
          <CardTitle className="text-xs flex items-center gap-2">
            <MessageSquare className="w-3.5 h-3.5" />
            {t("support.messages")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          <div className="space-y-3 max-h-[400px] overflow-y-auto mb-4">
            {messages.length === 0 && (
              <p className="text-xs text-muted-foreground text-center py-4">{t("support.noMessages")}</p>
            )}
            {messages.map((msg: any, i: number) => (
              <div
                key={i}
                className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                data-testid={`message-${i}`}
              >
                <div className={`max-w-[80%] rounded-lg p-3 text-xs ${
                  msg.role === "user"
                    ? "bg-primary/10 text-foreground"
                    : msg.role === "admin"
                    ? "bg-blue-500/10 text-foreground border border-blue-500/20"
                    : "bg-muted text-muted-foreground italic"
                }`}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold text-[10px]">
                      {msg.role === "user" ? t("common.you") : msg.role === "admin" ? t("support.adminSupport") : t("support.system")}
                    </span>
                    <span className="text-[9px] text-muted-foreground">{new Date(msg.timestamp).toLocaleString()}</span>
                  </div>
                  <p>{msg.content}</p>
                </div>
              </div>
            ))}
          </div>

          {current.status !== "closed" && current.status !== "resolved" && (
            <div className="flex gap-2">
              <Input
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder={t("support.typeMessage")}
                className="text-xs"
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && message.trim() && sendMutation.mutate(message.trim())}
                data-testid="input-message"
              />
              <Button
                size="sm"
                onClick={() => message.trim() && sendMutation.mutate(message.trim())}
                disabled={sendMutation.isPending || !message.trim()}
                data-testid="button-send-message"
              >
                <Send className="w-3.5 h-3.5" />
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export default function SupportPage() {
  const { t } = useTranslation();
  const { toast } = useToast();
  const [selectedTicket, setSelectedTicket] = useState<SupportTicket | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newTicket, setNewTicket] = useState({ subject: "", description: "", priority: "medium", category: "technical" });

  const ticketsQuery = useQuery<SupportTicket[]>({
    queryKey: ["/api/support/tickets"],
  });

  const createMutation = useMutation({
    mutationFn: async (data: typeof newTicket) => {
      const res = await apiRequest("POST", "/api/support/tickets", data);
      return res.json();
    },
    onSuccess: () => {
      toast({ title: t("support.ticketCreated") });
      setDialogOpen(false);
      setNewTicket({ subject: "", description: "", priority: "medium", category: "technical" });
      queryClient.invalidateQueries({ queryKey: ["/api/support/tickets"] });
    },
    onError: () => toast({ title: t("support.ticketCreateFailed"), variant: "destructive" }),
  });

  if (selectedTicket) {
    return (
      <div className="p-4 max-w-4xl mx-auto">
        <TicketDetail ticket={selectedTicket} onBack={() => setSelectedTicket(null)} />
      </div>
    );
  }

  const tickets = ticketsQuery.data || [];
  const openCount = tickets.filter(t => t.status === "open").length;
  const inProgressCount = tickets.filter(t => t.status === "in_progress").length;
  const resolvedCount = tickets.filter(t => t.status === "resolved").length;

  return (
    <div className="p-4 max-w-5xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold" data-testid="text-support-title">{t("support.title")}</h1>
          <p className="text-xs text-muted-foreground">{t("support.subtitle")}</p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" data-testid="button-new-ticket">
              <Plus className="w-3.5 h-3.5 ltr:mr-1 rtl:ml-1" />
              {t("support.newTicket")}
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle className="text-sm">{t("support.createTicket")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <Input
                placeholder={t("support.subjectPlaceholder")}
                value={newTicket.subject}
                onChange={(e) => setNewTicket({ ...newTicket, subject: e.target.value })}
                className="text-xs"
                data-testid="input-subject"
              />
              <Textarea
                placeholder={t("support.descriptionPlaceholder")}
                value={newTicket.description}
                onChange={(e) => setNewTicket({ ...newTicket, description: e.target.value })}
                className="text-xs min-h-[100px]"
                data-testid="input-description"
              />
              <div className="grid grid-cols-2 gap-3">
                <Select value={newTicket.priority} onValueChange={(v) => setNewTicket({ ...newTicket, priority: v })}>
                  <SelectTrigger className="text-xs" data-testid="select-priority">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="low">{t("common.low")}</SelectItem>
                    <SelectItem value="medium">{t("common.medium")}</SelectItem>
                    <SelectItem value="high">{t("common.high")}</SelectItem>
                    <SelectItem value="critical">{t("common.critical")}</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={newTicket.category} onValueChange={(v) => setNewTicket({ ...newTicket, category: v })}>
                  <SelectTrigger className="text-xs" data-testid="select-category">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="technical">{t("support.catTechnical")}</SelectItem>
                    <SelectItem value="billing">{t("support.catBilling")}</SelectItem>
                    <SelectItem value="account">{t("support.catAccount")}</SelectItem>
                    <SelectItem value="security">{t("support.catSecurity")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button
                className="w-full"
                size="sm"
                onClick={() => createMutation.mutate(newTicket)}
                disabled={createMutation.isPending || !newTicket.subject.trim() || !newTicket.description.trim()}
                data-testid="button-submit-ticket"
              >
                {createMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : t("support.submitTicket")}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="grid grid-cols-3 gap-3">
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-blue-500/10">
              <Clock className="w-4 h-4 text-blue-400" />
            </div>
            <div>
              <p className="text-lg font-bold" data-testid="text-open-count">{openCount}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.openTickets")}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-yellow-500/10">
              <AlertTriangle className="w-4 h-4 text-yellow-400" />
            </div>
            <div>
              <p className="text-lg font-bold" data-testid="text-progress-count">{inProgressCount}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.inProgressTickets")}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-3 flex items-center gap-3">
            <div className="p-2 rounded bg-green-500/10">
              <CheckCircle className="w-4 h-4 text-green-400" />
            </div>
            <div>
              <p className="text-lg font-bold" data-testid="text-resolved-count">{resolvedCount}</p>
              <p className="text-[10px] text-muted-foreground">{t("support.resolvedTickets")}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="py-3 px-4">
          <CardTitle className="text-xs flex items-center gap-2">
            <TicketCheck className="w-3.5 h-3.5" />
            {t("support.yourTickets")}
          </CardTitle>
        </CardHeader>
        <CardContent className="px-4 pb-4">
          {ticketsQuery.isLoading ? (
            <div className="flex justify-center py-8">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : tickets.length === 0 ? (
            <p className="text-xs text-muted-foreground text-center py-8" data-testid="text-no-tickets">
              {t("support.noTickets")}
            </p>
          ) : (
            <div className="space-y-2">
              {tickets.map((ticket) => (
                <div
                  key={ticket.id}
                  className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:bg-muted/30 cursor-pointer transition-colors"
                  onClick={() => setSelectedTicket(ticket)}
                  data-testid={`ticket-row-${ticket.id}`}
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium truncate">{ticket.subject}</p>
                    <p className="text-[10px] text-muted-foreground truncate">{ticket.description}</p>
                  </div>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <StatusBadge status={ticket.status} />
                    <PriorityBadge priority={ticket.priority} />
                    {ticket.remoteSessionActive && (
                      <Badge className="text-[10px] bg-green-500/20 text-green-400 border-green-500/30">
                        <Wifi className="w-3 h-3 ltr:mr-1 rtl:ml-1" />
                        {t("support.live")}
                      </Badge>
                    )}
                    <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                      {new Date(ticket.createdAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
