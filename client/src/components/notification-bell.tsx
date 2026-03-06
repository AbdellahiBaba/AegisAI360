import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Bell, AlertTriangle, Info, Zap, CheckCheck, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { queryClient, apiRequest } from "@/lib/queryClient";

interface Notification {
  id: number;
  title: string;
  message: string;
  type: string;
  read: boolean;
  actionUrl: string | null;
  createdAt: string;
}

const typeConfig: Record<string, { icon: typeof Bell; color: string }> = {
  critical: { icon: AlertTriangle, color: "text-severity-critical" },
  warning: { icon: AlertTriangle, color: "text-severity-medium" },
  action: { icon: Zap, color: "text-primary" },
  info: { icon: Info, color: "text-muted-foreground" },
};

function formatTimeAgo(dateStr: string) {
  const diff = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}

export function NotificationBell() {
  const [open, setOpen] = useState(false);

  const { data: unreadData } = useQuery<{ count: number }>({
    queryKey: ["/api/notifications/unread-count"],
    refetchInterval: 15000,
  });

  const { data: notifications } = useQuery<Notification[]>({
    queryKey: ["/api/notifications"],
    enabled: open,
  });

  const markRead = useMutation({
    mutationFn: async (id: number) => {
      await apiRequest("PATCH", `/api/notifications/${id}/read`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/unread-count"] });
    },
  });

  const markAllRead = useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/notifications/mark-all-read");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/notifications"] });
      queryClient.invalidateQueries({ queryKey: ["/api/notifications/unread-count"] });
    },
  });

  const unreadCount = unreadData?.count ?? 0;

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" data-testid="button-notifications">
          <Bell className="w-4 h-4" />
          {unreadCount > 0 && (
            <Badge className="absolute -top-1 -right-1 h-4 min-w-4 px-1 text-[9px] bg-severity-critical text-white border-0 flex items-center justify-center">
              {unreadCount > 99 ? "99+" : unreadCount}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[360px] p-0" align="end">
        <div className="flex items-center justify-between px-4 py-2.5 border-b">
          <span className="text-xs font-medium tracking-wider uppercase">Notifications</span>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              className="h-6 text-[10px]"
              onClick={() => markAllRead.mutate()}
              data-testid="button-mark-all-read"
            >
              <CheckCheck className="w-3 h-3 mr-1" />
              Mark all read
            </Button>
          )}
        </div>
        <ScrollArea className="max-h-[360px]">
          {!notifications || notifications.length === 0 ? (
            <div className="text-center text-xs text-muted-foreground py-8">
              No notifications
            </div>
          ) : (
            <div className="divide-y">
              {notifications.slice(0, 20).map((notif) => {
                const config = typeConfig[notif.type] || typeConfig.info;
                const Icon = config.icon;
                return (
                  <div
                    key={notif.id}
                    className={`flex gap-3 px-4 py-2.5 hover-elevate cursor-pointer ${!notif.read ? "bg-primary/5" : ""}`}
                    onClick={() => {
                      if (!notif.read) markRead.mutate(notif.id);
                      if (notif.actionUrl) window.location.href = notif.actionUrl;
                    }}
                    data-testid={`notification-item-${notif.id}`}
                  >
                    <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${config.color}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium truncate">{notif.title}</p>
                      <p className="text-[10px] text-muted-foreground line-clamp-2 mt-0.5">{notif.message}</p>
                      <span className="text-[9px] text-muted-foreground font-mono mt-1 block">
                        {formatTimeAgo(notif.createdAt)}
                      </span>
                    </div>
                    {!notif.read && (
                      <div className="w-2 h-2 rounded-full bg-primary mt-1.5 flex-shrink-0" />
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </ScrollArea>
      </PopoverContent>
    </Popover>
  );
}
