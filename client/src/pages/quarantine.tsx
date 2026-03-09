import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle, AlertDialogTrigger } from "@/components/ui/alert-dialog";
import { FileWarning, RotateCcw, Trash2, ShieldOff, Lock } from "lucide-react";
import type { QuarantineItem } from "@shared/schema";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const statusColors: Record<string, string> = {
  quarantined: "bg-severity-critical text-white",
  restored: "bg-status-online text-white",
  deleted: "bg-muted text-muted-foreground",
};

function formatTime(dateStr: string) {
  return new Date(dateStr).toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false,
  });
}

export default function Quarantine() {
  useDocumentTitle("Quarantine");
  const { t } = useTranslation();
  const { toast } = useToast();
  const { data: items, isLoading } = useQuery<QuarantineItem[]>({ queryKey: ["/api/quarantine"] });

  const updateMutation = useMutation({
    mutationFn: async ({ id, status, action }: { id: number; status: string; action: string }) => {
      const res = await apiRequest("PATCH", `/api/quarantine/${id}`, { status, action });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/quarantine"] });
      toast({ title: t("quarantine.itemUpdated") });
    },
  });

  const quarantinedCount = items?.filter((i) => i.status === "quarantined").length || 0;
  const restoredCount = items?.filter((i) => i.status === "restored").length || 0;
  const deletedCount = items?.filter((i) => i.status === "deleted").length || 0;

  if (isLoading) {
    return (
      <div className="p-4 md:p-6 space-y-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-[400px] w-full" />
      </div>
    );
  }

  return (
    <div className="p-4 md:p-6 space-y-4">
      <div>
        <h1 className="text-lg font-bold tracking-wider uppercase">{t("quarantine.title")}</h1>
        <p className="text-xs text-muted-foreground">{t("quarantine.subtitle")}</p>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("quarantine.totalItems")}</span>
          <p className="text-2xl font-bold font-mono mt-1" data-testid="stat-total-quarantine">{items?.length || 0}</p>
        </CardContent></Card>
        <Card className="border-severity-critical/30"><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("quarantine.quarantined")}</span>
          <p className="text-2xl font-bold font-mono text-severity-critical mt-1" data-testid="stat-quarantined">{quarantinedCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("quarantine.restored")}</span>
          <p className="text-2xl font-bold font-mono text-status-online mt-1" data-testid="stat-restored">{restoredCount}</p>
        </CardContent></Card>
        <Card><CardContent className="p-4">
          <span className="text-xs text-muted-foreground uppercase tracking-wider">{t("quarantine.deleted")}</span>
          <p className="text-2xl font-bold font-mono text-muted-foreground mt-1" data-testid="stat-deleted">{deletedCount}</p>
        </CardContent></Card>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase flex items-center gap-2">
            <Lock className="w-4 h-4 text-primary" />{t("quarantine.quarantinedItems")}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <ScrollArea className="w-full">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.file")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.threat")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.source")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.status")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.quarantinedBy")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.time")}</TableHead>
                  <TableHead className="text-[10px] uppercase tracking-wider">{t("quarantine.actions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items?.map((item) => (
                  <TableRow key={item.id} data-testid={`quarantine-row-${item.id}`}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <FileWarning className="w-4 h-4 text-severity-critical flex-shrink-0" />
                        <div>
                          <p className="text-xs font-mono font-bold" data-testid={`quarantine-file-${item.id}`}>{item.fileName}</p>
                          {item.fileHash && <p className="text-[10px] text-muted-foreground font-mono">{item.fileHash.slice(0, 16)}...</p>}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-severity-critical">{item.threat}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs font-mono">{item.sourceAsset || t("common.noData")}</span>
                    </TableCell>
                    <TableCell>
                      <Badge className={`text-[10px] ${statusColors[item.status] || statusColors.quarantined}`}>
                        {item.status}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-xs text-muted-foreground">{item.quarantinedBy || t("quarantine.system")}</span>
                    </TableCell>
                    <TableCell>
                      <span className="text-[10px] text-muted-foreground font-mono">
                        {formatTime(item.createdAt as unknown as string)}
                      </span>
                    </TableCell>
                    <TableCell>
                      {item.status === "quarantined" && (
                        <div className="flex items-center gap-1">
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="sm" variant="ghost" className="h-7 px-2" data-testid={`button-restore-${item.id}`}>
                                <RotateCcw className="w-3 h-3" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>{t("quarantine.restoreFile")}</AlertDialogTitle>
                                <AlertDialogDescription>
                                  {t("quarantine.restoreConfirm", { fileName: item.fileName })}
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>{t("quarantine.cancel")}</AlertDialogCancel>
                                <AlertDialogAction onClick={() => updateMutation.mutate({ id: item.id, status: "restored", action: "restored" })}>
                                  {t("quarantine.restore")}
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                          <AlertDialog>
                            <AlertDialogTrigger asChild>
                              <Button size="sm" variant="ghost" className="h-7 px-2 text-destructive" data-testid={`button-delete-${item.id}`}>
                                <Trash2 className="w-3 h-3" />
                              </Button>
                            </AlertDialogTrigger>
                            <AlertDialogContent>
                              <AlertDialogHeader>
                                <AlertDialogTitle>{t("quarantine.permanentlyDelete")}</AlertDialogTitle>
                                <AlertDialogDescription>
                                  {t("quarantine.deleteConfirm", { fileName: item.fileName })}
                                </AlertDialogDescription>
                              </AlertDialogHeader>
                              <AlertDialogFooter>
                                <AlertDialogCancel>{t("quarantine.cancel")}</AlertDialogCancel>
                                <AlertDialogAction
                                  className="bg-destructive"
                                  onClick={() => updateMutation.mutate({ id: item.id, status: "deleted", action: "deleted" })}
                                >
                                  {t("common.delete")}
                                </AlertDialogAction>
                              </AlertDialogFooter>
                            </AlertDialogContent>
                          </AlertDialog>
                        </div>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
