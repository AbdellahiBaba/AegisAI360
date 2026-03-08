import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ShieldCheck, ChevronRight, AlertTriangle, CheckCircle2, XCircle,
  Download, ArrowLeft, BarChart3, ListChecks, Search, FileDown,
} from "lucide-react";
import { generateCompliancePDF } from "@/lib/reportGenerator";

function GradeIndicator({ grade, percentage, size = "lg" }: { grade: string; percentage: number; size?: "sm" | "lg" }) {
  const dim = size === "lg" ? 96 : 56;
  const stroke = size === "lg" ? 6 : 4;
  const radius = (dim - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percentage / 100) * circumference;

  const gradeColor = percentage >= 80 ? "text-green-500" : percentage >= 60 ? "text-yellow-500" : percentage >= 40 ? "text-orange-500" : "text-red-500";
  const strokeColor = percentage >= 80 ? "stroke-green-500" : percentage >= 60 ? "stroke-yellow-500" : percentage >= 40 ? "stroke-orange-500" : "stroke-red-500";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width={dim} height={dim} className="-rotate-90">
        <circle cx={dim / 2} cy={dim / 2} r={radius} fill="none" stroke="currentColor" strokeWidth={stroke} className="text-muted/30" />
        <circle cx={dim / 2} cy={dim / 2} r={radius} fill="none" strokeWidth={stroke} strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round" className={strokeColor} style={{ transition: "stroke-dashoffset 0.5s ease" }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`font-bold font-mono ${gradeColor} ${size === "lg" ? "text-xl" : "text-sm"}`} data-testid="text-grade">{grade}</span>
        {size === "lg" && <span className="text-[10px] text-muted-foreground">{percentage}%</span>}
      </div>
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  if (status === "pass") return <CheckCircle2 className="w-4 h-4 text-green-500" />;
  if (status === "partial") return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
  return <XCircle className="w-4 h-4 text-red-500" />;
}

function PriorityBadge({ priority }: { priority: string }) {
  const variants: Record<string, string> = {
    critical: "bg-red-500/15 text-red-500 border-red-500/30",
    high: "bg-orange-500/15 text-orange-500 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-500 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-500 border-blue-500/30",
  };
  return (
    <Badge variant="outline" className={`text-[10px] ${variants[priority] || ""}`} data-testid={`badge-priority-${priority}`}>
      {priority.toUpperCase()}
    </Badge>
  );
}

function FrameworkOverview() {
  const { data: scoreData, isLoading: scoreLoading } = useQuery<any>({ queryKey: ["/api/compliance/score"] });
  const { data: frameworks, isLoading: fwLoading } = useQuery<any[]>({ queryKey: ["/api/compliance/frameworks"] });
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  if (selectedFramework) {
    return <FrameworkDetail frameworkId={selectedFramework} onBack={() => setSelectedFramework(null)} />;
  }

  if (scoreLoading || fwLoading) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-32 w-full" />
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-40" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h1 className="text-xl font-bold font-mono flex items-center gap-2" data-testid="text-page-title">
            <ShieldCheck className="w-5 h-5 text-primary" />
            Compliance Dashboard
          </h1>
          <p className="text-xs text-muted-foreground mt-1">Track your security posture against major compliance frameworks</p>
        </div>
      </div>

      {scoreData && (
        <Card data-testid="card-overall-score">
          <CardContent className="flex items-center gap-6 p-4 flex-wrap">
            <GradeIndicator grade={scoreData.overallGrade} percentage={scoreData.overall} />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold">Overall Compliance Score</p>
              <p className="text-xs text-muted-foreground mt-1">Aggregated score across all {scoreData.frameworks?.length || 0} frameworks</p>
              <Progress value={scoreData.overall} className="mt-2 h-2" data-testid="progress-overall" />
            </div>
            <div className="grid grid-cols-3 gap-3">
              {scoreData.frameworks?.map((fw: any) => (
                <div key={fw.id} className="text-center">
                  <p className="text-[10px] text-muted-foreground font-mono">{fw.name}</p>
                  <p className={`text-sm font-bold ${fw.percentage >= 70 ? "text-green-500" : fw.percentage >= 40 ? "text-yellow-500" : "text-red-500"}`}>{fw.grade}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {frameworks?.map((fw: any) => {
          const scoreInfo = scoreData?.frameworks?.find((s: any) => s.id === fw.id);
          return (
            <Card key={fw.id} className="hover-elevate cursor-pointer" onClick={() => setSelectedFramework(fw.id)} data-testid={`card-framework-${fw.id}`}>
              <CardHeader className="flex flex-row items-center justify-between gap-2 pb-2">
                <div className="min-w-0">
                  <CardTitle className="text-sm font-mono">{fw.name}</CardTitle>
                  <p className="text-[10px] text-muted-foreground">v{fw.version}</p>
                </div>
                {scoreInfo && <GradeIndicator grade={scoreInfo.grade} percentage={scoreInfo.percentage} size="sm" />}
              </CardHeader>
              <CardContent className="space-y-2">
                <p className="text-xs text-muted-foreground line-clamp-2">{fw.description}</p>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] text-muted-foreground">{fw.controlCount} controls</span>
                    <span className="text-[10px] text-muted-foreground">{fw.categoryCount} categories</span>
                  </div>
                  <ChevronRight className="w-4 h-4 text-muted-foreground" />
                </div>
                {scoreInfo && <Progress value={scoreInfo.percentage} className="h-1.5" />}
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}

function FrameworkDetail({ frameworkId, onBack }: { frameworkId: string; onBack: () => void }) {
  const { data: assessment, isLoading } = useQuery<any>({ queryKey: ["/api/compliance/assess", frameworkId] });

  if (isLoading) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-40" />
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (!assessment) return null;

  const passCount = assessment.controls?.filter((c: any) => c.status === "pass").length || 0;
  const partialCount = assessment.controls?.filter((c: any) => c.status === "partial").length || 0;
  const failCount = assessment.controls?.filter((c: any) => c.status === "fail").length || 0;

  return (
    <div className="space-y-4 p-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Button variant="ghost" size="icon" onClick={onBack} data-testid="button-back">
          <ArrowLeft className="w-4 h-4" />
        </Button>
        <div className="min-w-0">
          <h1 className="text-lg font-bold font-mono" data-testid="text-framework-name">{assessment.frameworkFullName}</h1>
          <p className="text-xs text-muted-foreground">Version {assessment.version}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card data-testid="card-score-summary">
          <CardContent className="flex flex-col items-center p-4 gap-2">
            <GradeIndicator grade={assessment.grade} percentage={assessment.percentage} />
            <p className="text-xs text-muted-foreground font-mono">{assessment.overallScore}/{assessment.maxScore} points</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <CheckCircle2 className="w-8 h-8 text-green-500" />
            <div>
              <p className="text-2xl font-bold font-mono" data-testid="text-pass-count">{passCount}</p>
              <p className="text-xs text-muted-foreground">Passing</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <div>
              <p className="text-2xl font-bold font-mono" data-testid="text-partial-count">{partialCount}</p>
              <p className="text-xs text-muted-foreground">Partial</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex items-center gap-3 p-4">
            <XCircle className="w-8 h-8 text-red-500" />
            <div>
              <p className="text-2xl font-bold font-mono" data-testid="text-fail-count">{failCount}</p>
              <p className="text-xs text-muted-foreground">Failing</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="controls">
        <TabsList>
          <TabsTrigger value="controls" data-testid="tab-controls">
            <ListChecks className="w-3.5 h-3.5 mr-1" /> Controls
          </TabsTrigger>
          <TabsTrigger value="gaps" data-testid="tab-gaps">
            <Search className="w-3.5 h-3.5 mr-1" /> Gap Analysis
          </TabsTrigger>
          <TabsTrigger value="categories" data-testid="tab-categories">
            <BarChart3 className="w-3.5 h-3.5 mr-1" /> Categories
          </TabsTrigger>
        </TabsList>

        <TabsContent value="controls">
          <Card>
            <ScrollArea className="max-h-[500px]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">Status</TableHead>
                    <TableHead className="w-24">ID</TableHead>
                    <TableHead>Control</TableHead>
                    <TableHead className="w-24">Category</TableHead>
                    <TableHead className="w-20 text-right">Score</TableHead>
                    <TableHead className="hidden lg:table-cell">Evidence</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assessment.controls?.map((control: any) => (
                    <TableRow key={control.id} data-testid={`row-control-${control.id}`}>
                      <TableCell><StatusIcon status={control.status} /></TableCell>
                      <TableCell className="font-mono text-xs">{control.id}</TableCell>
                      <TableCell>
                        <p className="text-xs font-medium">{control.name}</p>
                        <p className="text-[10px] text-muted-foreground">{control.description}</p>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">{control.category}</Badge>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs">{control.score}/{control.maxScore}</TableCell>
                      <TableCell className="hidden lg:table-cell text-[10px] text-muted-foreground max-w-[200px] truncate">{control.evidence}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          </Card>
        </TabsContent>

        <TabsContent value="gaps">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-500" />
                Gap Analysis - {assessment.gaps?.length || 0} issues found
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="max-h-[500px]">
                <div className="space-y-3">
                  {assessment.gaps?.map((gap: any, i: number) => (
                    <div key={i} className="flex items-start gap-3 p-3 rounded-md border" data-testid={`card-gap-${gap.control.id}`}>
                      <StatusIcon status={gap.control.status} />
                      <div className="flex-1 min-w-0 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-mono font-semibold">{gap.control.id}</span>
                          <span className="text-xs font-medium">{gap.control.name}</span>
                          <PriorityBadge priority={gap.priority} />
                        </div>
                        <p className="text-[10px] text-muted-foreground">{gap.control.description}</p>
                        <div className="flex items-center gap-1 mt-1">
                          <Badge variant="outline" className="text-[9px]">Score: {gap.control.score}/{gap.control.maxScore}</Badge>
                        </div>
                        <div className="mt-2 p-2 rounded bg-muted/50">
                          <p className="text-[10px] font-medium text-primary">Remediation:</p>
                          <p className="text-[10px] text-muted-foreground">{gap.control.remediation}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                  {(!assessment.gaps || assessment.gaps.length === 0) && (
                    <div className="text-center py-8 text-sm text-muted-foreground">
                      <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-green-500" />
                      All controls are passing
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="categories">
          <Card>
            <CardContent className="p-4 space-y-4">
              {assessment.categories?.map((cat: any) => (
                <div key={cat.name} className="space-y-1" data-testid={`category-${cat.name}`}>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium">{cat.name}</span>
                    <span className="text-xs font-mono text-muted-foreground">{cat.score}/{cat.maxScore} ({cat.percentage}%)</span>
                  </div>
                  <Progress value={cat.percentage} className="h-2" />
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div>
              <p className="text-xs font-medium">Compliance Report Summary</p>
              <p className="text-[10px] text-muted-foreground">Last assessed: {new Date(assessment.lastAssessed).toLocaleString()}</p>
            </div>
            <div className="flex gap-2 flex-wrap">
              <Button
                variant="outline"
                size="sm"
                onClick={() => generateCompliancePDF(assessment)}
                data-testid="button-generate-pdf-report"
              >
                <FileDown className="w-3.5 h-3.5 mr-1" />
                Generate PDF Report
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const report = {
                    framework: assessment.frameworkFullName,
                    version: assessment.version,
                    grade: assessment.grade,
                    score: `${assessment.overallScore}/${assessment.maxScore} (${assessment.percentage}%)`,
                    assessedAt: assessment.lastAssessed,
                    categories: assessment.categories,
                    gaps: assessment.gaps?.map((g: any) => ({
                      id: g.control.id,
                      name: g.control.name,
                      priority: g.priority,
                      score: `${g.control.score}/${g.control.maxScore}`,
                      remediation: g.control.remediation,
                    })),
                  };
                  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `compliance-${assessment.framework}-${new Date().toISOString().split("T")[0]}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                }}
                data-testid="button-export-report"
              >
                <Download className="w-3.5 h-3.5 mr-1" />
                Export JSON
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export default function CompliancePage() {
  return <FrameworkOverview />;
}
