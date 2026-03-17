import { useEffect, useRef, useState } from "react";
import { Terminal, Copy, Trash2, ChevronDown, Wifi, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

interface TrafficConsoleProps {
  trafficLog: string[];
  active: boolean;
  title?: string;
  className?: string;
}

function classifyLine(line: string): "sent" | "received" | "error" | "meta" | "separator" {
  const content = line.replace(/^\[\d{2}:\d{2}:\d{2}\.\d{3}\]\s*/, "");
  if (content.startsWith("─")) return "separator";
  if (content.startsWith("→")) return "sent";
  if (content.startsWith("←")) return "received";
  if (content.startsWith("!")) return "error";
  return "meta";
}

function lineColor(type: ReturnType<typeof classifyLine>): string {
  switch (type) {
    case "sent":      return "text-emerald-400";
    case "received":  return "text-sky-400";
    case "error":     return "text-red-400";
    case "separator": return "text-amber-500 opacity-60";
    case "meta":      return "text-slate-500";
  }
}

function lineTimestamp(line: string): string {
  const m = line.match(/^\[(\d{2}:\d{2}:\d{2}\.\d{3})\]/);
  return m ? m[1] : "";
}

function lineContent(line: string): string {
  return line.replace(/^\[\d{2}:\d{2}:\d{2}\.\d{3}\]\s*/, "");
}

export function TrafficConsole({ trafficLog, active, title = "Live Traffic Console", className = "" }: TrafficConsoleProps) {
  const { toast } = useToast();
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [lineCount, setLineCount] = useState(0);

  useEffect(() => {
    if (autoScroll && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
    setLineCount(trafficLog.length);
  }, [trafficLog.length, autoScroll]);

  const handleScroll = () => {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(atBottom);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(trafficLog.join("\n")).then(() => {
      toast({ title: "Copied", description: `${trafficLog.length} lines copied to clipboard` });
    });
  };

  const scrollToBottom = () => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    setAutoScroll(true);
  };

  return (
    <div className={`flex flex-col rounded-lg border border-slate-700 bg-[#0a0f1a] overflow-hidden shadow-2xl ${className}`}>
      <div className="flex items-center justify-between px-4 py-2 bg-[#0d1424] border-b border-slate-700">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-amber-500" />
          <span className="text-xs font-mono font-semibold text-slate-300">{title}</span>
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-slate-600 text-slate-500 font-mono">
            {lineCount} lines
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          {active ? (
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
              </span>
              <span className="text-[10px] text-emerald-400 font-mono">LIVE</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <WifiOff className="w-3 h-3 text-slate-500" />
              <span className="text-[10px] text-slate-500 font-mono">IDLE</span>
            </div>
          )}
          <Button
            size="sm" variant="ghost"
            className="h-6 px-2 text-slate-400 hover:text-slate-200 hover:bg-slate-700"
            onClick={handleCopy}
            data-testid="button-copy-traffic"
          >
            <Copy className="w-3 h-3 mr-1" />
            <span className="text-[10px]">Copy</span>
          </Button>
        </div>
      </div>

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed"
        style={{ minHeight: 260, maxHeight: 400 }}
        data-testid="traffic-console-output"
      >
        {trafficLog.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-600">
            <Terminal className="w-8 h-8 mb-2 opacity-30" />
            <span className="text-xs">Waiting for traffic...</span>
            <span className="text-[10px] mt-1 opacity-60">Raw HTTP/TCP exchanges will appear here</span>
          </div>
        ) : (
          trafficLog.map((line, i) => {
            const type = classifyLine(line);
            const ts = lineTimestamp(line);
            const content = lineContent(line);
            return (
              <div key={i} className="flex gap-2 leading-snug hover:bg-slate-800/40 px-1 rounded">
                {ts && (
                  <span className="text-slate-700 flex-shrink-0 w-[88px] text-right select-none">
                    {ts}
                  </span>
                )}
                <span className={`${lineColor(type)} whitespace-pre-wrap break-all flex-1`}>
                  {content}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>

      {!autoScroll && trafficLog.length > 0 && (
        <button
          onClick={scrollToBottom}
          className="absolute bottom-16 right-6 bg-amber-600 hover:bg-amber-500 text-white rounded-full p-1.5 shadow-lg transition-colors"
          data-testid="button-scroll-bottom"
        >
          <ChevronDown className="w-4 h-4" />
        </button>
      )}

      <div className="flex items-center justify-between px-4 py-1.5 bg-[#0d1424] border-t border-slate-700">
        <div className="flex items-center gap-4 text-[10px] font-mono">
          <span className="text-emerald-500">→ SENT</span>
          <span className="text-sky-500">← RECEIVED</span>
          <span className="text-red-500">! ERROR</span>
          <span className="text-slate-600">• META</span>
        </div>
        <span className="text-[10px] text-slate-700 font-mono">AegisAI360 Traffic Analyzer</span>
      </div>
    </div>
  );
}
