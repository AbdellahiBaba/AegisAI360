import { useEffect, useRef, useState } from "react";
import { Terminal, Copy, ChevronDown, WifiOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

interface TrafficConsoleProps {
  trafficLog: string[];
  active: boolean;
  title?: string;
  className?: string;
}

function classifyLine(line: string): "sent" | "received" | "error" | "meta" | "separator" | "banner" {
  const content = line.replace(/^\[\d{2}:\d{2}:\d{2}\.\d{3}\]\s*/, "");
  if (content.startsWith("─")) return "separator";
  if (content.startsWith("→")) return "sent";
  if (content.startsWith("←")) return "received";
  if (content.startsWith("!")) return "error";
  if (content.startsWith("▓") || content.startsWith("█") || content.startsWith("▄")) return "banner";
  return "meta";
}

function lineColor(type: ReturnType<typeof classifyLine>): string {
  switch (type) {
    case "sent":      return "text-emerald-400";
    case "received":  return "text-sky-400";
    case "error":     return "text-red-400";
    case "separator": return "text-amber-500/70";
    case "banner":    return "text-primary/80";
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

const MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789ABCDEF";

function MatrixRain({ active }: { active: boolean }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animRef = useRef<number | null>(null);

  useEffect(() => {
    if (!active) {
      if (animRef.current) cancelAnimationFrame(animRef.current);
      return;
    }
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const W = canvas.offsetWidth;
    const H = canvas.offsetHeight;
    canvas.width = W;
    canvas.height = H;

    const fontSize = 11;
    const cols = Math.floor(W / fontSize);
    const drops = Array(cols).fill(1);

    const draw = () => {
      ctx.fillStyle = "rgba(10, 15, 26, 0.08)";
      ctx.fillRect(0, 0, W, H);

      ctx.font = `${fontSize}px monospace`;
      for (let i = 0; i < drops.length; i++) {
        const char = MATRIX_CHARS[Math.floor(Math.random() * MATRIX_CHARS.length)];
        const brightness = Math.random();
        if (brightness > 0.92) {
          ctx.fillStyle = `rgba(212, 175, 55, ${0.6 + Math.random() * 0.4})`;
        } else {
          ctx.fillStyle = `rgba(34, 197, 94, ${0.08 + brightness * 0.15})`;
        }
        ctx.fillText(char, i * fontSize, drops[i] * fontSize);
        if (drops[i] * fontSize > H && Math.random() > 0.975) drops[i] = 0;
        drops[i]++;
      }
    };

    const loop = () => { draw(); animRef.current = requestAnimationFrame(loop); };
    animRef.current = requestAnimationFrame(loop);
    return () => { if (animRef.current) cancelAnimationFrame(animRef.current); };
  }, [active]);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 w-full h-full pointer-events-none"
      style={{ opacity: active ? 1 : 0, transition: "opacity 1s ease" }}
    />
  );
}

function GlitchText({ text, active }: { text: string; active: boolean }) {
  const [display, setDisplay] = useState(text);
  useEffect(() => {
    if (!active) { setDisplay(text); return; }
    let frame = 0;
    const glitchChars = "!#$%&@*?<>[]{}|\\^~`";
    const interval = setInterval(() => {
      frame++;
      if (frame % 6 === 0) {
        const arr = text.split("");
        const idx = Math.floor(Math.random() * arr.length);
        arr[idx] = glitchChars[Math.floor(Math.random() * glitchChars.length)];
        setDisplay(arr.join(""));
        setTimeout(() => setDisplay(text), 80);
      }
    }, 120);
    return () => clearInterval(interval);
  }, [active, text]);
  return <span>{display}</span>;
}

function TypewriterBoot({ active, onDone }: { active: boolean; onDone: () => void }) {
  const BOOT_LINES = [
    "AEGIS AI360 — INJECTION WARFARE ENGINE v4.0",
    "Initializing adaptive bypass module...",
    "Loading WAF signature database... [OK]",
    "Configuring payload mutation engine... [OK]",
    "Enabling learning state tracker... [OK]",
    "All systems armed. Commencing strike.",
  ];
  const [lines, setLines] = useState<string[]>([]);
  const [done, setDone] = useState(false);

  useEffect(() => {
    if (!active) { setLines([]); setDone(false); return; }
    let cancelled = false;
    const run = async () => {
      for (let i = 0; i < BOOT_LINES.length; i++) {
        if (cancelled) return;
        await new Promise<void>((r) => setTimeout(r, 280));
        if (!cancelled) setLines((prev) => [...prev, BOOT_LINES[i]]);
      }
      await new Promise<void>((r) => setTimeout(r, 500));
      if (!cancelled) { setDone(true); onDone(); }
    };
    run();
    return () => { cancelled = true; };
  }, [active]);

  if (!active && lines.length === 0) return null;
  if (done) return null;

  return (
    <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-[#0a0f1a]/95 p-6">
      <div className="w-full max-w-md space-y-1 font-mono text-xs">
        {lines.map((l, i) => (
          <div key={i} className={`flex items-center gap-2 ${i === 0 ? "text-primary font-bold text-sm mb-2" : "text-emerald-400/80"}`}>
            {i > 0 && <span className="text-emerald-500">$</span>}
            <span>{l}</span>
            {i === lines.length - 1 && <span className="animate-pulse text-emerald-400">█</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

export function TrafficConsole({ trafficLog, active, title = "Live Traffic Console", className = "" }: TrafficConsoleProps) {
  const { toast } = useToast();
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [lineCount, setLineCount] = useState(0);
  const [showBoot, setShowBoot] = useState(false);
  const wasActiveRef = useRef(false);

  useEffect(() => {
    if (active && !wasActiveRef.current) {
      setShowBoot(true);
    }
    if (!active && wasActiveRef.current) {
      setShowBoot(false);
    }
    wasActiveRef.current = active;
  }, [active]);

  useEffect(() => {
    if (autoScroll && bottomRef.current && !showBoot) {
      bottomRef.current.scrollIntoView({ behavior: "smooth" });
    }
    setLineCount(trafficLog.length);
  }, [trafficLog.length, autoScroll, showBoot]);

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
    <div
      className={`flex flex-col rounded-lg border overflow-hidden shadow-2xl relative transition-all duration-500 ${active ? "border-emerald-500/40 shadow-emerald-500/10" : "border-slate-700"} bg-[#0a0f1a] ${className}`}
      style={{ boxShadow: active ? "0 0 32px rgba(34,197,94,0.08), 0 4px 24px rgba(0,0,0,0.6)" : undefined }}
    >
      <TypewriterBoot active={showBoot} onDone={() => setShowBoot(false)} />

      <div className={`flex items-center justify-between px-4 py-2 border-b relative overflow-hidden ${active ? "bg-[#0a1a0f] border-emerald-500/20" : "bg-[#0d1424] border-slate-700"}`}>
        {active && (
          <div className="absolute inset-0 opacity-20 pointer-events-none">
            <MatrixRain active={active} />
          </div>
        )}
        <div className="flex items-center gap-2 relative z-10">
          <Terminal className={`w-4 h-4 transition-colors ${active ? "text-emerald-400" : "text-amber-500"}`} />
          <span className="text-xs font-mono font-semibold text-slate-300">
            <GlitchText text={title} active={active} />
          </span>
          <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-slate-600 text-slate-500 font-mono">
            {lineCount} lines
          </Badge>
        </div>
        <div className="flex items-center gap-2 relative z-10">
          {active ? (
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
              </span>
              <span className="text-[11px] text-emerald-400 font-mono font-bold tracking-widest">
                <GlitchText text="LIVE" active={active} />
              </span>
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

      {active && (
        <div className="h-px w-full bg-gradient-to-r from-transparent via-emerald-500/60 to-transparent animate-pulse" />
      )}

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed relative"
        style={{ minHeight: 280, maxHeight: 420 }}
        data-testid="traffic-console-output"
      >
        {trafficLog.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-slate-700">
            <div className="relative">
              <Terminal className="w-10 h-10 mb-2 opacity-20" />
              {active && <div className="absolute inset-0 rounded-full animate-ping opacity-10 bg-emerald-500" />}
            </div>
            <span className="text-xs text-slate-600">{active ? "Establishing connection..." : "Waiting for traffic..."}</span>
            <span className="text-[10px] mt-1 opacity-40">Raw HTTP/TCP exchanges will appear here</span>
          </div>
        ) : (
          trafficLog.map((line, i) => {
            const type = classifyLine(line);
            const ts = lineTimestamp(line);
            const content = lineContent(line);
            const isSep = type === "separator";
            return (
              <div
                key={i}
                className={`flex gap-2 leading-snug px-1 rounded transition-colors ${isSep ? "opacity-50" : "hover:bg-slate-800/30"}`}
              >
                {ts && (
                  <span className="text-slate-700 flex-shrink-0 w-[88px] text-right select-none tabular-nums">
                    {ts}
                  </span>
                )}
                <span className={`${lineColor(type)} whitespace-pre-wrap break-all flex-1 ${isSep ? "tracking-widest" : ""}`}>
                  {content}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>

      {active && (
        <div className="h-px w-full bg-gradient-to-r from-transparent via-emerald-500/40 to-transparent" />
      )}

      {!autoScroll && trafficLog.length > 0 && (
        <button
          onClick={scrollToBottom}
          className="absolute bottom-14 right-4 bg-amber-600 hover:bg-amber-500 text-white rounded-full p-1.5 shadow-lg transition-colors z-20"
          data-testid="button-scroll-bottom"
        >
          <ChevronDown className="w-4 h-4" />
        </button>
      )}

      <div className={`flex items-center justify-between px-4 py-1.5 border-t ${active ? "bg-[#0a1a0f] border-emerald-500/15" : "bg-[#0d1424] border-slate-700"}`}>
        <div className="flex items-center gap-3 text-[10px] font-mono">
          <span className="text-emerald-500">→ SENT</span>
          <span className="text-sky-500">← RECEIVED</span>
          <span className="text-red-500">! ERROR</span>
          <span className="text-amber-500/60">─ PHASE</span>
          <span className="text-slate-600">• META</span>
        </div>
        <span className={`text-[10px] font-mono tracking-wider ${active ? "text-emerald-700" : "text-slate-700"}`}>
          {active ? "AEGIS WARFARE ENGINE ACTIVE" : "AegisAI360 Traffic Analyzer"}
        </span>
      </div>
    </div>
  );
}
