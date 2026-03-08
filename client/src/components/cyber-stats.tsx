import { useState, useEffect, useRef } from "react";

interface StatConfig {
  label: string;
  value: number;
  suffix: string;
  color: string;
  sparkData: number[];
}

function generateSparkline(length: number, trend: "up" | "down" | "stable"): number[] {
  const data: number[] = [];
  let val = 30 + Math.random() * 40;
  for (let i = 0; i < length; i++) {
    const noise = (Math.random() - 0.5) * 15;
    const trendBias = trend === "up" ? 1.2 : trend === "down" ? -0.8 : 0;
    val = Math.max(5, Math.min(95, val + noise + trendBias));
    data.push(val);
  }
  return data;
}

function Sparkline({ data, color, width = 80, height = 28 }: { data: number[]; color: string; width?: number; height?: number }) {
  const min = Math.min(...data);
  const max = Math.max(...data);
  const range = max - min || 1;

  const points = data.map((val, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - ((val - min) / range) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(" ");

  const areaPoints = `0,${height} ${points} ${width},${height}`;

  return (
    <svg width={width} height={height} className="shrink-0">
      <defs>
        <linearGradient id={`spark-grad-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill={`url(#spark-grad-${color.replace("#", "")})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function AnimatedCounter({ target, suffix, duration = 2000 }: { target: number; suffix: string; duration?: number }) {
  const [count, setCount] = useState(0);
  const startRef = useRef<number | null>(null);
  const rafRef = useRef<number>(0);

  useEffect(() => {
    startRef.current = null;
    const animate = (now: number) => {
      if (startRef.current === null) startRef.current = now;
      const elapsed = now - startRef.current;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 4);
      setCount(Math.floor(eased * target));
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(animate);
      }
    };
    rafRef.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, duration]);

  return (
    <span className="font-mono font-bold tabular-nums">
      {count.toLocaleString()}{suffix}
    </span>
  );
}

export function CyberStats() {
  const [liveValues, setLiveValues] = useState({
    threats: 127453,
    agents: 3842,
    uptime: 9997,
    response: 12,
  });

  const sparklines = useRef({
    threats: generateSparkline(20, "up"),
    agents: generateSparkline(20, "stable"),
    uptime: generateSparkline(20, "up"),
    response: generateSparkline(20, "down"),
  });

  const stats: StatConfig[] = [
    { label: "Threats Blocked Today", value: liveValues.threats, suffix: "", color: "#ef4444", sparkData: sparklines.current.threats },
    { label: "Active Agents", value: liveValues.agents, suffix: "", color: "#22d3ee", sparkData: sparklines.current.agents },
    { label: "SOC Uptime", value: liveValues.uptime, suffix: "%", color: "#22c55e", sparkData: sparklines.current.uptime },
    { label: "Avg Response Time", value: liveValues.response, suffix: "ms", color: "#a855f7", sparkData: sparklines.current.response },
  ];

  useEffect(() => {
    const interval = setInterval(() => {
      setLiveValues(prev => ({
        threats: prev.threats + Math.floor(Math.random() * 30) + 5,
        agents: prev.agents + (Math.random() < 0.3 ? 1 : 0) - (Math.random() < 0.1 ? 1 : 0),
        uptime: 9997,
        response: Math.max(8, Math.min(18, prev.response + (Math.random() < 0.5 ? 1 : -1))),
      }));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="w-full rounded-md border border-border/50 bg-black/80 backdrop-blur-sm overflow-hidden" data-testid="cyber-stats">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-black/50">
        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase text-emerald-400">Live Security Metrics</span>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4">
        {stats.map((stat, i) => (
          <div
            key={stat.label}
            className={`p-4 ${i < stats.length - 1 ? "border-r border-border/20" : ""} ${i < 2 ? "border-b lg:border-b-0 border-border/20" : ""}`}
            data-testid={`stat-${stat.label.toLowerCase().replace(/\s+/g, "-")}`}
          >
            <div className="flex items-center gap-1.5 mb-2">
              <div className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: stat.color }} />
              <span className="text-[9px] font-mono tracking-[0.15em] uppercase text-muted-foreground">{stat.label}</span>
            </div>
            <div className="flex items-end justify-between gap-2">
              <div className="text-xl md:text-2xl" style={{ color: stat.color }}>
                <AnimatedCounter target={stat.value} suffix={stat.suffix} />
              </div>
              <Sparkline data={stat.sparkData} color={stat.color} width={60} height={24} />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
