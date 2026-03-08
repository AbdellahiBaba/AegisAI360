import { useState, useEffect, useRef } from "react";

interface Node {
  id: string;
  x: number;
  y: number;
  type: "server" | "endpoint" | "firewall" | "cloud" | "database";
  label: string;
  pulse: boolean;
}

interface Packet {
  id: number;
  fromNode: string;
  toNode: string;
  progress: number;
  isAttack: boolean;
  blocked: boolean;
}

const nodes: Node[] = [
  { id: "cloud", x: 50, y: 8, type: "cloud", label: "Internet", pulse: false },
  { id: "fw1", x: 50, y: 25, type: "firewall", label: "WAF", pulse: true },
  { id: "lb", x: 50, y: 42, type: "server", label: "Load Balancer", pulse: false },
  { id: "web1", x: 25, y: 58, type: "server", label: "Web-01", pulse: false },
  { id: "web2", x: 75, y: 58, type: "server", label: "Web-02", pulse: false },
  { id: "api", x: 50, y: 58, type: "server", label: "API Gateway", pulse: false },
  { id: "db1", x: 20, y: 78, type: "database", label: "DB Primary", pulse: false },
  { id: "db2", x: 80, y: 78, type: "database", label: "DB Replica", pulse: false },
  { id: "ep1", x: 10, y: 42, type: "endpoint", label: "EP-01", pulse: false },
  { id: "ep2", x: 90, y: 42, type: "endpoint", label: "EP-02", pulse: false },
  { id: "siem", x: 50, y: 92, type: "server", label: "SIEM", pulse: true },
];

const connections: [string, string][] = [
  ["cloud", "fw1"],
  ["fw1", "lb"],
  ["lb", "web1"],
  ["lb", "web2"],
  ["lb", "api"],
  ["web1", "db1"],
  ["web2", "db2"],
  ["api", "db1"],
  ["api", "db2"],
  ["ep1", "fw1"],
  ["ep2", "fw1"],
  ["db1", "siem"],
  ["db2", "siem"],
  ["web1", "siem"],
  ["web2", "siem"],
];

function getNodePos(id: string) {
  const node = nodes.find(n => n.id === id);
  return node ? { x: node.x, y: node.y } : { x: 50, y: 50 };
}

function NodeIcon({ type, x, y }: { type: string; x: number; y: number }) {
  const size = 10;
  const half = size / 2;
  switch (type) {
    case "firewall":
      return (
        <g>
          <rect x={x - half} y={y - half} width={size} height={size} rx={1.5} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.8} />
          <line x1={x - half + 2} y1={y} x2={x + half - 2} y2={y} stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <line x1={x} y1={y - half + 2} x2={x} y2={y + half - 2} stroke="hsl(var(--primary))" strokeWidth={0.6} />
        </g>
      );
    case "cloud":
      return (
        <g>
          <circle cx={x - 2} cy={y} r={3.5} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <circle cx={x + 2} cy={y - 1} r={3} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <circle cx={x + 1} cy={y + 1} r={2.5} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
        </g>
      );
    case "database":
      return (
        <g>
          <ellipse cx={x} cy={y - 2} rx={4} ry={1.8} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <line x1={x - 4} y1={y - 2} x2={x - 4} y2={y + 3} stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <line x1={x + 4} y1={y - 2} x2={x + 4} y2={y + 3} stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <ellipse cx={x} cy={y + 3} rx={4} ry={1.8} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
        </g>
      );
    case "endpoint":
      return (
        <g>
          <rect x={x - 4} y={y - 3} width={8} height={5} rx={0.5} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <line x1={x - 2} y1={y + 3} x2={x + 2} y2={y + 3} stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <line x1={x} y1={y + 2} x2={x} y2={y + 3} stroke="hsl(var(--primary))" strokeWidth={0.6} />
        </g>
      );
    default:
      return (
        <g>
          <rect x={x - half} y={y - half} width={size} height={size} rx={1.5} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.6} />
          <circle cx={x} cy={y} r={2} fill="hsl(var(--primary))" opacity={0.3} />
        </g>
      );
  }
}

export function CyberNetwork() {
  const [packets, setPackets] = useState<Packet[]>([]);
  const packetId = useRef(0);
  const [shieldFlash, setShieldFlash] = useState(false);

  useEffect(() => {
    const spawnPacket = () => {
      const conn = connections[Math.floor(Math.random() * connections.length)];
      const isAttack = Math.random() < 0.15;
      const fromNode = isAttack ? "cloud" : (Math.random() < 0.5 ? conn[0] : conn[1]);
      const toNode = isAttack ? "fw1" : (fromNode === conn[0] ? conn[1] : conn[0]);

      packetId.current++;
      const newPacket: Packet = {
        id: packetId.current,
        fromNode,
        toNode,
        progress: 0,
        isAttack,
        blocked: false,
      };

      setPackets(prev => [...prev.slice(-15), newPacket]);

      if (isAttack) {
        setTimeout(() => {
          setShieldFlash(true);
          setPackets(prev => prev.map(p => p.id === newPacket.id ? { ...p, blocked: true } : p));
          setTimeout(() => setShieldFlash(false), 600);
        }, 800);
      }
    };

    const interval = setInterval(spawnPacket, 600);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    let raf: number;
    const animate = () => {
      setPackets(prev =>
        prev
          .map(p => ({ ...p, progress: p.progress + (p.blocked ? 0 : 0.02) }))
          .filter(p => p.progress < 1.1 && !p.blocked || p.progress < 0.6)
      );
      raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <div className="w-full rounded-md border border-border/50 bg-black/60 backdrop-blur-sm overflow-hidden" data-testid="cyber-network">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-black/50">
        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase text-emerald-400">Network Topology</span>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{nodes.length} nodes</span>
      </div>
      <svg viewBox="0 0 100 100" className="w-full h-auto" style={{ maxHeight: 340 }}>
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="0.8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter id="attackGlow">
            <feGaussianBlur stdDeviation="1.2" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <radialGradient id="shieldGrad">
            <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.4" />
            <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
          </radialGradient>
        </defs>

        {connections.map(([from, to]) => {
          const f = getNodePos(from);
          const t = getNodePos(to);
          return (
            <line
              key={`${from}-${to}`}
              x1={f.x} y1={f.y} x2={t.x} y2={t.y}
              stroke="hsl(var(--primary))"
              strokeWidth={0.3}
              opacity={0.2}
            />
          );
        })}

        {packets.map((packet) => {
          const from = getNodePos(packet.fromNode);
          const to = getNodePos(packet.toNode);
          const x = from.x + (to.x - from.x) * packet.progress;
          const y = from.y + (to.y - from.y) * packet.progress;
          return (
            <g key={packet.id}>
              <circle
                cx={x} cy={y} r={packet.isAttack ? 1.2 : 0.8}
                fill={packet.isAttack ? (packet.blocked ? "#ef4444" : "#f97316") : "hsl(var(--primary))"}
                filter={packet.isAttack ? "url(#attackGlow)" : "url(#glow)"}
                opacity={packet.blocked ? 0.3 : 0.9}
              />
              {packet.blocked && (
                <g>
                  <line x1={x - 1.5} y1={y - 1.5} x2={x + 1.5} y2={y + 1.5} stroke="#ef4444" strokeWidth={0.4} />
                  <line x1={x + 1.5} y1={y - 1.5} x2={x - 1.5} y2={y + 1.5} stroke="#ef4444" strokeWidth={0.4} />
                </g>
              )}
            </g>
          );
        })}

        {shieldFlash && (
          <circle
            cx={getNodePos("fw1").x}
            cy={getNodePos("fw1").y}
            r={8}
            fill="url(#shieldGrad)"
            className="animate-ping"
            style={{ animationDuration: "0.6s", animationIterationCount: 1 }}
          />
        )}

        {nodes.map((node) => (
          <g key={node.id}>
            {node.pulse && (
              <circle cx={node.x} cy={node.y} r={6} fill="hsl(var(--primary))" opacity={0.05}>
                <animate attributeName="r" values="4;8;4" dur="3s" repeatCount="indefinite" />
                <animate attributeName="opacity" values="0.1;0.02;0.1" dur="3s" repeatCount="indefinite" />
              </circle>
            )}
            <NodeIcon type={node.type} x={node.x} y={node.y} />
            <text
              x={node.x}
              y={node.y + 9}
              textAnchor="middle"
              fill="hsl(var(--muted-foreground))"
              fontSize={2.5}
              fontFamily="monospace"
              opacity={0.7}
            >
              {node.label}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export function CyberRadar() {
  const [blips, setBlips] = useState<Array<{ id: number; angle: number; distance: number; severity: string }>>([]);
  const blipId = useRef(0);
  const [sweepAngle, setSweepAngle] = useState(0);

  useEffect(() => {
    let raf: number;
    const animate = () => {
      setSweepAngle(prev => (prev + 0.8) % 360);
      raf = requestAnimationFrame(animate);
    };
    raf = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(raf);
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      if (Math.random() < 0.4) {
        blipId.current++;
        const newBlip = {
          id: blipId.current,
          angle: Math.random() * 360,
          distance: 15 + Math.random() * 30,
          severity: Math.random() < 0.3 ? "critical" : Math.random() < 0.6 ? "high" : "medium",
        };
        setBlips(prev => [...prev.slice(-12), newBlip]);
      }
    }, 1800);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const fadeInterval = setInterval(() => {
      setBlips(prev => prev.filter(b => {
        const age = (blipId.current - b.id);
        return age < 15;
      }));
    }, 3000);
    return () => clearInterval(fadeInterval);
  }, []);

  const cx = 50;
  const cy = 50;

  return (
    <div className="w-full rounded-md border border-border/50 bg-black/70 backdrop-blur-sm overflow-hidden" data-testid="cyber-radar">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-black/50">
        <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase text-cyan-400">Threat Radar</span>
        <span className="text-[10px] font-mono text-muted-foreground ml-auto">{blips.length} detections</span>
      </div>
      <div className="flex items-center justify-center p-4">
        <svg viewBox="0 0 100 100" className="w-full max-w-[280px] h-auto">
          <defs>
            <radialGradient id="radarBg">
              <stop offset="0%" stopColor="#0a1628" />
              <stop offset="100%" stopColor="#050a14" />
            </radialGradient>
            <linearGradient id="sweepGrad" gradientTransform={`rotate(${sweepAngle}, 0.5, 0.5)`}>
              <stop offset="0%" stopColor="hsl(var(--primary))" stopOpacity="0.3" />
              <stop offset="100%" stopColor="hsl(var(--primary))" stopOpacity="0" />
            </linearGradient>
          </defs>

          <circle cx={cx} cy={cy} r={45} fill="url(#radarBg)" stroke="hsl(var(--primary))" strokeWidth={0.3} opacity={0.5} />
          <circle cx={cx} cy={cy} r={30} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.2} opacity={0.3} />
          <circle cx={cx} cy={cy} r={15} fill="none" stroke="hsl(var(--primary))" strokeWidth={0.2} opacity={0.3} />
          <line x1={cx} y1={cy - 45} x2={cx} y2={cy + 45} stroke="hsl(var(--primary))" strokeWidth={0.15} opacity={0.2} />
          <line x1={cx - 45} y1={cy} x2={cx + 45} y2={cy} stroke="hsl(var(--primary))" strokeWidth={0.15} opacity={0.2} />

          <g transform={`rotate(${sweepAngle}, ${cx}, ${cy})`}>
            <path
              d={`M ${cx} ${cy} L ${cx} ${cy - 45} A 45 45 0 0 1 ${cx + 45 * Math.sin(Math.PI / 6)} ${cy - 45 * Math.cos(Math.PI / 6)} Z`}
              fill="hsl(var(--primary))"
              opacity={0.08}
            />
            <line x1={cx} y1={cy} x2={cx} y2={cy - 45} stroke="hsl(var(--primary))" strokeWidth={0.5} opacity={0.6}>
              <animate attributeName="opacity" values="0.6;0.3;0.6" dur="0.1s" repeatCount="indefinite" />
            </line>
          </g>

          {blips.map((blip) => {
            const rad = (blip.angle * Math.PI) / 180;
            const bx = cx + blip.distance * Math.cos(rad);
            const by = cy + blip.distance * Math.sin(rad);
            const age = blipId.current - blip.id;
            const opacity = Math.max(0.2, 1 - age * 0.06);
            const color = blip.severity === "critical" ? "#ef4444" : blip.severity === "high" ? "#f59e0b" : "#22d3ee";
            return (
              <g key={blip.id}>
                <circle cx={bx} cy={by} r={2.5} fill={color} opacity={opacity * 0.15} />
                <circle cx={bx} cy={by} r={1} fill={color} opacity={opacity}>
                  <animate attributeName="r" values="0.8;1.2;0.8" dur="1.5s" repeatCount="indefinite" />
                </circle>
              </g>
            );
          })}

          <circle cx={cx} cy={cy} r={2} fill="hsl(var(--primary))" opacity={0.6}>
            <animate attributeName="r" values="1.5;2.5;1.5" dur="2s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.6;0.3;0.6" dur="2s" repeatCount="indefinite" />
          </circle>
        </svg>
      </div>
    </div>
  );
}
