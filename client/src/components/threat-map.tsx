import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Globe, MapPin, Activity, Shield } from "lucide-react";
import { useEffect, useState, useRef } from "react";

interface AttackOrigin {
  ip: string;
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  count: number;
  maxSeverity: string;
}

interface ThreatMapData {
  attackOrigins: AttackOrigin[];
  topCountries: { country: string; countryCode: string; count: number }[];
  totalAttacks: number;
}

const severityColors: Record<string, string> = {
  critical: "#ff2d55",
  high: "#ff6b35",
  medium: "#ffbe0b",
  low: "#00b4d8",
  info: "#64748b",
};

const severityGlow: Record<string, string> = {
  critical: "0 0 12px rgba(255,45,85,0.8), 0 0 24px rgba(255,45,85,0.4)",
  high: "0 0 10px rgba(255,107,53,0.7), 0 0 20px rgba(255,107,53,0.3)",
  medium: "0 0 8px rgba(255,190,11,0.6), 0 0 16px rgba(255,190,11,0.2)",
  low: "0 0 6px rgba(0,180,216,0.5), 0 0 12px rgba(0,180,216,0.2)",
  info: "0 0 4px rgba(100,116,139,0.4)",
};

function projectMercator(lat: number, lng: number, width: number, height: number): [number, number] {
  const x = ((lng + 180) / 360) * width;
  const latRad = (lat * Math.PI) / 180;
  const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
  const y = height / 2 - (mercN * width) / (2 * Math.PI);
  return [x, y];
}

function generateArcPath(x1: number, y1: number, x2: number, y2: number): string {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const dist = Math.sqrt(dx * dx + dy * dy);
  const curvature = Math.min(dist * 0.4, 80);
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - curvature;
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;
}

const continentPaths = [
  "M120,100 L130,90 L145,82 L160,78 L178,75 L195,72 L210,70 L225,73 L238,80 L245,88 L248,98 L245,108 L240,115 L232,120 L222,124 L210,128 L198,132 L185,138 L172,145 L160,152 L148,160 L138,170 L128,182 L118,195 L110,210 L105,225 L102,240 L100,255 L103,268 L110,278 L118,288 L125,298 L128,310 L125,318 L118,322 L110,315 L102,305 L95,292 L88,278 L82,262 L78,245 L76,228 L78,210 L82,195 L90,178 L100,162 L110,148 L120,135 L128,118 L125,108 L120,100 Z",
  "M150,82 L162,78 L172,82 L180,90 L186,100 L190,112 L188,125 L185,135 L180,145 L175,152 L168,158 L162,165 L155,172 L150,180 L148,190 L150,200 L155,212 L162,225 L168,238 L172,252 L175,265 L172,278 L168,288 L165,298 L168,310 L175,315 L180,308 L185,298 L190,285 L195,270 L198,255 L200,240 L198,225 L195,210 L190,198 L185,185 L180,172 L175,160 L170,148 L162,138 L155,128 L150,118 L148,108 L150,95 L150,82 Z",
  "M368,55 L388,48 L410,42 L432,38 L455,35 L478,33 L498,35 L518,38 L538,42 L555,48 L568,55 L575,65 L580,78 L582,90 L578,102 L572,112 L562,118 L550,122 L538,125 L525,128 L512,130 L500,128 L488,125 L475,120 L465,115 L455,118 L445,122 L435,128 L425,132 L415,130 L405,125 L398,118 L392,110 L388,100 L385,88 L382,78 L378,68 L372,60 L368,55 Z",
  "M420,135 L432,130 L445,132 L458,140 L468,150 L475,162 L480,175 L482,190 L478,205 L472,218 L465,228 L458,238 L450,245 L442,248 L435,245 L428,238 L422,228 L418,215 L415,200 L415,185 L418,170 L420,155 L420,140 L420,135 Z",
  "M478,125 L492,118 L508,115 L525,118 L542,125 L558,132 L572,128 L585,120 L598,112 L612,108 L628,112 L642,120 L652,132 L658,148 L662,165 L665,182 L662,200 L655,215 L648,228 L638,238 L628,242 L618,238 L610,230 L605,220 L602,208 L605,195 L610,182 L612,170 L608,158 L602,150 L592,148 L580,152 L568,160 L555,168 L542,172 L530,168 L518,160 L508,152 L498,148 L488,142 L482,135 L478,125 Z",
  "M590,250 L608,242 L628,235 L652,232 L675,238 L695,248 L712,262 L722,278 L725,295 L720,310 L710,322 L698,328 L682,330 L668,328 L655,322 L642,312 L632,300 L625,288 L618,275 L612,262 L605,255 L598,252 L590,250 Z",
  "M242,72 L255,68 L268,72 L278,80 L285,90 L288,100 L285,110 L278,118 L268,122 L258,118 L250,110 L245,100 L242,88 L242,72 Z",
  "M550,55 L570,50 L590,48 L610,50 L628,55 L642,62 L650,72 L652,85 L648,95 L640,102 L628,105 L615,102 L605,95 L598,85 L592,78 L582,72 L570,65 L558,60 L550,55 Z",
];

const gridLines = Array.from({ length: 7 }, (_, i) => {
  const y = (i + 1) * (400 / 8);
  return `M 0 ${y} L 800 ${y}`;
}).concat(
  Array.from({ length: 9 }, (_, i) => {
    const x = (i + 1) * (800 / 10);
    return `M ${x} 0 L ${x} 400`;
  })
);

const TARGET_X = 400;
const TARGET_Y = 200;

function WorldMapSVG({ origins }: { origins: AttackOrigin[] }) {
  const width = 800;
  const height = 400;
  const [hoveredOrigin, setHoveredOrigin] = useState<number | null>(null);

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full threat-map-svg" data-testid="threat-map-svg" role="img" aria-label={`World threat map showing ${origins.length} attack origins across global locations`}>
      <title>Global Threat Map</title>

      <defs>
        <radialGradient id="map-bg-gradient" cx="50%" cy="50%" r="70%">
          <stop offset="0%" stopColor="hsl(210 30% 12%)" />
          <stop offset="100%" stopColor="hsl(210 40% 6%)" />
        </radialGradient>
        <filter id="glow-critical">
          <feGaussianBlur stdDeviation="3" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="glow-high">
          <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <filter id="glow-default">
          <feGaussianBlur stdDeviation="2" result="coloredBlur" />
          <feMerge>
            <feMergeNode in="coloredBlur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
        <linearGradient id="arc-gradient-critical" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#ff2d55" stopOpacity="0.8" />
          <stop offset="100%" stopColor="#ff2d55" stopOpacity="0.1" />
        </linearGradient>
        <linearGradient id="arc-gradient-high" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#ff6b35" stopOpacity="0.7" />
          <stop offset="100%" stopColor="#ff6b35" stopOpacity="0.1" />
        </linearGradient>
        <linearGradient id="arc-gradient-medium" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#ffbe0b" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#ffbe0b" stopOpacity="0.1" />
        </linearGradient>
        <linearGradient id="arc-gradient-low" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00b4d8" stopOpacity="0.5" />
          <stop offset="100%" stopColor="#00b4d8" stopOpacity="0.1" />
        </linearGradient>
        <linearGradient id="arc-gradient-info" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#64748b" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#64748b" stopOpacity="0.1" />
        </linearGradient>
      </defs>

      <rect width={width} height={height} fill="url(#map-bg-gradient)" rx="4" />

      {gridLines.map((d, i) => (
        <path key={`grid-${i}`} d={d} stroke="hsl(210 20% 18%)" strokeWidth="0.3" opacity="0.4" fill="none" />
      ))}

      {continentPaths.map((d, i) => (
        <path
          key={i}
          d={d}
          fill="hsl(210 25% 18%)"
          stroke="hsl(185 40% 30%)"
          strokeWidth="0.6"
          opacity="0.7"
        />
      ))}

      {origins.map((origin, i) => {
        const [x, y] = projectMercator(origin.lat, origin.lng, width, height);
        const arcPath = generateArcPath(x, y, TARGET_X, TARGET_Y);
        const gradientId = `arc-gradient-${origin.maxSeverity || "info"}`;
        const isHovered = hoveredOrigin === i;

        return (
          <path
            key={`arc-${i}`}
            d={arcPath}
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeWidth={isHovered ? 2 : 1}
            opacity={isHovered ? 1 : 0.5}
            className="threat-arc"
            style={{ animationDelay: `${i * 0.3}s` }}
          />
        );
      })}

      <circle cx={TARGET_X} cy={TARGET_Y} r="6" className="target-pulse-outer" fill="none" stroke="hsl(185 85% 48%)" strokeWidth="1" />
      <circle cx={TARGET_X} cy={TARGET_Y} r="3" fill="hsl(185 85% 48%)" opacity="0.9" />

      {origins.map((origin, i) => {
        const [x, y] = projectMercator(origin.lat, origin.lng, width, height);
        const color = severityColors[origin.maxSeverity] || severityColors.info;
        const baseRadius = Math.min(3 + Math.log2(origin.count + 1) * 2, 12);
        const glowFilter = origin.maxSeverity === "critical" ? "url(#glow-critical)" : origin.maxSeverity === "high" ? "url(#glow-high)" : "url(#glow-default)";
        const isHovered = hoveredOrigin === i;

        return (
          <g
            key={`marker-${origin.ip}-${i}`}
            onMouseEnter={() => setHoveredOrigin(i)}
            onMouseLeave={() => setHoveredOrigin(null)}
            style={{ cursor: "pointer" }}
            data-testid={`threat-marker-${i}`}
          >
            <circle
              cx={x}
              cy={y}
              r={baseRadius + 6}
              fill={color}
              opacity="0.08"
              className="marker-pulse-ring"
              style={{ animationDelay: `${i * 0.2}s` }}
            />
            <circle
              cx={x}
              cy={y}
              r={baseRadius + 3}
              fill={color}
              opacity="0.15"
              className="marker-pulse-ring-inner"
              style={{ animationDelay: `${i * 0.2 + 0.5}s` }}
            />
            <circle
              cx={x}
              cy={y}
              r={isHovered ? baseRadius + 2 : baseRadius}
              fill={color}
              opacity={isHovered ? 0.8 : 0.5}
              filter={glowFilter}
              className="transition-all duration-200"
            />
            <circle
              cx={x}
              cy={y}
              r={2}
              fill={color}
              opacity={0.95}
            />
            {isHovered && (
              <g>
                <rect
                  x={x + 10}
                  y={y - 40}
                  width="140"
                  height="60"
                  rx="4"
                  fill="hsl(210 30% 10%)"
                  stroke="hsl(185 40% 30%)"
                  strokeWidth="0.5"
                  opacity="0.95"
                />
                <text x={x + 16} y={y - 24} fill="#e2e8f0" fontSize="9" fontFamily="monospace">{origin.ip}</text>
                <text x={x + 16} y={y - 12} fill="#94a3b8" fontSize="8" fontFamily="monospace">{origin.country}</text>
                <text x={x + 16} y={y} fill={color} fontSize="8" fontFamily="monospace" style={{ textTransform: "uppercase" }}>
                  {origin.maxSeverity}
                </text>
                <text x={x + 16} y={y + 12} fill="#94a3b8" fontSize="8" fontFamily="monospace">
                  {origin.count} event{origin.count !== 1 ? "s" : ""}
                </text>
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

function AnimatedCounter({ value }: { value: number }) {
  const [display, setDisplay] = useState(0);
  const prevValue = useRef(0);

  useEffect(() => {
    const start = prevValue.current;
    const end = value;
    const duration = 1200;
    const startTime = performance.now();

    function animate(now: number) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplay(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(animate);
    }

    requestAnimationFrame(animate);
    prevValue.current = value;
  }, [value]);

  return <span data-testid="text-attack-count">{display.toLocaleString()}</span>;
}

export function ThreatMap() {
  const { data, isLoading } = useQuery<ThreatMapData>({
    queryKey: ["/api/dashboard/threat-map"],
    refetchInterval: 30000,
  });

  if (isLoading) {
    return (
      <Card className="col-span-full" data-testid="threat-map-loading">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Threat Map
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-[280px] w-full rounded-md" />
        </CardContent>
      </Card>
    );
  }

  const origins = data?.attackOrigins || [];
  const topCountries = data?.topCountries || [];
  const totalAttacks = data?.totalAttacks || 0;
  const maxCountryCount = topCountries.length > 0 ? topCountries[0].count : 1;

  return (
    <Card className="col-span-full" data-testid="threat-map-card">
      <style>{`
        @keyframes pulseRing {
          0% { r: inherit; opacity: 0.15; }
          50% { opacity: 0.25; }
          100% { r: inherit; opacity: 0.15; }
        }
        @keyframes pulseRingInner {
          0% { opacity: 0.15; }
          50% { opacity: 0.3; }
          100% { opacity: 0.15; }
        }
        @keyframes targetPulse {
          0% { r: 6; opacity: 0.6; }
          50% { r: 12; opacity: 0.1; }
          100% { r: 6; opacity: 0.6; }
        }
        @keyframes arcDash {
          0% { stroke-dashoffset: 1000; }
          100% { stroke-dashoffset: 0; }
        }
        .marker-pulse-ring {
          animation: pulseRing 2.5s ease-in-out infinite;
        }
        .marker-pulse-ring-inner {
          animation: pulseRingInner 2s ease-in-out infinite;
        }
        .target-pulse-outer {
          animation: targetPulse 2s ease-in-out infinite;
        }
        .threat-arc {
          stroke-dasharray: 8, 4;
          animation: arcDash 20s linear infinite;
        }
        .threat-map-svg {
          background: transparent;
        }
      `}</style>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Global Threat Map
          </CardTitle>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1.5" data-testid="status-live-attacks">
              <Activity className="w-3.5 h-3.5 text-red-500" />
              <span className="text-xs font-mono font-semibold">
                <AnimatedCounter value={totalAttacks} />
              </span>
              <span className="text-xs text-muted-foreground font-mono">attacks</span>
            </div>
            <Badge variant="secondary" className="text-[10px] font-mono">
              <Shield className="w-3 h-3 mr-1" />
              {origins.length} sources
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 rounded-md border border-border" style={{ background: "hsl(210 40% 6%)" }} data-testid="threat-map-container">
            <div className="aspect-[2/1] relative">
              {origins.length === 0 ? (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-muted-foreground">
                  <Globe className="w-10 h-10 mb-2 opacity-30" />
                  <p className="text-xs font-mono">No geolocated threats detected</p>
                </div>
              ) : (
                <WorldMapSVG origins={origins} />
              )}
            </div>
          </div>

          <div className="space-y-3">
            <div>
              <h4 className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <Activity className="w-3 h-3 text-red-500" />
                Live Feed
              </h4>
              <ScrollArea className="h-[80px] mb-3">
                <div className="space-y-1">
                  {origins.length === 0 ? (
                    <p className="text-[10px] text-muted-foreground font-mono py-2 text-center">Waiting for events</p>
                  ) : (
                    origins.slice(0, 8).map((o, i) => (
                      <div
                        key={`${o.ip}-${i}`}
                        className="flex items-center gap-2 py-1 px-2 rounded text-[10px] font-mono"
                        style={{ animationDelay: `${i * 150}ms` }}
                        data-testid={`feed-entry-${i}`}
                      >
                        <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: severityColors[o.maxSeverity] || severityColors.info }} />
                        <span className="text-muted-foreground truncate">{o.ip}</span>
                        <span className="text-muted-foreground/60 truncate">{o.country}</span>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </div>
            <div className="border-t border-border pt-2">
              <h4 className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                <MapPin className="w-3 h-3" />
                Top Attacking Countries
              </h4>
              <ScrollArea className="h-[180px]">
                <div className="space-y-1">
                  {topCountries.length === 0 ? (
                    <p className="text-xs text-muted-foreground font-mono py-4 text-center">No data</p>
                  ) : (
                    topCountries.map((c, i) => {
                      const barWidth = Math.max((c.count / maxCountryCount) * 100, 5);
                      return (
                        <div
                          key={c.countryCode}
                          className="py-1.5 px-2 rounded-md"
                          data-testid={`country-row-${c.countryCode}`}
                        >
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-xs font-mono text-muted-foreground w-4 text-right shrink-0">{i + 1}.</span>
                              <span className="text-xs font-mono truncate">{c.country}</span>
                            </div>
                            <Badge variant="secondary" className="text-[10px] font-mono shrink-0">
                              {c.count}
                            </Badge>
                          </div>
                          <div className="ml-6 h-1 rounded-full bg-muted/30">
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{
                                width: `${barWidth}%`,
                                background: i === 0 ? severityColors.critical : i < 3 ? severityColors.high : severityColors.medium,
                              }}
                              data-testid={`progress-bar-${c.countryCode}`}
                            />
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </ScrollArea>
            </div>

            <div className="pt-2 border-t border-border">
              <div className="flex flex-wrap gap-2">
                {Object.entries(severityColors).map(([severity, color]) => (
                  <div key={severity} className="flex items-center gap-1">
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{
                        backgroundColor: color,
                        boxShadow: severityGlow[severity] || "none",
                      }}
                    />
                    <span className="text-[10px] text-muted-foreground capitalize font-mono">{severity}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
