import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Globe, MapPin } from "lucide-react";
import { useEffect, useState } from "react";

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
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#94a3b8",
};

function projectMercator(lat: number, lng: number, width: number, height: number): [number, number] {
  const x = ((lng + 180) / 360) * width;
  const latRad = (lat * Math.PI) / 180;
  const mercN = Math.log(Math.tan(Math.PI / 4 + latRad / 2));
  const y = height / 2 - (mercN * width) / (2 * Math.PI);
  return [x, y];
}

function WorldMapSVG({ origins }: { origins: AttackOrigin[] }) {
  const [pulsePhase, setPulsePhase] = useState(0);
  const width = 800;
  const height = 400;

  useEffect(() => {
    const interval = setInterval(() => {
      setPulsePhase(p => (p + 1) % 60);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  const continentPaths = [
    "M140,95 L160,85 L175,80 L195,82 L210,78 L225,85 L230,95 L235,105 L230,115 L225,125 L215,130 L200,135 L185,140 L170,145 L155,150 L145,155 L130,165 L120,175 L110,185 L105,195 L100,205 L95,215 L92,230 L95,245 L100,260 L108,275 L115,285 L120,295 L118,305 L112,310 L108,300 L100,290 L90,280 L85,265 L80,250 L78,235 L80,220 L85,205 L90,190 L100,175 L110,160 L120,145 L130,130 L135,115 L140,95 Z",
    "M170,150 L160,160 L155,175 L152,190 L155,205 L160,220 L168,235 L175,250 L178,265 L175,280 L170,290 L168,300 L172,310 L178,305 L185,295 L190,280 L195,265 L198,250 L195,235 L190,220 L185,205 L180,190 L175,175 L170,160 L170,150 Z",
    "M380,70 L400,65 L420,60 L440,55 L460,52 L480,50 L500,52 L520,55 L540,60 L560,65 L570,75 L575,85 L580,95 L578,105 L570,115 L560,120 L550,125 L540,128 L530,130 L520,128 L510,125 L500,120 L490,115 L480,112 L470,115 L460,120 L450,125 L440,130 L430,128 L420,125 L410,120 L400,115 L395,108 L392,100 L388,90 L385,80 L380,70 Z",
    "M425,135 L440,140 L455,150 L465,160 L470,175 L472,190 L468,205 L462,215 L455,225 L448,235 L440,240 L432,238 L425,232 L420,220 L418,205 L420,190 L422,175 L425,160 L425,135 Z",
    "M480,130 L495,125 L510,128 L525,135 L540,140 L555,138 L565,130 L575,125 L585,120 L600,115 L615,118 L630,125 L640,135 L645,150 L648,165 L650,180 L645,195 L640,210 L635,220 L628,225 L620,230 L612,228 L605,222 L600,215 L598,205 L600,195 L605,185 L608,175 L605,165 L600,158 L590,155 L580,158 L570,165 L560,170 L550,172 L540,168 L530,160 L520,155 L510,150 L500,148 L490,145 L485,138 L480,130 Z",
    "M595,245 L615,235 L635,230 L660,232 L680,240 L700,250 L715,265 L720,280 L718,295 L710,308 L695,315 L680,318 L665,315 L650,310 L638,300 L628,288 L620,275 L615,262 L610,252 L600,248 L595,245 Z",
  ];

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-full" data-testid="threat-map-svg">
      <rect width={width} height={height} fill="transparent" />

      <defs>
        <radialGradient id="pulse-gradient">
          <stop offset="0%" stopColor="hsl(185 85% 48%)" stopOpacity="0.6" />
          <stop offset="100%" stopColor="hsl(185 85% 48%)" stopOpacity="0" />
        </radialGradient>
      </defs>

      {continentPaths.map((d, i) => (
        <path
          key={i}
          d={d}
          fill="hsl(var(--muted))"
          stroke="hsl(var(--border))"
          strokeWidth="0.5"
          opacity="0.6"
        />
      ))}

      {origins.map((origin, i) => {
        const [x, y] = projectMercator(origin.lat, origin.lng, width, height);
        const color = severityColors[origin.maxSeverity] || severityColors.info;
        const baseRadius = Math.min(3 + Math.log2(origin.count + 1) * 2, 12);
        const pulseRadius = baseRadius + 4 + Math.sin((pulsePhase + i * 7) * 0.1) * 3;
        const pulseOpacity = 0.15 + Math.sin((pulsePhase + i * 7) * 0.1) * 0.1;

        return (
          <g key={`${origin.ip}-${i}`}>
            <circle
              cx={x}
              cy={y}
              r={pulseRadius}
              fill={color}
              opacity={pulseOpacity}
            />
            <circle
              cx={x}
              cy={y}
              r={baseRadius}
              fill={color}
              opacity={0.5}
              stroke={color}
              strokeWidth="1"
            />
            <circle
              cx={x}
              cy={y}
              r={2}
              fill={color}
              opacity={0.9}
            />
          </g>
        );
      })}
    </svg>
  );
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

  return (
    <Card className="col-span-full" data-testid="threat-map-card">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="text-sm font-medium tracking-wider uppercase font-mono flex items-center gap-2">
            <Globe className="w-4 h-4" />
            Global Threat Map
          </CardTitle>
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="secondary" className="text-[10px] font-mono">
              {origins.length} sources
            </Badge>
            <Badge variant="secondary" className="text-[10px] font-mono">
              {totalAttacks} attacks
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 rounded-md overflow-hidden border border-border bg-muted/20" data-testid="threat-map-container">
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
                <MapPin className="w-3 h-3" />
                Top Attacking Countries
              </h4>
              <ScrollArea className="h-[180px]">
                <div className="space-y-1.5">
                  {topCountries.length === 0 ? (
                    <p className="text-xs text-muted-foreground font-mono py-4 text-center">No data</p>
                  ) : (
                    topCountries.map((c, i) => (
                      <div
                        key={c.countryCode}
                        className="flex items-center justify-between gap-2 py-1.5 px-2 rounded-md"
                        data-testid={`country-row-${c.countryCode}`}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-xs font-mono text-muted-foreground w-4 text-right">{i + 1}.</span>
                          <span className="text-xs font-mono truncate">{c.country}</span>
                        </div>
                        <Badge variant="secondary" className="text-[10px] font-mono flex-shrink-0">
                          {c.count}
                        </Badge>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </div>

            <div className="pt-2 border-t border-border">
              <div className="flex flex-wrap gap-2">
                {Object.entries(severityColors).map(([severity, color]) => (
                  <div key={severity} className="flex items-center gap-1">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
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
