import { useState, useEffect, useRef } from "react";

const killChainStages = [
  { id: "recon", label: "Recon", detail: "Target profiling", color: "#64748b" },
  { id: "weaponize", label: "Weaponize", detail: "Payload crafted", color: "#8b5cf6" },
  { id: "deliver", label: "Deliver", detail: "Phishing email", color: "#f59e0b" },
  { id: "exploit", label: "Exploit", detail: "CVE-2024-XXX", color: "#ef4444" },
  { id: "install", label: "Install", detail: "Dropper active", color: "#dc2626" },
  { id: "c2", label: "C2", detail: "Beacon attempt", color: "#b91c1c" },
  { id: "actions", label: "Actions", detail: "Data exfil", color: "#991b1b" },
];

const defensePoints: Record<string, { label: string; stageIndex: number }> = {
  "deliver": { label: "Email Filter", stageIndex: 2 },
  "exploit": { label: "EDR Block", stageIndex: 3 },
  "install": { label: "Quarantine", stageIndex: 4 },
  "c2": { label: "Firewall", stageIndex: 5 },
};

export function CyberAttackFlow() {
  const [activeStage, setActiveStage] = useState(-1);
  const [blockedAt, setBlockedAt] = useState<number | null>(null);
  const [cycle, setCycle] = useState(0);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    let stageIdx = -1;
    const defenseKeys = Object.keys(defensePoints);
    const blockStageId = defenseKeys[cycle % defenseKeys.length];
    const blockIdx = defensePoints[blockStageId].stageIndex;

    intervalRef.current = setInterval(() => {
      stageIdx++;
      if (stageIdx <= blockIdx) {
        setActiveStage(stageIdx);
        if (stageIdx === blockIdx) {
          setBlockedAt(blockIdx);
          setTimeout(() => {
            if (intervalRef.current) clearInterval(intervalRef.current);
            setTimeout(() => {
              setActiveStage(-1);
              setBlockedAt(null);
              setCycle(prev => prev + 1);
            }, 1800);
          }, 100);
        }
      }
    }, 700);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [cycle]);

  return (
    <div className="w-full rounded-md border border-border/50 bg-black/80 backdrop-blur-sm overflow-hidden" data-testid="cyber-attack-flow">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border/30 bg-black/50">
        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
        <span className="text-[10px] font-mono tracking-[0.2em] uppercase text-red-400">Kill Chain Defense</span>
        <span className="text-[10px] font-mono text-muted-foreground ms-auto">MITRE ATT&CK</span>
      </div>
      <div className="px-3 pt-4 pb-10 md:px-6 md:pt-6 md:pb-12 overflow-x-auto">
        <div className="relative min-w-[480px]">
          <div className="absolute top-5 md:top-7 inset-x-0 mx-[7%] h-px bg-white/[0.08]" />

          <div className="relative grid grid-cols-7 w-full">
            {killChainStages.map((stage, index) => {
              const isActive = index <= activeStage;
              const isBlocked = blockedAt !== null && index === blockedAt;
              const defensePoint = defensePoints[stage.id];

              return (
                <div key={stage.id} className="flex flex-col items-center relative" data-testid={`stage-${stage.id}`}>
                  <div
                    className="w-10 h-10 md:w-14 md:h-14 rounded-md flex items-center justify-center relative transition-all duration-500 z-10"
                    style={{
                      backgroundColor: isBlocked ? "rgba(239,68,68,0.15)" : isActive ? `${stage.color}20` : "rgba(255,255,255,0.03)",
                      borderWidth: "1px",
                      borderStyle: "solid",
                      borderColor: isBlocked ? "#ef4444" : isActive ? `${stage.color}80` : "rgba(255,255,255,0.08)",
                      boxShadow: isBlocked ? "0 0 20px rgba(239,68,68,0.4)" : isActive ? `0 0 12px ${stage.color}30` : "none",
                    }}
                  >
                    {isBlocked ? (
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" className="animate-pulse">
                        <circle cx="12" cy="12" r="10" stroke="#ef4444" strokeWidth="2" />
                        <line x1="8" y1="8" x2="16" y2="16" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" />
                        <line x1="16" y1="8" x2="8" y2="16" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" />
                      </svg>
                    ) : (
                      <span
                        className="text-[10px] font-mono font-bold uppercase transition-colors duration-500"
                        style={{ color: isActive ? stage.color : "rgba(255,255,255,0.2)" }}
                      >
                        {String(index + 1).padStart(2, "0")}
                      </span>
                    )}
                    {isActive && !isBlocked && (
                      <div
                        className="absolute inset-0 rounded-md animate-ping"
                        style={{ backgroundColor: `${stage.color}10`, animationDuration: "1.5s" }}
                      />
                    )}
                  </div>
                  <span
                    className="text-[8px] md:text-[9px] font-mono font-bold tracking-wider uppercase mt-2 transition-colors duration-500 text-center"
                    style={{ color: isBlocked ? "#ef4444" : isActive ? stage.color : "rgba(255,255,255,0.25)" }}
                  >
                    {stage.label}
                  </span>
                  <span
                    className="text-[7px] md:text-[8px] font-mono mt-0.5 transition-colors duration-500 text-center"
                    style={{ color: isActive ? "rgba(255,255,255,0.5)" : "rgba(255,255,255,0.15)" }}
                  >
                    {isBlocked ? "BLOCKED" : stage.detail}
                  </span>

                  {defensePoint && (
                    <div className="absolute -bottom-7 left-1/2 -translate-x-1/2 flex flex-col items-center">
                      <div className="w-px h-2" style={{ backgroundColor: isBlocked ? "#22c55e" : "rgba(34,197,94,0.2)" }} />
                      <span
                        className="text-[6px] md:text-[7px] font-mono tracking-wider whitespace-nowrap px-1 py-0.5 rounded-sm transition-all duration-500"
                        style={{
                          backgroundColor: isBlocked ? "rgba(34,197,94,0.15)" : "transparent",
                          color: isBlocked ? "#22c55e" : "rgba(34,197,94,0.3)",
                          borderWidth: "1px",
                          borderStyle: "solid",
                          borderColor: isBlocked ? "rgba(34,197,94,0.4)" : "rgba(34,197,94,0.1)",
                        }}
                      >
                        {defensePoint.label}
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
