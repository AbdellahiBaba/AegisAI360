export function AegisLogo({ size = 36, showText = true }: { size?: number; showText?: boolean }) {
  return (
    <div className="flex items-center gap-2.5" data-testid="logo-aegis">
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="shieldGrad" x1="24" y1="0" x2="24" y2="48" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(192 90% 45%)" />
            <stop offset="100%" stopColor="hsl(192 90% 25%)" />
          </linearGradient>
          <linearGradient id="circuitGrad" x1="12" y1="12" x2="36" y2="36" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(200 100% 55%)" stopOpacity="0.6" />
            <stop offset="100%" stopColor="hsl(192 90% 40%)" stopOpacity="0.3" />
          </linearGradient>
        </defs>
        <path
          d="M24 2L6 10v12c0 11.1 7.7 21.4 18 24 10.3-2.6 18-12.9 18-24V10L24 2z"
          fill="url(#shieldGrad)"
          stroke="hsl(200 100% 55%)"
          strokeWidth="1"
          strokeOpacity="0.5"
        />
        <path
          d="M24 5L9 12v10c0 9.6 6.5 18.5 15 20.8V5z"
          fill="hsl(192 90% 35%)"
          fillOpacity="0.3"
        />
        <line x1="16" y1="18" x2="22" y2="18" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="22" y1="18" x2="22" y2="24" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="22" y1="24" x2="32" y2="24" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="26" y1="14" x2="26" y2="20" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="16" y1="28" x2="20" y2="28" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="20" y1="28" x2="20" y2="34" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <line x1="28" y1="30" x2="32" y2="30" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <circle cx="16" cy="18" r="1.5" fill="hsl(200 100% 55%)" />
        <circle cx="22" cy="24" r="1.5" fill="hsl(200 100% 55%)" />
        <circle cx="32" cy="24" r="1.5" fill="hsl(200 100% 55%)" />
        <circle cx="26" cy="14" r="1.5" fill="hsl(200 100% 55%)" />
        <circle cx="20" cy="34" r="1.5" fill="hsl(200 100% 55%)" />
        <rect x="11" y="38" width="7" height="2.5" rx="0.5" fill="hsl(192 90% 50%)" fillOpacity="0.9" />
        <rect x="20" y="38" width="7" height="2.5" rx="0.5" fill="hsl(0 80% 55%)" fillOpacity="0.9" />
        <rect x="29" y="38" width="7" height="2.5" rx="0.5" fill="hsl(0 0% 85%)" fillOpacity="0.9" />
      </svg>
      {showText && (
        <div className="flex flex-col">
          <span className="text-sm font-bold tracking-[0.2em] leading-tight">
            AEGIS<span className="text-primary">AI</span>
          </span>
          <span className="text-[9px] text-muted-foreground tracking-[0.3em] uppercase leading-tight">
            Cyber Defense
          </span>
        </div>
      )}
    </div>
  );
}

export function AegisLogoLarge() {
  return (
    <div className="flex flex-col items-center gap-3" data-testid="logo-aegis-large">
      <AegisLogo size={56} showText={false} />
      <div className="text-center">
        <h1 className="text-2xl font-bold tracking-[0.25em]">
          AEGIS<span className="text-primary">AI</span>
        </h1>
        <div className="flex items-center justify-center gap-2 mt-1">
          <div className="h-px w-8 bg-primary/30" />
          <p className="text-[10px] text-muted-foreground tracking-[0.4em] uppercase">
            Cyber Defense Platform
          </p>
          <div className="h-px w-8 bg-primary/30" />
        </div>
      </div>
    </div>
  );
}
