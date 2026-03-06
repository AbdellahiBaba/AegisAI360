export function AegisLogo({ size = 36, showText = true }: { size?: number; showText?: boolean }) {
  return (
    <div className="flex items-center gap-2.5" data-testid="logo-aegis">
      <svg width={size} height={size} viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="shieldGrad" x1="24" y1="0" x2="24" y2="48" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(45 100% 65%)" />
            <stop offset="50%" stopColor="hsl(42 90% 50%)" />
            <stop offset="100%" stopColor="hsl(38 85% 30%)" />
          </linearGradient>
          <linearGradient id="innerGrad" x1="24" y1="8" x2="24" y2="40" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(228 45% 12%)" />
            <stop offset="100%" stopColor="hsl(228 45% 5%)" />
          </linearGradient>
          <linearGradient id="circuitGrad" x1="12" y1="12" x2="36" y2="36" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="hsl(42 90% 60%)" stopOpacity="0.8" />
            <stop offset="100%" stopColor="hsl(42 90% 40%)" stopOpacity="0.4" />
          </linearGradient>
        </defs>
        <path
          d="M24 2L6 10v12c0 11.1 7.7 21.4 18 24 10.3-2.6 18-12.9 18-24V10L24 2z"
          fill="url(#shieldGrad)"
          stroke="hsl(45 100% 70%)"
          strokeWidth="0.5"
          strokeOpacity="0.6"
        />
        <path
          d="M24 6L10 12.5v9.5c0 9 6 17.5 14 19.8 8-2.3 14-10.8 14-19.8v-9.5L24 6z"
          fill="url(#innerGrad)"
          stroke="hsl(42 90% 50%)"
          strokeWidth="0.3"
          strokeOpacity="0.4"
        />
        <circle cx="24" cy="20" r="5" fill="none" stroke="url(#circuitGrad)" strokeWidth="1.2" />
        <circle cx="24" cy="20" r="2" fill="hsl(42 90% 55%)" />
        <line x1="24" y1="15" x2="24" y2="10" stroke="url(#circuitGrad)" strokeWidth="0.8" />
        <line x1="24" y1="25" x2="24" y2="30" stroke="url(#circuitGrad)" strokeWidth="0.8" />
        <line x1="19" y1="20" x2="14" y2="20" stroke="url(#circuitGrad)" strokeWidth="0.8" />
        <line x1="29" y1="20" x2="34" y2="20" stroke="url(#circuitGrad)" strokeWidth="0.8" />
        <line x1="20.5" y1="16.5" x2="17" y2="13" stroke="url(#circuitGrad)" strokeWidth="0.6" />
        <line x1="27.5" y1="16.5" x2="31" y2="13" stroke="url(#circuitGrad)" strokeWidth="0.6" />
        <line x1="20.5" y1="23.5" x2="17" y2="27" stroke="url(#circuitGrad)" strokeWidth="0.6" />
        <line x1="27.5" y1="23.5" x2="31" y2="27" stroke="url(#circuitGrad)" strokeWidth="0.6" />
        <circle cx="14" cy="20" r="1" fill="hsl(42 90% 55%)" fillOpacity="0.7" />
        <circle cx="34" cy="20" r="1" fill="hsl(42 90% 55%)" fillOpacity="0.7" />
        <circle cx="24" cy="10" r="1" fill="hsl(42 90% 55%)" fillOpacity="0.7" />
        <circle cx="24" cy="30" r="1" fill="hsl(42 90% 55%)" fillOpacity="0.7" />
        <rect x="18" y="33" width="12" height="1.5" rx="0.75" fill="hsl(42 90% 50%)" fillOpacity="0.5" />
        <rect x="20" y="36" width="8" height="1" rx="0.5" fill="hsl(42 90% 50%)" fillOpacity="0.3" />
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
