import { Router, Request, Response } from "express";

const router = Router();

interface TargetStats {
  totalReceived: number;
  windowCount: number;
  windowStart: number;
  currentRps: number;
  peakRps: number;
  lastReset: number;
  rpsHistory: number[];
  methodCounts: Record<string, number>;
  errorInjectionPct: number;
}

const stats: TargetStats = {
  totalReceived: 0,
  windowCount: 0,
  windowStart: Date.now(),
  currentRps: 0,
  peakRps: 0,
  lastReset: Date.now(),
  rpsHistory: [],
  methodCounts: {},
  errorInjectionPct: 0,
};

// Rolling RPS ticker — updates every 500ms
setInterval(() => {
  const now = Date.now();
  const elapsed = (now - stats.windowStart) / 1000;
  if (elapsed >= 1) {
    const rps = Math.floor(stats.windowCount / elapsed);
    stats.currentRps = rps;
    if (rps > stats.peakRps) stats.peakRps = rps;
    stats.rpsHistory.push(rps);
    if (stats.rpsHistory.length > 120) stats.rpsHistory.shift();
    stats.windowCount = 0;
    stats.windowStart = now;
  }
}, 500);

// ─── Target endpoint — responds as fast as possible ─────────────────────────
router.all("/hit", (req: Request, res: Response) => {
  stats.totalReceived++;
  stats.windowCount++;
  stats.methodCounts[req.method] = (stats.methodCounts[req.method] ?? 0) + 1;

  // Optional artificial error injection for resilience testing
  if (stats.errorInjectionPct > 0 && Math.random() * 100 < stats.errorInjectionPct) {
    return res.status(503).json({ ok: false, msg: "injected-error", t: Date.now() });
  }

  return res.json({ ok: true, received: stats.totalReceived, t: Date.now() });
});

// ─── Stats endpoint ──────────────────────────────────────────────────────────
router.get("/stats", (_req: Request, res: Response) => {
  return res.json({
    totalReceived: stats.totalReceived,
    currentRps: stats.currentRps,
    peakRps: stats.peakRps,
    rpsHistory: stats.rpsHistory.slice(-60),
    methodCounts: stats.methodCounts,
    errorInjectionPct: stats.errorInjectionPct,
    uptimeSecs: Math.floor((Date.now() - stats.lastReset) / 1000),
  });
});

// ─── Configure error injection ───────────────────────────────────────────────
router.post("/config", (req: Request, res: Response) => {
  const pct = parseFloat(req.body?.errorInjectionPct);
  if (!isNaN(pct) && pct >= 0 && pct <= 100) {
    stats.errorInjectionPct = pct;
  }
  return res.json({ errorInjectionPct: stats.errorInjectionPct });
});

// ─── Reset stats ─────────────────────────────────────────────────────────────
router.post("/reset", (_req: Request, res: Response) => {
  stats.totalReceived = 0;
  stats.windowCount = 0;
  stats.windowStart = Date.now();
  stats.currentRps = 0;
  stats.peakRps = 0;
  stats.lastReset = Date.now();
  stats.rpsHistory = [];
  stats.methodCounts = {};
  return res.json({ ok: true, reset: true });
});

export default router;
