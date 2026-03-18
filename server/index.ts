import express, { type Request, Response, NextFunction } from "express";
import path from "path";
import { fileURLToPath } from "url";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { WebhookHandlers } from "./webhookHandlers";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import xss from "xss";
import { intrusionDetectionMiddleware, trackRateLimitViolation } from "./securityMiddleware";

const app = express();
app.set("trust proxy", 1);
const httpServer = createServer(app);

declare module "http" {
  interface IncomingMessage {
    rawBody: unknown;
  }
}

export function log(message: string, source = "express") {
  const formattedTime = new Date().toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}

async function syncStripeEventToOrg(rawBody: Buffer): Promise<void> {
  try {
    const event = JSON.parse(rawBody.toString());
    const { storage: s } = await import("./storage");
    const obj = event?.data?.object;
    if (!obj) return;

    const SUBSCRIPTION_EVENTS = [
      "customer.subscription.created",
      "customer.subscription.updated",
      "customer.subscription.trial_will_end",
    ];
    const DELETED_EVENTS = ["customer.subscription.deleted"];
    const INVOICE_PAID = "invoice.paid";
    const INVOICE_FAILED = "invoice.payment_failed";

    if (SUBSCRIPTION_EVENTS.includes(event.type)) {
      const sub = obj;
      const org = sub.customer ? await s.getOrgByStripeCustomerId(sub.customer) : undefined;
      if (!org) return;
      const expiresAt = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
      await s.updateOrganization(org.id, {
        subscriptionStatus: sub.status,
        subscriptionExpiresAt: expiresAt,
        stripeSubscriptionId: sub.id,
      } as any);
      console.log(`[Stripe] Org #${org.id} subscription updated: status=${sub.status} expires=${expiresAt?.toISOString()}`);
    } else if (DELETED_EVENTS.includes(event.type)) {
      const sub = obj;
      const org = sub.customer ? await s.getOrgByStripeCustomerId(sub.customer) : undefined;
      if (!org) return;
      await s.updateOrganization(org.id, { subscriptionStatus: "canceled" } as any);
      console.log(`[Stripe] Org #${org.id} subscription canceled`);
    } else if (event.type === INVOICE_PAID) {
      const invoice = obj;
      const org = invoice.customer ? await s.getOrgByStripeCustomerId(invoice.customer) : undefined;
      if (!org) return;
      const periodEnd = invoice.lines?.data?.[0]?.period?.end;
      const updateData: any = { subscriptionStatus: "active" };
      if (periodEnd) updateData.subscriptionExpiresAt = new Date(periodEnd * 1000);
      await s.updateOrganization(org.id, updateData);
      console.log(`[Stripe] Org #${org.id} invoice paid — subscription active, expires ${updateData.subscriptionExpiresAt?.toISOString() ?? "unknown"}`);
    } else if (event.type === INVOICE_FAILED) {
      const invoice = obj;
      const org = invoice.customer ? await s.getOrgByStripeCustomerId(invoice.customer) : undefined;
      if (!org) return;
      await s.updateOrganization(org.id, { subscriptionStatus: "past_due" } as any);
      console.log(`[Stripe] Org #${org.id} payment failed — status set to past_due`);
    }
  } catch (err) {
    console.error("[Stripe] syncStripeEventToOrg error (non-fatal):", err);
  }
}

app.post(
  '/api/stripe/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const signature = req.headers['stripe-signature'];
    if (!signature) {
      return res.status(400).json({ error: 'Missing stripe-signature' });
    }
    try {
      const sig = Array.isArray(signature) ? signature[0] : signature;
      if (!Buffer.isBuffer(req.body)) {
        return res.status(500).json({ error: 'Webhook processing error' });
      }
      await WebhookHandlers.processWebhook(req.body as Buffer, sig);
      syncStripeEventToOrg(req.body).catch(() => {});
      res.status(200).json({ received: true });
    } catch (error: any) {
      console.error('Webhook error:', error.message);
      res.status(400).json({ error: 'Webhook processing error' });
    }
  }
);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

function sanitizeValue(value: any): any {
  if (typeof value === "string") {
    return xss(value);
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value && typeof value === "object") {
    const sanitized: Record<string, any> = {};
    for (const key of Object.keys(value)) {
      sanitized[key] = sanitizeValue(value[key]);
    }
    return sanitized;
  }
  return value;
}

app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  }),
);
app.use(express.urlencoded({ extended: false }));

app.use((req, _res, next) => {
  if (req.body && typeof req.body === "object") {
    req.body = sanitizeValue(req.body);
  }
  next();
});

const rateLimitHandler = (req: Request, _res: Response, _next: NextFunction, _options: any) => {
  trackRateLimitViolation(req.ip || req.socket.remoteAddress || "unknown");
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    rateLimitHandler(req, res, next, options);
    res.status(429).json({ error: "Too many requests, please try again later" });
  },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    rateLimitHandler(req, res, next, options);
    res.status(429).json({ error: "Too many requests, please try again later" });
  },
});

const ingestionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    rateLimitHandler(req, res, next, options);
    res.status(429).json({ error: "Too many requests, please try again later" });
  },
});

app.use("/api/login", authLimiter);
app.use("/api/register", authLimiter);
app.use("/api/ingest", ingestionLimiter);
app.use("/api", apiLimiter);
app.use("/api", intrusionDetectionMiddleware);

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      log(logLine);
    }
  });

  next();
});

(async () => {
  try {
    const { runMigrations } = await import('stripe-replit-sync');
    const databaseUrl = process.env.DATABASE_URL;
    if (databaseUrl) {
      console.log('Initializing Stripe schema...');
      await runMigrations({ databaseUrl });
      console.log('Stripe schema ready');

      const { getStripeSync } = await import('./stripeClient');
      const stripeSync = await getStripeSync();

      const domain = process.env.REPLIT_DOMAINS?.split(',')[0];
      if (domain) {
        try {
          const webhookBaseUrl = `https://${domain}`;
          const result = await stripeSync.findOrCreateManagedWebhook(
            `${webhookBaseUrl}/api/stripe/webhook`
          );
          console.log(`Stripe webhook configured: ${result?.webhook?.url || 'OK'}`);
        } catch (whErr) {
          console.log('Webhook setup skipped (non-fatal)');
        }
      } else {
        console.log('Skipping webhook setup (no domain available)');
      }

      stripeSync.syncBackfill()
        .then(() => console.log('Stripe data synced'))
        .catch((err: any) => console.error('Error syncing Stripe data:', err));
    }
  } catch (error) {
    console.error('Stripe initialization error (non-fatal):', error);
  }

  const { setupAuth } = await import("./auth");
  setupAuth(app);

  const { scrypt, randomBytes } = await import("crypto");
  const { promisify } = await import("util");
  const scryptAsync = promisify(scrypt);
  const { storage: storageInstance } = await import("./storage");
  try {
    const existingAdmin = await storageInstance.getUserByUsername("admin");
    if (!existingAdmin) {
      const adminPassword = process.env.ADMIN_PASSWORD || "aegis-admin-2024";
      const salt = randomBytes(16).toString("hex");
      const buf = (await scryptAsync(adminPassword, salt, 64)) as Buffer;
      const hashedPassword = `${buf.toString("hex")}.${salt}`;
      const adminOrg = await storageInstance.createOrganization({
        name: "AegisAI360",
        slug: "aegisai360",
        plan: "enterprise",
        maxUsers: 100,
      });
      await storageInstance.updateOrganization(adminOrg.id, {
        subscriptionStatus: "active",
        subscriptionExpiresAt: null,
        trialUsed: true,
      } as any);
      await storageInstance.createUser({
        username: "admin",
        password: hashedPassword,
        organizationId: adminOrg.id,
        role: "admin",
        isSuperAdmin: true,
      });
      console.log("Super admin account created (username: admin)");
    }
  } catch (err) {
    console.log("Admin seeding skipped (may already exist)");
  }

  try {
    const existingPlans = await storageInstance.getPlans();
    if (existingPlans.length === 0) {
      await storageInstance.createPlan({
        name: "starter",
        price: 2900,
        maxAgents: 5,
        maxLogsPerDay: 1000,
        maxCommandsPerDay: 50,
        maxThreatIntelQueries: 10,
        allowNetworkIsolation: false,
        allowProcessKill: false,
        allowFileScan: true,
        allowEndpointDownload: true,
        allowTerminalAccess: false,
        allowThreatIntel: false,
        allowAdvancedAnalytics: false,
        allowAegisAgent: false,
      });
      await storageInstance.createPlan({
        name: "professional",
        price: 9900,
        maxAgents: 25,
        maxLogsPerDay: 10000,
        maxCommandsPerDay: 200,
        maxThreatIntelQueries: 100,
        allowNetworkIsolation: true,
        allowProcessKill: true,
        allowFileScan: true,
        allowEndpointDownload: true,
        allowTerminalAccess: true,
        allowThreatIntel: true,
        allowAdvancedAnalytics: false,
        allowAegisAgent: false,
      });
      await storageInstance.createPlan({
        name: "enterprise",
        price: 29900,
        maxAgents: 100,
        maxLogsPerDay: 100000,
        maxCommandsPerDay: 1000,
        maxThreatIntelQueries: 500,
        allowNetworkIsolation: true,
        allowProcessKill: true,
        allowFileScan: true,
        allowEndpointDownload: true,
        allowTerminalAccess: true,
        allowThreatIntel: true,
        allowAdvancedAnalytics: true,
        allowAegisAgent: true,
      });
      console.log("Plans seeded (starter, professional, enterprise)");
    }
  } catch (err) {
    console.log("Plan seeding skipped (non-fatal)");
  }

  try {
    const { seedAllOrganizations } = await import("./seedRules");
    await seedAllOrganizations();
    console.log("Default rules and playbooks seeded");
  } catch (err) {
    console.log("Rule seeding skipped (non-fatal)");
  }

  try {
    const { startDataRetentionScheduler } = await import("./dataRetention");
    startDataRetentionScheduler();
  } catch (err) {
    console.log("Data retention scheduler failed to start (non-fatal)");
  }

  await registerRoutes(httpServer, app);

  try {
    const { startScanScheduler } = await import("./scanScheduler");
    startScanScheduler();
  } catch (err) {
    console.log("Scan scheduler start skipped (non-fatal)");
  }

  try {
    const { startReportScheduler } = await import("./reportScheduler");
    startReportScheduler();
  } catch (err) {
    console.log("Report scheduler start skipped (non-fatal)");
  }

  try {
    const { startSubscriptionEnforcer } = await import("./subscriptionEnforcer");
    startSubscriptionEnforcer();
  } catch (err) {
    console.log("Subscription enforcer start skipped (non-fatal)");
  }

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = process.env.NODE_ENV === "production" ? "Internal Server Error" : (err.message || "Internal Server Error");
    console.error("Internal Server Error:", err);
    if (res.headersSent) {
      return next(err);
    }
    return res.status(status).json({ message });
  });

  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const downloadsDir = path.resolve(currentDir, "..", "public", "downloads");
  app.use("/downloads", express.static(downloadsDir, {
    setHeaders: (res, filePath) => {
      if (filePath.endsWith(".exe")) {
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Disposition", "attachment; filename=" + path.basename(filePath));
      }
    }
  }));

  if (process.env.NODE_ENV === "production") {
    serveStatic(app);
  } else {
    const { setupVite } = await import("./vite");
    await setupVite(httpServer, app);
  }

  const port = parseInt(process.env.PORT || "5000", 10);
  httpServer.listen(
    {
      port,
      host: "0.0.0.0",
      reusePort: true,
    },
    () => {
      log(`serving on port ${port}`);
    },
  );
})();
