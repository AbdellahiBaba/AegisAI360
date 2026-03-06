import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { serveStatic } from "./static";
import { createServer } from "http";
import { WebhookHandlers } from "./webhookHandlers";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import xss from "xss";
import { intrusionDetectionMiddleware, trackRateLimitViolation } from "./securityMiddleware";

const app = express();
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
        name: "Platform Administration",
        slug: "platform-admin",
        plan: "enterprise",
        maxUsers: 100,
      });
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
    const { seedAllOrganizations } = await import("./seedRules");
    await seedAllOrganizations();
    console.log("Default rules and playbooks seeded");
  } catch (err) {
    console.log("Rule seeding skipped (non-fatal)");
  }

  await registerRoutes(httpServer, app);

  app.use((err: any, _req: Request, res: Response, next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = process.env.NODE_ENV === "production" ? "Internal Server Error" : (err.message || "Internal Server Error");
    console.error("Internal Server Error:", err);
    if (res.headersSent) {
      return next(err);
    }
    return res.status(status).json({ message });
  });

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
