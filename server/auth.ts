import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Express } from "express";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { generateSecret as totpGenerateSecret, generateURI as totpGenerateURI, verifySync as totpVerifySync } from "otplib";
import * as QRCode from "qrcode";
import { pool, db } from "./db";
import { storage } from "./storage";
import type { User } from "@shared/schema";
import { sql } from "drizzle-orm";

const scryptAsync = promisify(scrypt);

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000;

async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

async function comparePasswords(supplied: string, stored: string): Promise<boolean> {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

export let sessionMiddleware: ReturnType<typeof session>;

export function setupAuth(app: Express) {
  const PgStore = connectPg(session);

  const sessionSettings: session.SessionOptions = {
    secret: process.env.SESSION_SECRET!,
    resave: false,
    saveUninitialized: false,
    store: new PgStore({
      pool,
      createTableIfMissing: true,
    }),
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
    },
    proxy: true,
  };

  sessionMiddleware = session(sessionSettings);
  app.use(sessionMiddleware);
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user) return done(null, false, { message: "Invalid username or password" });

        if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) {
          const remaining = Math.ceil((new Date(user.lockedUntil).getTime() - Date.now()) / 60000);
          return done(null, false, { message: `Account temporarily locked. Try again in ${remaining} minute(s).` });
        }

        const valid = await comparePasswords(password, user.password);
        if (!valid) {
          const attempts = (user.failedLoginAttempts || 0) + 1;
          if (attempts >= MAX_FAILED_ATTEMPTS) {
            await storage.updateUserLockout(user.id, attempts, new Date(Date.now() + LOCKOUT_DURATION_MS));
            await storage.createSecurityEvent({
              organizationId: user.organizationId,
              eventType: "account_lockout",
              severity: "high",
              source: "auth",
              description: `Account "${user.username}" locked after ${MAX_FAILED_ATTEMPTS} failed login attempts`,
              status: "new",
            });
            return done(null, false, { message: "Account temporarily locked due to too many failed attempts. Try again in 15 minutes." });
          } else {
            await storage.updateUserLockout(user.id, attempts, null);
            return done(null, false, { message: "Invalid username or password" });
          }
        }

        if (user.failedLoginAttempts && user.failedLoginAttempts > 0) {
          await storage.updateUserLockout(user.id, 0, null);
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }),
  );

  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: string, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user || null);
    } catch (err) {
      done(err);
    }
  });

  app.post("/api/register", async (req, res, next) => {
    try {
      const { username, password, inviteCode } = req.body;
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password are required" });
      }
      if (password.length < 8) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
      }
      if (!/[A-Z]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one uppercase letter" });
      }
      if (!/[a-z]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one lowercase letter" });
      }
      if (!/[0-9]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one number" });
      }
      if (!/[!@#$%^&*()_+\-=]/.test(password)) {
        return res.status(400).json({ error: "Password must contain at least one special character (!@#$%^&*()_+-=)" });
      }

      const existing = await storage.getUserByUsername(username);
      if (existing) {
        return res.status(400).json({ error: "Username already taken" });
      }

      const hashedPassword = await hashPassword(password);
      let organizationId: number;
      let role = "admin";

      if (inviteCode) {
        const invite = await storage.getInviteByCode(inviteCode);
        if (!invite || invite.used || new Date(invite.expiresAt) < new Date()) {
          return res.status(400).json({ error: "Invalid or expired invite code" });
        }
        organizationId = invite.organizationId;
        role = invite.role;
        await storage.useInvite(invite.id);
      } else {
        const slug = username.toLowerCase().replace(/[^a-z0-9]/g, "-") + "-" + randomBytes(3).toString("hex");
        const org = await storage.createOrganization({
          name: `${username}'s Organization`,
          slug,
          plan: "starter",
          maxUsers: 5,
        });
        organizationId = org.id;
      }

      const user = await storage.createUser({
        username,
        password: hashedPassword,
        organizationId,
        role,
      });

      req.login(user, async (err) => {
        if (err) return next(err);
        await trackSessionMetadata(req, user);
        const { password: _, totpSecret: _ts, ...safeUser } = user;
        res.status(201).json(safeUser);
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "Registration failed" });
    }
  });

  async function trackSessionMetadata(req: any, user: User) {
    try {
      const sessionId = req.sessionID;
      if (sessionId) {
        const ipAddress = req.ip || req.headers["x-forwarded-for"] || req.connection?.remoteAddress || "unknown";
        const userAgent = req.headers["user-agent"] || "unknown";
        const existing = await storage.getSessionMetadata(sessionId);
        if (!existing) {
          await storage.createSessionMetadata({
            sessionId,
            userId: user.id,
            ipAddress: typeof ipAddress === "string" ? ipAddress : String(ipAddress),
            userAgent,
          });
        }
      }
    } catch (e) {
      console.error("Failed to track session metadata:", e);
    }
  }

  app.use(async (req, _res, next) => {
    if (req.isAuthenticated() && req.sessionID) {
      try {
        await storage.updateSessionLastActive(req.sessionID);
      } catch (err) { console.error("Failed to update session last active:", err); }
    }
    next();
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: User | false, info: any) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ error: info?.message || "Login failed" });

      if (user.totpEnabled) {
        const token = randomBytes(32).toString("hex");
        pendingTwoFactor.set(token, { userId: user.id, expiresAt: Date.now() + 5 * 60 * 1000 });
        setTimeout(() => pendingTwoFactor.delete(token), 5 * 60 * 1000);
        return res.json({ requiresTwoFactor: true, twoFactorToken: token });
      }

      req.login(user, async (err) => {
        if (err) return next(err);
        await trackSessionMetadata(req, user);
        const { password: _, totpSecret: _ts, ...safeUser } = user;
        res.json(safeUser);
      });
    })(req, res, next);
  });

  const pendingTwoFactor = new Map<string, { userId: string; expiresAt: number }>();

  app.post("/api/auth/2fa/verify-login", async (req, res, next) => {
    try {
      const { twoFactorToken, code } = req.body;
      if (!twoFactorToken || !code) {
        return res.status(400).json({ error: "Two-factor token and code are required" });
      }

      const pending = pendingTwoFactor.get(twoFactorToken);
      if (!pending || pending.expiresAt < Date.now()) {
        pendingTwoFactor.delete(twoFactorToken);
        return res.status(401).json({ error: "Two-factor session expired. Please login again." });
      }

      const user = await storage.getUser(pending.userId);
      if (!user || !user.totpSecret) {
        return res.status(401).json({ error: "Invalid two-factor session" });
      }

      const result = totpVerifySync({ token: code, secret: user.totpSecret });
      if (!result.valid) {
        return res.status(401).json({ error: "Invalid two-factor code" });
      }

      pendingTwoFactor.delete(twoFactorToken);

      req.login(user, async (err) => {
        if (err) return next(err);
        await trackSessionMetadata(req, user);
        const { password: _, totpSecret: _ts, ...safeUser } = user;
        res.json(safeUser);
      });
    } catch (error) {
      res.status(500).json({ error: "Two-factor verification failed" });
    }
  });

  app.post("/api/auth/2fa/setup", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;
      if (user.totpEnabled) {
        return res.status(400).json({ error: "Two-factor authentication is already enabled" });
      }

      const secret = totpGenerateSecret();
      const otpauth = totpGenerateURI({ issuer: "AegisAI360", label: user.username, secret, type: "totp" });
      const qrCode = await QRCode.toDataURL(otpauth);

      await storage.updateUserTotpSecret(user.id, secret);

      res.json({ secret, qrCode, otpauth });
    } catch (error) {
      res.status(500).json({ error: "Failed to setup two-factor authentication" });
    }
  });

  app.post("/api/auth/2fa/enable", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;
      const { code } = req.body;
      if (!code) return res.status(400).json({ error: "Verification code is required" });

      const freshUser = await storage.getUser(user.id);
      if (!freshUser?.totpSecret) {
        return res.status(400).json({ error: "Please complete 2FA setup first" });
      }

      const verifyResult = totpVerifySync({ token: code, secret: freshUser.totpSecret });
      if (!verifyResult.valid) {
        return res.status(400).json({ error: "Invalid verification code. Please try again." });
      }

      await storage.enableUserTotp(user.id);

      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "2fa_enabled",
        targetType: "user",
        targetId: user.id,
        details: "Two-factor authentication enabled",
      });

      res.json({ enabled: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to enable two-factor authentication" });
    }
  });

  app.post("/api/auth/2fa/disable", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;

      await storage.disableUserTotp(user.id);

      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "2fa_disabled",
        targetType: "user",
        targetId: user.id,
        details: "Two-factor authentication disabled",
      });

      res.json({ enabled: false });
    } catch (error) {
      res.status(500).json({ error: "Failed to disable two-factor authentication" });
    }
  });

  app.post("/api/logout", async (req, res, next) => {
    const sessionId = req.sessionID;
    req.logout(async (err) => {
      if (err) return next(err);
      try {
        if (sessionId) await storage.deleteSessionMetadata(sessionId);
      } catch (err) { console.error("Failed to delete session metadata on logout:", err); }
      res.sendStatus(200);
    });
  });

  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { password: _, totpSecret: _ts, ...safeUser } = req.user as User;
    res.json(safeUser);
  });

  app.get("/api/auth/sessions", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;
      const sessions = await storage.getSessionsByUser(user.id);
      const currentSessionId = req.sessionID;
      res.json(sessions.map(s => ({
        ...s,
        isCurrent: s.sessionId === currentSessionId,
      })));
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch sessions" });
    }
  });

  app.delete("/api/auth/sessions/:id", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;
      const sessionId = req.params.id;

      if (sessionId === req.sessionID) {
        return res.status(400).json({ error: "Cannot revoke current session. Use logout instead." });
      }

      const sessionMeta = await storage.getSessionMetadata(sessionId);
      if (!sessionMeta || sessionMeta.userId !== user.id) {
        return res.status(404).json({ error: "Session not found" });
      }

      await db.execute(sql`DELETE FROM "session" WHERE sid = ${sessionId}`);
      await storage.deleteSessionMetadata(sessionId);

      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "session_revoked",
        targetType: "session",
        targetId: sessionId,
        details: `Revoked session from ${sessionMeta.ipAddress || "unknown"}`,
      });

      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to revoke session" });
    }
  });

  app.post("/api/auth/sessions/revoke-all", requireAuth, async (req, res) => {
    try {
      const user = req.user as User;
      const currentSessionId = req.sessionID;

      const revokedSessionIds = await storage.deleteAllSessionsExcept(user.id, currentSessionId);

      for (const sid of revokedSessionIds) {
        try {
          await db.execute(sql`DELETE FROM "session" WHERE sid = ${sid}`);
        } catch (err) { console.error(`Failed to delete session ${sid}:`, err); }
      }

      await storage.createAuditLog({
        organizationId: user.organizationId,
        userId: user.id,
        action: "all_sessions_revoked",
        targetType: "session",
        targetId: user.id,
        details: `Revoked ${revokedSessionIds.length} other session(s)`,
      });

      res.json({ success: true, revokedCount: revokedSessionIds.length });
    } catch (error) {
      res.status(500).json({ error: "Failed to revoke sessions" });
    }
  });
}

export function requireAuth(req: any, res: any, next: any) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: "Authentication required" });
}

export function requireRole(...roles: string[]) {
  return (req: any, res: any, next: any) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Authentication required" });
    const user = req.user as User;
    if (!roles.includes(user.role)) return res.status(403).json({ error: "Insufficient permissions" });
    next();
  };
}

export function requireActiveSubscription(req: any, res: any, next: any) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: "Authentication required" });
  const user = req.user as User;
  if (user.isSuperAdmin) return next();
  const org = (req as any).__org;
  if (org && (org.subscriptionStatus === "active" || org.subscriptionStatus === "trial")) return next();
  res.status(403).json({ error: "Active subscription required", redirect: "/choose-plan" });
}

export function requirePlanFeature(feature: string) {
  return async (req: any, res: any, next: any) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Authentication required" });
    const user = req.user as User;
    if (user.isSuperAdmin) return next();
    const org = await storage.getOrganization(user.organizationId!);
    if (!org?.planId) return res.status(403).json({ error: "No plan selected", redirect: "/choose-plan" });
    const plan = await storage.getPlanById(org.planId);
    if (!plan) return res.status(403).json({ error: "Plan not found" });
    if (!(plan as any)[feature]) return res.status(403).json({ error: `Feature not available on your plan. Upgrade to access this feature.`, feature });
    next();
  };
}
