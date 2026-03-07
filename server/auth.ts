import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Express } from "express";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { pool } from "./db";
import { storage } from "./storage";
import type { User } from "@shared/schema";

const scryptAsync = promisify(scrypt);

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

  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());

  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user) return done(null, false, { message: "Invalid username or password" });
        const valid = await comparePasswords(password, user.password);
        if (!valid) return done(null, false, { message: "Invalid username or password" });
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

      req.login(user, (err) => {
        if (err) return next(err);
        const { password: _, ...safeUser } = user;
        res.status(201).json(safeUser);
      });
    } catch (error) {
      console.error("Registration error:", error);
      res.status(500).json({ error: "Registration failed" });
    }
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: User | false, info: any) => {
      if (err) return next(err);
      if (!user) return res.status(401).json({ error: info?.message || "Login failed" });
      req.login(user, (err) => {
        if (err) return next(err);
        const { password: _, ...safeUser } = user;
        res.json(safeUser);
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) return next(err);
      res.sendStatus(200);
    });
  });

  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const { password: _, ...safeUser } = req.user as User;
    res.json(safeUser);
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
