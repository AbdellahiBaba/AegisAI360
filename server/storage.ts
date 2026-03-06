import {
  users, securityEvents, incidents, threatIntel, securityPolicies,
  type User, type InsertUser,
  type SecurityEvent, type InsertSecurityEvent,
  type Incident, type InsertIncident,
  type ThreatIntel, type InsertThreatIntel,
  type SecurityPolicy, type InsertSecurityPolicy,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, gte, count } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  getSecurityEvents(): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;
  updateSecurityEventStatus(id: number, status: string): Promise<SecurityEvent | undefined>;
  getIncidents(): Promise<Incident[]>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: number, data: Partial<InsertIncident & { status: string }>): Promise<Incident | undefined>;
  getThreatIntel(): Promise<ThreatIntel[]>;
  createThreatIntel(intel: InsertThreatIntel): Promise<ThreatIntel>;
  updateThreatIntel(id: number, data: Partial<{ active: boolean }>): Promise<ThreatIntel | undefined>;
  getSecurityPolicies(): Promise<SecurityPolicy[]>;
  createSecurityPolicy(policy: InsertSecurityPolicy): Promise<SecurityPolicy>;
  updateSecurityPolicy(id: number, data: Partial<{ enabled: boolean }>): Promise<SecurityPolicy | undefined>;
  getDashboardStats(): Promise<{
    totalEvents: number;
    criticalAlerts: number;
    activeIncidents: number;
    threatScore: number;
    eventTrend: number;
    incidentTrend: number;
  }>;
  getEventTrend(): Promise<{ time: string; events: number }[]>;
  getEventCount(): Promise<number>;
}

export class DatabaseStorage implements IStorage {
  async getUser(id: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user || undefined;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.username, username));
    return user || undefined;
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async getSecurityEvents(): Promise<SecurityEvent[]> {
    return db.select().from(securityEvents).orderBy(desc(securityEvents.createdAt)).limit(200);
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent> {
    const [created] = await db.insert(securityEvents).values(event).returning();
    return created;
  }

  async updateSecurityEventStatus(id: number, status: string): Promise<SecurityEvent | undefined> {
    const [updated] = await db.update(securityEvents).set({ status }).where(eq(securityEvents.id, id)).returning();
    return updated;
  }

  async getIncidents(): Promise<Incident[]> {
    return db.select().from(incidents).orderBy(desc(incidents.createdAt));
  }

  async createIncident(incident: InsertIncident): Promise<Incident> {
    const [created] = await db.insert(incidents).values(incident).returning();
    return created;
  }

  async updateIncident(id: number, data: Partial<InsertIncident & { status: string }>): Promise<Incident | undefined> {
    const [updated] = await db.update(incidents)
      .set({ ...data, updatedAt: new Date() })
      .where(eq(incidents.id, id))
      .returning();
    return updated;
  }

  async getThreatIntel(): Promise<ThreatIntel[]> {
    return db.select().from(threatIntel).orderBy(desc(threatIntel.lastSeen));
  }

  async createThreatIntel(intel: InsertThreatIntel): Promise<ThreatIntel> {
    const [created] = await db.insert(threatIntel).values(intel).returning();
    return created;
  }

  async updateThreatIntel(id: number, data: Partial<{ active: boolean }>): Promise<ThreatIntel | undefined> {
    const [updated] = await db.update(threatIntel).set(data).where(eq(threatIntel.id, id)).returning();
    return updated;
  }

  async getSecurityPolicies(): Promise<SecurityPolicy[]> {
    return db.select().from(securityPolicies).orderBy(desc(securityPolicies.createdAt));
  }

  async createSecurityPolicy(policy: InsertSecurityPolicy): Promise<SecurityPolicy> {
    const [created] = await db.insert(securityPolicies).values(policy).returning();
    return created;
  }

  async updateSecurityPolicy(id: number, data: Partial<{ enabled: boolean }>): Promise<SecurityPolicy | undefined> {
    const [updated] = await db.update(securityPolicies).set({ ...data, updatedAt: new Date() }).where(eq(securityPolicies.id, id)).returning();
    return updated;
  }

  async getDashboardStats() {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [totalResult] = await db.select({ count: count() }).from(securityEvents)
      .where(gte(securityEvents.createdAt, oneDayAgo));
    const [criticalResult] = await db.select({ count: count() }).from(securityEvents)
      .where(and(eq(securityEvents.severity, "critical"), gte(securityEvents.createdAt, oneDayAgo)));
    const [activeResult] = await db.select({ count: count() }).from(incidents)
      .where(sql`${incidents.status} NOT IN ('resolved', 'closed')`);

    const totalEvents = totalResult?.count ?? 0;
    const criticalAlerts = criticalResult?.count ?? 0;
    const activeIncidents = activeResult?.count ?? 0;
    const threatScore = Math.min(100, Math.round(criticalAlerts * 15 + totalEvents * 0.5));

    return {
      totalEvents,
      criticalAlerts,
      activeIncidents,
      threatScore,
      eventTrend: Math.round((Math.random() - 0.3) * 30),
      incidentTrend: Math.round((Math.random() - 0.5) * 20),
    };
  }

  async getEventTrend(): Promise<{ time: string; events: number }[]> {
    const hours = [];
    for (let i = 23; i >= 0; i--) {
      const time = new Date(Date.now() - i * 60 * 60 * 1000);
      hours.push({
        start: new Date(time.getFullYear(), time.getMonth(), time.getDate(), time.getHours()),
        label: time.toLocaleTimeString("en-US", { hour: "2-digit", hour12: true }),
      });
    }

    const results: { time: string; events: number }[] = [];
    for (const hour of hours) {
      const end = new Date(hour.start.getTime() + 60 * 60 * 1000);
      const [result] = await db.select({ count: count() }).from(securityEvents)
        .where(and(
          gte(securityEvents.createdAt, hour.start),
          sql`${securityEvents.createdAt} < ${end}`,
        ));
      results.push({ time: hour.label, events: result?.count ?? 0 });
    }
    return results;
  }

  async getEventCount(): Promise<number> {
    const [result] = await db.select({ count: count() }).from(securityEvents);
    return result?.count ?? 0;
  }
}

export const storage = new DatabaseStorage();
