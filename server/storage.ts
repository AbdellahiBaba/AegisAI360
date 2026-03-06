import {
  users, organizations, securityEvents, incidents, threatIntel, securityPolicies,
  invites, assets, auditLogs, honeypotEvents, quarantineItems, responsePlaybooks,
  type User, type InsertUser,
  type Organization, type InsertOrganization,
  type SecurityEvent, type InsertSecurityEvent,
  type Incident, type InsertIncident,
  type ThreatIntel, type InsertThreatIntel,
  type SecurityPolicy, type InsertSecurityPolicy,
  type Invite, type InsertInvite,
  type Asset, type InsertAsset,
  type AuditLog, type InsertAuditLog,
  type HoneypotEvent, type InsertHoneypotEvent,
  type QuarantineItem, type InsertQuarantineItem,
  type ResponsePlaybook, type InsertResponsePlaybook,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, gte, count } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser & { organizationId?: number; role?: string }): Promise<User>;

  createOrganization(org: InsertOrganization): Promise<Organization>;
  getOrganization(id: number): Promise<Organization | undefined>;
  updateOrganization(id: number, data: Partial<InsertOrganization>): Promise<Organization | undefined>;
  getOrganizationUserCount(orgId: number): Promise<number>;

  getSecurityEvents(orgId: number): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;
  updateSecurityEventStatus(id: number, orgId: number, status: string): Promise<SecurityEvent | undefined>;

  getIncidents(orgId: number): Promise<Incident[]>;
  createIncident(incident: InsertIncident): Promise<Incident>;
  updateIncident(id: number, orgId: number, data: Partial<InsertIncident & { status: string }>): Promise<Incident | undefined>;

  getThreatIntel(orgId: number): Promise<ThreatIntel[]>;
  createThreatIntel(intel: InsertThreatIntel): Promise<ThreatIntel>;
  updateThreatIntel(id: number, orgId: number, data: Partial<{ active: boolean }>): Promise<ThreatIntel | undefined>;

  getSecurityPolicies(orgId: number): Promise<SecurityPolicy[]>;
  createSecurityPolicy(policy: InsertSecurityPolicy): Promise<SecurityPolicy>;
  updateSecurityPolicy(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<SecurityPolicy | undefined>;

  getInvites(orgId: number): Promise<Invite[]>;
  createInvite(invite: InsertInvite): Promise<Invite>;
  getInviteByCode(code: string): Promise<Invite | undefined>;
  useInvite(id: number): Promise<void>;

  getAssets(orgId: number): Promise<Asset[]>;
  createAsset(asset: InsertAsset): Promise<Asset>;
  updateAsset(id: number, orgId: number, data: Partial<InsertAsset>): Promise<Asset | undefined>;

  getAuditLogs(orgId: number): Promise<AuditLog[]>;
  createAuditLog(log: InsertAuditLog): Promise<AuditLog>;

  getHoneypotEvents(orgId: number): Promise<HoneypotEvent[]>;
  createHoneypotEvent(event: InsertHoneypotEvent): Promise<HoneypotEvent>;

  getQuarantineItems(orgId: number): Promise<QuarantineItem[]>;
  createQuarantineItem(item: InsertQuarantineItem): Promise<QuarantineItem>;
  updateQuarantineItem(id: number, orgId: number, data: Partial<{ status: string; action: string }>): Promise<QuarantineItem | undefined>;

  getResponsePlaybooks(orgId: number): Promise<ResponsePlaybook[]>;
  createResponsePlaybook(playbook: InsertResponsePlaybook): Promise<ResponsePlaybook>;
  updateResponsePlaybook(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<ResponsePlaybook | undefined>;

  getDashboardStats(orgId: number): Promise<{
    totalEvents: number;
    criticalAlerts: number;
    activeIncidents: number;
    threatScore: number;
    eventTrend: number;
    incidentTrend: number;
    assetCount: number;
    quarantineCount: number;
    honeypotActivity: number;
  }>;
  getEventTrend(orgId: number): Promise<{ time: string; events: number }[]>;
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

  async createUser(insertUser: InsertUser & { organizationId?: number; role?: string }): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async createOrganization(org: InsertOrganization): Promise<Organization> {
    const [created] = await db.insert(organizations).values(org).returning();
    return created;
  }

  async getOrganization(id: number): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
    return org || undefined;
  }

  async updateOrganization(id: number, data: Partial<InsertOrganization>): Promise<Organization | undefined> {
    const [updated] = await db.update(organizations).set(data).where(eq(organizations.id, id)).returning();
    return updated;
  }

  async getOrganizationUserCount(orgId: number): Promise<number> {
    const [result] = await db.select({ count: count() }).from(users).where(eq(users.organizationId, orgId));
    return result?.count ?? 0;
  }

  async getSecurityEvents(orgId: number): Promise<SecurityEvent[]> {
    return db.select().from(securityEvents)
      .where(eq(securityEvents.organizationId, orgId))
      .orderBy(desc(securityEvents.createdAt)).limit(200);
  }

  async createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent> {
    const [created] = await db.insert(securityEvents).values(event).returning();
    return created;
  }

  async updateSecurityEventStatus(id: number, orgId: number, status: string): Promise<SecurityEvent | undefined> {
    const [updated] = await db.update(securityEvents).set({ status })
      .where(and(eq(securityEvents.id, id), eq(securityEvents.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getIncidents(orgId: number): Promise<Incident[]> {
    return db.select().from(incidents)
      .where(eq(incidents.organizationId, orgId))
      .orderBy(desc(incidents.createdAt));
  }

  async createIncident(incident: InsertIncident): Promise<Incident> {
    const [created] = await db.insert(incidents).values(incident).returning();
    return created;
  }

  async updateIncident(id: number, orgId: number, data: Partial<InsertIncident & { status: string }>): Promise<Incident | undefined> {
    const [updated] = await db.update(incidents)
      .set({ ...data, updatedAt: new Date() })
      .where(and(eq(incidents.id, id), eq(incidents.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getThreatIntel(orgId: number): Promise<ThreatIntel[]> {
    return db.select().from(threatIntel)
      .where(eq(threatIntel.organizationId, orgId))
      .orderBy(desc(threatIntel.lastSeen));
  }

  async createThreatIntel(intel: InsertThreatIntel): Promise<ThreatIntel> {
    const [created] = await db.insert(threatIntel).values(intel).returning();
    return created;
  }

  async updateThreatIntel(id: number, orgId: number, data: Partial<{ active: boolean }>): Promise<ThreatIntel | undefined> {
    const [updated] = await db.update(threatIntel).set(data)
      .where(and(eq(threatIntel.id, id), eq(threatIntel.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getSecurityPolicies(orgId: number): Promise<SecurityPolicy[]> {
    return db.select().from(securityPolicies)
      .where(eq(securityPolicies.organizationId, orgId))
      .orderBy(desc(securityPolicies.createdAt));
  }

  async createSecurityPolicy(policy: InsertSecurityPolicy): Promise<SecurityPolicy> {
    const [created] = await db.insert(securityPolicies).values(policy).returning();
    return created;
  }

  async updateSecurityPolicy(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<SecurityPolicy | undefined> {
    const [updated] = await db.update(securityPolicies).set({ ...data, updatedAt: new Date() })
      .where(and(eq(securityPolicies.id, id), eq(securityPolicies.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getInvites(orgId: number): Promise<Invite[]> {
    return db.select().from(invites)
      .where(eq(invites.organizationId, orgId))
      .orderBy(desc(invites.createdAt));
  }

  async createInvite(invite: InsertInvite): Promise<Invite> {
    const [created] = await db.insert(invites).values(invite).returning();
    return created;
  }

  async getInviteByCode(code: string): Promise<Invite | undefined> {
    const [invite] = await db.select().from(invites).where(eq(invites.code, code));
    return invite || undefined;
  }

  async useInvite(id: number): Promise<void> {
    await db.update(invites).set({ used: true }).where(eq(invites.id, id));
  }

  async getAssets(orgId: number): Promise<Asset[]> {
    return db.select().from(assets)
      .where(eq(assets.organizationId, orgId))
      .orderBy(desc(assets.lastSeen));
  }

  async createAsset(asset: InsertAsset): Promise<Asset> {
    const [created] = await db.insert(assets).values(asset).returning();
    return created;
  }

  async updateAsset(id: number, orgId: number, data: Partial<InsertAsset>): Promise<Asset | undefined> {
    const [updated] = await db.update(assets).set({ ...data, lastSeen: new Date() })
      .where(and(eq(assets.id, id), eq(assets.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getAuditLogs(orgId: number): Promise<AuditLog[]> {
    return db.select().from(auditLogs)
      .where(eq(auditLogs.organizationId, orgId))
      .orderBy(desc(auditLogs.createdAt))
      .limit(500);
  }

  async createAuditLog(log: InsertAuditLog): Promise<AuditLog> {
    const [created] = await db.insert(auditLogs).values(log).returning();
    return created;
  }

  async getHoneypotEvents(orgId: number): Promise<HoneypotEvent[]> {
    return db.select().from(honeypotEvents)
      .where(eq(honeypotEvents.organizationId, orgId))
      .orderBy(desc(honeypotEvents.createdAt))
      .limit(200);
  }

  async createHoneypotEvent(event: InsertHoneypotEvent): Promise<HoneypotEvent> {
    const [created] = await db.insert(honeypotEvents).values(event).returning();
    return created;
  }

  async getQuarantineItems(orgId: number): Promise<QuarantineItem[]> {
    return db.select().from(quarantineItems)
      .where(eq(quarantineItems.organizationId, orgId))
      .orderBy(desc(quarantineItems.createdAt));
  }

  async createQuarantineItem(item: InsertQuarantineItem): Promise<QuarantineItem> {
    const [created] = await db.insert(quarantineItems).values(item).returning();
    return created;
  }

  async updateQuarantineItem(id: number, orgId: number, data: Partial<{ status: string; action: string }>): Promise<QuarantineItem | undefined> {
    const [updated] = await db.update(quarantineItems).set(data)
      .where(and(eq(quarantineItems.id, id), eq(quarantineItems.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getResponsePlaybooks(orgId: number): Promise<ResponsePlaybook[]> {
    return db.select().from(responsePlaybooks)
      .where(eq(responsePlaybooks.organizationId, orgId))
      .orderBy(desc(responsePlaybooks.createdAt));
  }

  async createResponsePlaybook(playbook: InsertResponsePlaybook): Promise<ResponsePlaybook> {
    const [created] = await db.insert(responsePlaybooks).values(playbook).returning();
    return created;
  }

  async updateResponsePlaybook(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<ResponsePlaybook | undefined> {
    const [updated] = await db.update(responsePlaybooks).set(data)
      .where(and(eq(responsePlaybooks.id, id), eq(responsePlaybooks.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getDashboardStats(orgId: number) {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [totalResult] = await db.select({ count: count() }).from(securityEvents)
      .where(and(eq(securityEvents.organizationId, orgId), gte(securityEvents.createdAt, oneDayAgo)));
    const [criticalResult] = await db.select({ count: count() }).from(securityEvents)
      .where(and(eq(securityEvents.organizationId, orgId), eq(securityEvents.severity, "critical"), gte(securityEvents.createdAt, oneDayAgo)));
    const [activeResult] = await db.select({ count: count() }).from(incidents)
      .where(and(eq(incidents.organizationId, orgId), sql`${incidents.status} NOT IN ('resolved', 'closed')`));
    const [assetResult] = await db.select({ count: count() }).from(assets)
      .where(eq(assets.organizationId, orgId));
    const [quarantineResult] = await db.select({ count: count() }).from(quarantineItems)
      .where(and(eq(quarantineItems.organizationId, orgId), eq(quarantineItems.status, "quarantined")));
    const [honeypotResult] = await db.select({ count: count() }).from(honeypotEvents)
      .where(and(eq(honeypotEvents.organizationId, orgId), gte(honeypotEvents.createdAt, oneDayAgo)));

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
      assetCount: assetResult?.count ?? 0,
      quarantineCount: quarantineResult?.count ?? 0,
      honeypotActivity: honeypotResult?.count ?? 0,
    };
  }

  async getEventTrend(orgId: number): Promise<{ time: string; events: number }[]> {
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
          eq(securityEvents.organizationId, orgId),
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
