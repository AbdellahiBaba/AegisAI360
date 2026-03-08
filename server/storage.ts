import {
  users, organizations, securityEvents, incidents, threatIntel, securityPolicies,
  invites, assets, auditLogs, honeypotEvents, quarantineItems, responsePlaybooks,
  apiKeys, firewallRules, alertRules, notifications, threatFeedConfigs, responseActions,
  scanResults, supportTickets, networkDevices, networkScans,
  plans, deviceTokens, agents, agentCommands, terminalAuditLogs, usageTracking,
  packetCaptures, arpAlerts, bandwidthLogs,
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
  type ApiKey, type InsertApiKey,
  type FirewallRule, type InsertFirewallRule,
  type AlertRule, type InsertAlertRule,
  type Notification, type InsertNotification,
  type ThreatFeedConfig, type InsertThreatFeedConfig,
  type ResponseAction, type InsertResponseAction,
  type ScanResult, type InsertScanResult,
  type SupportTicket, type InsertSupportTicket,
  type NetworkDevice, type InsertNetworkDevice,
  type NetworkScan, type InsertNetworkScan,
  type Plan, type InsertPlan,
  type DeviceToken, type InsertDeviceToken,
  type Agent, type InsertAgent,
  type AgentCommand, type InsertAgentCommand,
  type TerminalAuditLog, type InsertTerminalAuditLog,
  type UsageTracking, type InsertUsageTracking,
  type PacketCapture, type InsertPacketCapture,
  type ArpAlert, type InsertArpAlert,
  type BandwidthLog, type InsertBandwidthLog,
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, sql, and, gte, count, lt, ne } from "drizzle-orm";

export interface IStorage {
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser & { organizationId?: number; role?: string; isSuperAdmin?: boolean }): Promise<User>;
  getAllUsers(): Promise<Omit<User, "password">[]>;

  createOrganization(org: InsertOrganization): Promise<Organization>;
  getOrganization(id: number): Promise<Organization | undefined>;
  getAllOrganizations(): Promise<Organization[]>;
  updateOrganization(id: number, data: Partial<InsertOrganization & { suspended: boolean }>): Promise<Organization | undefined>;
  getOrganizationUserCount(orgId: number): Promise<number>;

  getSecurityEvents(orgId: number): Promise<SecurityEvent[]>;
  createSecurityEvent(event: InsertSecurityEvent): Promise<SecurityEvent>;
  updateSecurityEventStatus(id: number, orgId: number, status: string): Promise<SecurityEvent | undefined>;
  mitigateEventsByIp(orgId: number, ip: string): Promise<number>;

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
  getAllAuditLogs(): Promise<AuditLog[]>;
  createAuditLog(log: InsertAuditLog): Promise<AuditLog>;

  getHoneypotEvents(orgId: number): Promise<HoneypotEvent[]>;
  createHoneypotEvent(event: InsertHoneypotEvent): Promise<HoneypotEvent>;

  getQuarantineItems(orgId: number): Promise<QuarantineItem[]>;
  createQuarantineItem(item: InsertQuarantineItem): Promise<QuarantineItem>;
  updateQuarantineItem(id: number, orgId: number, data: Partial<{ status: string; action: string }>): Promise<QuarantineItem | undefined>;

  getResponsePlaybooks(orgId: number): Promise<ResponsePlaybook[]>;
  createResponsePlaybook(playbook: InsertResponsePlaybook): Promise<ResponsePlaybook>;
  updateResponsePlaybook(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<ResponsePlaybook | undefined>;

  getOrganizationUsers(orgId: number): Promise<Omit<User, "password">[]>;
  updateUserRole(userId: string, orgId: number, role: string): Promise<Omit<User, "password"> | undefined>;

  getApiKeys(orgId: number): Promise<ApiKey[]>;
  createApiKey(key: InsertApiKey): Promise<ApiKey>;
  deleteApiKey(id: number, orgId: number): Promise<boolean>;
  getApiKeyByHash(keyHash: string): Promise<ApiKey | undefined>;
  touchApiKey(id: number): Promise<void>;

  getFirewallRules(orgId: number): Promise<FirewallRule[]>;
  createFirewallRule(rule: InsertFirewallRule): Promise<FirewallRule>;
  updateFirewallRule(id: number, orgId: number, data: Partial<{ status: string }>): Promise<FirewallRule | undefined>;
  deleteFirewallRule(id: number, orgId: number): Promise<boolean>;

  getAlertRules(orgId: number): Promise<AlertRule[]>;
  createAlertRule(rule: InsertAlertRule): Promise<AlertRule>;
  updateAlertRule(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<AlertRule | undefined>;
  deleteAlertRule(id: number, orgId: number): Promise<boolean>;
  incrementAlertRuleTrigger(id: number): Promise<void>;

  getNotifications(orgId: number, userId?: string): Promise<Notification[]>;
  createNotification(n: InsertNotification): Promise<Notification>;
  markNotificationRead(id: number): Promise<void>;
  markAllNotificationsRead(orgId: number, userId: string): Promise<void>;
  getUnreadNotificationCount(orgId: number, userId: string): Promise<number>;

  getThreatFeedConfigs(orgId: number): Promise<ThreatFeedConfig[]>;
  createThreatFeedConfig(config: InsertThreatFeedConfig): Promise<ThreatFeedConfig>;
  updateThreatFeedConfig(id: number, orgId: number, data: Partial<InsertThreatFeedConfig & { lastSync: Date }>): Promise<ThreatFeedConfig | undefined>;

  getResponseActions(orgId: number): Promise<ResponseAction[]>;
  createResponseAction(action: InsertResponseAction): Promise<ResponseAction>;
  updateResponseAction(id: number, data: Partial<{ status: string; result: string; completedAt: Date }>): Promise<ResponseAction | undefined>;

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
    blockedIps: number;
    activeRules: number;
  }>;
  getEventTrend(orgId: number): Promise<{ time: string; events: number }[]>;
  getEventCount(): Promise<number>;
  getPlatformStats(): Promise<{ totalOrgs: number; totalUsers: number; totalEvents: number }>;

  getScanResults(orgId: number): Promise<ScanResult[]>;
  createScanResult(result: InsertScanResult): Promise<ScanResult>;
  updateScanResult(id: number, data: Partial<{ status: string; results: string; findings: number; severity: string; completedAt: Date }>): Promise<ScanResult | undefined>;

  getSupportTickets(orgId: number): Promise<SupportTicket[]>;
  getAllSupportTickets(): Promise<SupportTicket[]>;
  getSupportTicket(id: number): Promise<SupportTicket | undefined>;
  createSupportTicket(ticket: InsertSupportTicket): Promise<SupportTicket>;
  updateSupportTicket(id: number, data: Partial<{ status: string; priority: string; assignedTo: string | null; remoteSessionRequested: boolean; remoteSessionActive: boolean; messages: any }>): Promise<SupportTicket | undefined>;

  getNetworkDevices(orgId: number): Promise<NetworkDevice[]>;
  getNetworkDevice(id: number): Promise<NetworkDevice | undefined>;
  getNetworkDeviceByMac(orgId: number, macAddress: string): Promise<NetworkDevice | undefined>;
  createNetworkDevice(device: InsertNetworkDevice): Promise<NetworkDevice>;
  updateNetworkDevice(id: number, data: Partial<NetworkDevice>): Promise<NetworkDevice | undefined>;
  deleteNetworkDevice(id: number): Promise<void>;
  getNetworkScans(orgId: number): Promise<NetworkScan[]>;
  createNetworkScan(scan: InsertNetworkScan): Promise<NetworkScan>;
  updateNetworkScan(id: number, data: Partial<NetworkScan>): Promise<NetworkScan | undefined>;

  getPlans(): Promise<Plan[]>;
  getPlanById(id: number): Promise<Plan | undefined>;
  getPlanByName(name: string): Promise<Plan | undefined>;
  createPlan(plan: InsertPlan): Promise<Plan>;

  createDeviceToken(token: InsertDeviceToken): Promise<DeviceToken>;
  getDeviceToken(token: string): Promise<DeviceToken | undefined>;
  getDeviceTokensByOrg(orgId: number): Promise<DeviceToken[]>;
  markTokenUsed(id: number, agentId: number): Promise<void>;

  createAgent(agent: InsertAgent): Promise<Agent>;
  getAgentById(id: number): Promise<Agent | undefined>;
  getAgentsByOrg(orgId: number): Promise<Agent[]>;
  updateAgentHeartbeat(id: number, data: { lastSeen: Date; cpuUsage?: number; ramUsage?: number; ip?: string }): Promise<Agent | undefined>;
  updateAgentStatus(id: number, status: string): Promise<void>;

  createCommand(cmd: InsertAgentCommand): Promise<AgentCommand>;
  getCommandById(id: number): Promise<AgentCommand | undefined>;
  getCommandsByAgent(agentId: number): Promise<AgentCommand[]>;
  getPendingCommands(agentId: number): Promise<AgentCommand[]>;
  updateCommandStatus(id: number, data: { status: string; result?: string; executedAt?: Date }): Promise<AgentCommand | undefined>;

  createTerminalLog(log: InsertTerminalAuditLog): Promise<TerminalAuditLog>;
  getTerminalLogsByAgent(agentId: number, orgId: number): Promise<TerminalAuditLog[]>;

  getUsageForToday(orgId: number): Promise<UsageTracking | undefined>;
  incrementUsage(orgId: number, field: keyof Pick<UsageTracking, 'agentsRegistered' | 'logsSent' | 'commandsExecuted' | 'terminalCommandsExecuted' | 'threatIntelQueries'>): Promise<void>;

  createPacketCapture(capture: InsertPacketCapture): Promise<PacketCapture>;
  getPacketCaptures(orgId: number): Promise<PacketCapture[]>;
  getPacketCapturesByAgent(agentId: number, orgId: number): Promise<PacketCapture[]>;

  createArpAlert(alert: InsertArpAlert): Promise<ArpAlert>;
  getArpAlerts(orgId: number): Promise<ArpAlert[]>;
  getArpAlertsByAgent(agentId: number, orgId: number): Promise<ArpAlert[]>;

  createBandwidthLog(log: InsertBandwidthLog): Promise<BandwidthLog>;
  getBandwidthLogs(agentId: number, orgId: number): Promise<BandwidthLog[]>;
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

  async createUser(insertUser: InsertUser & { organizationId?: number; role?: string; isSuperAdmin?: boolean }): Promise<User> {
    const [user] = await db.insert(users).values(insertUser).returning();
    return user;
  }

  async getAllUsers(): Promise<Omit<User, "password">[]> {
    return db.select({
      id: users.id, username: users.username, organizationId: users.organizationId,
      role: users.role, isSuperAdmin: users.isSuperAdmin,
    }).from(users).orderBy(desc(users.username));
  }

  async createOrganization(org: InsertOrganization): Promise<Organization> {
    const [created] = await db.insert(organizations).values(org).returning();
    return created;
  }

  async getOrganization(id: number): Promise<Organization | undefined> {
    const [org] = await db.select().from(organizations).where(eq(organizations.id, id));
    return org || undefined;
  }

  async getAllOrganizations(): Promise<Organization[]> {
    return db.select().from(organizations).orderBy(desc(organizations.createdAt));
  }

  async updateOrganization(id: number, data: Partial<InsertOrganization & { suspended: boolean }>): Promise<Organization | undefined> {
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
      .orderBy(desc(securityEvents.createdAt)).limit(500);
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

  async mitigateEventsByIp(orgId: number, ip: string): Promise<number> {
    const result = await db.update(securityEvents)
      .set({ mitigated: true, status: "resolved" })
      .where(and(
        eq(securityEvents.organizationId, orgId),
        eq(securityEvents.sourceIp, ip),
        ne(securityEvents.status, "resolved"),
      )).returning();
    return result.length;
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

  async getAllAuditLogs(): Promise<AuditLog[]> {
    return db.select().from(auditLogs)
      .orderBy(desc(auditLogs.createdAt))
      .limit(1000);
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

  async getOrganizationUsers(orgId: number): Promise<Omit<User, "password">[]> {
    const result = await db.select({
      id: users.id, username: users.username,
      organizationId: users.organizationId, role: users.role, isSuperAdmin: users.isSuperAdmin,
    }).from(users).where(eq(users.organizationId, orgId));
    return result as Omit<User, "password">[];
  }

  async updateUserRole(userId: string, orgId: number, role: string): Promise<Omit<User, "password"> | undefined> {
    const [updated] = await db.update(users).set({ role })
      .where(and(eq(users.id, userId), eq(users.organizationId, orgId)))
      .returning({ id: users.id, username: users.username, organizationId: users.organizationId, role: users.role, isSuperAdmin: users.isSuperAdmin });
    return updated as Omit<User, "password"> | undefined;
  }

  async getApiKeys(orgId: number): Promise<ApiKey[]> {
    return db.select().from(apiKeys)
      .where(eq(apiKeys.organizationId, orgId))
      .orderBy(desc(apiKeys.createdAt));
  }

  async createApiKey(key: InsertApiKey): Promise<ApiKey> {
    const [created] = await db.insert(apiKeys).values(key).returning();
    return created;
  }

  async deleteApiKey(id: number, orgId: number): Promise<boolean> {
    const result = await db.delete(apiKeys)
      .where(and(eq(apiKeys.id, id), eq(apiKeys.organizationId, orgId)))
      .returning();
    return result.length > 0;
  }

  async getApiKeyByHash(keyHash: string): Promise<ApiKey | undefined> {
    const [key] = await db.select().from(apiKeys).where(eq(apiKeys.keyHash, keyHash));
    return key || undefined;
  }

  async touchApiKey(id: number): Promise<void> {
    await db.update(apiKeys).set({ lastUsed: new Date() }).where(eq(apiKeys.id, id));
  }

  async getFirewallRules(orgId: number): Promise<FirewallRule[]> {
    return db.select().from(firewallRules)
      .where(eq(firewallRules.organizationId, orgId))
      .orderBy(desc(firewallRules.createdAt));
  }

  async createFirewallRule(rule: InsertFirewallRule): Promise<FirewallRule> {
    const [created] = await db.insert(firewallRules).values(rule).returning();
    return created;
  }

  async updateFirewallRule(id: number, orgId: number, data: Partial<{ status: string }>): Promise<FirewallRule | undefined> {
    const [updated] = await db.update(firewallRules).set(data)
      .where(and(eq(firewallRules.id, id), eq(firewallRules.organizationId, orgId)))
      .returning();
    return updated;
  }

  async deleteFirewallRule(id: number, orgId: number): Promise<boolean> {
    const result = await db.delete(firewallRules)
      .where(and(eq(firewallRules.id, id), eq(firewallRules.organizationId, orgId)))
      .returning();
    return result.length > 0;
  }

  async getAlertRules(orgId: number): Promise<AlertRule[]> {
    return db.select().from(alertRules)
      .where(eq(alertRules.organizationId, orgId))
      .orderBy(desc(alertRules.createdAt));
  }

  async createAlertRule(rule: InsertAlertRule): Promise<AlertRule> {
    const [created] = await db.insert(alertRules).values(rule).returning();
    return created;
  }

  async updateAlertRule(id: number, orgId: number, data: Partial<{ enabled: boolean }>): Promise<AlertRule | undefined> {
    const [updated] = await db.update(alertRules).set(data)
      .where(and(eq(alertRules.id, id), eq(alertRules.organizationId, orgId)))
      .returning();
    return updated;
  }

  async deleteAlertRule(id: number, orgId: number): Promise<boolean> {
    const result = await db.delete(alertRules)
      .where(and(eq(alertRules.id, id), eq(alertRules.organizationId, orgId)))
      .returning();
    return result.length > 0;
  }

  async incrementAlertRuleTrigger(id: number): Promise<void> {
    await db.update(alertRules).set({
      triggerCount: sql`${alertRules.triggerCount} + 1`,
      lastTriggered: new Date(),
    }).where(eq(alertRules.id, id));
  }

  async getNotifications(orgId: number, userId?: string): Promise<Notification[]> {
    const conditions = [eq(notifications.organizationId, orgId)];
    if (userId) conditions.push(eq(notifications.userId, userId));
    return db.select().from(notifications)
      .where(and(...conditions))
      .orderBy(desc(notifications.createdAt))
      .limit(100);
  }

  async createNotification(n: InsertNotification): Promise<Notification> {
    const [created] = await db.insert(notifications).values(n).returning();
    return created;
  }

  async markNotificationRead(id: number): Promise<void> {
    await db.update(notifications).set({ read: true }).where(eq(notifications.id, id));
  }

  async markAllNotificationsRead(orgId: number, userId: string): Promise<void> {
    await db.update(notifications).set({ read: true })
      .where(and(eq(notifications.organizationId, orgId), eq(notifications.userId, userId)));
  }

  async getUnreadNotificationCount(orgId: number, userId: string): Promise<number> {
    const [result] = await db.select({ count: count() }).from(notifications)
      .where(and(
        eq(notifications.organizationId, orgId),
        eq(notifications.userId, userId),
        eq(notifications.read, false),
      ));
    return result?.count ?? 0;
  }

  async getThreatFeedConfigs(orgId: number): Promise<ThreatFeedConfig[]> {
    return db.select().from(threatFeedConfigs)
      .where(eq(threatFeedConfigs.organizationId, orgId));
  }

  async createThreatFeedConfig(config: InsertThreatFeedConfig): Promise<ThreatFeedConfig> {
    const [created] = await db.insert(threatFeedConfigs).values(config).returning();
    return created;
  }

  async updateThreatFeedConfig(id: number, orgId: number, data: Partial<InsertThreatFeedConfig & { lastSync: Date }>): Promise<ThreatFeedConfig | undefined> {
    const [updated] = await db.update(threatFeedConfigs).set(data)
      .where(and(eq(threatFeedConfigs.id, id), eq(threatFeedConfigs.organizationId, orgId)))
      .returning();
    return updated;
  }

  async getResponseActions(orgId: number): Promise<ResponseAction[]> {
    return db.select().from(responseActions)
      .where(eq(responseActions.organizationId, orgId))
      .orderBy(desc(responseActions.createdAt))
      .limit(200);
  }

  async createResponseAction(action: InsertResponseAction): Promise<ResponseAction> {
    const [created] = await db.insert(responseActions).values(action).returning();
    return created;
  }

  async updateResponseAction(id: number, data: Partial<{ status: string; result: string; completedAt: Date }>): Promise<ResponseAction | undefined> {
    const [updated] = await db.update(responseActions).set(data)
      .where(eq(responseActions.id, id))
      .returning();
    return updated;
  }

  async getDashboardStats(orgId: number) {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const twoDaysAgo = new Date(Date.now() - 48 * 60 * 60 * 1000);

    const [totalResult] = await db.select({ count: count() }).from(securityEvents)
      .where(and(eq(securityEvents.organizationId, orgId), gte(securityEvents.createdAt, oneDayAgo)));
    const [prevResult] = await db.select({ count: count() }).from(securityEvents)
      .where(and(eq(securityEvents.organizationId, orgId), gte(securityEvents.createdAt, twoDaysAgo), lt(securityEvents.createdAt, oneDayAgo)));
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
    const [blockedResult] = await db.select({ count: count() }).from(firewallRules)
      .where(and(eq(firewallRules.organizationId, orgId), eq(firewallRules.status, "active")));
    const [rulesResult] = await db.select({ count: count() }).from(alertRules)
      .where(and(eq(alertRules.organizationId, orgId), eq(alertRules.enabled, true)));

    const totalEvents = totalResult?.count ?? 0;
    const prevEvents = prevResult?.count ?? 0;
    const criticalAlerts = criticalResult?.count ?? 0;
    const activeIncidents = activeResult?.count ?? 0;
    const threatScore = Math.min(100, Math.round(criticalAlerts * 15 + totalEvents * 0.5));

    const eventTrend = prevEvents > 0 ? Math.round(((totalEvents - prevEvents) / prevEvents) * 100) : 0;

    return {
      totalEvents,
      criticalAlerts,
      activeIncidents,
      threatScore,
      eventTrend,
      incidentTrend: 0,
      assetCount: assetResult?.count ?? 0,
      quarantineCount: quarantineResult?.count ?? 0,
      honeypotActivity: honeypotResult?.count ?? 0,
      blockedIps: blockedResult?.count ?? 0,
      activeRules: rulesResult?.count ?? 0,
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

  async getPlatformStats(): Promise<{ totalOrgs: number; totalUsers: number; totalEvents: number }> {
    const [orgs] = await db.select({ count: count() }).from(organizations);
    const [usersCount] = await db.select({ count: count() }).from(users);
    const [events] = await db.select({ count: count() }).from(securityEvents);
    return {
      totalOrgs: orgs?.count ?? 0,
      totalUsers: usersCount?.count ?? 0,
      totalEvents: events?.count ?? 0,
    };
  }

  async getScanResults(orgId: number): Promise<ScanResult[]> {
    return db.select().from(scanResults).where(eq(scanResults.organizationId, orgId)).orderBy(desc(scanResults.createdAt));
  }

  async createScanResult(result: InsertScanResult): Promise<ScanResult> {
    const [created] = await db.insert(scanResults).values(result).returning();
    return created;
  }

  async updateScanResult(id: number, data: Partial<{ status: string; results: string; findings: number; severity: string; completedAt: Date }>): Promise<ScanResult | undefined> {
    const [updated] = await db.update(scanResults).set(data).where(eq(scanResults.id, id)).returning();
    return updated;
  }

  async getSupportTickets(orgId: number): Promise<SupportTicket[]> {
    return db.select().from(supportTickets).where(eq(supportTickets.organizationId, orgId)).orderBy(desc(supportTickets.createdAt));
  }

  async getAllSupportTickets(): Promise<SupportTicket[]> {
    return db.select().from(supportTickets).orderBy(desc(supportTickets.createdAt));
  }

  async getSupportTicket(id: number): Promise<SupportTicket | undefined> {
    const [ticket] = await db.select().from(supportTickets).where(eq(supportTickets.id, id));
    return ticket || undefined;
  }

  async createSupportTicket(ticket: InsertSupportTicket): Promise<SupportTicket> {
    const [created] = await db.insert(supportTickets).values(ticket).returning();
    return created;
  }

  async updateSupportTicket(id: number, data: Partial<{ status: string; priority: string; assignedTo: string | null; remoteSessionRequested: boolean; remoteSessionActive: boolean; messages: any }>): Promise<SupportTicket | undefined> {
    const [updated] = await db.update(supportTickets).set({ ...data, updatedAt: new Date() }).where(eq(supportTickets.id, id)).returning();
    return updated;
  }

  async getNetworkDevices(orgId: number): Promise<NetworkDevice[]> {
    return db.select().from(networkDevices).where(eq(networkDevices.organizationId, orgId)).orderBy(desc(networkDevices.lastSeen));
  }

  async getNetworkDevice(id: number): Promise<NetworkDevice | undefined> {
    const [device] = await db.select().from(networkDevices).where(eq(networkDevices.id, id));
    return device || undefined;
  }

  async getNetworkDeviceByMac(orgId: number, macAddress: string): Promise<NetworkDevice | undefined> {
    const [device] = await db.select().from(networkDevices)
      .where(and(eq(networkDevices.organizationId, orgId), eq(networkDevices.macAddress, macAddress)));
    return device || undefined;
  }

  async createNetworkDevice(device: InsertNetworkDevice): Promise<NetworkDevice> {
    const [created] = await db.insert(networkDevices).values(device).returning();
    return created;
  }

  async updateNetworkDevice(id: number, data: Partial<NetworkDevice>): Promise<NetworkDevice | undefined> {
    const [updated] = await db.update(networkDevices).set(data).where(eq(networkDevices.id, id)).returning();
    return updated;
  }

  async deleteNetworkDevice(id: number): Promise<void> {
    await db.delete(networkDevices).where(eq(networkDevices.id, id));
  }

  async getNetworkScans(orgId: number): Promise<NetworkScan[]> {
    return db.select().from(networkScans).where(eq(networkScans.organizationId, orgId)).orderBy(desc(networkScans.createdAt));
  }

  async createNetworkScan(scan: InsertNetworkScan): Promise<NetworkScan> {
    const [created] = await db.insert(networkScans).values(scan).returning();
    return created;
  }

  async updateNetworkScan(id: number, data: Partial<NetworkScan>): Promise<NetworkScan | undefined> {
    const [updated] = await db.update(networkScans).set(data).where(eq(networkScans.id, id)).returning();
    return updated;
  }

  async getPlans(): Promise<Plan[]> {
    return db.select().from(plans);
  }

  async getPlanById(id: number): Promise<Plan | undefined> {
    const [plan] = await db.select().from(plans).where(eq(plans.id, id));
    return plan || undefined;
  }

  async getPlanByName(name: string): Promise<Plan | undefined> {
    const [plan] = await db.select().from(plans).where(eq(plans.name, name));
    return plan || undefined;
  }

  async createPlan(plan: InsertPlan): Promise<Plan> {
    const [created] = await db.insert(plans).values(plan).returning();
    return created;
  }

  async createDeviceToken(token: InsertDeviceToken): Promise<DeviceToken> {
    const [created] = await db.insert(deviceTokens).values(token).returning();
    return created;
  }

  async getDeviceToken(token: string): Promise<DeviceToken | undefined> {
    const [dt] = await db.select().from(deviceTokens).where(eq(deviceTokens.token, token));
    return dt || undefined;
  }

  async getDeviceTokensByOrg(orgId: number): Promise<DeviceToken[]> {
    return db.select().from(deviceTokens).where(eq(deviceTokens.organizationId, orgId)).orderBy(desc(deviceTokens.createdAt));
  }

  async markTokenUsed(id: number, agentId: number): Promise<void> {
    await db.update(deviceTokens).set({ used: true, usedByAgentId: agentId }).where(eq(deviceTokens.id, id));
  }

  async createAgent(agent: InsertAgent): Promise<Agent> {
    const [created] = await db.insert(agents).values(agent).returning();
    return created;
  }

  async getAgentById(id: number): Promise<Agent | undefined> {
    const [agent] = await db.select().from(agents).where(eq(agents.id, id));
    return agent || undefined;
  }

  async getAgentsByOrg(orgId: number): Promise<Agent[]> {
    return db.select().from(agents).where(eq(agents.organizationId, orgId)).orderBy(desc(agents.lastSeen));
  }

  async updateAgentHeartbeat(id: number, data: { lastSeen: Date; cpuUsage?: number; ramUsage?: number; ip?: string }): Promise<Agent | undefined> {
    const [updated] = await db.update(agents).set({ ...data, status: "online" }).where(eq(agents.id, id)).returning();
    return updated;
  }

  async updateAgentStatus(id: number, status: string): Promise<void> {
    await db.update(agents).set({ status }).where(eq(agents.id, id));
  }

  async createCommand(cmd: InsertAgentCommand): Promise<AgentCommand> {
    const [created] = await db.insert(agentCommands).values(cmd).returning();
    return created;
  }

  async getCommandById(id: number): Promise<AgentCommand | undefined> {
    const [cmd] = await db.select().from(agentCommands).where(eq(agentCommands.id, id)).limit(1);
    return cmd;
  }

  async getCommandsByAgent(agentId: number): Promise<AgentCommand[]> {
    return db.select().from(agentCommands).where(eq(agentCommands.agentId, agentId)).orderBy(desc(agentCommands.createdAt)).limit(100);
  }

  async getPendingCommands(agentId: number): Promise<AgentCommand[]> {
    return db.select().from(agentCommands).where(and(eq(agentCommands.agentId, agentId), eq(agentCommands.status, "pending"))).orderBy(agentCommands.createdAt);
  }

  async updateCommandStatus(id: number, data: { status: string; result?: string; executedAt?: Date }): Promise<AgentCommand | undefined> {
    const [updated] = await db.update(agentCommands).set(data).where(eq(agentCommands.id, id)).returning();
    return updated;
  }

  async createTerminalLog(log: InsertTerminalAuditLog): Promise<TerminalAuditLog> {
    const [created] = await db.insert(terminalAuditLogs).values(log).returning();
    return created;
  }

  async getTerminalLogsByAgent(agentId: number, orgId: number): Promise<TerminalAuditLog[]> {
    return db.select().from(terminalAuditLogs).where(and(eq(terminalAuditLogs.agentId, agentId), eq(terminalAuditLogs.organizationId, orgId))).orderBy(desc(terminalAuditLogs.createdAt)).limit(200);
  }

  async getUsageForToday(orgId: number): Promise<UsageTracking | undefined> {
    const today = new Date().toISOString().slice(0, 10);
    const [usage] = await db.select().from(usageTracking).where(and(eq(usageTracking.organizationId, orgId), eq(usageTracking.date, today)));
    return usage || undefined;
  }

  async incrementUsage(orgId: number, field: keyof Pick<UsageTracking, 'agentsRegistered' | 'logsSent' | 'commandsExecuted' | 'terminalCommandsExecuted' | 'threatIntelQueries'>): Promise<void> {
    const today = new Date().toISOString().slice(0, 10);
    const existing = await this.getUsageForToday(orgId);
    if (existing) {
      await db.update(usageTracking).set({ [field]: sql`${usageTracking[field]} + 1` }).where(eq(usageTracking.id, existing.id));
    } else {
      const initial: InsertUsageTracking = { organizationId: orgId, date: today, agentsRegistered: 0, logsSent: 0, commandsExecuted: 0, terminalCommandsExecuted: 0, threatIntelQueries: 0 };
      (initial as any)[field] = 1;
      await db.insert(usageTracking).values(initial);
    }
  }

  async createPacketCapture(capture: InsertPacketCapture): Promise<PacketCapture> {
    const [created] = await db.insert(packetCaptures).values(capture).returning();
    return created;
  }

  async getPacketCaptures(orgId: number): Promise<PacketCapture[]> {
    return db.select().from(packetCaptures).where(eq(packetCaptures.organizationId, orgId)).orderBy(desc(packetCaptures.createdAt)).limit(100);
  }

  async getPacketCapturesByAgent(agentId: number, orgId: number): Promise<PacketCapture[]> {
    return db.select().from(packetCaptures).where(and(eq(packetCaptures.agentId, agentId), eq(packetCaptures.organizationId, orgId))).orderBy(desc(packetCaptures.createdAt)).limit(50);
  }

  async createArpAlert(alert: InsertArpAlert): Promise<ArpAlert> {
    const [created] = await db.insert(arpAlerts).values(alert).returning();
    return created;
  }

  async getArpAlerts(orgId: number): Promise<ArpAlert[]> {
    return db.select().from(arpAlerts).where(eq(arpAlerts.organizationId, orgId)).orderBy(desc(arpAlerts.createdAt)).limit(200);
  }

  async getArpAlertsByAgent(agentId: number, orgId: number): Promise<ArpAlert[]> {
    return db.select().from(arpAlerts).where(and(eq(arpAlerts.agentId, agentId), eq(arpAlerts.organizationId, orgId))).orderBy(desc(arpAlerts.createdAt)).limit(100);
  }

  async createBandwidthLog(log: InsertBandwidthLog): Promise<BandwidthLog> {
    const [created] = await db.insert(bandwidthLogs).values(log).returning();
    return created;
  }

  async getBandwidthLogs(agentId: number, orgId: number): Promise<BandwidthLog[]> {
    return db.select().from(bandwidthLogs).where(and(eq(bandwidthLogs.agentId, agentId), eq(bandwidthLogs.organizationId, orgId))).orderBy(desc(bandwidthLogs.timestamp)).limit(200);
  }
}

export const storage = new DatabaseStorage();
