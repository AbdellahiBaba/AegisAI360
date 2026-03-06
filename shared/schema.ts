import { sql } from "drizzle-orm";
import { pgTable, text, varchar, serial, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/chat";

export const organizations = pgTable("organizations", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  plan: text("plan").notNull().default("starter"),
  stripeCustomerId: text("stripe_customer_id"),
  stripeSubscriptionId: text("stripe_subscription_id"),
  maxUsers: integer("max_users").notNull().default(5),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  organizationId: integer("organization_id").references(() => organizations.id),
  role: text("role").notNull().default("analyst"),
});

export const securityEvents = pgTable("security_events", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  eventType: text("event_type").notNull(),
  severity: text("severity").notNull(),
  source: text("source").notNull(),
  sourceIp: text("source_ip"),
  destinationIp: text("destination_ip"),
  port: integer("port"),
  protocol: text("protocol"),
  description: text("description").notNull(),
  status: text("status").notNull().default("new"),
  rawData: text("raw_data"),
  techniqueId: text("technique_id"),
  tactic: text("tactic"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const incidents = pgTable("incidents", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  title: text("title").notNull(),
  description: text("description").notNull(),
  severity: text("severity").notNull(),
  status: text("status").notNull().default("open"),
  assignee: text("assignee"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const threatIntel = pgTable("threat_intel", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  indicatorType: text("indicator_type").notNull(),
  value: text("value").notNull(),
  threatType: text("threat_type").notNull(),
  severity: text("severity").notNull(),
  source: text("source").notNull(),
  description: text("description"),
  active: boolean("active").notNull().default(true),
  firstSeen: timestamp("first_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
  lastSeen: timestamp("last_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const securityPolicies = pgTable("security_policies", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  name: text("name").notNull(),
  description: text("description").notNull(),
  tier: text("tier").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  rules: text("rules"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const invites = pgTable("invites", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  email: text("email"),
  role: text("role").notNull().default("analyst"),
  code: text("code").notNull().unique(),
  used: boolean("used").notNull().default(false),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
});

export const assets = pgTable("assets", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  ipAddress: text("ip_address"),
  os: text("os"),
  status: text("status").notNull().default("online"),
  riskScore: integer("risk_score").notNull().default(0),
  lastSeen: timestamp("last_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const auditLogs = pgTable("audit_logs", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  userId: varchar("user_id"),
  action: text("action").notNull(),
  targetType: text("target_type"),
  targetId: text("target_id"),
  details: text("details"),
  ipAddress: text("ip_address"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const honeypotEvents = pgTable("honeypot_events", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  honeypotName: text("honeypot_name").notNull(),
  attackerIp: text("attacker_ip").notNull(),
  service: text("service").notNull(),
  action: text("action").notNull(),
  payload: text("payload"),
  country: text("country"),
  sessionId: text("session_id"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const quarantineItems = pgTable("quarantine_items", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  fileName: text("file_name").notNull(),
  fileHash: text("file_hash"),
  threat: text("threat").notNull(),
  sourceAsset: text("source_asset"),
  action: text("action").notNull().default("quarantined"),
  status: text("status").notNull().default("quarantined"),
  quarantinedBy: text("quarantined_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const responsePlaybooks = pgTable("response_playbooks", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  name: text("name").notNull(),
  description: text("description").notNull(),
  triggerConditions: text("trigger_conditions"),
  actions: text("actions"),
  enabled: boolean("enabled").notNull().default(true),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertOrganizationSchema = createInsertSchema(organizations).omit({
  id: true,
  createdAt: true,
});
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;
export type Organization = typeof organizations.$inferSelect;

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
});
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export const insertSecurityEventSchema = createInsertSchema(securityEvents).omit({
  id: true,
  createdAt: true,
});
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;

export const insertIncidentSchema = createInsertSchema(incidents).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
export type Incident = typeof incidents.$inferSelect;

export const insertThreatIntelSchema = createInsertSchema(threatIntel).omit({
  id: true,
  firstSeen: true,
  lastSeen: true,
});
export type InsertThreatIntel = z.infer<typeof insertThreatIntelSchema>;
export type ThreatIntel = typeof threatIntel.$inferSelect;

export const insertSecurityPolicySchema = createInsertSchema(securityPolicies).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});
export type InsertSecurityPolicy = z.infer<typeof insertSecurityPolicySchema>;
export type SecurityPolicy = typeof securityPolicies.$inferSelect;

export const insertInviteSchema = createInsertSchema(invites).omit({
  id: true,
  createdAt: true,
});
export type InsertInvite = z.infer<typeof insertInviteSchema>;
export type Invite = typeof invites.$inferSelect;

export const insertAssetSchema = createInsertSchema(assets).omit({
  id: true,
  lastSeen: true,
});
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assets.$inferSelect;

export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({
  id: true,
  createdAt: true,
});
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;

export const insertHoneypotEventSchema = createInsertSchema(honeypotEvents).omit({
  id: true,
  createdAt: true,
});
export type InsertHoneypotEvent = z.infer<typeof insertHoneypotEventSchema>;
export type HoneypotEvent = typeof honeypotEvents.$inferSelect;

export const insertQuarantineItemSchema = createInsertSchema(quarantineItems).omit({
  id: true,
  createdAt: true,
});
export type InsertQuarantineItem = z.infer<typeof insertQuarantineItemSchema>;
export type QuarantineItem = typeof quarantineItems.$inferSelect;

export const insertResponsePlaybookSchema = createInsertSchema(responsePlaybooks).omit({
  id: true,
  createdAt: true,
});
export type InsertResponsePlaybook = z.infer<typeof insertResponsePlaybookSchema>;
export type ResponsePlaybook = typeof responsePlaybooks.$inferSelect;
