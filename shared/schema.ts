import { sql } from "drizzle-orm";
import { pgTable, text, varchar, serial, integer, bigint, timestamp, boolean, jsonb } from "drizzle-orm/pg-core";
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
  subscriptionStatus: text("subscription_status").notNull().default("inactive"),
  planId: integer("plan_id"),
  maxUsers: integer("max_users").notNull().default(5),
  suspended: boolean("suspended").notNull().default(false),
  defenseMode: text("defense_mode").notNull().default("auto"),
  logRetentionDays: integer("log_retention_days").notNull().default(90),
  auditRetentionDays: integer("audit_retention_days").notNull().default(365),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  organizationId: integer("organization_id").references(() => organizations.id),
  role: text("role").notNull().default("analyst"),
  isSuperAdmin: boolean("is_super_admin").notNull().default(false),
  totpSecret: text("totp_secret"),
  totpEnabled: boolean("totp_enabled").notNull().default(false),
  failedLoginAttempts: integer("failed_login_attempts").notNull().default(0),
  lockedUntil: timestamp("locked_until"),
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
  mitigated: boolean("mitigated").notNull().default(false),
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

export const apiKeys = pgTable("api_keys", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  name: text("name").notNull(),
  description: text("description"),
  keyHash: text("key_hash").notNull(),
  keyPrefix: text("key_prefix").notNull(),
  permissions: text("permissions").notNull().default("ingest"),
  expiresAt: timestamp("expires_at"),
  lastUsed: timestamp("last_used"),
  revokedAt: timestamp("revoked_at"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const firewallRules = pgTable("firewall_rules", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  ruleType: text("rule_type").notNull(),
  value: text("value").notNull(),
  action: text("action").notNull().default("block"),
  reason: text("reason"),
  createdBy: varchar("created_by"),
  expiresAt: timestamp("expires_at"),
  status: text("status").notNull().default("active"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const alertRules = pgTable("alert_rules", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  name: text("name").notNull(),
  conditions: text("conditions").notNull(),
  severity: text("severity").notNull().default("medium"),
  actions: text("actions").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  lastTriggered: timestamp("last_triggered"),
  triggerCount: integer("trigger_count").notNull().default(0),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const notifications = pgTable("notifications", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  userId: varchar("user_id"),
  title: text("title").notNull(),
  message: text("message").notNull(),
  type: text("type").notNull().default("info"),
  read: boolean("read").notNull().default(false),
  actionUrl: text("action_url"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const threatFeedConfigs = pgTable("threat_feed_configs", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  feedName: text("feed_name").notNull(),
  apiKey: text("api_key"),
  enabled: boolean("enabled").notNull().default(false),
  lastSync: timestamp("last_sync"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const responseActions = pgTable("response_actions", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  actionType: text("action_type").notNull(),
  target: text("target").notNull(),
  status: text("status").notNull().default("pending"),
  executedBy: varchar("executed_by"),
  details: text("details"),
  result: text("result"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  completedAt: timestamp("completed_at"),
});

export const insertOrganizationSchema = createInsertSchema(organizations).omit({ id: true, createdAt: true });
export type InsertOrganization = z.infer<typeof insertOrganizationSchema>;
export type Organization = typeof organizations.$inferSelect;

export const insertUserSchema = createInsertSchema(users).pick({ username: true, password: true });
export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;

export const insertSecurityEventSchema = createInsertSchema(securityEvents).omit({ id: true, createdAt: true });
export type InsertSecurityEvent = z.infer<typeof insertSecurityEventSchema>;
export type SecurityEvent = typeof securityEvents.$inferSelect;

export const insertIncidentSchema = createInsertSchema(incidents).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertIncident = z.infer<typeof insertIncidentSchema>;
export type Incident = typeof incidents.$inferSelect;

export const insertThreatIntelSchema = createInsertSchema(threatIntel).omit({ id: true, firstSeen: true, lastSeen: true });
export type InsertThreatIntel = z.infer<typeof insertThreatIntelSchema>;
export type ThreatIntel = typeof threatIntel.$inferSelect;

export const insertSecurityPolicySchema = createInsertSchema(securityPolicies).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertSecurityPolicy = z.infer<typeof insertSecurityPolicySchema>;
export type SecurityPolicy = typeof securityPolicies.$inferSelect;

export const insertInviteSchema = createInsertSchema(invites).omit({ id: true, createdAt: true });
export type InsertInvite = z.infer<typeof insertInviteSchema>;
export type Invite = typeof invites.$inferSelect;

export const insertAssetSchema = createInsertSchema(assets).omit({ id: true, lastSeen: true });
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assets.$inferSelect;

export const insertAuditLogSchema = createInsertSchema(auditLogs).omit({ id: true, createdAt: true });
export type InsertAuditLog = z.infer<typeof insertAuditLogSchema>;
export type AuditLog = typeof auditLogs.$inferSelect;

export const insertHoneypotEventSchema = createInsertSchema(honeypotEvents).omit({ id: true, createdAt: true });
export type InsertHoneypotEvent = z.infer<typeof insertHoneypotEventSchema>;
export type HoneypotEvent = typeof honeypotEvents.$inferSelect;

export const insertQuarantineItemSchema = createInsertSchema(quarantineItems).omit({ id: true, createdAt: true });
export type InsertQuarantineItem = z.infer<typeof insertQuarantineItemSchema>;
export type QuarantineItem = typeof quarantineItems.$inferSelect;

export const insertResponsePlaybookSchema = createInsertSchema(responsePlaybooks).omit({ id: true, createdAt: true });
export type InsertResponsePlaybook = z.infer<typeof insertResponsePlaybookSchema>;
export type ResponsePlaybook = typeof responsePlaybooks.$inferSelect;

export const insertApiKeySchema = createInsertSchema(apiKeys).omit({ id: true, createdAt: true, lastUsed: true });
export type InsertApiKey = z.infer<typeof insertApiKeySchema>;
export type ApiKey = typeof apiKeys.$inferSelect;

export const insertFirewallRuleSchema = createInsertSchema(firewallRules).omit({ id: true, createdAt: true });
export type InsertFirewallRule = z.infer<typeof insertFirewallRuleSchema>;
export type FirewallRule = typeof firewallRules.$inferSelect;

export const insertAlertRuleSchema = createInsertSchema(alertRules).omit({ id: true, createdAt: true, lastTriggered: true, triggerCount: true });
export type InsertAlertRule = z.infer<typeof insertAlertRuleSchema>;
export type AlertRule = typeof alertRules.$inferSelect;

export const insertNotificationSchema = createInsertSchema(notifications).omit({ id: true, createdAt: true });
export type InsertNotification = z.infer<typeof insertNotificationSchema>;
export type Notification = typeof notifications.$inferSelect;

export const insertThreatFeedConfigSchema = createInsertSchema(threatFeedConfigs).omit({ id: true, createdAt: true, lastSync: true });
export type InsertThreatFeedConfig = z.infer<typeof insertThreatFeedConfigSchema>;
export type ThreatFeedConfig = typeof threatFeedConfigs.$inferSelect;

export const insertResponseActionSchema = createInsertSchema(responseActions).omit({ id: true, createdAt: true, completedAt: true });
export type InsertResponseAction = z.infer<typeof insertResponseActionSchema>;
export type ResponseAction = typeof responseActions.$inferSelect;

export const scanResults = pgTable("scan_results", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  scanType: text("scan_type").notNull(),
  target: text("target").notNull(),
  status: text("status").notNull().default("running"),
  results: text("results"),
  findings: integer("findings").notNull().default(0),
  severity: text("severity").notNull().default("info"),
  executedBy: varchar("executed_by"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  completedAt: timestamp("completed_at"),
});

export const insertScanResultSchema = createInsertSchema(scanResults).omit({ id: true, createdAt: true, completedAt: true });
export type InsertScanResult = z.infer<typeof insertScanResultSchema>;
export type ScanResult = typeof scanResults.$inferSelect;

export const supportTickets = pgTable("support_tickets", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  userId: varchar("user_id"),
  subject: text("subject").notNull(),
  description: text("description").notNull(),
  status: text("status").notNull().default("open"),
  priority: text("priority").notNull().default("medium"),
  category: text("category").notNull().default("technical"),
  assignedTo: varchar("assigned_to"),
  remoteSessionRequested: boolean("remote_session_requested").notNull().default(false),
  remoteSessionActive: boolean("remote_session_active").notNull().default(false),
  messages: jsonb("messages").notNull().default([]),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertSupportTicketSchema = createInsertSchema(supportTickets).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertSupportTicket = z.infer<typeof insertSupportTicketSchema>;
export type SupportTicket = typeof supportTickets.$inferSelect;

export const networkDevices = pgTable("network_devices", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  macAddress: text("mac_address").notNull(),
  ipAddress: text("ip_address").notNull(),
  hostname: text("hostname"),
  manufacturer: text("manufacturer"),
  deviceType: text("device_type").notNull().default("unknown"),
  os: text("os"),
  status: text("status").notNull().default("online"),
  authorization: text("authorization").notNull().default("unknown"),
  lastSeen: timestamp("last_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
  firstSeen: timestamp("first_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
  dataIn: bigint("data_in", { mode: "number" }).notNull().default(0),
  dataOut: bigint("data_out", { mode: "number" }).notNull().default(0),
  networkName: text("network_name"),
  signalStrength: integer("signal_strength"),
  location: text("location"),
  notes: text("notes"),
  isCompanyDevice: boolean("is_company_device").notNull().default(false),
  assignedUser: text("assigned_user"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertNetworkDeviceSchema = createInsertSchema(networkDevices).omit({ id: true, createdAt: true });
export type InsertNetworkDevice = z.infer<typeof insertNetworkDeviceSchema>;
export type NetworkDevice = typeof networkDevices.$inferSelect;

export const networkScans = pgTable("network_scans", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").references(() => organizations.id),
  networkName: text("network_name"),
  scanType: text("scan_type").notNull().default("quick"),
  status: text("status").notNull().default("running"),
  devicesFound: integer("devices_found").notNull().default(0),
  unauthorizedCount: integer("unauthorized_count").notNull().default(0),
  vulnerabilities: jsonb("vulnerabilities"),
  results: jsonb("results"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  completedAt: timestamp("completed_at"),
});

export const insertNetworkScanSchema = createInsertSchema(networkScans).omit({ id: true, createdAt: true });
export type InsertNetworkScan = z.infer<typeof insertNetworkScanSchema>;
export type NetworkScan = typeof networkScans.$inferSelect;

export const plans = pgTable("plans", {
  id: serial("id").primaryKey(),
  name: text("name").notNull().unique(),
  price: integer("price").notNull().default(0),
  maxAgents: integer("max_agents").notNull().default(1),
  maxLogsPerDay: integer("max_logs_per_day").notNull().default(100),
  maxCommandsPerDay: integer("max_commands_per_day").notNull().default(10),
  maxThreatIntelQueries: integer("max_threat_intel_queries").notNull().default(10),
  allowNetworkIsolation: boolean("allow_network_isolation").notNull().default(false),
  allowProcessKill: boolean("allow_process_kill").notNull().default(false),
  allowFileScan: boolean("allow_file_scan").notNull().default(false),
  allowEndpointDownload: boolean("allow_endpoint_download").notNull().default(false),
  allowTerminalAccess: boolean("allow_terminal_access").notNull().default(false),
  allowThreatIntel: boolean("allow_threat_intel").notNull().default(false),
  allowAdvancedAnalytics: boolean("allow_advanced_analytics").notNull().default(false),
});

export const insertPlanSchema = createInsertSchema(plans).omit({ id: true });
export type InsertPlan = z.infer<typeof insertPlanSchema>;
export type Plan = typeof plans.$inferSelect;

export const deviceTokens = pgTable("device_tokens", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  token: text("token").notNull().unique(),
  used: boolean("used").notNull().default(false),
  usedByAgentId: integer("used_by_agent_id"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertDeviceTokenSchema = createInsertSchema(deviceTokens).omit({ id: true, createdAt: true, used: true, usedByAgentId: true });
export type InsertDeviceToken = z.infer<typeof insertDeviceTokenSchema>;
export type DeviceToken = typeof deviceTokens.$inferSelect;

export const agents = pgTable("agents", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  deviceToken: text("device_token").notNull(),
  hostname: text("hostname").notNull(),
  os: text("os"),
  ip: text("ip"),
  lastSeen: timestamp("last_seen").default(sql`CURRENT_TIMESTAMP`).notNull(),
  status: text("status").notNull().default("online"),
  cpuUsage: integer("cpu_usage"),
  ramUsage: integer("ram_usage"),
  telemetry: jsonb("telemetry"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertAgentSchema = createInsertSchema(agents).omit({ id: true, createdAt: true, lastSeen: true });
export type InsertAgent = z.infer<typeof insertAgentSchema>;
export type Agent = typeof agents.$inferSelect;

export const agentCommands = pgTable("agent_commands", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull().references(() => agents.id),
  command: text("command").notNull(),
  params: text("params"),
  status: text("status").notNull().default("pending"),
  result: text("result"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  executedAt: timestamp("executed_at"),
});

export const insertAgentCommandSchema = createInsertSchema(agentCommands).omit({ id: true, createdAt: true, executedAt: true, result: true });
export type InsertAgentCommand = z.infer<typeof insertAgentCommandSchema>;
export type AgentCommand = typeof agentCommands.$inferSelect;

export const terminalAuditLogs = pgTable("terminal_audit_logs", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  agentId: integer("agent_id").notNull().references(() => agents.id),
  command: text("command").notNull(),
  output: text("output"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertTerminalAuditLogSchema = createInsertSchema(terminalAuditLogs).omit({ id: true, createdAt: true });
export type InsertTerminalAuditLog = z.infer<typeof insertTerminalAuditLogSchema>;
export type TerminalAuditLog = typeof terminalAuditLogs.$inferSelect;

export const usageTracking = pgTable("usage_tracking", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  date: text("date").notNull(),
  agentsRegistered: integer("agents_registered").notNull().default(0),
  logsSent: integer("logs_sent").notNull().default(0),
  commandsExecuted: integer("commands_executed").notNull().default(0),
  terminalCommandsExecuted: integer("terminal_commands_executed").notNull().default(0),
  threatIntelQueries: integer("threat_intel_queries").notNull().default(0),
});

export const insertUsageTrackingSchema = createInsertSchema(usageTracking).omit({ id: true });
export type InsertUsageTracking = z.infer<typeof insertUsageTrackingSchema>;
export type UsageTracking = typeof usageTracking.$inferSelect;

export const packetCaptures = pgTable("packet_captures", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull().references(() => agents.id),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  captureData: jsonb("capture_data").notNull(),
  duration: integer("duration").notNull(),
  packetCount: integer("packet_count").notNull().default(0),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertPacketCaptureSchema = createInsertSchema(packetCaptures).omit({ id: true, createdAt: true });
export type InsertPacketCapture = z.infer<typeof insertPacketCaptureSchema>;
export type PacketCapture = typeof packetCaptures.$inferSelect;

export const arpAlerts = pgTable("arp_alerts", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull().references(() => agents.id),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  ip: text("ip").notNull(),
  oldMac: text("old_mac"),
  newMac: text("new_mac").notNull(),
  alertType: text("alert_type").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertArpAlertSchema = createInsertSchema(arpAlerts).omit({ id: true, createdAt: true });
export type InsertArpAlert = z.infer<typeof insertArpAlertSchema>;
export type ArpAlert = typeof arpAlerts.$inferSelect;

export const bandwidthLogs = pgTable("bandwidth_logs", {
  id: serial("id").primaryKey(),
  agentId: integer("agent_id").notNull().references(() => agents.id),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  interfaceName: text("interface_name").notNull(),
  bytesIn: bigint("bytes_in", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytes_out", { mode: "number" }).notNull().default(0),
  timestamp: timestamp("timestamp").default(sql`CURRENT_TIMESTAMP`).notNull(),
})

export const insertBandwidthLogSchema = createInsertSchema(bandwidthLogs).omit({ id: true, timestamp: true });
export type InsertBandwidthLog = z.infer<typeof insertBandwidthLogSchema>;
export type BandwidthLog = typeof bandwidthLogs.$inferSelect;

export const notificationChannels = pgTable("notification_channels", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  name: text("name").notNull(),
  type: text("type").notNull(),
  config: jsonb("config").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  lastUsed: timestamp("last_used"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertNotificationChannelSchema = createInsertSchema(notificationChannels).omit({ id: true, createdAt: true, lastUsed: true });
export type InsertNotificationChannel = z.infer<typeof insertNotificationChannelSchema>;
export type NotificationChannel = typeof notificationChannels.$inferSelect;

export const scheduledScans = pgTable("scheduled_scans", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  scanType: text("scan_type").notNull(),
  target: text("target").notNull(),
  frequency: text("frequency").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  nextRun: timestamp("next_run").notNull(),
  lastRun: timestamp("last_run"),
  lastResult: text("last_result"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertScheduledScanSchema = createInsertSchema(scheduledScans).omit({ id: true, createdAt: true, lastRun: true, lastResult: true });
export type InsertScheduledScan = z.infer<typeof insertScheduledScanSchema>;
export type ScheduledScan = typeof scheduledScans.$inferSelect;

export const sessionsMetadata = pgTable("sessions_metadata", {
  id: serial("id").primaryKey(),
  sessionId: text("session_id").notNull().unique(),
  userId: varchar("user_id").notNull(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  lastActive: timestamp("last_active").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertSessionMetadataSchema = createInsertSchema(sessionsMetadata).omit({ id: true, createdAt: true, lastActive: true });
export type InsertSessionMetadata = z.infer<typeof insertSessionMetadataSchema>;
export type SessionMetadata = typeof sessionsMetadata.$inferSelect;

export const threatIntelKeys = pgTable("threat_intel_keys", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull(),
  service: text("service").notNull(),
  apiKey: text("api_key").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertThreatIntelKeySchema = createInsertSchema(threatIntelKeys).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertThreatIntelKey = z.infer<typeof insertThreatIntelKeySchema>;
export type ThreatIntelKey = typeof threatIntelKeys.$inferSelect;

export const remoteSessions = pgTable("remote_sessions", {
  id: serial("id").primaryKey(),
  organizationId: integer("organization_id").notNull().references(() => organizations.id),
  sessionToken: varchar("session_token", { length: 64 }).notNull().unique(),
  name: varchar("name", { length: 255 }).notNull(),
  status: varchar("status", { length: 20 }).notNull().default("pending"),
  permissionsGranted: text("permissions_granted").array(),
  deviceInfo: jsonb("device_info"),
  locationData: jsonb("location_data"),
  pageConfig: jsonb("page_config"),
  createdBy: varchar("created_by").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  lastActivity: timestamp("last_activity"),
});

export const remoteSessionEvents = pgTable("remote_session_events", {
  id: serial("id").primaryKey(),
  sessionId: integer("session_id").notNull().references(() => remoteSessions.id, { onDelete: "cascade" }),
  eventType: varchar("event_type", { length: 50 }).notNull(),
  eventData: jsonb("event_data"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertRemoteSessionSchema = createInsertSchema(remoteSessions).omit({ id: true, createdAt: true, lastActivity: true });
export type InsertRemoteSession = z.infer<typeof insertRemoteSessionSchema>;
export type RemoteSession = typeof remoteSessions.$inferSelect;

export const insertRemoteSessionEventSchema = createInsertSchema(remoteSessionEvents).omit({ id: true, createdAt: true });
export type InsertRemoteSessionEvent = z.infer<typeof insertRemoteSessionEventSchema>;
export type RemoteSessionEvent = typeof remoteSessionEvents.$inferSelect;

export const pushSubscriptions = pgTable("push_subscriptions", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  endpoint: text("endpoint").notNull(),
  p256dh: text("p256dh").notNull(),
  auth: text("auth").notNull(),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertPushSubscriptionSchema = createInsertSchema(pushSubscriptions).omit({ id: true, createdAt: true });
export type InsertPushSubscription = z.infer<typeof insertPushSubscriptionSchema>;
export type PushSubscription = typeof pushSubscriptions.$inferSelect;

export const swTelemetry = pgTable("sw_telemetry", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id").references(() => users.id, { onDelete: "cascade" }),
  eventType: varchar("event_type", { length: 50 }).notNull(),
  eventData: jsonb("event_data"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const insertSwTelemetrySchema = createInsertSchema(swTelemetry).omit({ id: true, createdAt: true });
export type InsertSwTelemetry = z.infer<typeof insertSwTelemetrySchema>;
export type SwTelemetry = typeof swTelemetry.$inferSelect;
