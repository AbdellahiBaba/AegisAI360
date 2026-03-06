import { sql } from "drizzle-orm";
import { pgTable, text, varchar, serial, integer, timestamp, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export * from "./models/chat";

export const users = pgTable("users", {
  id: varchar("id").primaryKey().default(sql`gen_random_uuid()`),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
});

export const securityEvents = pgTable("security_events", {
  id: serial("id").primaryKey(),
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
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

export const incidents = pgTable("incidents", {
  id: serial("id").primaryKey(),
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
  name: text("name").notNull(),
  description: text("description").notNull(),
  tier: text("tier").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  rules: text("rules"),
  createdAt: timestamp("created_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
  updatedAt: timestamp("updated_at").default(sql`CURRENT_TIMESTAMP`).notNull(),
});

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
