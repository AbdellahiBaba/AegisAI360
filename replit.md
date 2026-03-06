# AegisAI - Security Operations Center Dashboard

## Overview
Multi-tenant SaaS SOC dashboard with AI-powered threat detection, real-time monitoring via WebSockets, Stripe billing, organization-based data separation, role-based access control, and expanded cybersecurity defense tools.

## Tech Stack
- **Frontend**: React + TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter (routing), TanStack Query
- **Backend**: Express.js + TypeScript, WebSocket (ws), Passport.js (auth)
- **Database**: PostgreSQL via Drizzle ORM
- **AI**: OpenAI via Replit AI Integrations (gpt-4o-mini)
- **Payments**: Stripe via Replit connector (stripe-replit-sync)
- **Fonts**: Space Grotesk (sans), JetBrains Mono (mono)

## Architecture
```
shared/schema.ts          - Drizzle schema + Zod insert schemas + types (15 tables)
shared/models/chat.ts     - Conversations/messages tables
server/index.ts           - Express app bootstrap, Stripe init, seed
server/routes.ts          - All API routes + WebSocket + AI streaming + billing
server/storage.ts         - DatabaseStorage implementing IStorage (org-scoped)
server/auth.ts            - Passport-local, sessions, register/login/logout, RBAC
server/seed.ts            - Initial seed data (org, events, incidents, assets, etc.)
server/stripeClient.ts    - Stripe SDK client via Replit connector
server/webhookHandlers.ts - Stripe webhook processing
server/seed-products.ts   - Creates 3 Stripe pricing tiers
server/db.ts              - Drizzle + pg pool setup
server/replit_integrations/chat/storage.ts - Chat CRUD
client/src/App.tsx         - Layout with sidebar, auth, theme toggle, 14 routes
client/src/pages/          - 14 pages (see below)
client/src/components/     - AppSidebar (grouped nav), ThemeProvider, shadcn components
client/src/hooks/          - use-auth, use-toast, use-mobile
```

## Database Tables
- `organizations` - Multi-tenant orgs (plan, slug, stripe IDs)
- `users` - Auth (varchar UUID PK, org FK, role)
- `invites` - Invite codes (org FK, role, expiry)
- `security_events` - Security alerts (org-scoped, ATT&CK technique/tactic)
- `incidents` - Incident tracking with workflow statuses
- `threat_intel` - IOC indicators with active toggle
- `security_policies` - Policy definitions with tier/enable
- `assets` - Network assets (type, IP, OS, risk score, status)
- `audit_logs` - Action audit trail (user, action, target)
- `honeypot_events` - Attacker interactions (service, payload, country)
- `quarantine_items` - Quarantined files (threat, source, status)
- `response_playbooks` - Automated response procedures
- `conversations` - AI chat conversations
- `messages` - Chat messages with role
- `stripe.*` - Auto-managed by stripe-replit-sync (products, prices, subscriptions, etc.)

## Pages
1. Dashboard - 7 stat cards, event trend chart, severity breakdown, recent alerts, live feed
2. Security Events - Search, filter, detail sheet, status management
3. Incidents - Card grid, create dialog, status workflow
4. Threat Intel - IOC table, type icons, active toggle
5. AI Analysis - Streaming chat, conversation management
6. Policies - Tier badges, enable/disable, create dialog
7. Network Map - Asset inventory with risk scores, add asset
8. ATT&CK Heatmap - MITRE matrix coverage, detection frequency
9. Forensic Timeline - Audit log with filters, CSV export
10. Honeypot Dashboard - Live attack feed, country origins, service breakdown
11. Quarantine - File management with restore/delete actions
12. Response Playbooks - Create/toggle automated response procedures
13. Organization Settings - Team members, invite system, role management
14. Billing - Pricing tiers (Starter $9, Professional $29, Enterprise $79)

## Auth & Multi-Tenancy
- Passport-local with scrypt hashing, connect-pg-simple sessions
- Registration creates new org (admin role) or uses invite code to join existing org
- All data routes scoped by `organizationId`
- Roles: admin, analyst, auditor, readonly
- `requireAuth` middleware on all `/api/*` data routes
- `requireRole("admin")` on org management and billing routes

## Stripe Integration
- 3 products: Starter ($9/mo, 5 users), Professional ($29/mo, 25 users), Enterprise ($79/mo, unlimited)
- Stripe connector via Replit integrations
- stripe-replit-sync handles schema, webhooks, data sync
- Webhook route registered BEFORE express.json() middleware
- Products seeded via `npx tsx server/seed-products.ts`

## Design Tokens
- Primary: cyan (185 85% 48%)
- Severity: critical (red), high (orange), medium (yellow), low (blue), info (slate)
- Status: online (green), away (amber), busy (red), offline (slate)

## Sidebar Navigation (Grouped)
- Operations: Dashboard, Security Events, Incidents, AI Analysis
- Detection: Threat Intel, Network Map, ATT&CK Heatmap, Honeypot
- Response: Quarantine, Playbooks, Policies, Forensic Timeline
- Admin: Settings, Billing (admin-only)

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection
- `SESSION_SECRET` - Session encryption
- `AI_INTEGRATIONS_OPENAI_API_KEY` - Auto-set by Replit integration
- `AI_INTEGRATIONS_OPENAI_BASE_URL` - Auto-set by Replit integration
- Stripe credentials managed by Replit connector

## Commands
- `npm run dev` - Start dev server (Express + Vite)
- `npm run db:push` - Push schema to database
- `npx tsx server/seed-products.ts` - Seed Stripe products
