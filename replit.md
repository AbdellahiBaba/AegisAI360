# AegisAI - Defensive Cybersecurity Platform

## Overview
Enterprise-grade multi-tenant SaaS SOC platform with real-time threat monitoring, one-click defense response actions, firewall management, alert rules engine, super admin system, AI-powered threat detection, WebSocket live feeds, Stripe billing, organization-based data separation, role-based access control, security scanning tools, threat simulation engine, and configurable automation defense modes.

## Tech Stack
- **Frontend**: React + TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter (routing), TanStack Query
- **Backend**: Express.js + TypeScript, WebSocket (ws), Passport.js (auth)
- **Database**: PostgreSQL via Drizzle ORM
- **AI**: OpenAI via Replit AI Integrations (gpt-4o-mini)
- **Payments**: Stripe via Replit connector (stripe-replit-sync)
- **i18n**: i18next + react-i18next (English + Arabic with RTL support)
- **Fonts**: Space Grotesk (sans), Cairo (Arabic/RTL), JetBrains Mono (mono)
- **Security**: Helmet (headers), express-rate-limit, xss sanitization, intrusion detection

## Architecture
```
shared/schema.ts          - Drizzle schema + Zod insert schemas + types (18+ tables)
shared/models/chat.ts     - Conversations/messages tables
server/index.ts           - Express app bootstrap, Stripe init, super admin seed, rule seeding, security middleware chain
server/securityMiddleware.ts - Intrusion detection, IP blocking, attack classification, security stats
server/routes.ts          - All API routes + WebSocket + AI streaming + billing + scanning + simulation
server/storage.ts         - DatabaseStorage implementing IStorage (org-scoped)
server/auth.ts            - Passport-local, sessions, register/login/logout, RBAC
server/ingestion.ts       - Real data ingestion APIs (syslog, SIEM, generic)
server/alertEngine.ts     - Alert rules evaluation engine with defense mode support
server/seedRules.ts       - Pre-built detection rules + response playbooks seeder
server/scanEngine.ts      - Security scanning engine (port/DNS/SSL/header/vulnerability)
server/threatSimulator.ts - Threat simulation engine (6 attack scenarios)
server/superAdmin.ts      - Super admin middleware and platform management
server/threatFeeds.ts     - Threat feed integration
server/responseEngine.ts  - One-click defense response actions
server/stripeClient.ts    - Stripe SDK client via Replit connector
server/webhookHandlers.ts - Stripe webhook processing
server/seed-products.ts   - Creates 3 Stripe pricing tiers
server/db.ts              - Drizzle + pg pool setup
server/replit_integrations/chat/storage.ts - Chat CRUD
client/src/i18n/index.ts   - i18next init (EN/AR, localStorage persistence, RTL dir toggling)
client/src/i18n/en.json    - English translations (~300+ keys, organized by page namespace)
client/src/i18n/ar.json    - Arabic translations (matching en.json structure)
client/src/App.tsx         - Layout with sidebar, auth, notification bell, language switcher, public+auth routes
client/src/pages/          - 18 authenticated pages + landing page + 6 public pages, all translated
client/src/pages/public/   - About, Features, Pricing, Privacy, Terms, Refund (public, no auth required)
client/src/pages/landing.tsx - Main landing page with Matrix rain animation, hero, stats
client/src/pages/scanner.tsx - Security scanner with 5 scan types (tabs) + scan history
client/src/components/     - AppSidebar, Logo, NotificationBell, LanguageSwitcher, ThemeProvider, PublicLayout, MatrixRain, shadcn
client/src/hooks/          - use-auth, use-toast, use-mobile
```

## Database Tables
- `organizations` - Multi-tenant orgs (plan, slug, stripe IDs, defenseMode)
- `users` - Auth (varchar UUID PK, org FK, role, isSuperAdmin)
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
- `firewall_rules` - IP/domain/port/CIDR blocking rules with expiry
- `alert_rules` - Custom alert rule conditions and actions
- `response_actions` - Log of all response actions taken
- `notifications` - User notifications with read status
- `scan_results` - Security scan results (port/DNS/SSL/header/vuln scans)
- `support_tickets` - Support tickets (subject, description, status, priority, category, messages JSONB, remote session flags)
- `conversations` - AI chat conversations
- `messages` - Chat messages with role
- `stripe.*` - Auto-managed by stripe-replit-sync

## Pages
1. Dashboard (Security Center) - Security Level indicator, 7 stat cards, emergency lockdown, event trends, live feed, response actions feed
2. Security Events - Search, filter, detail sheet, status management, block IP, create incident buttons
3. Incidents - Card grid, create dialog, status workflow, execute playbook
4. Threat Intel - IOC table, type icons, active toggle, block IP, sinkhole domain
5. AI Analysis - Streaming chat, conversation management
6. Policies - Tier badges, enable/disable, create dialog
7. Network Map - Asset inventory with risk scores, add asset
8. ATT&CK Heatmap - MITRE matrix coverage, detection frequency
9. Forensic Timeline - Audit log with filters, CSV export
10. Honeypot Dashboard - Live attack feed, country origins, service breakdown, block attacker IP
11. Quarantine - File management with restore/delete actions
12. Response Playbooks - Create/toggle automated response procedures
13. Organization Settings - Team members, invite system, role management, defense mode toggle, threat simulator
14. Billing - Pricing tiers (Starter $9, Professional $29, Enterprise $79)
15. Firewall Management - Rules table, add/edit/toggle/delete rules, search/filter
16. Alert Rules - Rules list, conditions builder, enable/disable, delete
17. Super Admin - Platform stats, org management, user table, system health, audit log, security tab, support ticket management
18. Security Scanner - Port scanner, DNS lookup, SSL checker, header audit, vulnerability scan, scan history
19. Support Center - Create/track support tickets, message thread, request remote assistance

## Security Scanner
5 scan types accessible at `/scanner`:
- **Port Scanner**: TCP connection scan across 23 common ports using Node.js `net.Socket`, risk-classified
- **DNS Lookup**: Resolves A, AAAA, MX, NS, TXT, CNAME records using `dns.promises`
- **SSL/TLS Checker**: Grabs certificates via `tls.connect`, grades A-F, flags expired/self-signed/expiring
- **Header Audit**: Checks 8 security headers (HSTS, CSP, X-Frame-Options, etc.), scores percentage, grades A-F
- **Vulnerability Scanner**: Checks 20 common paths (.env, .git, admin panels, backup dirs), severity-rated
- All results stored in `scan_results` table and high-risk findings create `security_events`
- APIs: POST `/api/scan/ports|dns|ssl|headers|vulnerabilities`, GET `/api/scan/history`

## Threat Simulation Engine
6 attack scenarios for testing automated defense (admin only):
1. **SSH Brute Force** - 15+ rapid login attempts from a single IP
2. **Ransomware Outbreak** - Dropper, C2 beacon, file encryption, data exfiltration
3. **Phishing Campaign** - Malicious emails, credential harvesting, compromised user
4. **Port Scan Sweep** - Network recon across 12 ports from external IP
5. **Data Exfiltration** - DB queries, DNS tunneling, bulk encrypted transfer
6. **APT Kill Chain** - Full lifecycle: recon, exploit, persistence, lateral movement, credential dump, exfil
- APIs: GET `/api/simulate/scenarios`, POST `/api/simulate/:scenario`

## Automation Defense Modes
Three modes controlling how AlertEngine responds to threats:
- **Full Auto** (default): All rules execute automatically (block IPs, quarantine files, sinkhole domains)
- **Semi-Auto**: Destructive actions create pending approval notifications instead of executing
- **Manual**: Only notifications generated; all defensive actions require manual execution
- Stored in `organizations.defenseMode` column
- APIs: GET `/api/settings/defense-mode`, PATCH `/api/settings/defense-mode`

## Pre-Built Detection Rules (12 rules, auto-seeded)
SSH Brute Force, Ransomware, SQL Injection, XSS, Port Scan, Data Exfiltration, Phishing, Lateral Movement, Privilege Escalation, C2 Beacon, Zero-Day Exploit, Unauthorized Access

## Pre-Built Response Playbooks (6 playbooks, auto-seeded)
Ransomware Containment, Phishing Response, Brute Force Mitigation, Data Exfiltration Response, Malware Outbreak, Insider Threat Response

## Auth & Multi-Tenancy
- Passport-local with scrypt hashing, connect-pg-simple sessions
- Registration creates new org (admin role) or uses invite code to join existing org
- All data routes scoped by `organizationId`
- Roles: admin, analyst, auditor, readonly
- Super admin: username `admin`, password from `ADMIN_PASSWORD` env var (default: `aegis-admin-2024`)
- `requireAuth` middleware on all `/api/*` data routes
- `requireRole("admin")` on org management and billing routes
- `requireSuperAdmin` on `/api/admin/*` routes

## Response Actions
- Block IP (creates firewall rule, mitigates related events)
- Create Incident from Event
- Isolate Asset
- Sinkhole Domain
- Emergency Lockdown (blocks all critical event source IPs)
- Execute Playbook (multi-step automated response)
- Auto-Quarantine (alert engine auto-quarantines malware/ransomware events)
- Auto-Sinkhole (alert engine auto-blocks domain-like sources)
- Auto Threat Response (POST /api/response/auto-defend) - automatic block+incident+notify for critical threats

## Data Ingestion APIs
- POST `/api/ingest/syslog` - Syslog format ingestion
- POST `/api/ingest/siem` - SIEM integration (Splunk/QRadar format)
- POST `/api/ingest/generic` - Generic event ingestion

## Public Pages
- Landing Page (`/`) - Matrix rain animation, hero with typing text, feature showcase, stats counters, CTA
- Features (`/features`) - Platform capabilities grid with icons
- Pricing (`/pricing`) - 3 tiers (Starter $9, Professional $29, Enterprise $79)
- About (`/about`) - Mission, values, team section
- Privacy (`/privacy`) - Privacy policy
- Terms (`/terms`) - Terms of service
- Refund (`/refund`) - Refund policy
- All public pages use `PublicLayout` with shared header/footer
- Public pages accessible without authentication via `RootRouter` in App.tsx

## Visual Identity
- Professional cybersecurity dark theme (forced dark mode, no light toggle)
- Background: `228 45% 3%` (deep midnight navy), Primary: `42 90% 50%` (gold/amber)
- Favicon: SVG shield with gold gradient (`client/public/favicon.svg`)
- Logo: Shield SVG with gold gradients, circuit-eye motif, accent lines
- Grid background pattern, scanline animation
- Security Level 1 through 5 CSS indicator classes
- Severity colors: critical (red), high (orange), medium (yellow), low (blue), info (slate)

## Sidebar Navigation (5 Groups)
- OVERVIEW: Dashboard, AI Analysis
- DETECT: Security Events, ATT&CK Map, Scanner, Honeypot, Alert Rules
- RESPOND: Incidents, Quarantine, Playbooks, Firewall, Policies
- RESEARCH: Threat Intel, Network Map, Forensics
- ADMIN: Settings, Billing, Support, Super Admin (super admin only)

## Internationalization (i18n)
- Languages: English (default), Arabic (RTL)
- Library: i18next + react-i18next
- Translation files: `client/src/i18n/en.json` and `client/src/i18n/ar.json`
- Language preference persisted to localStorage key `aegis-lang`
- RTL: `dir` and `lang` attributes set on `<html>` element dynamically
- Language switcher in header (authenticated) and auth page (unauthenticated)
- All pages and core components fully translated (300+ keys each language)
- CSS uses logical properties (me/ms/start/end/border-e) for RTL compatibility

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection
- `SESSION_SECRET` - Session encryption
- `ADMIN_PASSWORD` - Super admin password (default: aegis-admin-2024)
- `AI_INTEGRATIONS_OPENAI_API_KEY` - Auto-set by Replit integration
- `AI_INTEGRATIONS_OPENAI_BASE_URL` - Auto-set by Replit integration
- Stripe credentials managed by Replit connector

## Commands
- `npm run dev` - Start dev server (Express + Vite)
- `npm run db:push` - Push schema to database
- `npx tsx server/seed-products.ts` - Seed Stripe products
