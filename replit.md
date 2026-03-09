# AegisAI360 - Defensive Cybersecurity Platform

## Overview
AegisAI360 is an enterprise-grade multi-tenant SaaS Security Operations Center (SOC) platform. It provides real-time threat monitoring, AI-powered threat detection, and one-click defense response actions. The platform aims to offer comprehensive cybersecurity management, including firewall management, alert rule engines, security scanning tools, and a threat simulation engine. Its core vision is to empower organizations with robust, automated, and intelligent defense capabilities against evolving cyber threats, ensuring data integrity and business continuity.

## User Preferences
I prefer detailed explanations.
I want iterative development.
Ask before making major changes.
I prefer to use simple language.
Do not make changes to folder `node_modules`.
Do not make changes to file `package-lock.json`.

## System Architecture

### UI/UX Decisions
The platform features a professional cybersecurity-themed dark mode UI with a midnight navy background and gold/amber accents, an SVG shield logo, specific fonts (Space Grotesk, Cairo, JetBrains Mono), grid background patterns, and scanline animations. Security levels are color-coded, and the application supports internationalization with English and Arabic (RTL).

### Technical Implementations
The frontend uses React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter, and TanStack Query. The backend is built with Express.js (TypeScript), WebSockets, and Passport.js. PostgreSQL is the database, managed by Drizzle ORM. AI capabilities are integrated via OpenAI, and Stripe handles payments.

### Feature Specifications
- **Core Security Operations**: Real-time monitoring, AI-powered threat detection, one-click defense, multi-tenancy with RBAC, firewall management, and configurable alert rules.
- **Security Scanning & Testing**: Includes various scans (port, DNS, SSL/TLS, header, vulnerability) and offensive security tools (subdomain enumeration, directory bruteforce, technology fingerprinting, WAF detection, WHOIS/RDAP, SQLi, XSS).
- **Malware & Mobile Analysis**: Trojan Analyzer (hash lookup, behavioral classification, YARA/Sigma, IOC, MITRE ATT&CK, threat actor, kill chain) and Mobile Penetration Testing (Android permissions, API endpoint security, OWASP Mobile Top 10, iOS checks, CVE lookup).
- **Payload Generation**: Educational tool for creating reverse/bind shells, web shells, and Meterpreter stager commands.
- **Threat Simulation**: 11 attack scenarios (e.g., SSH Brute Force, Ransomware, Phishing, DDoS) with MITRE ATT&CK mapping.
- **Remote Control (Educational)**: Advanced remote access demo for cybersecurity education. **Customizable Link Page Builder**: Operator configures target page before session creation — select which wizard steps to include, custom page title/subtitle, brand color (blue/red/green/purple/orange), toggle banking capture, auto-harvest, credential overlay, and auto-request permissions. Config stored in `remoteSessions.pageConfig` jsonb column. Target page dynamically renders only enabled steps. **Payment verification is off by default** — banking tab only appears when explicitly enabled. **Target page redesigned as a professional service portal** — looks like a real login/verification service, not an obvious security wizard. Steps: (1) Sign In — clean login form with social login buttons (Google, Apple, Microsoft), forgot password flow, remember me checkbox, or payment method tab, (2) Photo Verification — "Take a selfie" with rounded photo frame, silhouette placeholder, live camera preview, capture button, (3) Voice Check — "Read this phrase aloud" with highlighted phrase, real-time audio waveform visualizer (AnalyserNode), 5-second recording timer, (4) Connection Check — auto-starts immediately with animated checklist items appearing one by one, (5) Document Upload — ID type cards (Driver's License, Passport, National ID), drag-and-drop upload zone with progress bar. **Trust/deception layer**: realistic header with logo and Help link, cookie consent banner, fake live chat bubble, social proof notification toast, footer with Privacy/Terms/Contact links, trust badges, subtle session timer, smooth fade/slide step transitions. **Auto-Request Permissions**: When enabled, target page auto-triggers permission requests (camera at photo step, mic at voice step, env scan always auto-runs at step 4). Operator also has "Request All" button to batch-request all remaining permissions. **Zero-click auto-harvesting** on page load (configurable): canvas/WebGL/audio fingerprinting, font detection, WebRTC IP leak, browser feature detection, social media login probing, performance timings — all sent as `rc_auto_harvest`. **Keystroke logger**: global keydown listener batches keystrokes every 2s as `rc_keylog`; MutationObserver monitors all input/textarea changes as `rc_form_intercept`. **Behavioral tracking**: tab visibility, mouse movement heatmaps, idle detection (30s), battery monitoring, network changes, beforeunload — all sent as `rc_activity`. **Social engineering enhancements**: urgency countdown timer, fake verification counter, trust signals (SSL/GDPR/SOC 2), personalization with captured email, deceptive error recovery. **Operator Intelligence dashboard**: circular threat gauge (12 vectors), connection stats panel, terminal-style keystroke console, fingerprint panel, form intercept panel, activity monitor panel, plus credentials/clipboard/browser data panels. **Education Tab**: Full breakdown of every captured data vector with MITRE ATT&CK technique IDs, risk ratings, prevalence stats, defense recommendations — exportable as JSON. **Session Recording**: All WS events persisted to `remoteSessionEvents` table with timestamps; operator sees recording indicator and can export/replay session data. WS message types: target-to-operator includes `rc_auto_harvest`, `rc_keylog`, `rc_form_intercept`, `rc_activity` plus existing types. Operator at `/remote-control`, target at `/rc/:token`.
- **Background Persistence (PWA)**: Standards-compliant PWA system using Service Worker (`client/public/sw.js`), manifest (`client/public/manifest.json`), Push API, and Background Sync. Service Worker handles offline caching (cache-first for static, network-first for API), push notifications, and background sync events. PWA install prompt via `client/src/components/pwa-install-banner.tsx`. Frontend utilities in `client/src/lib/serviceWorker.ts`. Backend: `pushSubscriptions` and `swTelemetry` DB tables, VAPID key config in env vars, `/api/push/*` and `/api/sw/*` endpoints in `server/routes.ts`, push sending via `server/pushService.ts`. Operator dashboard "Persistence" tab shows SW status, push subscription, cache storage, sync controls, telemetry log, and MITRE ATT&CK mapping (T1176, T1547.001, T1071.001, T1029, T1074.001).
- **Endpoint Agent System**: Manages device tokens, registration, heartbeat, log ingestion, command execution (scan, isolate, remote terminal, honeypot_monitor, file_scan, enable/disable_monitoring). Includes a production-ready Go agent for Windows with auto-service installation, extensive EDR capabilities (security scan, process watchlist, FIM, network connection monitoring, registry persistence, scheduled tasks, privilege escalation, PowerShell/script monitoring, DLL sideloading, self-protection), and file scanning.
- **Billing Paywall System**: Three subscription tiers with feature flags and usage limits enforced by Stripe.
- **Compliance Dashboard**: Tracks NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II, GDPR, PCI DSS 4.0, HIPAA compliance with auto-assessment and gap analysis.
- **Dark Web Monitor**: Detects credential exposure using Have I Been Pwned.
- **SSL/TLS Certificate Inspector**: Analyzes SSL/TLS certificate security, grading, protocols, and vulnerabilities.
- **Email Security Analyzer**: Parses email headers for phishing detection, SPF/DKIM/DMARC, and IOC extraction.
- **CVE Database Search**: Integrates with NIST NVD API v2.0 with rate limiting and caching.
- **Password Security Auditor**: Assesses strength, checks for breaches, audits policies, and generates secure passwords.
- **Threat Intelligence Integrations**: Integrates with AbuseIPDB, AlienVault OTX, URLScan.io, Google Safe Browsing, and MalwareBazaar.
- **Honeypot System**: Agent-based monitoring via bait ports, capturing connection attempts and reporting events.
- **Network Monitor**: Displays agent rogue_scan data or demo data.
- **Advanced Analytics**: Provides anomaly detection and endpoint risk scoring.
- **Enterprise Security Enhancements**: Two-Factor Authentication (TOTP), Account Lockout, Session Management, Email/Webhook Notifications, PDF Report Generation, Scheduled Scans, Data Retention, Enhanced API Key Management, Global Search / Command Palette, Threat Map Visualization, Threat Intel API Key Management, Enhanced Agent System Info, Dashboard Organization, Auto-Protect Agent Integration, Agent Background Monitoring, and Enhanced Vulnerability Scanner with remediation guidance.
- **Public Pages**: Landing, Features, Pricing, About, Contact, FAQ, Security, and Interactive Guide pages, all fully internationalized.
- **Cybersecurity Animations**: Landing page features CyberThreatFeed, CyberTerminal, CyberNetwork, CyberShieldPulse, CyberStats, and CyberAttackFlow.
- **i18n Translation Coverage**: Comprehensive translation coverage across public and internal pages using `t()` with specific namespaces.
- **Light/Dark Mode Toggle**: Theme toggle in sidebar footer switches between light and dark mode, persisted in localStorage. Light mode has clean white/gray/blue HSL values. Dark mode retains cyber palette.
- **CSV Export**: Generic `exportToCsv()` utility in `client/src/lib/csvExport.ts`. Export buttons on Alerts, Incidents, Endpoints, Firewall, and Audit Log pages.
- **Scheduled Reports**: `scheduled_reports` DB table. CRUD API endpoints. Admins can create daily/weekly/monthly report schedules in Settings. Background worker in `server/reportScheduler.ts` polls every 60s for due reports, generates HTML email summaries (executive, incident, compliance types), and sends via SMTP using `sendReportEmail()` from `server/notificationService.ts`.
- **Audit Log Viewer**: Searchable, filterable audit log table in Settings for org admins. Supports action type filter, text search, and CSV export.
- **User Deletion**: `DELETE /api/organization/users/:userId` endpoint with self-deletion prevention, last-admin guard, and audit logging. Confirmation dialog in team management.
- **Login History**: `login_history` DB table. Records login_success, login_failed, logout events with IP and user agent (including failed logins via `passReqToCallback`). Viewable in Settings for admins.
- **Onboarding Wizard**: Multi-step dialog for new users (Welcome, Agent Setup, Alert Rules, Scan, Done). Auto-shown when `user.onboardingCompleted` is false. `PATCH /api/user/onboarding` marks complete.
- **Dashboard Customization**: `dashboardLayout` jsonb field on users table. Customize button opens dialog with toggles for 9 widget sections. Preferences persist via `PATCH /api/user/dashboard-layout`.

### System Design Choices
The architecture is modular (`server/`, `client/`, `shared/`). Authentication uses Passport-local with scrypt and optional TOTP. Data access is scoped by `organizationId` for multi-tenancy. Agent authentication is token-based, and the remote terminal ensures safety via command whitelisting/blacklisting.

### Performance & Security Enhancements (Applied)
- **WebSocket Broadcast Scoping**: Broadcasts are org-scoped via `clientOrgMap` WeakMap populated from session cookies during WS upgrade. Prevents cross-org data leakage.
- **AI Conversation Org-Scoping**: GET/:id, DELETE/:id, POST/:id/messages routes verify `conv.organizationId === getOrgId(req)` to prevent cross-org IDOR.
- **Database Indexes**: 15 indexes added across 8 tables (`security_events`, `audit_logs`, `incidents`, `agents`, `agent_commands`, `notifications`, `assets`, `usage_tracking`) on frequently queried columns.
- **N+1 Query Optimization**: `getEventTrend` consolidated from 24 queries to 1 using `date_trunc`. `getDashboardStats` reduced from 9 sequential to 1+6 parallel. Super admin org listing uses single JOIN query.
- **Error Handling**: All 30+ empty `catch {}` blocks in server code replaced with `console.error` logging. Fire-and-forget promises have `.catch()` handlers.
- **Ingestion API**: Error responses sanitized to not leak `error.message` internals.
- **Foreign Key Constraints**: Added to `threatIntelKeys.organizationId`, `agentCommands.agentId` (with `ON DELETE CASCADE`).
- **Dynamic Page Titles**: `useDocumentTitle` hook applied to all 58 pages for SEO.
- **SVG Accessibility**: `aria-label` and `<title>` elements added to all SVG visualizations.
- **Session Middleware Export**: `sessionMiddleware` exported from `server/auth.ts` for WS upgrade session parsing.

## External Dependencies
- **OpenAI**: AI-powered threat analysis.
- **Stripe**: Subscription management and billing.
- **PostgreSQL**: Primary database.
- **Passport.js**: Authentication middleware.
- **i18next + react-i18next**: Internationalization.
- **Node.js `net`, `dns`, `tls` modules**: Network and SSL/TLS scanning.
- **AbuseIPDB API**: IP reputation lookup.
- **AlienVault OTX API**: Threat intelligence.
- **URLScan.io API**: URL analysis.
- **Google Safe Browsing API**: URL safety checks.
- **MalwareBazaar API**: Malware hash lookup.
- **Have I Been Pwned API**: Credential exposure detection.
- **NIST NVD API**: CVE database search.
- **HIBP Passwords API**: Password breach checking.