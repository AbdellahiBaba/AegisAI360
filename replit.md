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
The platform features a professional cybersecurity-themed dark mode user interface. Key visual elements include a deep midnight navy background, gold/amber primary accents, an SVG shield logo with gold gradients and a circuit-eye motif, and specific fonts like Space Grotesk, Cairo (for RTL), and JetBrains Mono. It uses a grid background pattern and scanline animations. Security levels are indicated via CSS classes, and severity is color-coded (critical, high, medium, low, info). The application supports internationalization with English and Arabic (RTL) languages, with dynamic `dir` and `lang` attribute switching and logical CSS properties for RTL compatibility.

### Technical Implementations
The frontend is built with React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter, and TanStack Query. The backend utilizes Express.js with TypeScript, WebSocket for live feeds, and Passport.js for authentication. PostgreSQL is used as the database, managed via Drizzle ORM. AI capabilities are integrated using OpenAI (gpt-4o-mini), and payment processing is handled by Stripe.

### Feature Specifications
- **Real-time Monitoring**: Provides live feeds of security events and network activities.
- **AI-powered Threat Detection**: Analyzes security events using AI to identify threats.
- **One-Click Defense Response**: Enables immediate actions such as IP blocking, asset isolation, and playbook execution.
- **Multi-tenancy & RBAC**: Supports multiple organizations with data separation and role-based access control (admin, analyst, auditor, readonly).
- **Firewall Management**: Allows creation, editing, and management of firewall rules.
- **Alert Rules Engine**: Configurable engine to define custom alert conditions and actions.
- **Security Scanning**: Includes port, DNS, SSL/TLS, header, and vulnerability scanning capabilities.
- **Penetration Testing Tools**: Advanced offensive security suite including subdomain enumeration (DNS brute-force + crt.sh), directory bruteforce (500+ paths), technology fingerprinting, WAF detection (12 WAF types), WHOIS/RDAP lookup, SQL injection testing (18 payloads), and XSS testing (20 payloads). All tools work against real targets with SSRF protection.
- **Hash & Password Tools**: Standalone page with hash identifier (MD5/SHA-1/SHA-256/SHA-512/bcrypt), hash cracker (dictionary attack with 200+ common passwords), and password strength analyzer (entropy, crack time estimation, weakness analysis).
- **Threat Simulation Engine**: Offers 6 attack scenarios (SSH Brute Force, Ransomware, Phishing, Port Scan Sweep, Data Exfiltration, APT Kill Chain) to test defenses.
- **Automation Defense Modes**: Three modes (Full Auto, Semi-Auto, Manual) control the level of automated response.
- **Network/Infrastructure Monitor**: Real infrastructure scanning (port scan, SSL check, header audit, vulnerability path scan) for user-provided servers/domains/IPs, with device management and real-time monitoring.
- **Protection Center**: One-click "Protect Me" page with protection score, checklist, and auto-activation of all defenses.
- **Smart Remediation**: Scan results include one-click fix buttons that create real firewall rules and alert rules.
- **Data Ingestion**: APIs for Syslog, SIEM, and generic event ingestion.
- **Super Admin System**: Provides platform-level management, organization oversight, and system health monitoring. Super admin (isSuperAdmin=true) has full unrestricted access with no billing plan restrictions.

#### Endpoint Agent System (NEW)
- **Device Token Management**: Generate single-use tokens via `/api/agent/device-token/create` to register endpoint agents.
- **Agent Registration**: Agents register with hostname, OS, IP via `/api/agent/register` using device tokens.
- **Heartbeat Monitoring**: Agents send periodic heartbeats with CPU/RAM metrics via `/api/agent/heartbeat`.
- **Log Ingestion**: Agents send security events via `/api/agent/logs` with plan-based rate limiting.
- **Command System**: SOC analysts send commands to agents (system scan, list processes, isolate network, etc.). Agents poll for pending commands and report results.
- **Remote Terminal**: Built-in terminal UI for remote command execution on agents. Commands are validated against a whitelist (whoami, ifconfig, netstat, ps, ls, etc.). Destructive commands (rm, del, format, sudo) are always blocked. All terminal activity is logged in audit logs.
- **Frontend Pages**: `/endpoints` (agent dashboard), `/download-agent` (token generation + agent download), `/endpoints/:agentId/terminal` (remote terminal).
- **Windows Installer Bundle**: Complete installer in `/installer` directory with Go agent (main.go), WinSW service wrapper (AegisAI360Agent.xml), NSIS installer script (installer.nsi), and build README. Build with `go build -o agent.exe main.go` + `makensis installer.nsi`.
- **Files**: `server/agentApi.ts`, `client/src/pages/endpoints.tsx`, `client/src/pages/download-agent.tsx`, `client/src/pages/agent-terminal.tsx`, `installer/main.go`, `installer/installer.nsi`, `installer/AegisAI360Agent.xml`

#### Billing Paywall System (NEW)
- **Plans Table**: Three tiers (starter $29/mo, professional $99/mo, enterprise $299/mo) with feature flags and usage limits.
- **Subscription Enforcement**: New users are redirected to `/choose-plan` until they have an active subscription. Super admin bypasses all restrictions.
- **Usage Tracking**: Daily usage tracked per organization (agents, logs, commands, terminal commands, threat intel queries).
- **Plan Features**: `allowNetworkIsolation`, `allowProcessKill`, `allowFileScan`, `allowEndpointDownload`, `allowTerminalAccess`, `allowThreatIntel`, `allowAdvancedAnalytics`.
- **Frontend Pages**: `/choose-plan` (plan selection), `/billing/success`, `/billing/error`.
- **Organization Fields**: `subscription_status` (active/inactive/trial/canceled), `plan_id` (references plans table).

#### Threat Intelligence API Integration (NEW)
- **AbuseIPDB**: IP reputation lookup via `/api/threat-intel/ip`. Returns abuse confidence score, reports, country, ISP.
- **AlienVault OTX**: Indicator lookup via `/api/threat-intel/otx-lookup`. Supports IP, domain, URL, hash types.
- **URLScan.io**: URL analysis via `/api/threat-intel/urlscan`. Submits URLs for scanning.
- **Google Safe Browsing**: URL safety check via `/api/threat-intel/safebrowsing`. Checks against malware/phishing lists.
- **MalwareBazaar**: Hash lookup via `/api/threat-intel/hash`. No API key required (free API).
- **Stub Data**: When API keys are not configured, returns realistic demo data with a "Demo Data" badge.
- **Files**: `server/services/threatIntel/` directory with individual service files.

#### Advanced Analytics (NEW)
- **Anomaly Detection**: `/api/analytics/anomaly-detection` - heuristic analysis of security events, returns anomaly score and detected anomalies.
- **Endpoint Risk Score**: `/api/analytics/endpoint-risk-score` - calculates risk scores based on agent status, CPU/RAM, last seen time.

#### Documentation (NEW)
- **Agent Documentation**: `/docs/agent` page with comprehensive documentation covering registration flow, command system, terminal usage, API reference, Go agent skeleton, and plan feature matrix.

### Database Schema
- **New Tables**: `plans`, `device_tokens`, `agents`, `agent_commands`, `terminal_audit_logs`, `usage_tracking`
- **Modified Tables**: `organizations` (added `subscription_status`, `plan_id` columns)
- **Total Tables**: 28+ tables covering all platform functionality

### System Design Choices
- **Modular Architecture**: Codebase is organized into `server/`, `client/`, and `shared/` directories.
- **Authentication**: Passport-local with scrypt hashing and session management.
- **Organization Scoping**: All data access is scoped by `organizationId` to ensure multi-tenancy.
- **Agent Auth**: Device token-based authentication for agent API endpoints (no user session required).
- **Terminal Safety**: Command whitelist + blocked pattern list for remote terminal execution.

## External Dependencies
- **OpenAI**: Integrated for AI-powered threat analysis (gpt-4o-mini).
- **Stripe**: Used for subscription management and billing via the `stripe-replit-sync` connector.
- **PostgreSQL**: Primary database for all application data, accessed via Drizzle ORM.
- **Passport.js**: Authentication middleware.
- **i18next + react-i18next**: For internationalization and localization.
- **Node.js `net` and `dns` modules**: Used for network scanning functionalities (Port Scanner, DNS Lookup).
- **Node.js `tls` module**: Used for SSL/TLS certificate checking.
- **AbuseIPDB API**: IP reputation (optional, needs ABUSEIPDB_API_KEY).
- **AlienVault OTX API**: Threat intelligence (optional, needs OTX_API_KEY).
- **URLScan.io API**: URL analysis (optional, needs URLSCAN_API_KEY).
- **Google Safe Browsing API**: URL safety (optional, needs GOOGLE_SAFE_BROWSING_API_KEY).
- **MalwareBazaar API**: Malware hash lookup (free, no key needed).

## Key Technical Notes
- **Session Cookie**: `secure: process.env.NODE_ENV === "production"` + `proxy: true` in `server/auth.ts`
- **parseActions()**: Handles both `string[]` and `{type: string}[]` formats for alert rule actions
- **DB Pattern**: Use `and()` with `eq(table.organizationId, orgId)` for all org-scoped queries
- **Super Admin**: username=`admin`, bypasses all billing/plan restrictions via `isSuperAdmin` check
- **Plans Seeded**: starter (id=1), professional (id=2), enterprise (id=3) in plans table
