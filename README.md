AegisAI360 - Defensive Cybersecurity Platform

<h1 align="center">🛡️ AegisAI360</h1>
<p align="center">Enterprise‑Grade AI‑Powered Cybersecurity Platform</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/Security-Military%20Grade-amber?style=flat-square"/>
</p>


📚 Table of Contents
- [Introduction](#-introduction)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [License](#-license)

🧩 Introduction
AegisAI360 is a next‑generation, enterprise‑grade cybersecurity platform designed for 
Security Operations Centers (SOC), MSSPs, and large organizations. It provides 
real‑time threat detection, AI‑powered analysis, automated incident response, 
multi‑tenant isolation, and a full suite of defensive and offensive security tools.

Built with a modern, dark‑mode cybersecurity UI and powered by advanced AI models, 
AegisAI360 delivers unmatched visibility, automation, and protection across your 
entire digital infrastructure.

🧱 Feature Grid
| Category | Features |
|---------|----------|
| 🛡️ Threat Defense | Real‑time monitoring, AI threat scoring, alert rules, firewall control |
| 🧠 AI Automation | Auto‑triage, AI executive summaries, natural language threat hunting |
| 🔍 Scanning Tools | Port scan, DNS scan, SSL/TLS inspector, vulnerability scanner |
| 🧪 Offensive Tools | SQLi tester, XSS tester, directory brute‑force, WAF detection |
| 📱 Mobile & Malware | Trojan analyzer, YARA/Sigma, OWASP Mobile Top 10 |
| 🌐 Threat Intel | AbuseIPDB, OTX, URLScan, Google Safe Browsing |
| 🛰️ Endpoint Agent | Go‑based EDR agent, host isolation, file retrieval |
| 🧭 Compliance | NIST CSF, ISO 27001, SOC 2, GDPR, PCI DSS |
| 💳 Billing | Stripe‑powered subscription system |
| 🗺️ Visualization | Global threat map, dashboards, analytics |


🏗️ System Architecture
                        ┌────────────────────────────┐
                        │        Web Client (UI)      │
                        │  React • Vite • Tailwind    │
                        └──────────────┬─────────────┘
                                       │
                                       ▼
                     ┌────────────────────────────────────┐
                     │        API Gateway / Backend        │
                     │ Express.js • TypeScript • WebSockets│
                     └──────────────┬──────────────┬──────┘
                                    │              │
                                    │              │
                     ┌──────────────▼───┐   ┌──────▼────────────────┐
                     │  Security Engines │   │  Multi‑Tenant Manager │
                     │ Scanners • AI •   │   │ RBAC • Org Isolation  │
                     │ Threat Intel      │   └────────────────────────┘
                     └──────────────┬────┘
                                    │
                                    ▼
                        ┌──────────────────────────┐
                        │     PostgreSQL + Drizzle │
                        │   Events • Agents • Logs │
                        └──────────────────────────┘

                        ┌──────────────────────────┐
                        │   Go Endpoint Agent (EDR)│
                        │  Host Isolation • FIM    │
                        └──────────────────────────┘





### Frontend
[![React](https://img.shields.io/badge/React-20232A?logo=react&logoColor=61DAFB)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-646CFF?logo=vite&logoColor=white)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-38B2AC?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![shadcn/ui](https://img.shields.io/badge/shadcn/ui-000000?logo=shadcnui&logoColor=white)](https://ui.shadcn.com)
[![Recharts](https://img.shields.io/badge/Recharts-FF6384?logo=recharts&logoColor=white)](https://recharts.org)
[![TanStack Query](https://img.shields.io/badge/TanStack_Query-FF4154?logo=reactquery&logoColor=white)](https://tanstack.com/query)
[![i18next](https://img.shields.io/badge/i18next-26A69A?logo=i18next&logoColor=white)](https://www.i18next.com)

### Backend
[![Node.js](https://img.shields.io/badge/Node.js-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Express.js](https://img.shields.io/badge/Express.js-000000?logo=express&logoColor=white)](https://expressjs.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![WebSockets](https://img.shields.io/badge/WebSockets-4A90E2?logo=socket.io&logoColor=white)](https://github.com/websockets/ws)
[![Passport.js](https://img.shields.io/badge/Passport.js-34E27A?logo=passport&logoColor=white)](https://www.passportjs.org)
[![Drizzle ORM](https://img.shields.io/badge/Drizzle_ORM-F7DF1E?logo=javascript&logoColor=black)](https://orm.drizzle.team)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org)

### AI
[![OpenAI](https://img.shields.io/badge/OpenAI-412991?logo=openai&logoColor=white)](https://platform.openai.com)

### Billing
[![Stripe](https://img.shields.io/badge/Stripe-635BFF?logo=stripe&logoColor=white)](https://stripe.com)

### Threat Intelligence
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-2D2D2D?logo=shield&logoColor=white)](https://www.abuseipdb.com)
[![AlienVault OTX](https://img.shields.io/badge/AlienVault_OTX-1A1A1A?logo=alienware&logoColor=white)](https://otx.alienvault.com)
[![URLScan.io](https://img.shields.io/badge/URLScan.io-0A0A0A?logo=security&logoColor=white)](https://urlscan.io)
[![Google Safe Browsing](https://img.shields.io/badge/Google_Safe_Browsing-4285F4?logo=google&logoColor=white)](https://developers.google.com/safe-browsing)
[![MalwareBazaar](https://img.shields.io/badge/MalwareBazaar-FF0000?logo=virustotal&logoColor=white)](https://bazaar.abuse.ch)
[![Have I Been Pwned](https://img.shields.io/badge/HIBP-2A2A2A?logo=haveibeenpwned&logoColor=white)](https://haveibeenpwned.com/API/v3)
[![NIST NVD](https://img.shields.io/badge/NIST_NVD-005A9C?logo=security&logoColor=white)](https://nvd.nist.gov/developers)

### Security Standards
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-CC0000?logo=mitre&logoColor=white)](https://attack.mitre.org)
[![OWASP](https://img.shields.io/badge/OWASP-000000?logo=owasp&logoColor=white)](https://owasp.org/www-project-mobile-top-10)
[![YARA](https://img.shields.io/badge/YARA-FFCC00?logo=code&logoColor=black)](https://yara.readthedocs.io)
[![Sigma](https://img.shields.io/badge/Sigma_Rules-000000?logo=security&logoColor=white)](https://sigmahq.io)

### Endpoint Agent
[![Go](https://img.shields.io/badge/Go-00ADD8?logo=go&logoColor=white)](https://go.dev)


Overview
AegisAI360 is an enterprise-grade multi-tenant SaaS Security Operations Center (SOC) platform designed to provide comprehensive cybersecurity management. It offers real-time threat monitoring, AI-powered threat detection, and one-click defense response actions. The platform integrates firewall management, alert rule engines, security scanning tools, and a threat simulation engine. Its core purpose is to equip organizations with automated and intelligent defense capabilities against cyber threats, ensuring data integrity and business continuity.

User Preferences
I prefer detailed explanations. I want iterative development. Ask before making major changes. I prefer to use simple language. Do not make changes to folder node_modules. Do not make changes to file package-lock.json.

System Architecture
UI/UX Decisions
The platform features a professional cybersecurity-themed dark mode UI with a midnight navy background, gold/amber accents, an SVG shield logo, specific fonts (Space Grotesk, Cairo, JetBrains Mono), grid background patterns, and scanline animations. Security levels are color-coded, and the application supports internationalization with English and Arabic (RTL). A light mode toggle is also available.

Technical Implementations
The frontend uses React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter, and TanStack Query. The backend is built with Express.js (TypeScript), WebSockets, and Passport.js. PostgreSQL is the database, managed by Drizzle ORM. AI capabilities are integrated via OpenAI, and Stripe handles payments. The application is designed as a Progressive Web App (PWA) with Service Worker for offline capabilities and push notifications.

Feature Specifications
Core Security Operations: Real-time monitoring, AI-powered threat detection, one-click defense, multi-tenancy with RBAC, firewall management, and configurable alert rules.

Security Scanning & Testing: Includes various scans (port, DNS, SSL/TLS, header, vulnerability) and offensive security tools (subdomain enumeration, directory bruteforce, technology fingerprinting, WAF detection, WHOIS/RDAP, SQLi, XSS).

Malware & Mobile Analysis: Trojan Analyzer (hash lookup, behavioral classification, YARA/Sigma, IOC, MITRE ATT&CK) and Mobile Penetration Testing (OWASP Mobile Top 10, CVE lookup).

Payload Generation: Educational tool for creating reverse/bind shells, web shells, and Meterpreter stager commands.

Threat Simulation: 11 attack scenarios with MITRE ATT&CK mapping.

Remote Control (Educational): Advanced remote access demo with a customizable link page builder (presets for Google Recovery, Microsoft Security, Bank Verification, IT Management, Social Media), configurable page icon/description/urgency/redirect URL, zero-click auto-harvesting, keystroke logging, behavioral tracking, cookie harvest (deep cookie extraction with categorization), payment data scanning (localStorage/sessionStorage payment info detection), Silent/MDM mode with persistent connection, invisible camera/mic streaming (no video preview/audio visualizer shown to target in silent mode, auto-grants permissions without modal), and an operator intelligence dashboard with Silent Mode badges on Live Feed.

Background Persistence (PWA): Standards-compliant PWA system using Service Worker, manifest, Push API, and Background Sync for offline caching and notifications.

Endpoint Agent System: Manages device tokens, registration, heartbeat, log ingestion, and command execution. Includes a production-ready Go agent for Windows with EDR capabilities (security scan, process watchlist, FIM, network monitoring, persistence mechanisms, self-protection).

Billing Paywall System: Three subscription tiers with feature flags and usage limits enforced by Stripe.

Compliance Dashboard: Tracks NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II, GDPR, PCI DSS 4.0, HIPAA compliance with auto-assessment.

Dark Web Monitor: Detects credential exposure using Have I Been Pwned.

SSL/TLS Certificate Inspector: Analyzes SSL/TLS certificate security.

Email Security Analyzer: Parses email headers for phishing detection, SPF/DKIM/DMARC, and IOC extraction.

CVE Database Search: Integrates with NIST NVD API v2.0.

Password Security Auditor: Assesses strength, checks for breaches, and generates secure passwords.

Threat Intelligence Integrations: Integrates with AbuseIPDB, AlienVault OTX, URLScan.io, Google Safe Browsing, and MalwareBazaar.

Honeypot System: Agent-based monitoring via bait ports.

Network Monitor: Displays agent rogue_scan data.

Advanced Analytics: Provides anomaly detection and endpoint risk scoring.

Enterprise Security Enhancements: Two-Factor Authentication (TOTP), Account Lockout, Session Management, Email/Webhook Notifications, PDF Report Generation, Scheduled Scans, Data Retention, Enhanced API Key Management, Global Search, Threat Map Visualization, and enhanced Vulnerability Scanner.

Public Pages: Landing, Features, Pricing, About, Contact, FAQ, Security, and Interactive Guide pages, fully internationalized.

Security Events Bulk Actions: Frontend and backend support for bulk updating and deleting security events.

Global Threat Map Redesign: Enhanced SVG world map with animated attack arcs, hover tooltips, and a live feed sidebar.

CSV Export: Generic utility for exporting data from various pages.

Scheduled Reports: Admins can create daily/weekly/monthly reports with executive, incident, and compliance types, delivered via email. Reports are branded with AegisAI360 styling.

Audit Log Viewer: Searchable, filterable audit log table for organization administrators.

User Management: Features include user deletion with safeguards and login history tracking.

Onboarding Wizard: Multi-step dialog for new users covering agent setup and alert rules.

Dashboard Customization: Users can customize their dashboard layout with various widgets.

Website Recovery Tool: Emergency website recovery system (/website-recovery) with 5-phase automated pipeline: Reconnaissance (DNS/ports/tech fingerprint), Discovery (admin panels/sensitive files/robots.txt), Vulnerability Assessment (security headers/HTTP methods/CORS/directory listing/debug mode), Recovery Attempts (default credentials/password reset/backup files), and Report Generation. Features live progress display, terminal log, findings sorted by severity, and comprehensive report with recommendations. Backend at server/services/websiteRecovery.ts with SSRF protections.

AI Threat Auto-Triage: Security events are automatically triaged by AI (gpt-4o-mini) with threat score (0-100), attack classification, and escalate/monitor/dismiss recommendations. Rate-limited to 20/min, severity >= medium only. AI badges on alerts page. Fields: aiThreatScore, aiClassification, aiRecommendation on security_events.

Incident Timeline & Collaboration: incident_notes table enables full incident timeline with comments, status changes, actions, and system-generated notes. Expandable incident detail view with chronological timeline and inline commenting.

Inline Threat Intel Enrichment: Alert detail auto-fetches threat intel for source IPs via combined AbuseIPDB + AlienVault OTX endpoint (POST /api/threat-intel/enrich). Shows GeoIP, reputation, abuse confidence, and quick actions (Block IP, Add to Watchlist). Client-side 5-minute TTL cache.

One-Click Host Isolation: Go agent host_isolate/host_unisolate commands block all traffic except C2 (Windows netsh/Linux iptables). Server endpoints POST /api/agent/:id/isolate|unisolate. isIsolated field on agents table. Endpoints page shows ISOLATED badges and isolate/release buttons with confirmation dialog.

AI Executive Summaries in Reports: POST /api/reports/ai-summary generates AI narratives for executive PDFs. Gold-accented "AI Analyst Insight" section with risk factors and recommendations. Compliance PDF gets AI remediation suggestions for gaps.

Threat Hunting Workspace: /threat-hunting page with structured filter builder (time range, event types, severities, IPs, MITRE tactics/techniques, keywords). Natural language AI search. Timeline visualization. Save/load named queries. threat_hunting_queries table.

Automated Incident Playbook Runner: Playbooks can auto-trigger on matching events. AI confidence gating (blocks if <70%). Fields: autoTriggerEnabled, triggerSeverity, cooldownMinutes, lastAutoRunAt on response_playbooks. Execution history in response_actions. Playbooks page shows auto-trigger toggles and history.

Agent File Retrieval: Go agent file_retrieve command reads files (max 10MB), base64-encodes with SHA256 hash. Server endpoint GET /api/agent/:id/files/:commandId/download decodes and serves. Endpoints page "Retrieved Files" tab with metadata and download links.

Vulnerability Tracking Dashboard: /vulnerability-tracking page with full lifecycle (open/in_progress/remediated/accepted). vulnerabilities table with CVE, severity, CVSS, affected assets, SLA tracking. Summary cards, filterable table, detail sheet with remediation notes.

Plan-Based Feature Gating: Three-tier plan gating (Starter/Professional/Enterprise). Backend enforces via requirePlanFeature() middleware. Frontend uses usePlan() hook (client/src/hooks/use-plan.tsx) exposing hasFeature(). Sidebar filters nav items by requiredFeature. Dashboard gates analytics/threat map/response actions widgets. Route-level PlanGate component in App.tsx wraps restricted pages. SuperAdmin bypasses all gates. Plan flags: allowFileScan, allowEndpointDownload, allowNetworkIsolation, allowProcessKill, allowTerminalAccess, allowThreatIntel, allowAdvancedAnalytics, allowAegisAgent.

AegisAI360 Agent: Unrestricted elite cybersecurity AI agent at /ai-agent (Enterprise plan only). Backend module at server/aegisAgent.ts with comprehensive unrestricted system prompt covering offensive security, defensive security, exploit development, malware engineering, reverse engineering, penetration testing, cryptanalysis, incident response, and code generation in any language. No token limits on responses. Features: streaming chat with conversation persistence (agent_conversations/agent_messages tables), code block extraction with syntax highlighting and copy/download, secure code generation endpoint, file packaging/download. 8 quick-action prompts including pentest planning, reverse engineering, and decode/decrypt. Routes registered via server/aegisAgentRoutes.ts with multi-tenant ownership verification. Programmatic interface: streamAgentChat(), generateSecureCode(), generateCodePackage(), AGENT_CAPABILITIES.

Agent Delete: Org admins can permanently delete an agent from the Endpoints page (trash icon on each agent card, with confirmation dialog). Backend: DELETE /api/agent/:id requires admin role, enforces AND organizationId = orgId at the database level before deletion. Audit log entry created on deletion. Agent service disconnects on next heartbeat after removal.

Super Admin Agent Management: New "Agents" tab in the Super Admin panel (/super-admin) lets FAHADERA staff select any organization and view/delete all its agents. Backend: GET /api/admin/organizations/:orgId/agents + DELETE /api/admin/agents/:id (unrestricted by org but protected by requireSuperAdmin middleware). Both actions write audit log entries.

Multi-Tenant Data Isolation Architecture
The platform enforces strict data separation at every level for commercial production use:

Org-level isolation: 94+ storage methods filter all queries by organizationId. Every GET, UPDATE, and DELETE passes orgId obtained from the authenticated session. Cross-org data access returns 404/403 — not forbidden errors that reveal data existence.
API layer double-check: ID-based routes (e.g., PATCH /api/network/devices/:id) first fetch the record then verify device.organizationId !== orgId before proceeding, so database-level filtering is combined with app-level ownership verification.
User-level isolation within org: Notifications filter by both orgId AND userId. AI conversations are org-scoped (team collaboration appropriate for SOC). Audit logs visible only to admins within their own org.
WebSocket scoping: Real-time broadcasts are filtered by organizationId so no org receives another's events.
Super admin bypass: isSuperAdmin=true unlocks cross-org access ONLY in the /api/admin/* router, which is gated by the requireSuperAdmin middleware. All other routes treat super admins as regular org members of their own org.
Agent auth isolation: Agents authenticate via device tokens that are org-scoped. Heartbeats and command polling are tied to the agent's registered org, not session cookies.
System Design Choices
The architecture is modular, separating server, client, and shared components. Authentication uses Passport-local with scrypt and optional TOTP. Data access is scoped by organizationId for multi-tenancy. Agent authentication is token-based. Performance and security enhancements include WebSocket broadcast scoping, AI conversation org-scoping, database indexing, N+1 query optimization, robust error handling, and sanitized API error responses.

External Dependencies
OpenAI: AI-powered threat analysis.
Stripe: Subscription management and billing.
PostgreSQL: Primary database.
Passport.js: Authentication middleware.
i18next + react-i18next: Internationalization.
Node.js net, dns, tls modules: Network and SSL/TLS scanning.
AbuseIPDB API: IP reputation lookup.
AlienVault OTX API: Threat intelligence.
URLScan.io API: URL analysis.
Google Safe Browsing API: URL safety checks.
MalwareBazaar API: Malware hash lookup.
Have I Been Pwned API: Credential exposure detection.
NIST NVD API: CVE database search.
HIBP Passwords API: Password breach checking.
