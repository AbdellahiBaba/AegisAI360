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
The platform features a professional cybersecurity-themed dark mode user interface with a deep midnight navy background and gold/amber accents. It utilizes an SVG shield logo, Space Grotesk, Cairo (for RTL), and JetBrains Mono fonts, grid background patterns, and scanline animations. Security levels and severity are indicated via CSS classes and color-coding. The application supports internationalization with English and Arabic (RTL) languages.

### Technical Implementations
The frontend is built with React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter, and TanStack Query. The backend uses Express.js with TypeScript, WebSockets for live feeds, and Passport.js for authentication. PostgreSQL is the database, managed via Drizzle ORM. AI capabilities are integrated using OpenAI (gpt-4o-mini), and payment processing is handled by Stripe.

### Feature Specifications
- **Core Security Operations**: Real-time monitoring, AI-powered threat detection, one-click defense response, multi-tenancy with RBAC, firewall management, and a configurable alert rules engine.
- **Security Scanning & Testing**: Includes port, DNS, SSL/TLS, header, and vulnerability scanning. Advanced offensive security tools cover subdomain enumeration, directory bruteforce, technology fingerprinting, WAF detection, WHOIS/RDAP lookup, SQL injection, and XSS testing.
- **Malware & Mobile Analysis**: Trojan Analyzer for malware analysis (hash lookup, behavioral classification, YARA/Sigma rule generation, IOC extraction) and Mobile Penetration Testing (Android permission risk analysis, API endpoint security testing, OWASP Mobile Top 10 checks, device CVE lookup).
- **Payload Generation**: Educational tool to generate reverse/bind shells, web shells, and Meterpreter stager commands in various languages, with encoding options.
- **Threat Simulation**: Offers 6 attack scenarios (SSH Brute Force, Ransomware, Phishing, Port Scan Sweep, Data Exfiltration, APT Kill Chain) to test defenses.
- **Endpoint Agent System**: Manages device token generation, agent registration, heartbeat monitoring, log ingestion, command execution (system scan, isolate network, remote terminal, honeypot_monitor, file_scan, enable/disable_monitoring), and remote terminal with command whitelisting/blacklisting. Includes a production-ready Go agent for Windows with extensive capabilities (packet capture, rogue scan, vuln scan, ARP monitor, bandwidth stats, honeypot monitoring). Agent runs as a Windows Service with auto-restart on failure, delayed auto-start, and persistent background monitoring (process watchlist, file integrity, network connection monitoring). Reports run mode (service/tray/terminal) in telemetry. Agent reports security events and file scan results directly via POST `/api/agent/security-events` and `/api/agent/file-scan`.
- **Billing Paywall System**: Three subscription tiers (starter, professional, enterprise) with feature flags and usage limits, enforced via Stripe integration. Includes usage tracking and redirects new users to plan selection.
- **Compliance Dashboard**: Tracks compliance with NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II, GDPR, PCI DSS 4.0, HIPAA, offering auto-assessment and gap analysis.
- **Dark Web Monitor**: Detects credential exposure via Have I Been Pwned public API (no key needed for domain lookups), with optional HIBP_API_KEY for per-email breach lookups ($3.50/mo). Uses 10-min cached breach list. No mock/simulated data.
- **SSL/TLS Certificate Inspector**: Analyzes SSL/TLS certificate security for domains, including grading, protocol detection, and vulnerability checks.
- **Email Security Analyzer**: Parses email headers for phishing detection, SPF/DKIM/DMARC authentication, and IOC extraction.
- **CVE Database Search**: Integrates with NIST NVD API v2.0 with rate limiting (1 req/6s without key), exponential backoff retry (3 attempts), 5-min result cache, and optional NVD_API_KEY for higher rate limits. No mock/fallback data.
- **Password Security Auditor**: Assesses password strength, checks for breaches (HIBP), audits password policies, and generates secure passwords.
- **Threat Intelligence Integrations**: Integrates with AbuseIPDB, AlienVault OTX, URLScan.io, Google Safe Browsing, and MalwareBazaar. MalwareBazaar works without API key. Others show "API Key Required" with setup URLs when keys aren't configured (no fake demo data). API status endpoint at GET /api/threat-intel/api-status.
- **Honeypot System**: Agent-based honeypot monitoring via `honeypot_monitor` command. Agent opens TCP listeners on bait ports (23, 445, 1433, 3389, 5900, 8080), captures connection attempts, and reports events to POST /api/agent/honeypot-events.
- **Network Monitor**: Uses real agent rogue_scan data when agents are online. Falls back to demo data (clearly marked) when no agents available. Agent scan results auto-populate network_devices via MAC-based upsert.
- **Advanced Analytics**: Provides anomaly detection and endpoint risk scoring.

### Enterprise Security Enhancements
- **Two-Factor Authentication (TOTP)**: RFC 6238 TOTP via `otplib` + `qrcode`. Setup/enable/disable in Settings. Login flow returns `requiresTwoFactor` challenge when enabled. Uses `otplib` `generateSecret`/`verifySync`/`generateURI` API.
- **Account Lockout**: 5 failed login attempts triggers 15-minute lockout. Counter resets on success. Lockout events logged as security events.
- **Session Management**: `sessions_metadata` table tracks IP, user-agent, last active. Users can view and revoke active sessions from Settings. "Revoke All Other Sessions" for emergency use.
- **Email/Webhook Notifications**: `notification_channels` table. Webhook (with HMAC signing, SSRF protection) and Email (SMTP via nodemailer). Integrated into AlertEngine for auto-dispatch. Test button in Settings.
- **PDF Report Generation**: Client-side via `jspdf` + `jspdf-autotable`. Executive Summary (dashboard), Compliance Assessment, and Incident Report. Per-tool-page PDF export on Scanner, SSL Inspector, Dark Web Monitor, CVE Database, Network Monitor, Email Analyzer, Trojan Analyzer, Password Auditor, and Mobile Pentest pages. Professional formatting with branding.
- **Scheduled Scans**: `scheduled_scans` table with daily/weekly/monthly frequency. Background scheduler checks every 60s. Supports network_scan, vulnerability_scan, dark_web_check, ssl_check. Dedicated page at `/scheduled-scans`.
- **Data Retention**: Configurable per-org retention days for security events and audit logs. Daily cleanup job removes old data. Manual "Run Cleanup Now" in Settings.
- **API Key Management**: Enhanced with description, expiration, soft-revocation, rotation (24h grace period), last-used tracking. Full CRUD UI in Settings.
- **Global Search / Command Palette**: Ctrl+K/Cmd+K opens search across security events, incidents, network devices, CVEs, and navigation pages. Uses shadcn CommandDialog.
- **Threat Map Visualization**: SVG world map on dashboard showing attack origins with Mercator projection. Uses ipwho.is (HTTPS) for geolocation with in-memory cache. Color-coded severity dots with animated pulses.
- **Threat Intel API Key Management**: `threat_intel_keys` table stores per-org API keys for AbuseIPDB, OTX, URLScan.io, Google Safe Browsing. Admin UI on Threat Intel page to add/update/remove keys. DB keys take priority over env vars. CRUD via POST/DELETE `/api/threat-intel/api-keys`.
- **Enhanced Agent System Info**: Agent telemetry stored in `agents.telemetry` JSONB column. Endpoints page shows tabbed detail view (System Info / Commands / Bandwidth) with CPU/RAM/disk progress bars, network info, top processes table, and system metadata.
- **Dashboard Organization**: Sections with headings (Overview, Analytics, Activity, Response), collapsible Quick Actions, prominent full-width Threat Map, improved stat card grid layout.
- **Auto-Protect Agent Integration**: "Protect Me" activation (POST `/api/protection/activate`) auto-pushes `security_scan`, `honeypot_monitor`, and `enable_monitoring` commands to all online agents. `autoThreatResponse` in ResponseEngine dispatches `security_scan` and `network_firewall_add` to agents on critical malware/C2 events. Protection Center UI shows agent monitoring status, deployment history, and "Deploy to All Agents" button. Agent monitoring contributes to protection score.
- **Agent Background Monitoring**: `installer/monitor.go` implements 4 continuous goroutines: periodic security scan (10min), process watchlist (2min, 24+ malicious process names), file integrity monitoring (critical dirs, SHA-256 tracking), and network connection monitoring (3min, suspicious ports). Controlled via `enable_monitoring`/`disable_monitoring` commands.
- **File Scanning**: `file_scan` agent command scans common malware drop locations (Downloads, Temp, AppData, startup folders), hashes executables (SHA-256), detects recently modified files and suspicious filenames. Results displayed in File Scans tab on Endpoints page.

### System Design Choices
The architecture is modular, organized into `server/`, `client/`, and `shared/` directories. Authentication uses Passport-local with scrypt hashing and optional TOTP 2FA. All data access is scoped by `organizationId` for multi-tenancy. Agent authentication is token-based. The remote terminal ensures safety through command whitelisting and blacklisting.

## External Dependencies
- **OpenAI**: Integrated for AI-powered threat analysis.
- **Stripe**: Used for subscription management and billing.
- **PostgreSQL**: Primary database.
- **Passport.js**: Authentication middleware.
- **i18next + react-i18next**: For internationalization.
- **Node.js `net`, `dns`, `tls` modules**: For network and SSL/TLS scanning.
- **AbuseIPDB API**: For IP reputation lookup.
- **AlienVault OTX API**: For threat intelligence.
- **URLScan.io API**: For URL analysis.
- **Google Safe Browsing API**: For URL safety checks.
- **MalwareBazaar API**: For malware hash lookup.
- **Have I Been Pwned API**: For credential exposure detection.
- **NIST NVD API**: For CVE database search.
- **HIBP Passwords API**: For password breach checking.