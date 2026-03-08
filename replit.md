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
- **Endpoint Agent System**: Manages device token generation, agent registration, heartbeat monitoring, log ingestion, command execution (system scan, isolate network, remote terminal, honeypot_monitor), and remote terminal with command whitelisting/blacklisting. Includes a production-ready Go agent for Windows with extensive capabilities (packet capture, rogue scan, vuln scan, ARP monitor, bandwidth stats, honeypot monitoring).
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

### System Design Choices
The architecture is modular, organized into `server/`, `client/`, and `shared/` directories. Authentication uses Passport-local with scrypt hashing. All data access is scoped by `organizationId` for multi-tenancy. Agent authentication is token-based. The remote terminal ensures safety through command whitelisting and blacklisting.

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