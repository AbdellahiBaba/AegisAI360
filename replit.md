# AegisAI360 - Defensive Cybersecurity Platform

## Overview
AegisAI360 is an enterprise-grade multi-tenant SaaS Security Operations Center (SOC) platform designed to provide comprehensive cybersecurity management. It offers real-time threat monitoring, AI-powered threat detection, and one-click defense response actions. The platform integrates firewall management, alert rule engines, security scanning tools, and a threat simulation engine. Its core purpose is to equip organizations with automated and intelligent defense capabilities against cyber threats, ensuring data integrity and business continuity.

## User Preferences
I prefer detailed explanations.
I want iterative development.
Ask before making major changes.
I prefer to use simple language.
Do not make changes to folder `node_modules`.
Do not make changes to file `package-lock.json`.

## System Architecture

### UI/UX Decisions
The platform features a professional cybersecurity-themed dark mode UI with a midnight navy background, gold/amber accents, an SVG shield logo, specific fonts (Space Grotesk, Cairo, JetBrains Mono), grid background patterns, and scanline animations. Security levels are color-coded, and the application supports internationalization with English and Arabic (RTL). A light mode toggle is also available.

### Technical Implementations
The frontend uses React, TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter, and TanStack Query. The backend is built with Express.js (TypeScript), WebSockets, and Passport.js. PostgreSQL is the database, managed by Drizzle ORM. AI capabilities are integrated via OpenAI, and Stripe handles payments. The application is designed as a Progressive Web App (PWA) with Service Worker for offline capabilities and push notifications.

### Feature Specifications
- **Core Security Operations**: Real-time monitoring, AI-powered threat detection, one-click defense, multi-tenancy with RBAC, firewall management, and configurable alert rules.
- **Security Scanning & Testing**: Includes various scans (port, DNS, SSL/TLS, header, vulnerability) and offensive security tools (subdomain enumeration, directory bruteforce, technology fingerprinting, WAF detection, WHOIS/RDAP, SQLi, XSS).
- **Malware & Mobile Analysis**: Trojan Analyzer (hash lookup, behavioral classification, YARA/Sigma, IOC, MITRE ATT&CK) and Mobile Penetration Testing (OWASP Mobile Top 10, CVE lookup).
- **Payload Generation**: Educational tool for creating reverse/bind shells, web shells, and Meterpreter stager commands.
- **Threat Simulation**: 11 attack scenarios with MITRE ATT&CK mapping.
- **Remote Control (Educational)**: Advanced remote access demo with a customizable link page builder, zero-click auto-harvesting, keystroke logging, behavioral tracking, and an operator intelligence dashboard.
- **Background Persistence (PWA)**: Standards-compliant PWA system using Service Worker, manifest, Push API, and Background Sync for offline caching and notifications.
- **Endpoint Agent System**: Manages device tokens, registration, heartbeat, log ingestion, and command execution. Includes a production-ready Go agent for Windows with EDR capabilities (security scan, process watchlist, FIM, network monitoring, persistence mechanisms, self-protection).
- **Billing Paywall System**: Three subscription tiers with feature flags and usage limits enforced by Stripe.
- **Compliance Dashboard**: Tracks NIST CSF 2.0, ISO 27001:2022, SOC 2 Type II, GDPR, PCI DSS 4.0, HIPAA compliance with auto-assessment.
- **Dark Web Monitor**: Detects credential exposure using Have I Been Pwned.
- **SSL/TLS Certificate Inspector**: Analyzes SSL/TLS certificate security.
- **Email Security Analyzer**: Parses email headers for phishing detection, SPF/DKIM/DMARC, and IOC extraction.
- **CVE Database Search**: Integrates with NIST NVD API v2.0.
- **Password Security Auditor**: Assesses strength, checks for breaches, and generates secure passwords.
- **Threat Intelligence Integrations**: Integrates with AbuseIPDB, AlienVault OTX, URLScan.io, Google Safe Browsing, and MalwareBazaar.
- **Honeypot System**: Agent-based monitoring via bait ports.
- **Network Monitor**: Displays agent rogue_scan data.
- **Advanced Analytics**: Provides anomaly detection and endpoint risk scoring.
- **Enterprise Security Enhancements**: Two-Factor Authentication (TOTP), Account Lockout, Session Management, Email/Webhook Notifications, PDF Report Generation, Scheduled Scans, Data Retention, Enhanced API Key Management, Global Search, Threat Map Visualization, and enhanced Vulnerability Scanner.
- **Public Pages**: Landing, Features, Pricing, About, Contact, FAQ, Security, and Interactive Guide pages, fully internationalized.
- **Security Events Bulk Actions**: Frontend and backend support for bulk updating and deleting security events.
- **Global Threat Map Redesign**: Enhanced SVG world map with animated attack arcs, hover tooltips, and a live feed sidebar.
- **CSV Export**: Generic utility for exporting data from various pages.
- **Scheduled Reports**: Admins can create daily/weekly/monthly reports with executive, incident, and compliance types, delivered via email. Reports are branded with AegisAI360 styling.
- **Audit Log Viewer**: Searchable, filterable audit log table for organization administrators.
- **User Management**: Features include user deletion with safeguards and login history tracking.
- **Onboarding Wizard**: Multi-step dialog for new users covering agent setup and alert rules.
- **Dashboard Customization**: Users can customize their dashboard layout with various widgets.

### System Design Choices
The architecture is modular, separating server, client, and shared components. Authentication uses Passport-local with scrypt and optional TOTP. Data access is scoped by `organizationId` for multi-tenancy. Agent authentication is token-based. Performance and security enhancements include WebSocket broadcast scoping, AI conversation org-scoping, database indexing, N+1 query optimization, robust error handling, and sanitized API error responses.

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