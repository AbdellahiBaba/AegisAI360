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
- **Threat Simulation Engine**: Offers 6 attack scenarios (SSH Brute Force, Ransomware, Phishing, Port Scan Sweep, Data Exfiltration, APT Kill Chain) to test defenses.
- **Automation Defense Modes**: Three modes (Full Auto, Semi-Auto, Manual) control the level of automated response.
- **Network/Infrastructure Monitor**: Real infrastructure scanning (port scan, SSL check, header audit, vulnerability path scan) for user-provided servers/domains/IPs, with device management and real-time monitoring.
- **Protection Center**: One-click "Protect Me" page with protection score, checklist, and auto-activation of all defenses.
- **Smart Remediation**: Scan results include one-click fix buttons that create real firewall rules and alert rules.
- **Data Ingestion**: APIs for Syslog, SIEM, and generic event ingestion.
- **Super Admin System**: Provides platform-level management, organization oversight, and system health monitoring.

### System Design Choices
- **Modular Architecture**: Codebase is organized into `server/`, `client/`, and `shared/` directories.
- **Database Schema**: Comprehensive schema with over 20 tables covering organizations, users, security events, incidents, threat intelligence, assets, policies, audit logs, and more.
- **Authentication**: Passport-local with scrypt hashing and session management.
- **Organization Scoping**: All data access is scoped by `organizationId` to ensure multi-tenancy.
- **API Endpoints**: Structured API for various functionalities including authentication, data ingestion, scanning, simulation, billing, and system management.

## External Dependencies
- **OpenAI**: Integrated for AI-powered threat analysis (gpt-4o-mini).
- **Stripe**: Used for subscription management and billing via the `stripe-replit-sync` connector.
- **PostgreSQL**: Primary database for all application data, accessed via Drizzle ORM.
- **Passport.js**: Authentication middleware.
- **i18next + react-i18next**: For internationalization and localization.
- **Node.js `net` and `dns` modules**: Used for network scanning functionalities (Port Scanner, DNS Lookup).
- **Node.js `tls` module**: Used for SSL/TLS certificate checking.