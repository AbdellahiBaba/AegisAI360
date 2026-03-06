# AegisAI - Security Operations Center Dashboard

## Overview
Browser-based SOC dashboard with AI-powered threat detection, real-time monitoring via WebSockets, incident management, threat intelligence tracking, and an AI analysis chat interface. Purely defensive — no offensive capabilities.

## Tech Stack
- **Frontend**: React + TypeScript, Vite, Tailwind CSS, shadcn/ui, Recharts, Wouter (routing), TanStack Query
- **Backend**: Express.js + TypeScript, WebSocket (ws)
- **Database**: PostgreSQL via Drizzle ORM
- **AI**: OpenAI via Replit AI Integrations (gpt-4o-mini)
- **Fonts**: Space Grotesk (sans), JetBrains Mono (mono)

## Architecture
```
shared/schema.ts          - Drizzle schema + Zod insert schemas + types
shared/models/chat.ts     - Conversations/messages tables
server/index.ts           - Express app bootstrap + seed
server/routes.ts          - All API routes + WebSocket + AI streaming
server/storage.ts         - DatabaseStorage implementing IStorage
server/seed.ts            - Initial seed data (runs once)
server/db.ts              - Drizzle + pg pool setup
server/replit_integrations/chat/storage.ts - Chat CRUD
client/src/App.tsx         - Layout with sidebar, theme toggle, routes
client/src/pages/          - 6 pages: dashboard, alerts, incidents, threat-intel, ai-analysis, policies
client/src/components/     - AppSidebar, ThemeProvider, shadcn components
```

## Database Tables
- `users` - Auth (varchar UUID PK)
- `security_events` - Security alerts (serial PK)
- `incidents` - Incident tracking with workflow statuses (serial PK)
- `threat_intel` - IOC indicators with active toggle (serial PK)
- `security_policies` - Policy definitions with tier/enable (serial PK)
- `conversations` - AI chat conversations (serial PK)
- `messages` - Chat messages with role (serial PK, FK to conversations)

## Key Features
- Real-time event generation every 20s via WebSocket broadcast
- Dashboard with stat cards, area chart (24h trend), pie chart (severity breakdown), live feed
- Security Events page with search, filter by severity/status, detail sheet, status management
- Incidents page with card grid, create dialog, status workflow progression
- Threat Intel page with IOC table, type icons, active toggle, add IOC dialog
- AI Analysis page with streaming chat, conversation management, security system prompt
- Policies page with tier badges, enable/disable switch, create dialog
- Dark/light mode with cyber theme (cyan primary, severity color system)

## Design Tokens
- Primary: cyan (185 85% 48%)
- Severity colors: critical (red), high (orange), medium (yellow), low (blue), info (slate)
- Status: online (green), away (amber), busy (red), offline (slate)

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection
- `SESSION_SECRET` - Session encryption
- `AI_INTEGRATIONS_OPENAI_API_KEY` - Auto-set by Replit integration
- `AI_INTEGRATIONS_OPENAI_BASE_URL` - Auto-set by Replit integration

## Commands
- `npm run dev` - Start dev server (Express + Vite)
- `npm run db:push` - Push schema to database
