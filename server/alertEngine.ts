import { storage } from "./storage";
import type { SecurityEvent, AlertRule, ResponsePlaybook } from "@shared/schema";
import { dispatchToChannels } from "./notificationService";
import OpenAI from "openai";
import { aiCacheKey, getCached, setCache } from "./aiCache";

const DESTRUCTIVE_ACTIONS = ["block_source", "auto_quarantine", "auto_sinkhole"];
const PLAYBOOK_DESTRUCTIVE_ACTIONS = ["isolate_host", "block_ip", "kill_process", "quarantine_file"];

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const MIN_TRIAGE_SEVERITY = "medium";

const AI_TRIAGE_RATE_LIMIT = 20;
const AI_TRIAGE_WINDOW_MS = 60 * 1000;
let aiTriageTimestamps: number[] = [];

function canMakeAiCall(): boolean {
  const now = Date.now();
  aiTriageTimestamps = aiTriageTimestamps.filter(t => now - t < AI_TRIAGE_WINDOW_MS);
  if (aiTriageTimestamps.length >= AI_TRIAGE_RATE_LIMIT) return false;
  aiTriageTimestamps.push(now);
  return true;
}

function shouldTriageEvent(event: SecurityEvent): boolean {
  const sevIndex = SEVERITY_ORDER.indexOf(event.severity);
  const minIndex = SEVERITY_ORDER.indexOf(MIN_TRIAGE_SEVERITY);
  return sevIndex >= minIndex;
}

const openai = new OpenAI({
  apiKey: process.env.AI_INTEGRATIONS_OPENAI_API_KEY,
  baseURL: process.env.AI_INTEGRATIONS_OPENAI_BASE_URL,
});

async function aiTriageEvent(event: SecurityEvent): Promise<{ aiThreatScore: number; aiClassification: string; aiRecommendation: string } | null> {
  if (!shouldTriageEvent(event)) return null;
  if (!canMakeAiCall()) return null;

  try {
    const prompt = `Triage: ${event.eventType}|${event.severity}|${event.source}|src:${event.sourceIp || "N/A"}|dst:${event.destinationIp || "N/A"}|port:${event.port || "N/A"}|${event.protocol || "N/A"}|${event.description}|${event.techniqueId || "N/A"}|${event.tactic || "N/A"}\nJSON: {"threatScore":<0-100>,"classification":"<credential_stuffing|reconnaissance|malware|exfiltration|lateral_movement|privilege_escalation|command_and_control|ransomware|phishing|insider_threat|policy_violation|brute_force|denial_of_service|web_attack|other>","recommendation":"<escalate|monitor|dismiss>","reasoning":"<1 sentence>"}`;

    const cKey = aiCacheKey("triage", event.eventType, event.severity, event.sourceIp || "", event.description.substring(0, 100));
    const cached = getCached(cKey);
    if (cached) {
      const match = cached.match(/\{[\s\S]*\}/);
      if (match) {
        const p = JSON.parse(match[0]);
        return {
          aiThreatScore: Math.max(0, Math.min(100, Math.round(Number(p.threatScore) || 0))),
          aiClassification: String(p.classification || "other"),
          aiRecommendation: `${["escalate","monitor","dismiss"].includes(p.recommendation) ? p.recommendation : "monitor"}${p.reasoning ? ` | ${p.reasoning}` : ""}`,
        };
      }
    }

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "SOC triage AI. JSON only." },
        { role: "user", content: prompt },
      ],
      temperature: 0.3,
      max_tokens: 200,
    });

    const content = response.choices[0]?.message?.content?.trim();
    if (content) setCache(cKey, content);
    if (!content) return null;

    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return null;

    const parsed = JSON.parse(jsonMatch[0]);
    const score = Math.max(0, Math.min(100, Math.round(Number(parsed.threatScore) || 0)));
    const classification = String(parsed.classification || "other");
    const recommendation = ["escalate", "monitor", "dismiss"].includes(parsed.recommendation)
      ? parsed.recommendation
      : "monitor";
    const reasoning = parsed.reasoning ? ` | ${parsed.reasoning}` : "";

    return {
      aiThreatScore: score,
      aiClassification: classification,
      aiRecommendation: `${recommendation}${reasoning}`,
    };
  } catch (err) {
    console.error("AI triage error:", err);
    return null;
  }
}

export class AlertEngine {
  private broadcast: (data: unknown) => void;

  constructor(broadcast: (data: unknown) => void) {
    this.broadcast = broadcast;
  }

  async evaluateEvent(event: SecurityEvent) {
    if (!event.organizationId) return;

    this.runAiTriage(event).catch(err => console.error("AI triage background error:", err));

    try {
      const rules = await storage.getAlertRules(event.organizationId);
      const activeRules = rules.filter(r => r.enabled);

      for (const rule of activeRules) {
        const matches = this.matchesConditions(event, rule);
        if (matches) {
          await this.executeActions(event, rule);
        }
      }
    } catch (err) {
      console.error("Alert engine evaluation error:", err);
    }

    this.runAutoPlaybooks(event).catch(err => console.error("Auto-playbook error:", err));
  }

  private async runAutoPlaybooks(event: SecurityEvent) {
    if (!event.organizationId) return;
    try {
      const playbooks = await storage.getResponsePlaybooks(event.organizationId);
      const autoPlaybooks = playbooks.filter(p => p.enabled && p.autoTriggerEnabled);

      for (const playbook of autoPlaybooks) {
        const sevIndex = SEVERITY_ORDER.indexOf(event.severity);
        const triggerIndex = SEVERITY_ORDER.indexOf(playbook.triggerSeverity || "critical");
        if (sevIndex < triggerIndex) continue;

        if (playbook.lastAutoRunAt) {
          const cooldownMs = (playbook.cooldownMinutes || 30) * 60 * 1000;
          if (Date.now() - new Date(playbook.lastAutoRunAt).getTime() < cooldownMs) continue;
        }

        const conditionsMatch = this.matchesPlaybookConditions(event, playbook);
        if (!conditionsMatch) continue;

        await this.executePlaybook(event, playbook);
      }
    } catch (err) {
      console.error("Auto-playbook evaluation error:", err);
    }
  }

  private matchesPlaybookConditions(event: SecurityEvent, playbook: ResponsePlaybook): boolean {
    if (!playbook.triggerConditions) return true;
    try {
      const conditions = JSON.parse(playbook.triggerConditions);
      if (!conditions || !Array.isArray(conditions)) return true;
      for (const cond of conditions) {
        const eventVal = this.getEventField(event, cond.field);
        if (cond.operator === "equals" && String(eventVal).toLowerCase() !== String(cond.value).toLowerCase()) return false;
        if (cond.operator === "contains" && !String(eventVal).toLowerCase().includes(String(cond.value).toLowerCase())) return false;
      }
      return true;
    } catch { return true; }
  }

  private async executePlaybook(event: SecurityEvent, playbook: ResponsePlaybook) {
    const orgId = event.organizationId!;
    try {
      const actions = playbook.actions ? JSON.parse(playbook.actions) : [];
      const hasDestructive = actions.some((a: any) => {
        const actionType = typeof a === "string" ? a : a.type;
        return PLAYBOOK_DESTRUCTIVE_ACTIONS.includes(actionType);
      });

      let aiConfidence = 100;
      if (hasDestructive) {
        try {
          const confPrompt = `Event:${event.eventType}|${event.severity}|${event.sourceIp || event.source}|${event.description.substring(0, 150)}\nPlaybook:${playbook.name}|Actions:${playbook.actions}\nExecute? {"confidence":<0-100>,"reasoning":"<brief>"}`;
          const confCacheKey = aiCacheKey("playbook-conf", event.eventType, event.severity, playbook.name);
          const confCached = getCached(confCacheKey);
          let confContent: string | undefined;
          if (confCached) {
            confContent = confCached;
          } else {
            const confResponse = await openai.chat.completions.create({
              model: "gpt-4o-mini",
              messages: [
                { role: "system", content: "SOC analyst. JSON only." },
                { role: "user", content: confPrompt },
              ],
              temperature: 0.2,
              max_tokens: 150,
            });
            confContent = confResponse.choices[0]?.message?.content?.trim();
            if (confContent) setCache(confCacheKey, confContent);
          }
          if (confContent) {
            const match = confContent.match(/\{[\s\S]*\}/);
            if (match) {
              const parsed = JSON.parse(match[0]);
              aiConfidence = Math.max(0, Math.min(100, Math.round(Number(parsed.confidence) || 0)));
            }
          }
        } catch (err) {
          console.error("AI confidence check failed, defaulting to low confidence:", err);
          aiConfidence = 50;
        }

        if (aiConfidence < 70) {
          await storage.createNotification({
            organizationId: orgId,
            userId: null,
            title: `Playbook Pending Review: ${playbook.name}`,
            message: `AI confidence ${aiConfidence}% is below threshold (70%) for auto-execution. Event: ${event.description.slice(0, 80)}`,
            type: "warning",
            actionUrl: "/playbooks",
          });
          this.broadcast({ type: "notification", orgId });
          try {
            await storage.createResponseAction({
              organizationId: orgId,
              actionType: "pending_review",
              target: `playbook:${playbook.id}`,
              status: "pending",
              executedBy: "system/auto",
              details: `AI confidence: ${aiConfidence}%. Blocked auto-execution for event: ${event.description.slice(0, 100)}`,
              result: null,
            });
          } catch {}
          return;
        }
      }

      await storage.updateResponsePlaybook(playbook.id, orgId, { lastAutoRunAt: new Date() });

      for (const rawAction of actions) {
        const actionType = typeof rawAction === "string" ? rawAction : rawAction.type;
        try {
          await storage.createResponseAction({
            organizationId: orgId,
            actionType: actionType || "unknown",
            target: `playbook:${playbook.id}`,
            status: "completed",
            executedBy: "system/auto",
            details: `Auto-triggered by event: ${event.eventType} - ${event.description.slice(0, 100)} (AI confidence: ${aiConfidence}%)`,
            result: `Executed action: ${actionType}`,
          });
        } catch {}
      }

      await storage.createNotification({
        organizationId: orgId,
        userId: null,
        title: `Playbook Auto-Executed: ${playbook.name}`,
        message: `${actions.length} action(s) executed for event: ${event.description.slice(0, 80)} (AI confidence: ${aiConfidence}%)`,
        type: "action",
        actionUrl: "/playbooks",
      });
      this.broadcast({ type: "playbook_executed", playbookName: playbook.name, orgId });
    } catch (err) {
      console.error("Playbook execution error:", err);
    }
  }

  private async runAiTriage(event: SecurityEvent) {
    try {
      const result = await aiTriageEvent(event);
      if (result) {
        await storage.updateSecurityEventAiTriage(event.id, result);
        this.broadcast({ type: "event_ai_triaged", eventId: event.id, ...result, orgId: event.organizationId });
      }
    } catch (err) {
      console.error("Failed to store AI triage result:", err);
    }
  }

  private matchesConditions(event: SecurityEvent, rule: AlertRule): boolean {
    try {
      const conditions = JSON.parse(rule.conditions);
      if (!conditions || !Array.isArray(conditions)) return false;

      for (const condition of conditions) {
        const { field, operator, value } = condition;
        const eventValue = this.getEventField(event, field);

        switch (operator) {
          case "equals":
            if (String(eventValue).toLowerCase() !== String(value).toLowerCase()) return false;
            break;
          case "contains":
            if (!String(eventValue).toLowerCase().includes(String(value).toLowerCase())) return false;
            break;
          case "in":
            if (!value.split(",").map((v: string) => v.trim().toLowerCase()).includes(String(eventValue).toLowerCase())) return false;
            break;
          case "severity_gte": {
            const severityOrder = ["info", "low", "medium", "high", "critical"];
            if (severityOrder.indexOf(String(eventValue)) < severityOrder.indexOf(String(value))) return false;
            break;
          }
          case "not_equals":
            if (String(eventValue).toLowerCase() === String(value).toLowerCase()) return false;
            break;
          default:
            return false;
        }
      }

      return true;
    } catch (err) {
      console.error("Error matching alert rule conditions:", err);
      return false;
    }
  }

  private getEventField(event: SecurityEvent, field: string): string {
    const fieldMap: Record<string, string | null | undefined> = {
      event_type: event.eventType,
      severity: event.severity,
      source: event.source,
      source_ip: event.sourceIp,
      destination_ip: event.destinationIp,
      protocol: event.protocol,
      description: event.description,
      technique_id: event.techniqueId,
      tactic: event.tactic,
    };
    return fieldMap[field] || "";
  }

  private async executeActions(event: SecurityEvent, rule: AlertRule) {
    try {
      const actions = JSON.parse(rule.actions);
      const orgId = event.organizationId!;

      await storage.incrementAlertRuleTrigger(rule.id);

      let defenseMode = "auto";
      try {
        const org = await storage.getOrganization(orgId);
        if (org && (org as any).defenseMode) {
          defenseMode = (org as any).defenseMode;
        }
      } catch (err) { console.error("Failed to fetch organization defense mode:", err); }

      for (const rawAction of actions) {
        const action = typeof rawAction === "string" ? rawAction : rawAction.type;
        if (!action) continue;

        const isDestructive = DESTRUCTIVE_ACTIONS.includes(action);

        if (isDestructive && defenseMode === "manual") {
          await storage.createNotification({
            organizationId: orgId,
            userId: null,
            title: `Manual Approval Required: ${action}`,
            message: `Rule "${rule.name}" wants to execute "${action}" for event: ${event.description.slice(0, 80)}. Defense mode is set to Manual - action requires manual execution.`,
            type: "warning",
            actionUrl: "/alert-rules",
          });
          this.broadcast({ type: "notification", orgId });
          continue;
        }

        if (isDestructive && defenseMode === "semi-auto") {
          await storage.createNotification({
            organizationId: orgId,
            userId: null,
            title: `Pending Approval: ${action}`,
            message: `Rule "${rule.name}" recommends "${action}" for event from ${event.source}: ${event.description.slice(0, 80)}. Semi-auto mode - review and approve.`,
            type: "warning",
            actionUrl: "/settings",
          });
          this.broadcast({ type: "notification", orgId });
          continue;
        }

        switch (action) {
          case "create_incident":
            await storage.createIncident({
              organizationId: orgId,
              title: `[Alert] ${rule.name}: ${event.description.slice(0, 100)}`,
              description: `Auto-created by alert rule "${rule.name}".\n\nEvent: ${event.description}\nSource: ${event.source}\nIP: ${event.sourceIp || 'N/A'}`,
              severity: rule.severity,
              status: "open",
            });
            break;

          case "notify":
            await storage.createNotification({
              organizationId: orgId,
              userId: null,
              title: `Alert: ${rule.name}`,
              message: `${event.description} (${event.severity})`,
              type: rule.severity === "critical" ? "critical" : "warning",
              actionUrl: "/alerts",
            });
            this.broadcast({ type: "notification", orgId });
            break;

          case "block_source":
            if (event.sourceIp) {
              try {
                await storage.createFirewallRule({
                  organizationId: orgId,
                  ruleType: "ip_block",
                  value: event.sourceIp,
                  action: "block",
                  reason: `Auto-blocked by alert rule: ${rule.name}`,
                  createdBy: null,
                  status: "active",
                });
              } catch (err) { console.error("Failed to create firewall rule for block_source:", err); }
            }
            break;

          case "auto_quarantine":
            if (event.eventType.toLowerCase().includes("malware") || event.eventType.toLowerCase().includes("ransomware")) {
              try {
                await storage.createQuarantineItem({
                  organizationId: orgId,
                  fileName: event.source + "_" + Date.now(),
                  fileHash: "auto_" + event.id,
                  threat: event.eventType || event.description.slice(0, 50),
                  sourceAsset: event.source,
                  action: "quarantined",
                  status: "quarantined",
                  quarantinedBy: null,
                });
              } catch (err) { console.error("Failed to create quarantine item:", err); }
            }
            break;

          case "auto_sinkhole":
            if (event.source && /^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/.test(event.source)) {
              try {
                await storage.createFirewallRule({
                  organizationId: orgId,
                  ruleType: "domain_block",
                  value: event.source,
                  action: "sinkhole",
                  reason: `Auto-sinkholed by alert rule: ${rule.name}`,
                  createdBy: null,
                  status: "active",
                });
              } catch (err) { console.error("Failed to create firewall rule for auto_sinkhole:", err); }
            }
            break;

          default:
            break;
        }
      }

      await storage.createNotification({
        organizationId: orgId,
        userId: null,
        title: `Rule Triggered: ${rule.name}`,
        message: `Alert rule matched event from ${event.source}: ${event.description.slice(0, 80)}`,
        type: "action",
        actionUrl: "/alert-rules",
      });

      this.broadcast({ type: "alert_triggered", rule: rule.name, orgId });

      dispatchToChannels({
        ruleName: rule.name,
        severity: rule.severity,
        eventDescription: event.description,
        eventSource: event.source,
        sourceIp: event.sourceIp || null,
        timestamp: new Date().toISOString(),
        organizationId: orgId,
      }).catch((err) => console.error("Notification dispatch error:", err));
    } catch (err) {
      console.error("Alert action execution error:", err);
    }
  }
}
