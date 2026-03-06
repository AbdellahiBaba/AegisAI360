import { storage } from "./storage";
import type { SecurityEvent, AlertRule } from "@shared/schema";

export class AlertEngine {
  private broadcast: (data: unknown) => void;

  constructor(broadcast: (data: unknown) => void) {
    this.broadcast = broadcast;
  }

  async evaluateEvent(event: SecurityEvent) {
    if (!event.organizationId) return;

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
    } catch {
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

      for (const action of actions) {
        switch (action.type) {
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
              } catch {}
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
              } catch {}
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
              } catch {}
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
    } catch (err) {
      console.error("Alert action execution error:", err);
    }
  }
}
