import { storage } from "./storage";

export class ResponseEngine {
  private broadcast: (data: unknown) => void;

  constructor(broadcast: (data: unknown) => void) {
    this.broadcast = broadcast;
  }

  async blockIP(orgId: number, ip: string, reason: string, userId: string): Promise<{ ruleId: number; mitigatedCount: number }> {
    const rule = await storage.createFirewallRule({
      organizationId: orgId,
      ruleType: "ip_block",
      value: ip,
      action: "block",
      reason,
      createdBy: userId,
      status: "active",
    });

    const mitigatedCount = await storage.mitigateEventsByIp(orgId, ip);

    const action = await storage.createResponseAction({
      organizationId: orgId,
      actionType: "block_ip",
      target: ip,
      status: "completed",
      executedBy: userId,
      details: JSON.stringify({ reason, mitigatedCount }),
      result: `Blocked IP ${ip}. ${mitigatedCount} events mitigated.`,
    });
    await storage.updateResponseAction(action.id, { completedAt: new Date() });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "block_ip",
      targetType: "firewall_rule",
      targetId: String(rule.id),
      details: `Blocked IP: ${ip} - ${reason}`,
    });

    await storage.createNotification({
      organizationId: orgId,
      userId: null,
      title: "IP Blocked",
      message: `IP ${ip} has been blocked. ${mitigatedCount} events mitigated.`,
      type: "action",
    });

    this.broadcast({ type: "response_action", action: { type: "block_ip", target: ip }, orgId });
    return { ruleId: rule.id, mitigatedCount };
  }

  async isolateAsset(orgId: number, assetId: number, userId: string): Promise<{ asset: any; incidentId?: number }> {
    const asset = await storage.updateAsset(assetId, orgId, { status: "isolated" } as any);
    if (!asset) throw new Error("Asset not found");

    const incident = await storage.createIncident({
      organizationId: orgId,
      title: `Asset Isolated: ${asset.name}`,
      description: `Asset ${asset.name} (${asset.ipAddress}) has been isolated due to security concerns.`,
      severity: "high",
      status: "investigating",
      assignee: null,
    });

    if (asset.ipAddress) {
      await this.blockIP(orgId, asset.ipAddress, `Auto-block: asset ${asset.name} isolated`, userId);
    }

    const action = await storage.createResponseAction({
      organizationId: orgId,
      actionType: "isolate_asset",
      target: asset.name,
      status: "completed",
      executedBy: userId,
      details: JSON.stringify({ assetId, ip: asset.ipAddress }),
      result: `Asset ${asset.name} isolated. Incident #${incident.id} created.`,
    });
    await storage.updateResponseAction(action.id, { completedAt: new Date() });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "isolate_asset",
      targetType: "asset",
      targetId: String(assetId),
      details: `Isolated asset: ${asset.name}`,
    });

    await storage.createNotification({
      organizationId: orgId,
      userId: null,
      title: "Asset Isolated",
      message: `${asset.name} has been network-isolated. Incident #${incident.id} created.`,
      type: "critical",
      actionUrl: `/incidents`,
    });

    this.broadcast({ type: "response_action", action: { type: "isolate_asset", target: asset.name }, orgId });
    return { asset, incidentId: incident.id };
  }

  async quarantineFile(orgId: number, fileName: string, fileHash: string, threat: string, sourceAsset: string, userId: string) {
    const item = await storage.createQuarantineItem({
      organizationId: orgId,
      fileName,
      fileHash,
      threat,
      sourceAsset,
      action: "quarantined",
      status: "quarantined",
      quarantinedBy: userId,
    });

    await storage.createResponseAction({
      organizationId: orgId,
      actionType: "quarantine_file",
      target: fileName,
      status: "completed",
      executedBy: userId,
      details: JSON.stringify({ fileHash, threat, sourceAsset }),
      result: `File ${fileName} quarantined.`,
    });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "quarantine_file",
      targetType: "quarantine",
      targetId: String(item.id),
      details: `Quarantined: ${fileName} (${threat})`,
    });

    this.broadcast({ type: "response_action", action: { type: "quarantine_file", target: fileName }, orgId });
    return item;
  }

  async sinkholeDomain(orgId: number, domain: string, userId: string) {
    const rule = await storage.createFirewallRule({
      organizationId: orgId,
      ruleType: "domain_block",
      value: domain,
      action: "sinkhole",
      reason: `Domain sinkholed by operator`,
      createdBy: userId,
      status: "active",
    });

    await storage.createThreatIntel({
      organizationId: orgId,
      indicatorType: "domain",
      value: domain,
      threatType: "malware",
      severity: "high",
      source: "AegisAI360 Response",
      description: `Domain sinkholed via response action`,
      active: true,
    });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "sinkhole_domain",
      targetType: "firewall_rule",
      targetId: String(rule.id),
      details: `Sinkholed domain: ${domain}`,
    });

    this.broadcast({ type: "response_action", action: { type: "sinkhole_domain", target: domain }, orgId });
    return rule;
  }

  async createIncidentFromEvent(orgId: number, eventId: number, userId: string) {
    const events = await storage.getSecurityEvents(orgId);
    const event = events.find(e => e.id === eventId);
    if (!event) throw new Error("Event not found");

    const incident = await storage.createIncident({
      organizationId: orgId,
      title: `[Auto] ${event.description}`,
      description: `Incident created from security event #${eventId}.\n\nSource: ${event.source}\nIP: ${event.sourceIp || 'N/A'}\nTechnique: ${event.techniqueId || 'N/A'}`,
      severity: event.severity,
      status: "open",
    });

    await storage.updateSecurityEventStatus(eventId, orgId, "investigating");

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "create_incident_from_event",
      targetType: "incident",
      targetId: String(incident.id),
      details: `Created from event #${eventId}`,
    });

    return incident;
  }

  async executePlaybook(orgId: number, playbookId: number, context: Record<string, any>, userId: string) {
    const playbooks = await storage.getResponsePlaybooks(orgId);
    const playbook = playbooks.find(p => p.id === playbookId);
    if (!playbook) throw new Error("Playbook not found");

    const action = await storage.createResponseAction({
      organizationId: orgId,
      actionType: "execute_playbook",
      target: playbook.name,
      status: "executing",
      executedBy: userId,
      details: JSON.stringify({ playbookId, context }),
    });

    const actions = playbook.actions?.split(",").map(a => a.trim()) || [];
    const results: string[] = [];

    for (const step of actions) {
      try {
        if (step === "block_ip" && context.ip) {
          await this.blockIP(orgId, context.ip, `Playbook: ${playbook.name}`, userId);
          results.push(`Blocked IP: ${context.ip}`);
        } else if (step === "isolate_host" && context.assetId) {
          await this.isolateAsset(orgId, context.assetId, userId);
          results.push(`Isolated asset: ${context.assetId}`);
        } else if (step === "quarantine_file" && context.fileName) {
          await this.quarantineFile(orgId, context.fileName, context.fileHash || "", context.threat || "Unknown", context.sourceAsset || "", userId);
          results.push(`Quarantined: ${context.fileName}`);
        } else if (step === "create_incident") {
          const inc = await storage.createIncident({
            organizationId: orgId,
            title: `[Playbook] ${playbook.name}`,
            description: `Auto-incident from playbook execution.`,
            severity: "high",
            status: "open",
          });
          results.push(`Created incident #${inc.id}`);
        } else {
          results.push(`Step "${step}" completed`);
        }
      } catch (err: any) {
        results.push(`Step "${step}" failed: ${err.message}`);
      }
    }

    await storage.updateResponseAction(action.id, {
      status: "completed",
      result: results.join("; "),
      completedAt: new Date(),
    });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "execute_playbook",
      targetType: "playbook",
      targetId: String(playbookId),
      details: results.join("; "),
    });

    await storage.createNotification({
      organizationId: orgId,
      userId: null,
      title: "Playbook Executed",
      message: `${playbook.name}: ${results.length} steps completed.`,
      type: "action",
    });

    this.broadcast({ type: "response_action", action: { type: "execute_playbook", target: playbook.name }, orgId });
    return { results };
  }

  async autoThreatResponse(orgId: number, event: { id: number; eventType: string; severity: string; source: string; sourceIp: string | null; description: string }) {
    const actionsTaken: string[] = [];
    const eventTypeLower = event.eventType.toLowerCase();

    if (event.severity === "critical" && (eventTypeLower.includes("malware") || eventTypeLower.includes("ransomware") || eventTypeLower.includes("c2"))) {
      if (event.sourceIp) {
        try {
          await storage.createFirewallRule({
            organizationId: orgId,
            ruleType: "ip_block",
            value: event.sourceIp,
            action: "block",
            reason: `Auto-defend: ${event.eventType} from ${event.source}`,
            createdBy: null,
            status: "active",
          });
          await storage.mitigateEventsByIp(orgId, event.sourceIp);
          actionsTaken.push(`Blocked IP ${event.sourceIp}`);
        } catch {}
      }

      const incident = await storage.createIncident({
        organizationId: orgId,
        title: `[Auto-Defend] ${event.eventType}: ${event.description.slice(0, 80)}`,
        description: `Automated threat response triggered for event #${event.id}.\n\nSource: ${event.source}\nIP: ${event.sourceIp || "N/A"}\nType: ${event.eventType}`,
        severity: "critical",
        status: "investigating",
      });
      actionsTaken.push(`Created incident #${incident.id}`);

      await storage.createNotification({
        organizationId: orgId,
        userId: null,
        title: "Auto-Defend Activated",
        message: `Automated response to ${event.eventType} from ${event.source}. ${actionsTaken.length} actions taken.`,
        type: "critical",
        actionUrl: "/incidents",
      });
      actionsTaken.push("Notification sent");

      await storage.createResponseAction({
        organizationId: orgId,
        actionType: "auto_threat_response",
        target: event.source,
        status: "completed",
        executedBy: null,
        details: JSON.stringify({ eventId: event.id, eventType: event.eventType, sourceIp: event.sourceIp }),
        result: actionsTaken.join("; "),
      });

      this.broadcast({ type: "auto_defend", orgId, actions: actionsTaken });
    }

    return { actionsTaken };
  }

  async emergencyLockdown(orgId: number, userId: string) {
    const events = await storage.getSecurityEvents(orgId);
    const assets = await storage.getAssets(orgId);

    const criticalIps = new Set<string>();
    for (const event of events) {
      if ((event.severity === "critical" || event.severity === "high") && event.sourceIp && event.status === "new") {
        criticalIps.add(event.sourceIp);
      }
    }

    let blocked = 0;
    for (const ip of criticalIps) {
      try {
        await this.blockIP(orgId, ip, "Emergency lockdown", userId);
        blocked++;
      } catch {}
    }

    let isolated = 0;
    for (const asset of assets) {
      if (asset.riskScore >= 70 && asset.status !== "isolated") {
        try {
          await storage.updateAsset(asset.id, orgId, { status: "isolated" } as any);
          isolated++;
        } catch {}
      }
    }

    const incident = await storage.createIncident({
      organizationId: orgId,
      title: "[EMERGENCY] System Lockdown Initiated",
      description: `Emergency lockdown: ${blocked} IPs blocked, ${isolated} high-risk assets isolated.`,
      severity: "critical",
      status: "investigating",
    });

    await storage.createAuditLog({
      organizationId: orgId,
      userId,
      action: "emergency_lockdown",
      targetType: "system",
      targetId: "lockdown",
      details: `Blocked ${blocked} IPs, isolated ${isolated} assets`,
    });

    await storage.createNotification({
      organizationId: orgId,
      userId: null,
      title: "EMERGENCY LOCKDOWN",
      message: `Lockdown active: ${blocked} IPs blocked, ${isolated} assets isolated.`,
      type: "critical",
    });

    this.broadcast({ type: "emergency_lockdown", orgId });
    return { blocked, isolated, incidentId: incident.id };
  }
}
