package com.security.incident.agents;

import com.security.incident.events.AgentEvent;
import com.security.incident.workflow.IncidentReport;
import com.security.incident.workflow.IncidentReport.IncidentStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

/**
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                       AGENT 3 – REMEDIATOR                             │
 * │                                                                         │
 * │  Responsibility: Take action on confirmed threats.                      │
 * │                                                                         │
 * │  Step 1 – Draft a firewall block rule (Cisco FTD ACL entry)             │
 * │  Step 2 – Call testRuleInSandbox() MCP tool to validate it              │
 * │  Step 3 – If sandbox passes, call blockEndpoint() to quarantine the IP  │
 * │  Step 4 – Present a human-readable remediation summary to the user      │
 * │                                                                         │
 * │  Safety gate: Never auto-approve if sandbox finds false positives.      │
 * │  Always sets approvedForProduction=false – a human must confirm.        │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
@Component
public class RemediatorAgent {

    private static final Logger log = LoggerFactory.getLogger(RemediatorAgent.class);

    private final ChatClient             chatClient;
    private final ApplicationEventPublisher events;

    private static final String SYSTEM_PROMPT = """
        You are the REMEDIATOR agent in an Automated Incident Response system.
        
        You have access to two Cisco MCP tools:
        - testRuleInSandbox(sourceIp, ruleName, action, protocol, portRange)
        - blockEndpoint(ipAddress, reason, blockAction)
        
        Your job for a CONFIRMED THREAT IP:
        
        STEP 1 – Design the block rule:
          - Rule name format: "BLOCK-{IP_UNDERSCORED}-{THREAT_CATEGORY}"
          - Action: FULL_BLOCK for CRITICAL threats, RATE_LIMIT for MEDIUM
          - Protocol: TCP for most threats, ANY for lateral movement
          - Port range: "1-65535" for brute force, specific ports for targeted attacks
          - Draft a concise rationale for the rule
        
        STEP 2 – Call testRuleInSandbox with your proposed rule parameters.
          Inspect the result carefully:
          - If recommendation = "APPROVE" and false_positives is empty → proceed to block
          - If recommendation = "REJECT" or false_positives is NOT empty → do NOT block, revise
          - If recommendation = "REVISE" → narrow the rule scope and document why
        
        STEP 3 – If sandbox approved, call blockEndpoint with QUARANTINE action.
        
        STEP 4 – Return your remediation in this EXACT JSON format:
        {
          "sandbox_approved": true | false,
          "rule_name": "<rule name>",
          "action_taken": "BLOCKED" | "QUARANTINED" | "RATE_LIMITED" | "DEFERRED",
          "rollback_id": "<rollback_id from blockEndpoint or null>",
          "sandbox_recommendation": "APPROVE" | "REJECT" | "REVISE",
          "false_positives_found": [],
          "remediation_summary": "<3-5 sentence human-readable summary for the SOC analyst>",
          "user_action_required": "<what the human needs to do next>"
        }
        
        IMPORTANT SAFETY RULES:
        - NEVER block if sandbox finds false_positives
        - NEVER skip the sandbox test
        - ALWAYS include rollback_id so the action can be reversed
        - If in doubt, set action_taken = "DEFERRED" and ask the analyst to review
        """;

    public RemediatorAgent(ChatClient.Builder builder,
                           ApplicationEventPublisher events) {
        this.chatClient = builder.build();
        this.events     = events;
    }

    /**
     * Core remediation loop.
     * Only called if AnalyzerAgent confirmed GENUINE_THREAT (not false positive).
     */
    public IncidentReport remediate(IncidentReport report) {
        // Guard: don't remediate false positives or escalated incidents
        if (report.isFalsePositive()) {
            log.info("[RemediatorAgent] Skipping – false positive detected by Analyzer");
            report.addAudit("RemediatorAgent", "SKIPPED", "False positive – no remediation needed");
            return report;
        }
        if (report.getStatus() == IncidentStatus.ESCALATED) {
            log.warn("[RemediatorAgent] Skipping – incident flagged for human escalation");
            report.addAudit("RemediatorAgent", "SKIPPED", "Escalated to SOC team");
            return report;
        }

        String ip = report.getPrimaryThreatIp();
        log.info("[RemediatorAgent] Starting remediation for IP {} – incident {}",
            ip, report.getIncidentId());
        events.publishEvent(new AgentEvent("RemediatorAgent", "STARTED",
            String.format("Designing block rule for %s, running sandbox validation...", ip)));

        try {
            String userPrompt = buildRemediationPrompt(report);

            String response = chatClient
                .prompt()
                .system(SYSTEM_PROMPT)
                .user(userPrompt)
                .call()
                .content();

            log.info("[RemediatorAgent] Remediation response:\n{}", response);
            parseAndEnrichReport(response, report);

            String logMsg = String.format(
                "Action: %s | Sandbox: %s | FP Found: %s | Rollback: %s",
                extractString(response, "action_taken"),
                extractString(response, "sandbox_recommendation"),
                extractString(response, "false_positives_found"),
                extractString(response, "rollback_id")
            );

            events.publishEvent(new AgentEvent("RemediatorAgent", "COMPLETED", logMsg));
            report.addAudit("RemediatorAgent", "REMEDIATION_COMPLETE", logMsg);

            // Require human approval before production push
            report.setApprovedForProduction(false);  // ALWAYS requires human sign-off
            report.setStatus(IncidentStatus.AWAITING_APPROVAL);

        } catch (Exception e) {
            log.error("[RemediatorAgent] Remediation failed: {}", e.getMessage(), e);
            events.publishEvent(new AgentEvent("RemediatorAgent", "ERROR", e.getMessage()));
            report.addAudit("RemediatorAgent", "ERROR", e.getMessage());
            report.setStatus(IncidentStatus.ESCALATED);
        }

        return report;
    }

    private String buildRemediationPrompt(IncidentReport report) {
        return String.format("""
            Remediate this CONFIRMED THREAT:
            
            IP Address: %s
            Threat Category: %s
            Analyzer Verdict: %s
            Threat Confidence: %.0f%%
            
            Incident Context:
            - Incident ID: %s
            - Other suspicious IPs in this incident: %s
            - Monitor summary: %s
            
            Follow the steps in your system prompt:
            1. Design the block rule
            2. Test in sandbox via testRuleInSandbox tool
            3. If sandbox approves, execute blockEndpoint
            4. Return the JSON remediation summary
            """,
            report.getPrimaryThreatIp(),
            report.getThreatCategory(),
            report.getAnalyzerVerdict(),
            report.getThreatConfidence() * 100,
            report.getIncidentId(),
            report.getSuspiciousIps(),
            report.getMonitorSummary()
        );
    }

    private void parseAndEnrichReport(String json, IncidentReport report) {
        String cleaned = json.trim().replaceAll("```json", "").replaceAll("```", "").trim();

        boolean sandboxOk  = extractBoolean(cleaned, "sandbox_approved");
        String actionTaken = extractString(cleaned, "action_taken");
        String rollbackId  = extractString(cleaned, "rollback_id");
        String summary     = extractString(cleaned, "remediation_summary");
        String userAction  = extractString(cleaned, "user_action_required");
        String sbxRec      = extractString(cleaned, "sandbox_recommendation");

        report.setRollbackId(rollbackId.isEmpty() ? null : rollbackId);
        report.setRemediationSummary(
            String.format("ACTION: %s | SANDBOX: %s\n\n%s\n\n⚠️  NEXT STEP (Human Required): %s",
                actionTaken, sbxRec, summary, userAction)
        );
        report.setApprovedForProduction(false);  // Always false – human must confirm
    }

    // ── JSON helpers ──────────────────────────────────────────────────────

    private String extractString(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return "";
        int colon = json.indexOf(':', idx);
        if (colon == -1) return "";
        String after = json.substring(colon + 1).trim();
        if (after.startsWith("\"")) {
            int end = after.indexOf('"', 1);
            return end == -1 ? "" : after.substring(1, end);
        }
        // Handle array or null
        int end = after.indexOf('\n');
        return end == -1 ? after.trim() : after.substring(0, end).trim();
    }

    private boolean extractBoolean(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return false;
        int colon = json.indexOf(':', idx);
        return json.substring(colon + 1).trim().startsWith("true");
    }
}
