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
 * │                        AGENT 2 – ANALYZER                              │
 * │                                                                         │
 * │  Responsibility: Deep-analyze the primary threat IP identified by       │
 * │  the Monitor. Determines whether this is a genuine threat or a         │
 * │  false positive using:                                                  │
 * │    – getEndpointStatus() MCP tool (ISE posture, threat score)           │
 * │    – LLM reasoning over the combined evidence                           │
 * │    – Confidence scoring (0.0 – 1.0)                                     │
 * │                                                                         │
 * │  Output: Verdict (GENUINE_THREAT | FALSE_POSITIVE | NEEDS_ESCALATION)   │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
@Component
public class AnalyzerAgent {

    private static final Logger log = LoggerFactory.getLogger(AnalyzerAgent.class);

    private final ChatClient             chatClient;
    private final ApplicationEventPublisher events;

    private static final String SYSTEM_PROMPT = """
        You are the ANALYZER agent in an Automated Incident Response system.
        
        You have access to the Cisco ISE MCP tool: getEndpointStatus.
        
        Your job:
        1. Call getEndpointStatus(ipAddress) for the IP under investigation.
        2. Analyze ALL available evidence:
           - Endpoint profile (is it a known managed asset?)
           - Posture status (compliant? non-compliant?)
           - Quarantine state (already blocked? flagged?)
           - Threat score (0=safe, 100=certain threat)
           - Compliance tags
           - Whether the IP is in the threat intelligence feed
           - The monitor's summary (provided in the user message)
        3. Apply these false-positive heuristics:
           - If endpoint_profile is a known-good profile AND threat_score < 30 → likely false positive
           - If IP is in compliance_tags["patch-compliant", "av-active"] → lower likelihood of threat
           - If quarantine_state is already BLOCKED → duplicate action, skip
           - If IP is in threat intel feed AND threat_score > 70 → high confidence threat
           - If auth failures > 50 from an external IP → almost certainly brute force
        4. Respond in this EXACT JSON format:
        {
          "verdict": "GENUINE_THREAT" | "FALSE_POSITIVE" | "NEEDS_ESCALATION",
          "false_positive": true | false,
          "threat_confidence": <0.0 to 1.0>,
          "threat_category": "<category e.g. Brute Force, Lateral Movement, C2 Communication>",
          "reasoning": "<detailed multi-sentence LLM analysis of why this verdict was reached>",
          "recommended_action": "<specific next step for the Remediator>",
          "endpoint_summary": "<one-line summary of the endpoint's profile>"
        }
        
        Be thorough. A false-positive block could disrupt legitimate business operations.
        A missed genuine threat could lead to a breach.
        """;

    public AnalyzerAgent(ChatClient.Builder builder,
                         ApplicationEventPublisher events) {
        this.chatClient = builder.build();
        this.events     = events;
    }

    /**
     * Analyze the primary threat IP from the Monitor's findings.
     * Enriches the report with verdict, confidence, and false-positive determination.
     */
    public IncidentReport analyze(IncidentReport report) {
        String ip = report.getPrimaryThreatIp();

        if (ip == null || ip.isBlank()) {
            log.info("[AnalyzerAgent] No primary threat IP to analyze – skipping");
            report.addAudit("AnalyzerAgent", "SKIPPED", "No suspicious IPs found by Monitor");
            return report;
        }

        log.info("[AnalyzerAgent] Analyzing IP {} for incident {}", ip, report.getIncidentId());
        report.setStatus(IncidentStatus.ANALYZING);
        events.publishEvent(new AgentEvent("AnalyzerAgent", "STARTED",
            String.format("Analyzing IP %s – pulling ISE endpoint data and running LLM analysis...", ip)));

        try {
            String userPrompt = String.format("""
                Analyze this IP for threats: %s
                
                Monitor's findings:
                - Total logs scanned: %d
                - Suspicious events found: %d
                - All suspicious IPs in this incident: %s
                - Monitor summary: %s
                
                Please call getEndpointStatus for this IP and provide your verdict.
                """,
                ip,
                report.getTotalLogsScanned(),
                report.getSuspiciousEventsFound(),
                report.getSuspiciousIps(),
                report.getMonitorSummary()
            );

            String response = chatClient
                .prompt()
                .system(SYSTEM_PROMPT)
                .user(userPrompt)
                .call()
                .content();

            log.info("[AnalyzerAgent] LLM verdict:\n{}", response);
            parseAndEnrichReport(response, report);

            String logMsg = String.format(
                "Verdict: %s | Confidence: %.0f%% | Category: %s | FalsePositive: %s",
                report.getAnalyzerVerdict(),
                report.getThreatConfidence() * 100,
                report.getThreatCategory(),
                report.isFalsePositive()
            );
            events.publishEvent(new AgentEvent("AnalyzerAgent", "COMPLETED", logMsg));
            report.addAudit("AnalyzerAgent", "ANALYSIS_COMPLETE", logMsg);

            if (report.isFalsePositive()) {
                report.setStatus(IncidentStatus.FALSE_POSITIVE);
            }

        } catch (Exception e) {
            log.error("[AnalyzerAgent] Analysis failed: {}", e.getMessage(), e);
            events.publishEvent(new AgentEvent("AnalyzerAgent", "ERROR", e.getMessage()));
            report.addAudit("AnalyzerAgent", "ERROR", e.getMessage());
            // Default to escalation on error – safer than auto-blocking
            report.setAnalyzerVerdict("NEEDS_ESCALATION");
            report.setThreatConfidence(0.5);
            report.setStatus(IncidentStatus.ESCALATED);
        }

        return report;
    }

    private void parseAndEnrichReport(String json, IncidentReport report) {
        String cleaned = json.trim().replaceAll("```json", "").replaceAll("```", "").trim();

        String verdict     = extractString(cleaned, "verdict");
        boolean fp         = extractBoolean(cleaned, "false_positive");
        double confidence  = extractDouble(cleaned, "threat_confidence", 0.5);
        String category    = extractString(cleaned, "threat_category");
        String reasoning   = extractString(cleaned, "reasoning");

        report.setAnalyzerVerdict(verdict.isEmpty() ? "NEEDS_ESCALATION" : verdict);
        report.setFalsePositive(fp);
        report.setThreatConfidence(confidence);
        report.setThreatCategory(category.isEmpty() ? "Unknown" : category);

        // Build a rich multi-line analysis summary
        String summary = String.format(
            "IP: %s | Verdict: %s | Confidence: %.0f%% | Category: %s\n\nAnalysis: %s",
            report.getPrimaryThreatIp(), verdict, confidence * 100, category, reasoning
        );
        report.setAnalyzerVerdict(summary);

        // Status transition
        if (!fp && confidence > 0.7) {
            report.setStatus(IncidentStatus.OPEN);  // → proceed to Remediator
        } else if (fp) {
            report.setStatus(IncidentStatus.FALSE_POSITIVE);
        } else {
            report.setStatus(IncidentStatus.ESCALATED);
        }
    }

    // ── JSON helpers ──────────────────────────────────────────────────────

    private String extractString(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return "";
        int colon = json.indexOf(':', idx);
        int q1    = json.indexOf('"', colon + 1);
        if (q1 == -1) return "";
        // Handle multiline string (find closing " not preceded by \)
        int q2 = q1 + 1;
        while (q2 < json.length()) {
            if (json.charAt(q2) == '"' && json.charAt(q2-1) != '\\') break;
            q2++;
        }
        return q2 >= json.length() ? "" : json.substring(q1 + 1, q2);
    }

    private boolean extractBoolean(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return false;
        int colon = json.indexOf(':', idx);
        String rest = json.substring(colon + 1).trim();
        return rest.startsWith("true");
    }

    private double extractDouble(String json, String key, double def) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return def;
        int colon = json.indexOf(':', idx);
        StringBuilder num = new StringBuilder();
        boolean dot = false;
        for (int i = colon + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (Character.isDigit(c)) { num.append(c); }
            else if (c == '.' && !dot) { dot = true; num.append(c); }
            else if (!num.isEmpty()) break;
        }
        try { return num.isEmpty() ? def : Double.parseDouble(num.toString()); }
        catch (NumberFormatException e) { return def; }
    }
}
