package com.security.incident.agents;

import com.security.incident.events.AgentEvent;
import com.security.incident.workflow.IncidentReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                         AGENT 1 – MONITOR                              │
 * │                                                                         │
 * │  Responsibility: Actively scan Cisco ISE logs via the MCP Server.       │
 * │  Identify IPs with suspicious patterns (brute-force, port-scans,        │
 * │  lateral movement, excessive auth failures).                            │
 * │                                                                         │
 * │  Pattern: Agentic loop – calls getSecurityLogs tool, reasons over       │
 * │  results, and populates the IncidentReport with suspicious IPs.         │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
@Component
public class MonitorAgent {

    private static final Logger log = LoggerFactory.getLogger(MonitorAgent.class);

    private final ChatClient      chatClient;
    private final ApplicationEventPublisher events;

    private static final String SYSTEM_PROMPT = """
        You are the MONITOR agent in an Automated Incident Response system.
        
        You have access to Cisco ISE security tools via MCP.
        
        Your job:
        1. Call getSecurityLogs(count=50, severityFilter="ALL") to retrieve recent logs.
        2. Analyze the logs to identify source IPs showing suspicious behaviour:
           - More than 5 failed authentication attempts from the same IP
           - EventType: BRUTE_FORCE, PORT_SCAN, LATERAL_MOVEMENT, EXFILTRATION_ATTEMPT
           - Severity: HIGH or CRITICAL events
           - Any unknown IP generating multiple HIGH-severity events
        3. Compile a deduplicated list of suspicious IPs.
        4. Respond in this EXACT JSON format (no markdown, no prose before or after):
        {
          "suspicious_ips": ["ip1", "ip2"],
          "total_logs_scanned": <number>,
          "suspicious_events_found": <number>,
          "summary": "<one-paragraph human-readable summary>"
        }
        
        Be precise. Do NOT flag known-safe or monitoring IPs unless they are clearly compromised.
        """;

    public MonitorAgent(ChatClient.Builder builder,
                        ApplicationEventPublisher events) {
        // Attach the MCP tools so the LLM can call getSecurityLogs()
        this.chatClient = builder.build();
        this.events     = events;
    }

    /**
     * Entry point called by the Workflow.
     * Runs the agentic loop: LLM reasons → calls MCP tool → reasons again → returns result.
     */
    public IncidentReport scan(IncidentReport report) {
        log.info("[MonitorAgent] Starting log scan for incident {}", report.getIncidentId());
        events.publishEvent(new AgentEvent("MonitorAgent", "STARTED",
            "Scanning Cisco ISE logs for suspicious activity..."));

        try {
            // Spring AI's ChatClient runs the full agentic loop:
            // prompt → LLM chooses tool → tool executes → LLM gets result → final response
            String response = chatClient
                .prompt()
                .system(SYSTEM_PROMPT)
                .user("Scan the last 50 Cisco ISE log entries and identify all suspicious source IPs. " +
                      "Return your findings as JSON.")
                .call()
                .content();

            log.info("[MonitorAgent] Raw LLM response:\n{}", response);

            // Parse the JSON response from the LLM
            parseAndEnrichReport(response, report);

            events.publishEvent(new AgentEvent("MonitorAgent", "COMPLETED",
                String.format("Found %d suspicious IPs in %d log entries: %s",
                    report.getSuspiciousIps().size(),
                    report.getTotalLogsScanned(),
                    report.getSuspiciousIps())));

            report.addAudit("MonitorAgent", "LOG_SCAN",
                "Scanned " + report.getTotalLogsScanned() + " logs, found " +
                report.getSuspiciousEventsFound() + " suspicious events. IPs: " +
                report.getSuspiciousIps());

        } catch (Exception e) {
            log.error("[MonitorAgent] Scan failed: {}", e.getMessage(), e);
            events.publishEvent(new AgentEvent("MonitorAgent", "ERROR", e.getMessage()));
            report.addAudit("MonitorAgent", "ERROR", e.getMessage());
        }

        return report;
    }

    private void parseAndEnrichReport(String jsonResponse, IncidentReport report) {
        try {
            // Use basic JSON parsing (in production, use Jackson ObjectMapper)
            String cleaned = jsonResponse.trim();
            if (cleaned.startsWith("```")) {
                cleaned = cleaned.replaceAll("```json", "").replaceAll("```", "").trim();
            }

            // Simple extraction (replace with ObjectMapper in production)
            List<String> ips = extractJsonArray(cleaned, "suspicious_ips");
            int logsScanned  = extractJsonInt(cleaned, "total_logs_scanned", 50);
            int suspEvents   = extractJsonInt(cleaned, "suspicious_events_found", ips.size());
            String summary   = extractJsonString(cleaned, "summary");

            report.setSuspiciousIps(ips);
            report.setTotalLogsScanned(logsScanned);
            report.setSuspiciousEventsFound(suspEvents);
            report.setMonitorSummary(summary);

            // Set the most-threatening IP as primary (first in list)
            if (!ips.isEmpty()) {
                report.setPrimaryThreatIp(ips.get(0));
            }

        } catch (Exception e) {
            log.warn("[MonitorAgent] Could not parse LLM JSON, using fallback: {}", e.getMessage());
            // Fallback: extract IPs using regex pattern
            List<String> fallbackIps = extractIpsFallback(jsonResponse);
            report.setSuspiciousIps(fallbackIps);
            report.setTotalLogsScanned(50);
            report.setSuspiciousEventsFound(fallbackIps.size());
            report.setMonitorSummary("Monitor scan completed. " + fallbackIps.size() + " suspicious IPs identified.");
            if (!fallbackIps.isEmpty()) report.setPrimaryThreatIp(fallbackIps.get(0));
        }
    }

    // ── Minimal JSON helpers ──────────────────────────────────────────────

    @SuppressWarnings("unchecked")
    private List<String> extractJsonArray(String json, String key) {
        // Locate "key": [ ... ]
        int start = json.indexOf("\"" + key + "\"");
        if (start == -1) return List.of();
        int arrStart = json.indexOf('[', start);
        int arrEnd   = json.indexOf(']', arrStart);
        if (arrStart == -1 || arrEnd == -1) return List.of();
        String arr = json.substring(arrStart + 1, arrEnd);
        return java.util.Arrays.stream(arr.split(","))
            .map(s -> s.trim().replace("\"", ""))
            .filter(s -> !s.isEmpty())
            .toList();
    }

    private int extractJsonInt(String json, String key, int def) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return def;
        int colon = json.indexOf(':', idx);
        if (colon == -1) return def;
        StringBuilder num = new StringBuilder();
        for (int i = colon + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (Character.isDigit(c)) num.append(c);
            else if (!num.isEmpty()) break;
        }
        return num.isEmpty() ? def : Integer.parseInt(num.toString());
    }

    private String extractJsonString(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx == -1) return "";
        int start = json.indexOf('"', json.indexOf(':', idx) + 1);
        if (start == -1) return "";
        int end = json.indexOf('"', start + 1);
        return end == -1 ? "" : json.substring(start + 1, end);
    }

    private List<String> extractIpsFallback(String text) {
        java.util.regex.Pattern ipPattern =
            java.util.regex.Pattern.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b");
        return ipPattern.matcher(text).results()
            .map(m -> m.group(1))
            .distinct()
            .toList();
    }
}
