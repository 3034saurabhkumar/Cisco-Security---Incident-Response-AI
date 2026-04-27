package com.security.incident.mcp.service;

import com.security.incident.mcp.model.LogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ CISCO ISE MCP SERVER                                                    │
 * │                                                                         │
 * │ Exposes 5 tools via Spring AI's @Tool annotation.                       │
 * │ All logic is delegated to the CiscoIseClient interface.                 │
 * │                                                                         │
 * │ Tools:                                                                  │
 * │ 1. getSecurityLogs – RADIUS/TACACS audit log stream                     │
 * │ 2. getEndpointStatus – Profiling + posture state for an IP              │
 * │ 3. blockEndpoint – Quarantine / block via ISE REST API                  │
 * │ 4. testRuleInSandbox – Validate FTD rule before production push         │
 * │ 5. getActivePolicies – List current AuthZ policies                      │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
@Service
public class CiscoIseMcpServer {

    private static final Logger log = LoggerFactory.getLogger(CiscoIseMcpServer.class);

    private final CiscoIseClient iseClient;

    public CiscoIseMcpServer(Optional<CiscoIseClient> iseClient) {
        // Fallback to a placeholder if no client is registered
        this.iseClient = (iseClient != null && iseClient.isPresent())
                ? iseClient.get()
                : new PlaceholderIseClient();
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tool 1 – Get Security Logs
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Retrieve recent security log entries from Cisco ISE RADIUS/TACACS audit log.
            Returns authentication events, policy violations, and anomaly alerts.
            Use this to scan for suspicious source IPs, brute-force patterns, and policy breaches.
            """)
    public List<LogEntry> getSecurityLogs(
            @ToolParam(description = "Number of recent log entries to retrieve (1-200)") int count,
            @ToolParam(description = "Filter by severity: LOW, MEDIUM, HIGH, CRITICAL, or ALL") String severityFilter) {
        log.info("[MCP:ISE] getSecurityLogs called – count={}, severity={}", count, severityFilter);
        return iseClient.getSecurityLogs(count, severityFilter);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tool 2 – Get Endpoint Status
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Query Cisco ISE for the current security posture and profile of an endpoint by IP address.
            Returns quarantine state, compliance tags, threat score, and connected network device.
            Essential before blocking – confirms the IP is active and fetches its risk profile.
            """)
    public Map<String, Object> getEndpointStatus(
            @ToolParam(description = "IPv4 address of the endpoint to inspect") String ipAddress) {
        log.info("[MCP:ISE] getEndpointStatus called – ip={}", ipAddress);
        return iseClient.getEndpointStatus(ipAddress);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tool 3 – Block Endpoint
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Block or quarantine an endpoint in Cisco ISE by IP address.
            This updates the ISE Authorization Policy to assign the endpoint to a quarantine VLAN
            and pushes a Change-of-Authorization (CoA) to the Network Access Server.
            Use only after the Analyzer has confirmed the IP is NOT a false positive.
            Returns a rollback_id that can be used to reverse the action.
            """)
    public Map<String, Object> blockEndpoint(
            @ToolParam(description = "IPv4 address of the endpoint to block") String ipAddress,
            @ToolParam(description = "Human-readable reason for blocking (used in audit log)") String reason,
            @ToolParam(description = "Block action: QUARANTINE, FULL_BLOCK, or RATE_LIMIT") String blockAction) {
        log.warn("[MCP:ISE] blockEndpoint called – ip={}, action={}, reason={}", ipAddress, blockAction, reason);
        return iseClient.blockEndpoint(ipAddress, reason, blockAction);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tool 4 – Test Rule in Sandbox
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
            Validates a proposed Cisco FTD/ASA firewall rule in a sandboxed network replica
            BEFORE pushing it to production. Runs traffic simulation against the rule
            and reports false positives, false negatives, and performance impact.
            Always call this before recommending a block rule to the user.
            """)
    public Map<String, Object> testRuleInSandbox(
            @ToolParam(description = "Source IP address the rule will block") String sourceIp,
            @ToolParam(description = "Proposed rule name (descriptive)") String ruleName,
            @ToolParam(description = "Action: BLOCK or RATE_LIMIT") String action,
            @ToolParam(description = "Target protocol: TCP, UDP, ICMP, or ANY") String protocol,
            @ToolParam(description = "Port range, e.g. '1-65535' or '443'") String portRange) {
        log.info("[MCP:FTD-Sandbox] testRuleInSandbox – ip={}, rule={}", sourceIp, ruleName);
        return iseClient.testRuleInSandbox(sourceIp, ruleName, action, protocol, portRange);
    }

    // ─────────────────────────────────────────────────────────────────────
    // Tool 5 – Get Active Policies
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
            List the currently active Cisco ISE Authorization Policies and Cisco FTD Access Control Rules.
            Use this to check if a block rule for an IP already exists before creating a duplicate,
            or to understand the current security posture baseline.
            """)
    public Map<String, Object> getActivePolicies() {
        log.info("[MCP:ISE] getActivePolicies called");
        return iseClient.getActivePolicies();
    }

    /**
     * Placeholder client used when a real implementation is not provided.
     */
    private static class PlaceholderIseClient implements CiscoIseClient {
        @Override
        public List<LogEntry> getSecurityLogs(int c, String s) {
            return List.of();
        }

        @Override
        public Map<String, Object> getEndpointStatus(String ip) {
            return Map.of("ip_address", ip, "status", "STUB_MODE", "message", "Real Cisco ISE client not configured");
        }

        @Override
        public Map<String, Object> blockEndpoint(String ip, String r, String a) {
            return Map.of("success", false, "message", "Stub mode: Cannot block");
        }

        @Override
        public Map<String, Object> testRuleInSandbox(String s, String n, String a, String p, String pr) {
            return Map.of("passed", true, "message", "Stub mode: Sandbox simulation bypassed");
        }

        @Override
        public Map<String, Object> getActivePolicies() {
            return Map.of("policies", List.of(), "message", "Stub mode: No active policies found");
        }
    }
}
