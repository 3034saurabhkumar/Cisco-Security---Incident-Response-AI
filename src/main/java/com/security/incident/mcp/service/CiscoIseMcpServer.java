package com.security.incident.mcp.service;

import com.security.incident.mcp.model.LogEntry;
import com.security.incident.mcp.model.LogEntry.EventType;
import com.security.incident.mcp.model.LogEntry.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │               CISCO ISE  MCP SERVER  (Simulated)                        │
 * │                                                                         │
 * │  Exposes 5 tools via Spring AI's @Tool annotation, which Spring AI      │
 * │  MCP Server Starter auto-registers on the MCP stdio/SSE transport.      │
 * │                                                                         │
 * │  Tools:                                                                 │
 * │    1. getSecurityLogs      – RADIUS/TACACS audit log stream             │
 * │    2. getEndpointStatus    – Profiling + posture state for an IP        │
 * │    3. blockEndpoint        – Quarantine / block via ISE REST API        │
 * │    4. testRuleInSandbox    – Validate FTD rule before production push   │
 * │    5. getActivePolicies    – List current AuthZ policies                │
 * └─────────────────────────────────────────────────────────────────────────┘
 *
 *  Real-world equivalent: This would call Cisco ISE ERS API or pxGrid,
 *  and Cisco FMC/FTD REST API.  Here we return realistic simulated data
 *  so the agents can run without a real lab.
 */
@Service
public class CiscoIseMcpServer {

    private static final Logger log = LoggerFactory.getLogger(CiscoIseMcpServer.class);

    // ── Simulated persistent state ────────────────────────────────────────
    private final Map<String, String>  blockedEndpoints  = new ConcurrentHashMap<>();
    private final AtomicInteger        requestCounter    = new AtomicInteger(1000);

    // Known-good IPs that should never trigger – to make false-positive testing interesting
    private static final Set<String> KNOWN_SAFE_IPS = Set.of(
        "10.0.1.50",  // internal monitoring server
        "10.0.1.51",  // patch management server
        "192.168.10.5" // printer (high auth failures = normal)
    );

    // Simulated threat intelligence feed
    private static final Set<String> THREAT_INTEL_IPS = Set.of(
        "185.220.101.47",  // known Tor exit node
        "198.199.67.82",   // flagged C2 server
        "103.21.244.0",    // compromised cloud instance
        "45.33.32.156"     // known scanner (shodan)
    );

    // ─────────────────────────────────────────────────────────────────────
    //  Tool 1 – Get Security Logs
    // ─────────────────────────────────────────────────────────────────────

    /**
     * In a real production environment, you would modify the code in the
     * getSecurityLogs()
     *  method to call the Cisco ISE ERS API or pxGrid.
     */
    @Tool(description = """
        Retrieve recent security log entries from Cisco ISE RADIUS/TACACS audit log.
        Returns authentication events, policy violations, and anomaly alerts.
        Use this to scan for suspicious source IPs, brute-force patterns, and policy breaches.
        """)
    public List<LogEntry> getSecurityLogs(
        @ToolParam(description = "Number of recent log entries to retrieve (1-200)") int count,
        @ToolParam(description = "Filter by severity: LOW, MEDIUM, HIGH, CRITICAL, or ALL") String severityFilter
    ) {
        log.info("[MCP:ISE] getSecurityLogs called – count={}, severity={}", count, severityFilter);

        int limit = Math.min(Math.max(count, 1), 200);
        List<LogEntry> all = generateSimulatedLogs(50);   // simulate a rolling log window

        return all.stream()
            .filter(e -> severityFilter.equalsIgnoreCase("ALL")
                      || e.severity().name().equalsIgnoreCase(severityFilter))
            .limit(limit)
            .collect(Collectors.toList());
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Tool 2 – Get Endpoint Status
    // ─────────────────────────────────────────────────────────────────────

    // Check if an IP is a known device or a threat.
    @Tool(description = """
        Query Cisco ISE for the current security posture and profile of an endpoint by IP address.
        Returns quarantine state, compliance tags, threat score, and connected network device.
        Essential before blocking – confirms the IP is active and fetches its risk profile.
        """)
    public Map<String, Object> getEndpointStatus(
        @ToolParam(description = "IPv4 address of the endpoint to inspect") String ipAddress
    ) {
        log.info("[MCP:ISE] getEndpointStatus called – ip={}", ipAddress);

        boolean isThreat   = THREAT_INTEL_IPS.contains(ipAddress);
        boolean isSafe     = KNOWN_SAFE_IPS.contains(ipAddress);
        boolean isBlocked  = blockedEndpoints.containsKey(ipAddress);

        // Deterministic but realistic response based on IP characteristics
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ip_address",        ipAddress);
        result.put("mac_address",       deterministicMac(ipAddress));
        result.put("hostname",          isThreat ? "UNKNOWN" : "CORP-WS-" + ipAddress.replace(".", "-"));
        result.put("endpoint_profile",  isThreat ? "Unknown-Device" : "Windows11-Workstation");
        result.put("os_version",        isThreat ? "Unknown" : "Windows 11 22H2");
        result.put("posture_status",    isThreat ? "NON_COMPLIANT" : isSafe ? "COMPLIANT" : "PENDING");
        result.put("quarantine_state",  isBlocked ? "BLOCKED" : isThreat ? "PENDING_REVIEW" : "CLEAN");
        result.put("threat_score",      isThreat ? 92 : isSafe ? 2 : 45);
        result.put("last_seen",         Instant.now().minus(isThreat ? 2 : 30, ChronoUnit.MINUTES).toString());
        result.put("connected_nas",     "ISE-NAS-01.corp.local");
        result.put("compliance_tags",   isSafe ? List.of("patch-compliant", "av-active") : List.of());
        result.put("is_in_threat_intel", isThreat);
        result.put("already_blocked",   isBlocked);
        result.put("block_reason",      isBlocked ? blockedEndpoints.get(ipAddress) : null);

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Tool 3 – Block Endpoint
    // ─────────────────────────────────────────────────────────────────────

    // Automatically quarantine a suspicious device.
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
        @ToolParam(description = "Block action: QUARANTINE, FULL_BLOCK, or RATE_LIMIT") String blockAction
    ) {
        log.warn("[MCP:ISE] blockEndpoint called – ip={}, action={}, reason={}", ipAddress, blockAction, reason);

        if (KNOWN_SAFE_IPS.contains(ipAddress)) {
            return Map.of(
                "success", false,
                "message", "BLOCKED by ISE policy: IP " + ipAddress + " is on the safe-list. Manual override required.",
                "ip_address", ipAddress
            );
        }

        String rollbackId = "RBK-" + requestCounter.incrementAndGet();
        String requestId  = "BLK-" + requestCounter.incrementAndGet();
        blockedEndpoints.put(ipAddress, reason);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("request_id",    requestId);
        result.put("ip_address",    ipAddress);
        result.put("success",       true);
        result.put("action",        blockAction);
        result.put("policy_name",   "AutoBlock-IncidentResponse");
        result.put("vlan_assigned", "VLAN-999-QUARANTINE");
        result.put("timestamp",     Instant.now().toString());
        result.put("rollback_id",   rollbackId);
        result.put("message",       "Endpoint quarantined. CoA sent to NAS. RADIUS session terminated.");
        result.put("audit_trail",   "Blocked by Spring AI IncidentResponse Workflow. Reason: " + reason);

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Tool 4 – Test Rule in Sandbox
    // ─────────────────────────────────────────────────────────────────────

    /*
     * Verify a firewall rule before applying it to avoid breaking business operations.
     */
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
        @ToolParam(description = "Port range, e.g. '1-65535' or '443'") String portRange
    ) {
        log.info("[MCP:FTD-Sandbox] testRuleInSandbox – ip={}, rule={}", sourceIp, ruleName);

        String testId = "SBX-" + requestCounter.incrementAndGet();
        boolean isThreat = THREAT_INTEL_IPS.contains(sourceIp);
        boolean isSafe   = KNOWN_SAFE_IPS.contains(sourceIp);

        List<String> falsePositives = isSafe
            ? List.of(sourceIp + " (known-safe IP – DO NOT BLOCK)")
            : List.of();

        List<String> fpWarnings = new ArrayList<>();
        // Simulate subnet collision check
        if (sourceIp.startsWith("10.0.1.")) {
            fpWarnings.add("Subnet 10.0.1.0/24 contains internal services – verify scope");
        }

        List<String> sandboxLog = List.of(
            "[SANDBOX] Replaying last 10,000 flows against proposed rule...",
            "[SANDBOX] Rule: " + action + " " + sourceIp + " proto=" + protocol + " ports=" + portRange,
            "[SANDBOX] Matched flows: " + (isThreat ? 847 : 12),
            "[SANDBOX] False positive candidates: " + falsePositives.size(),
            "[SANDBOX] Lateral movement blocked: " + (isThreat ? "YES (23 internal hops)" : "N/A"),
            "[SANDBOX] Performance impact on FTD cluster: " + (portRange.equals("1-65535") ? "MEDIUM" : "LOW"),
            "[SANDBOX] Test completed. Recommendation: " + (isThreat ? "APPROVE" : isSafe ? "REJECT" : "REVISE")
        );

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("test_id",            testId);
        result.put("source_ip",          sourceIp);
        result.put("rule_name",          ruleName);
        result.put("passed",             !isSafe);
        result.put("false_positives",    falsePositives);
        result.put("fp_warnings",        fpWarnings);
        result.put("false_negatives",    List.of());
        result.put("coverage_score",     isThreat ? 0.94 : 0.31);
        result.put("performance_impact", portRange.equals("1-65535") ? "MEDIUM" : "LOW");
        result.put("collateral_damage",  isSafe ? "HIGH – safe endpoint would be blocked" : "NONE");
        result.put("recommendation",     isThreat ? "APPROVE" : isSafe ? "REJECT" : "REVISE");
        result.put("sandbox_log",        sandboxLog);
        result.put("confidence_score",   isThreat ? 0.97 : 0.42);

        return result;
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Tool 5 – Get Active Policies
    // ─────────────────────────────────────────────────────────────────────

    @Tool(description = """
        List the currently active Cisco ISE Authorization Policies and Cisco FTD Access Control Rules.
        Use this to check if a block rule for an IP already exists before creating a duplicate,
        or to understand the current security posture baseline.
        """)
    public Map<String, Object> getActivePolicies() {
        log.info("[MCP:ISE] getActivePolicies called");

        List<Map<String, Object>> policies = new ArrayList<>();

        policies.add(Map.of(
            "policy_id", "POL-001",
            "name", "Default-Corporate-Access",
            "type", "ISE_AUTHZ",
            "condition", "AD-Group:Corp-Users AND Posture:Compliant",
            "result", "PERMIT-FULL-ACCESS",
            "priority", 10
        ));
        policies.add(Map.of(
            "policy_id", "POL-002",
            "name", "Guest-Restricted-Access",
            "type", "ISE_AUTHZ",
            "condition", "Identity:Guest",
            "result", "PERMIT-GUEST-VLAN",
            "priority", 20
        ));
        policies.add(Map.of(
            "policy_id", "POL-100",
            "name", "AutoBlock-IncidentResponse",
            "type", "ISE_AUTHZ + FTD_ACL",
            "condition", "BlockList:IncidentResponse",
            "result", "QUARANTINE-VLAN-999",
            "priority", 1,  // Highest priority
            "blocked_ips", new ArrayList<>(blockedEndpoints.keySet())
        ));

        return Map.of(
            "policy_count", policies.size(),
            "policies", policies,
            "ftd_acl_rules", blockedEndpoints.size(),
            "last_sync", Instant.now().minus(5, ChronoUnit.MINUTES).toString()
        );
    }

    // ─────────────────────────────────────────────────────────────────────
    //  Private helpers
    // ─────────────────────────────────────────────────────────────────────

    // Generate dummy logs to allow for testing and demos without needing a live Cisco ISE lab.
    private List<LogEntry> generateSimulatedLogs(int count) {
        List<LogEntry> logs = new ArrayList<>();
        Random rng = new Random(42);  // deterministic seed for reproducible demos

        // Pool of IPs – mix of threats, safe, and ambiguous
        List<String> ipPool = List.of(
            "185.220.101.47",  // Tor – confirmed threat
            "198.199.67.82",   // C2 – confirmed threat
            "10.0.1.50",       // safe monitoring server
            "192.168.10.5",    // printer (safe)
            "172.16.44.23",    // ambiguous internal
            "10.10.20.88",     // ambiguous internal
            "103.21.244.0",    // compromised cloud
            "192.168.1.102",   // normal workstation
            "172.16.0.55"      // ambiguous
        );

        EventType[] types = EventType.values();
        Severity[]  severities = {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL, Severity.HIGH};

        for (int i = 0; i < count; i++) {
            String ip = ipPool.get(rng.nextInt(ipPool.size()));
            boolean isThreat = THREAT_INTEL_IPS.contains(ip);

            EventType type = isThreat
                ? (rng.nextBoolean() ? EventType.BRUTE_FORCE : EventType.LATERAL_MOVEMENT)
                : types[rng.nextInt(types.length)];

            Severity sev = isThreat ? Severity.CRITICAL : severities[rng.nextInt(severities.length)];

            int attempts = isThreat ? (50 + rng.nextInt(200)) : (rng.nextInt(8));

            logs.add(new LogEntry(
                "EVT-" + (9000 + i),
                Instant.now().minus(i * 2L, ChronoUnit.MINUTES),
                ip,
                "10.0.0.1",
                type,
                isThreat ? "unknown" : "user" + rng.nextInt(100) + "@corp.local",
                deterministicMac(ip),
                "GigabitEthernet1/" + rng.nextInt(48),
                isThreat ? "5400.1 Authentication failed" : null,
                attempts,
                sev,
                String.format("[ISE] %s from %s – %d attempts – %s", type, ip, attempts, sev)
            ));
        }
        return logs;
    }

    private String deterministicMac(String ip) {
        int hash = Math.abs(ip.hashCode());
        return String.format("AA:BB:%02X:%02X:%02X:%02X",
            (hash >> 24) & 0xFF, (hash >> 16) & 0xFF,
            (hash >> 8)  & 0xFF,  hash        & 0xFF);
    }
}
