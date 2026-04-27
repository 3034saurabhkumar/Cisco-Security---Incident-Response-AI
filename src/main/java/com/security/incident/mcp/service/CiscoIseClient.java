package com.security.incident.mcp.service;

import com.security.incident.mcp.model.LogEntry;
import java.util.List;
import java.util.Map;

/**
 * Gateway interface for Cisco ISE operations.
 */
public interface CiscoIseClient {
    List<LogEntry> getSecurityLogs(int count, String severityFilter);

    Map<String, Object> getEndpointStatus(String ipAddress);

    Map<String, Object> blockEndpoint(String ipAddress, String reason, String blockAction);

    Map<String, Object> testRuleInSandbox(String sourceIp, String ruleName, String action, String protocol,
            String portRange);

    Map<String, Object> getActivePolicies();
}
