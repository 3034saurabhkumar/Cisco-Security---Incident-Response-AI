package com.security.incident.mcp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/**
 * Represents a single security log event from the Cisco ISE RADIUS/TACACS log stream.
 * The MCP tool returns a list of these to the Monitor Agent.
 */
public record LogEntry(

    @JsonProperty("event_id")      String eventId,
    @JsonProperty("timestamp")     Instant timestamp,
    @JsonProperty("source_ip")     String sourceIp,
    @JsonProperty("destination_ip") String destinationIp,
    @JsonProperty("event_type")    EventType eventType,
    @JsonProperty("username")      String username,
    @JsonProperty("endpoint_mac")  String endpointMac,
    @JsonProperty("nas_port")      String nasPort,
    @JsonProperty("failure_reason") String failureReason,
    @JsonProperty("auth_attempts") int authAttempts,
    @JsonProperty("severity")      Severity severity,
    @JsonProperty("raw_message")   String rawMessage

) {
    public enum EventType {
        AUTH_FAILURE, AUTH_SUCCESS, POLICY_VIOLATION,
        ANOMALOUS_TRAFFIC, PORT_SCAN, BRUTE_FORCE,
        LATERAL_MOVEMENT, EXFILTRATION_ATTEMPT
    }

    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }

    /** Quick helper: is this log worth escalating? */
    public boolean isSuspicious() {
        return severity == Severity.HIGH || severity == Severity.CRITICAL
            || authAttempts > 5
            || eventType == EventType.BRUTE_FORCE
            || eventType == EventType.PORT_SCAN
            || eventType == EventType.LATERAL_MOVEMENT
            || eventType == EventType.EXFILTRATION_ATTEMPT;
    }
}
