package com.security.incident.mcp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.List;

// ─────────────────────────────────────────────────────────────────────────────
// EndpointStatus  –  Cisco ISE endpoint profiling & quarantine state
// ─────────────────────────────────────────────────────────────────────────────
public record EndpointStatus(

    @JsonProperty("ip_address")       String ipAddress,
    @JsonProperty("mac_address")      String macAddress,
    @JsonProperty("hostname")         String hostname,
    @JsonProperty("endpoint_profile") String endpointProfile,   // e.g. "Windows10-Workstation"
    @JsonProperty("os_version")       String osVersion,
    @JsonProperty("posture_status")   PostureStatus postureStatus,
    @JsonProperty("quarantine_state") QuarantineState quarantineState,
    @JsonProperty("compliance_tags")  List<String> complianceTags,
    @JsonProperty("last_seen")        Instant lastSeen,
    @JsonProperty("connected_nas")    String connectedNas,       // Network Access Server
    @JsonProperty("threat_score")     int threatScore            // 0-100

) {
    public enum PostureStatus { COMPLIANT, NON_COMPLIANT, PENDING, UNKNOWN }
    public enum QuarantineState { CLEAN, QUARANTINED, BLOCKED, PENDING_REVIEW }
}


// ─────────────────────────────────────────────────────────────────────────────
// BlockResult  –  Response from the ISE quarantine / block API
// ─────────────────────────────────────────────────────────────────────────────
record BlockResult(

    @JsonProperty("request_id")   String requestId,
    @JsonProperty("ip_address")   String ipAddress,
    @JsonProperty("success")      boolean success,
    @JsonProperty("action")       BlockAction action,
    @JsonProperty("policy_name")  String policyName,            // ISE AuthZ policy updated
    @JsonProperty("vlan_assigned") String vlanAssigned,          // Quarantine VLAN
    @JsonProperty("timestamp")    Instant timestamp,
    @JsonProperty("message")      String message,
    @JsonProperty("rollback_id")  String rollbackId             // Use to undo the block

) {
    public enum BlockAction { QUARANTINE, FULL_BLOCK, RATE_LIMIT, REDIRECT_TO_REMEDIATION }
}


// ─────────────────────────────────────────────────────────────────────────────
// FirewallRule  –  A proposed Cisco FTD / ASA block rule
// ─────────────────────────────────────────────────────────────────────────────
record FirewallRule(

    @JsonProperty("rule_name")    String ruleName,
    @JsonProperty("source_ip")   String sourceIp,
    @JsonProperty("destination")  String destination,            // "any" or specific subnet
    @JsonProperty("action")       String action,                 // "BLOCK" | "ALLOW"
    @JsonProperty("protocol")     String protocol,               // TCP, UDP, ICMP, ANY
    @JsonProperty("port_range")   String portRange,              // "1-65535" or specific
    @JsonProperty("direction")    String direction,              // "INGRESS" | "EGRESS" | "BOTH"
    @JsonProperty("priority")     int priority,                  // Lower = higher priority
    @JsonProperty("expiry_hours") int expiryHours,              // 0 = permanent
    @JsonProperty("rationale")    String rationale               // LLM-generated explanation

) {}


// ─────────────────────────────────────────────────────────────────────────────
// SandboxResult  –  Result of testing the firewall rule in a sandboxed env
// ─────────────────────────────────────────────────────────────────────────────
record SandboxResult(

    @JsonProperty("test_id")          String testId,
    @JsonProperty("rule_tested")      FirewallRule ruleTested,
    @JsonProperty("passed")           boolean passed,
    @JsonProperty("false_positives")  List<String> falsePositiveIps,   // Legitimate IPs that would be blocked
    @JsonProperty("false_negatives")  List<String> falseNegativeIps,   // Threat IPs that would slip through
    @JsonProperty("coverage_score")   double coverageScore,            // 0.0 – 1.0
    @JsonProperty("performance_impact") String performanceImpact,      // LOW / MEDIUM / HIGH
    @JsonProperty("collateral_damage") String collateralDamage,        // description of side-effects
    @JsonProperty("recommendation")   String recommendation,           // APPROVE / REVISE / REJECT
    @JsonProperty("sandbox_log")      List<String> sandboxLog          // detailed test output

) {}
