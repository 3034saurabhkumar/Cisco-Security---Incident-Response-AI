package com.security.incident.workflow;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Immutable-ish carrier that flows through the agentic pipeline.
 *
 *  MonitorAgent  ──→  IncidentReport  ──→  AnalyzerAgent  ──→  RemediatorAgent
 *
 *  Each agent enriches the report; the Workflow persists it.
 */
public class IncidentReport {

    // ── Identity ──────────────────────────────────────────────────────────
    private String incidentId;
    private Instant createdAt = Instant.now();
    private IncidentStatus status = IncidentStatus.OPEN;

    // ── Monitor findings ─────────────────────────────────────────────────
    private List<String> suspiciousIps     = new ArrayList<>();
    private String       monitorSummary;
    private int          totalLogsScanned;
    private int          suspiciousEventsFound;

    // ── Analyzer findings ────────────────────────────────────────────────
    private String       primaryThreatIp;
    private boolean      falsePositive       = false;
    private String       analyzerVerdict;      // LLM-generated analysis
    private double       threatConfidence;     // 0.0 – 1.0
    private String       threatCategory;       // e.g. "Brute Force + Lateral Movement"
    private Map<String, Object> endpointDetails;

    // ── Remediator output ─────────────────────────────────────────────────
    private Map<String, Object> proposedRule;
    private Map<String, Object> sandboxResult;
    private String              remediationSummary;
    private boolean             approvedForProduction = false;
    private String              rollbackId;

    // ── Audit trail ──────────────────────────────────────────────────────
    private List<AuditEntry> auditTrail = new ArrayList<>();

    public enum IncidentStatus {
        OPEN, ANALYZING, AWAITING_APPROVAL, REMEDIATED, FALSE_POSITIVE, ESCALATED
    }

    public record AuditEntry(
        Instant timestamp,
        String agent,
        String action,
        String detail
    ) {}

    // ── Factory ──────────────────────────────────────────────────────────

    public static IncidentReport create(String incidentId) {
        IncidentReport r = new IncidentReport();
        r.incidentId = incidentId;
        return r;
    }

    public void addAudit(String agent, String action, String detail) {
        auditTrail.add(new AuditEntry(Instant.now(), agent, action, detail));
    }

    // ── Getters / Setters (verbose but explicit – no Lombok for clarity) ──

    public String getIncidentId() { return incidentId; }
    public Instant getCreatedAt() { return createdAt; }

    public IncidentStatus getStatus() { return status; }
    public void setStatus(IncidentStatus s) { this.status = s; }

    public List<String> getSuspiciousIps() { return suspiciousIps; }
    public void setSuspiciousIps(List<String> ips) { this.suspiciousIps = ips; }

    public String getMonitorSummary() { return monitorSummary; }
    public void setMonitorSummary(String s) { this.monitorSummary = s; }

    public int getTotalLogsScanned() { return totalLogsScanned; }
    public void setTotalLogsScanned(int n) { this.totalLogsScanned = n; }

    public int getSuspiciousEventsFound() { return suspiciousEventsFound; }
    public void setSuspiciousEventsFound(int n) { this.suspiciousEventsFound = n; }

    public String getPrimaryThreatIp() { return primaryThreatIp; }
    public void setPrimaryThreatIp(String ip) { this.primaryThreatIp = ip; }

    public boolean isFalsePositive() { return falsePositive; }
    public void setFalsePositive(boolean fp) { this.falsePositive = fp; }

    public String getAnalyzerVerdict() { return analyzerVerdict; }
    public void setAnalyzerVerdict(String v) { this.analyzerVerdict = v; }

    public double getThreatConfidence() { return threatConfidence; }
    public void setThreatConfidence(double c) { this.threatConfidence = c; }

    public String getThreatCategory() { return threatCategory; }
    public void setThreatCategory(String c) { this.threatCategory = c; }

    public Map<String, Object> getEndpointDetails() { return endpointDetails; }
    public void setEndpointDetails(Map<String, Object> d) { this.endpointDetails = d; }

    public Map<String, Object> getProposedRule() { return proposedRule; }
    public void setProposedRule(Map<String, Object> r) { this.proposedRule = r; }

    public Map<String, Object> getSandboxResult() { return sandboxResult; }
    public void setSandboxResult(Map<String, Object> r) { this.sandboxResult = r; }

    public String getRemediationSummary() { return remediationSummary; }
    public void setRemediationSummary(String s) { this.remediationSummary = s; }

    public boolean isApprovedForProduction() { return approvedForProduction; }
    public void setApprovedForProduction(boolean a) { this.approvedForProduction = a; }

    public String getRollbackId() { return rollbackId; }
    public void setRollbackId(String id) { this.rollbackId = id; }

    public List<AuditEntry> getAuditTrail() { return auditTrail; }
}
