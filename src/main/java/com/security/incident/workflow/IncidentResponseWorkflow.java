package com.security.incident.workflow;

import com.security.incident.agents.AnalyzerAgent;
import com.security.incident.agents.MonitorAgent;
import com.security.incident.agents.RemediatorAgent;
import com.security.incident.events.AgentEvent;
import com.security.incident.workflow.IncidentReport.IncidentStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │                  AUTOMATED INCIDENT RESPONSE WORKFLOW                  │
 * │                                                                         │
 * │  Orchestrates the 3 AI agents in a sequential agentic pipeline:         │
 * │                                                                         │
 * │  ┌───────────┐     ┌───────────┐     ┌─────────────┐                   │
 * │  │  MONITOR  │────▶│ ANALYZER  │────▶│ REMEDIATOR  │                   │
 * │  │  Agent 1  │     │  Agent 2  │     │   Agent 3   │                   │
 * │  └───────────┘     └───────────┘     └─────────────┘                   │
 * │   Scan ISE logs    FP detection +     Sandbox test +                    │
 * │   Find threat IPs  LLM reasoning      Block + report                   │
 * │                                                                         │
 * │  Each agent communicates via shared IncidentReport state.               │
 * │  Decision gates prevent unsafe auto-remediation.                        │
 * └─────────────────────────────────────────────────────────────────────────┘
 */
@Service
public class IncidentResponseWorkflow {

    private static final Logger log = LoggerFactory.getLogger(IncidentResponseWorkflow.class);

    // In-memory store (replace with Redis/DB in production)
    private final Map<String, IncidentReport> incidentStore = new ConcurrentHashMap<>();

    private final MonitorAgent     monitorAgent;
    private final AnalyzerAgent    analyzerAgent;
    private final RemediatorAgent  remediatorAgent;
    private final ApplicationEventPublisher events;

    public IncidentResponseWorkflow(MonitorAgent monitorAgent,
                                    AnalyzerAgent analyzerAgent,
                                    RemediatorAgent remediatorAgent,
                                    ApplicationEventPublisher events) {
        this.monitorAgent    = monitorAgent;
        this.analyzerAgent   = analyzerAgent;
        this.remediatorAgent = remediatorAgent;
        this.events          = events;
    }

    /**
     * Trigger the full agentic incident response pipeline.
     * Returns the enriched IncidentReport with all findings and recommendations.
     */
    public IncidentReport runPipeline() {
        String incidentId = "INC-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        IncidentReport report = IncidentReport.create(incidentId);
        incidentStore.put(incidentId, report);

        log.info("═══════════════════════════════════════════════════════════");
        log.info("  INCIDENT RESPONSE PIPELINE STARTED – {}", incidentId);
        log.info("═══════════════════════════════════════════════════════════");

        events.publishEvent(new AgentEvent("Workflow", "PIPELINE_START",
            "Incident " + incidentId + " – starting 3-agent pipeline"));

        // ── STAGE 1: MONITOR ──────────────────────────────────────────────
        log.info("[Workflow] Stage 1/3 – MonitorAgent: Scanning logs...");
        try {
            report = monitorAgent.scan(report);
        } catch (Exception e) {
            return handlePipelineError(report, "MonitorAgent", e);
        }

        if (report.getSuspiciousIps().isEmpty()) {
            log.info("[Workflow] No suspicious IPs found. Closing incident as clean.");
            report.setStatus(IncidentStatus.REMEDIATED);
            report.setMonitorSummary("No suspicious activity detected in the log window.");
            events.publishEvent(new AgentEvent("Workflow", "PIPELINE_CLEAN",
                "No threats found – incident closed"));
            return report;
        }

        log.info("[Workflow] Monitor found {} suspicious IPs: {}",
            report.getSuspiciousIps().size(), report.getSuspiciousIps());

        // ── STAGE 2: ANALYZER ─────────────────────────────────────────────
        log.info("[Workflow] Stage 2/3 – AnalyzerAgent: Analyzing {}...",
            report.getPrimaryThreatIp());
        try {
            report = analyzerAgent.analyze(report);
        } catch (Exception e) {
            return handlePipelineError(report, "AnalyzerAgent", e);
        }

        // Decision gate: stop pipeline on false positive
        if (report.isFalsePositive()) {
            log.info("[Workflow] ✅ FALSE POSITIVE confirmed by AnalyzerAgent – no remediation");
            report.setStatus(IncidentStatus.FALSE_POSITIVE);
            events.publishEvent(new AgentEvent("Workflow", "FALSE_POSITIVE",
                "IP " + report.getPrimaryThreatIp() + " determined to be a false positive"));
            finalizeReport(report);
            return report;
        }

        // Decision gate: escalate uncertain cases
        if (report.getThreatConfidence() < 0.6) {
            log.warn("[Workflow] ⚠️  Low confidence ({}) – escalating to SOC team",
                report.getThreatConfidence());
            report.setStatus(IncidentStatus.ESCALATED);
            events.publishEvent(new AgentEvent("Workflow", "ESCALATED",
                "Low confidence – incident escalated to SOC team for manual review"));
            finalizeReport(report);
            return report;
        }

        log.info("[Workflow] Analyzer confirmed GENUINE THREAT (confidence: {})",
            report.getThreatConfidence());

        // ── STAGE 3: REMEDIATOR ───────────────────────────────────────────
        log.info("[Workflow] Stage 3/3 – RemediatorAgent: Drafting and testing block rule...");
        try {
            report = remediatorAgent.remediate(report);
        } catch (Exception e) {
            return handlePipelineError(report, "RemediatorAgent", e);
        }

        // ── FINAL STATUS ──────────────────────────────────────────────────
        finalizeReport(report);
        return report;
    }

    /**
     * Human approves the suggested remediation and pushes it to production.
     * This is the human-in-the-loop gate – the Remediator never auto-approves.
     */
    public IncidentReport approveRemediation(String incidentId) {
        IncidentReport report = incidentStore.get(incidentId);
        if (report == null) {
            throw new IllegalArgumentException("Incident not found: " + incidentId);
        }
        if (report.getStatus() != IncidentStatus.AWAITING_APPROVAL) {
            throw new IllegalStateException("Incident " + incidentId +
                " is not in AWAITING_APPROVAL state: " + report.getStatus());
        }

        log.info("[Workflow] Human approved remediation for incident {}", incidentId);
        report.setApprovedForProduction(true);
        report.setStatus(IncidentStatus.REMEDIATED);
        report.addAudit("HumanOperator", "APPROVED",
            "Production block approved for IP: " + report.getPrimaryThreatIp());

        events.publishEvent(new AgentEvent("Workflow", "APPROVED",
            "Human approved block for " + report.getPrimaryThreatIp() +
            " – rule is now ACTIVE in production"));

        return report;
    }

    public IncidentReport getIncident(String incidentId) {
        return incidentStore.get(incidentId);
    }

    public Map<String, IncidentReport> getAllIncidents() {
        return Map.copyOf(incidentStore);
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private void finalizeReport(IncidentReport report) {
        log.info("═══════════════════════════════════════════════════════════");
        log.info("  PIPELINE COMPLETE – {} | Status: {}",
            report.getIncidentId(), report.getStatus());
        log.info("  Suspicious IPs:    {}", report.getSuspiciousIps());
        log.info("  Primary Threat:    {}", report.getPrimaryThreatIp());
        log.info("  False Positive:    {}", report.isFalsePositive());
        log.info("  Confidence:        {}", report.getThreatConfidence());
        log.info("═══════════════════════════════════════════════════════════");

        events.publishEvent(new AgentEvent("Workflow", "PIPELINE_COMPLETE",
            "Incident " + report.getIncidentId() + " resolved with status: " + report.getStatus()));
    }

    private IncidentReport handlePipelineError(IncidentReport report, String agent, Exception e) {
        log.error("[Workflow] Pipeline failed at {}: {}", agent, e.getMessage(), e);
        report.setStatus(IncidentStatus.ESCALATED);
        report.addAudit("Workflow", "PIPELINE_ERROR",
            "Failed at " + agent + ": " + e.getMessage());
        events.publishEvent(new AgentEvent("Workflow", "PIPELINE_ERROR",
            "Pipeline failed at " + agent + " – escalating to SOC"));
        return report;
    }
}
