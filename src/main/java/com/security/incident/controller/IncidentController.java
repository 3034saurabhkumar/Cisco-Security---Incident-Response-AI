package com.security.incident.controller;

import com.security.incident.events.AgentEvent;
import com.security.incident.workflow.IncidentReport;
import com.security.incident.workflow.IncidentResponseWorkflow;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Async;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * REST API for the Incident Response System.
 *
 *  POST   /api/incidents/trigger      → Starts the agentic pipeline
 *  GET    /api/incidents/stream       → SSE stream of real-time agent events
 *  GET    /api/incidents/{id}         → Get incident report by ID
 *  GET    /api/incidents              → List all incidents
 *  POST   /api/incidents/{id}/approve → Human approves the remediation
 *
 * The SSE stream lets you watch the 3 agents work in real time.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/incidents")
@CrossOrigin(origins = "*")
public class IncidentController {

    private static final Logger log = LoggerFactory.getLogger(IncidentController.class);

    private final IncidentResponseWorkflow workflow;
    private final ExecutorService          executor = Executors.newCachedThreadPool();

    // Active SSE connections
    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();

    // ─────────────────────────────────────────────────────────────────────
    //  1. Trigger the agentic pipeline
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Starts the 3-agent pipeline asynchronously.
     * Returns immediately with the incident ID; poll /api/incidents/{id} for results,
     * or watch /api/incidents/stream for real-time SSE events.
     */
    @PostMapping("/trigger")
    public ResponseEntity<Map<String, String>> triggerIncident() {
        log.info("[API] Incident response pipeline triggered");

        // Run pipeline in background thread so HTTP returns immediately
        executor.submit(() -> {
            try {
                IncidentReport result = workflow.runPipeline();
                log.info("[API] Pipeline completed for {}", result.getIncidentId());
            } catch (Exception e) {
                log.error("[API] Pipeline error: {}", e.getMessage(), e);
            }
        });

        return ResponseEntity.accepted()
            .body(Map.of(
                "status",  "PIPELINE_STARTED",
                "message", "Incident response pipeline is running. Watch /api/incidents/stream for events.",
                "stream",  "/api/incidents/stream"
            ));
    }

    // ─────────────────────────────────────────────────────────────────────
    //  2. SSE stream – real-time agent events
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Server-Sent Events endpoint.
     * Connect with: curl -N <a href="http://localhost:8080/api/incidents/stream">...</a>
     * Or use EventSource in JavaScript.
     */
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamEvents() {
        SseEmitter emitter = new SseEmitter(300_000L); // 5-minute timeout
        emitters.add(emitter);

        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(()    -> emitters.remove(emitter));
        emitter.onError(e      -> emitters.remove(emitter));

        // Send a welcome event
        try {
            emitter.send(SseEmitter.event()
                .name("connected")
                .data(Map.of("message", "Connected to Incident Response SSE stream")));
        } catch (IOException e) {
            log.warn("Could not send welcome SSE event: {}", e.getMessage());
        }

        return emitter;
    }

    /**
     * Listens for AgentEvent application events and broadcasts to all SSE clients.
     */
    @Async
    @EventListener
    public void onAgentEvent(AgentEvent event) {
        Map<String, String> payload = Map.of(
            "agent",     event.getAgentName(),
            "status",    event.getStatus(),
            "message",   event.getMessage(),
            "timestamp", event.getTimestamp().toString()
        );

        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event()
                    .name("agent-event")
                    .data(payload));
            } catch (IOException e) {
                emitters.remove(emitter);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  3. Incident CRUD
    // ─────────────────────────────────────────────────────────────────────

    @GetMapping("/{incidentId}")
    public ResponseEntity<IncidentReport> getIncident(@PathVariable String incidentId) {
        IncidentReport report = workflow.getIncident(incidentId);
        if (report == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(report);
    }

    @GetMapping
    public ResponseEntity<Map<String, IncidentReport>> getAllIncidents() {
        return ResponseEntity.ok(workflow.getAllIncidents());
    }

    // ─────────────────────────────────────────────────────────────────────
    //  4. Human-in-the-loop approval
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Human operator approves the AI's remediation recommendation.
     * This is the safety gate – the system NEVER auto-applies production changes.
     */
    @PostMapping("/{incidentId}/approve")
    public ResponseEntity<IncidentReport> approveRemediation(
            @PathVariable String incidentId) {
        try {
            IncidentReport report = workflow.approveRemediation(incidentId);
            log.info("[API] Human approved remediation for incident {}", incidentId);
            return ResponseEntity.ok(report);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest()
                .body(null);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    //  5. Health + system info
    // ─────────────────────────────────────────────────────────────────────

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status",       "UP",
            "agents",       java.util.List.of("MonitorAgent", "AnalyzerAgent", "RemediatorAgent"),
            "mcp_server",   "CiscoIseMcpServer (simulated)",
            "active_stream_connections", emitters.size(),
            "total_incidents", workflow.getAllIncidents().size()
        ));
    }
}
