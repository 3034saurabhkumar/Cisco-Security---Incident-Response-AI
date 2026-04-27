package com.security.incident.events;

import java.time.Instant;

/**
 * Spring Application Event published by each agent during execution.
 * The REST controller streams these as Server-Sent Events (SSE) to the client,
 * giving real-time visibility into the agentic pipeline.
 */
public class AgentEvent {

    private final String  agentName;
    private final String  status;      // STARTED | COMPLETED | ERROR | INFO
    private final String  message;
    private final Instant timestamp;

    public AgentEvent(String agentName, String status, String message) {
        this.agentName = agentName;
        this.status    = status;
        this.message   = message;
        this.timestamp = Instant.now();
    }

    public String  getAgentName() { return agentName; }
    public String  getStatus()    { return status; }
    public String  getMessage()   { return message; }
    public Instant getTimestamp() { return timestamp; }

    @Override
    public String toString() {
        return String.format("[%s] %s – %s: %s", timestamp, agentName, status, message);
    }
}
