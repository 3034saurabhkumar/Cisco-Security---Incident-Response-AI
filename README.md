# 🛡️ Automated Incident Response AI
### Spring Boot + Spring AI + Custom MCP Server

An agentic AI system that autonomously monitors Cisco ISE security logs,
analyzes threats with an LLM, and proposes sandboxed firewall rules —
all coordinated through a custom MCP (Model Context Protocol) server.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    REST API + SSE Stream                            │
│  POST /api/incidents/trigger    GET /api/incidents/stream           │
│  GET  /api/incidents/{id}       POST /api/incidents/{id}/approve    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │  IncidentResponseWorkflow  │  (Orchestrator)
              └─────────────┬─────────────┘
                            │ Sequential Pipeline
          ┌─────────────────┼──────────────────┐
          │                 │                  │
    ┌─────▼──────┐   ┌──────▼─────┐   ┌───────▼──────┐
    │  MONITOR   │   │  ANALYZER  │   │  REMEDIATOR  │
    │  Agent 1   │──▶│  Agent 2   │──▶│   Agent 3    │
    │            │   │            │   │              │
    │ Scan ISE   │   │ FP detect  │   │ Sandbox rule │
    │ logs via   │   │ + LLM      │   │ + block IP   │
    │ MCP tool   │   │ reasoning  │   │ via MCP      │
    └────────────┘   └────────────┘   └──────────────┘
          │                │                  │
          └────────────────┴──────────────────┘
                           │  MCP Tool Calls
              ┌────────────▼──────────────────────┐
              │      CiscoIseMcpServer (MCP)       │
              │  @Tool  getSecurityLogs()          │
              │  @Tool  getEndpointStatus()        │
              │  @Tool  blockEndpoint()            │
              │  @Tool  testRuleInSandbox()        │
              │  @Tool  getActivePolicies()        │
              └───────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │  Anthropic Claude       │
              │  (claude-sonnet-4)      │
              │  via Spring AI          │
              └─────────────────────────┘
```

---

## Project Structure

```
incident-response-ai/
├── pom.xml
└── src/main/java/com/security/incident/
    ├── IncidentResponseApplication.java        ← Spring Boot entry point
    │
    ├── mcp/
    │   ├── service/
    │   │   └── CiscoIseMcpServer.java          ← MCP Server (@Tool methods)
    │   └── model/
    │       ├── LogEntry.java                   ← ISE log event model
    │       └── SecurityModels.java             ← Endpoint/Block/Sandbox models
    │
    ├── agents/
    │   ├── MonitorAgent.java                   ← Agent 1: Log scanning
    │   ├── AnalyzerAgent.java                  ← Agent 2: Threat analysis
    │   └── RemediatorAgent.java                ← Agent 3: Rule + block
    │
    ├── workflow/
    │   ├── IncidentResponseWorkflow.java       ← Pipeline orchestrator
    │   └── IncidentReport.java                 ← Shared state carrier
    │
    ├── events/
    │   └── AgentEvent.java                     ← SSE broadcast events
    │
    ├── config/
    │   └── AgentConfig.java                    ← Spring AI + MCP wiring
    │
    └── controller/
        └── IncidentController.java             ← REST + SSE endpoints
```

---

## Tech Stack

| Component       | Technology                          |
|-----------------|-------------------------------------|
| Framework       | Spring Boot 3.3 + Java 21           |
| AI Orchestration| Spring AI 1.0.0                     |
| LLM             | Anthropic Claude (claude-sonnet-4)  |
| MCP Server      | Spring AI MCP Server Starter        |
| MCP Protocol    | @Tool annotations + stdio/SSE       |
| Streaming       | Spring MVC SSE (SseEmitter)         |
| Build           | Maven                               |

---

## Setup & Run

### 1. Prerequisites
- Java 21+
- Maven 3.9+
- Anthropic API Key

### 2. Set your API key

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Build & run

```bash
cd incident-response-ai
mvn clean package -DskipTests
java -jar target/incident-response-ai-1.0.0.jar
```

---

## API Usage

### Trigger the 3-agent pipeline

```bash
curl -X POST http://localhost:8080/api/incidents/trigger
```

Response:
```json
{
  "status": "PIPELINE_STARTED",
  "message": "Incident response pipeline is running...",
  "stream": "/api/incidents/stream"
}
```

### Watch real-time SSE events (in another terminal)

```bash
curl -N http://localhost:8080/api/incidents/stream
```

You'll see events like:
```
event: agent-event
data: {"agent":"MonitorAgent","status":"STARTED","message":"Scanning Cisco ISE logs..."}

event: agent-event
data: {"agent":"MonitorAgent","status":"COMPLETED","message":"Found 2 suspicious IPs: [185.220.101.47, 198.199.67.82]"}

event: agent-event
data: {"agent":"AnalyzerAgent","status":"STARTED","message":"Analyzing IP 185.220.101.47..."}

event: agent-event
data: {"agent":"RemediatorAgent","status":"COMPLETED","message":"Sandbox APPROVED, block applied, rollback: RBK-1002"}
```

### Get incident report

```bash
curl http://localhost:8080/api/incidents/INC-ABC12345
```

### Approve the AI's recommended remediation (human-in-the-loop)

```bash
curl -X POST http://localhost:8080/api/incidents/INC-ABC12345/approve
```

---

## Agent Decision Logic

```
MonitorAgent
    │ Calls: getSecurityLogs(50, "ALL")
    │ Flags IPs with: auth_attempts > 5, EventType IN [BRUTE_FORCE, PORT_SCAN...]
    ▼
    Suspicious IPs found?
    ├── NO  → Close incident: CLEAN
    └── YES ▼
        AnalyzerAgent
            │ Calls: getEndpointStatus(primaryIp)
            │ LLM evaluates: threat score, posture, compliance tags, ISE profile
            ▼
            Verdict?
            ├── FALSE_POSITIVE        → Close: FALSE_POSITIVE (no action)
            ├── confidence < 0.6      → Close: ESCALATED (human SOC review)
            └── GENUINE_THREAT ▼
                RemediatorAgent
                    │ Designs FTD block rule
                    │ Calls: testRuleInSandbox(...)
                    │ Sandbox result?
                    │   REJECT / false_positives found → DEFERRED (human review)
                    │   APPROVE ▼
                    │ Calls: blockEndpoint(ip, reason, QUARANTINE)
                    ▼
                    Status: AWAITING_APPROVAL
                    (human must call /approve to push to production)
```

---

## MCP Server Tools

The `CiscoIseMcpServer` exposes 5 tools via `@Tool` annotations:

| Tool | Description |
|------|-------------|
| `getSecurityLogs` | RADIUS/TACACS log stream with auth events |
| `getEndpointStatus` | ISE endpoint profile + posture + threat score |
| `blockEndpoint` | Quarantine via ISE CoA + assign quarantine VLAN |
| `testRuleInSandbox` | Validate FTD ACL rule against simulated traffic |
| `getActivePolicies` | List ISE AuthZ policies + FTD ACL rules |

These tools are auto-registered by Spring AI's MCP Server Starter and available:
- **In-process**: via `MethodToolCallbackProvider` (used by agents in this app)
- **Via MCP stdio**: any external MCP client (Claude Desktop, etc.) can connect

---

## Extending to Production

| Area | Production Implementation |
|------|--------------------------|
| MCP Server | Replace simulated methods with real **Cisco ISE ERS API** calls |
| Firewall | Integrate with **Cisco FMC REST API** for real FTD rule pushes |
| Persistence | Replace in-memory store with **PostgreSQL** or **Redis** |
| Auth | Add **OAuth2/JWT** to the REST API |
| Multi-threat | Run agents in **parallel** for multiple IPs (CompletableFuture) |
| Notifications | Add **PagerDuty / Slack** webhooks on ESCALATED status |
| Audit log | Write to **Splunk** or **Elastic** for SIEM integration |

---

## Learning Outcomes (SDE Transition)

This project demonstrates:
- ✅ **Spring Boot 3** – REST APIs, SSE streaming, async processing
- ✅ **Spring AI** – ChatClient, tool calling, agentic loops
- ✅ **MCP Protocol** – Custom server with @Tool annotations
- ✅ **Agent Design Patterns** – Monitor → Analyze → Remediate pipeline
- ✅ **Human-in-the-loop** – Safety gate before production changes
- ✅ **Domain-Driven Design** – Rich domain model (IncidentReport)
- ✅ **Event-Driven** – ApplicationEventPublisher + @EventListener
