package com.security.incident;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Automated Incident Response AI
 *
 *  Architecture:
 *  ┌────────────────────────────────────────────────────────────────┐
 *  │  REST API (/api/incidents)  +  SSE Stream (/api/incidents/stream)│
 *  └───────────────────────────┬────────────────────────────────────┘
 *                              │
 *                   IncidentResponseWorkflow
 *                              │
 *             ┌────────────────┼─────────────────┐
 *             ▼                ▼                  ▼
 *       MonitorAgent     AnalyzerAgent     RemediatorAgent
 *       (Scan logs)      (FP detection)    (Sandbox + Block)
 *             │                │                  │
 *             └────────────────┴──────────────────┘
 *                              │
 *                    CiscoIseMcpServer  (MCP)
 *                    ┌─────────────────────────┐
 *                    │  getSecurityLogs         │
 *                    │  getEndpointStatus       │
 *                    │  blockEndpoint           │
 *                    │  testRuleInSandbox       │
 *                    │  getActivePolicies       │
 *                    └─────────────────────────┘
 *                              │
 *                    Anthropic Claude (LLM)
 *                    via Spring AI ChatClient
 */
@SpringBootApplication
@EnableAsync   // for async SSE broadcasting
public class IncidentResponseApplication {

    public static void main(String[] args) {
        SpringApplication.run(IncidentResponseApplication.class, args);
    }
}
