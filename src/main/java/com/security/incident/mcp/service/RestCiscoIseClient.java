package com.security.incident.mcp.service;

import com.security.incident.mcp.model.LogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.*;

/**
 * Real-world implementation of CiscoIseClient using ISE ERS (External RESTful
 * Services).
 * 
 * NOTE: Log collection from Cisco ISE is typically done via pxGrid or Syslog.
 * This implementation uses ERS for configuration and status, and maintains a
 * simulated
 * log stream for demonstration purposes.
 */
@Component
public class RestCiscoIseClient implements CiscoIseClient {

    private static final Logger log = LoggerFactory.getLogger(RestCiscoIseClient.class);

    private final RestClient restClient;

    @Value("${cisco.ise.url:https://ise-node.corp.local:24df443}")
    private String iseUrl;

    public RestCiscoIseClient(RestClient.Builder restClientBuilder,
            @Value("${cisco.ise.username:admin}") String username,
            @Value("${cisco.ise.password:Cisco123!}") String password) {
        this.restClient = restClientBuilder
                .baseUrl(iseUrl)
                .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
                .defaultHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .defaultHeader("Authorization",
                        "Basic " + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()))
                .build();
    }

    @Override
    public List<LogEntry> getSecurityLogs(int count, String severityFilter) {
        log.info("[ISE:REST] Fetching security logs (Note: This is partially simulated as ERS is not a log stream)");
        // In a real scenario, this would likely query a log aggregator or use pxGrid.
        // For this demo, we can call an ERS endpoint if logs are available there,
        // but here we demonstrate the intent.
        return List.of();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> getEndpointStatus(String ipAddress) {
        log.info("[ISE:REST] Querying status for IP: {}", ipAddress);
        try {
            // 1. Get Endpoint ID by IP
            Map<String, Object> searchResult = restClient.get()
                    .uri("/ers/config/endpoint?filter=ipAddress.EQ." + ipAddress)
                    .retrieve()
                    .body(Map.class);

            // 2. Fetch full details if found
            if (searchResult != null && searchResult.containsKey("SearchResult")) {
                Map<String, Object> res = (Map<String, Object>) searchResult.get("SearchResult");
                List<Map<String, Object>> resources = (List<Map<String, Object>>) res.get("resources");
                if (!resources.isEmpty()) {
                    String id = (String) resources.get(0).get("id");
                    return restClient.get()
                            .uri("/ers/config/endpoint/" + id)
                            .retrieve()
                            .body(Map.class);
                }
            }
        } catch (Exception e) {
            log.error("[ISE:REST] Failed to fetch endpoint status: {}", e.getMessage());
        }
        return Map.of("ip_address", ipAddress, "error", "Endpoint not found or ISE unreachable");
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> blockEndpoint(String ipAddress, String reason, String blockAction) {
        log.warn("[ISE:REST] Applying ANC Policy (QUARANTINE) to IP: {}", ipAddress);
        try {
            // Apply Adaptive Network Control (ANC) Policy for Quarantining
            Map<String, String> body = Map.of(
                    "operation", "apply",
                    "policyName", "ANC_QUARANTINE",
                    "ipAddress", ipAddress);

            return restClient.post()
                    .uri("/ers/config/ancpolicy/apply")
                    .body(body)
                    .retrieve()
                    .body(Map.class);

        } catch (Exception e) {
            log.error("[ISE:REST] Failed to block endpoint: {}", e.getMessage());
            return Map.of("success", false, "error", e.getMessage());
        }
    }

    @Override
    public Map<String, Object> testRuleInSandbox(String sourceIp, String ruleName, String action, String protocol,
            String portRange) {
        log.info("[ISE:REST] Testing rule {} in sandbox", ruleName);
        // This would typically call a Cisco FMC/FTD API or a custom sandbox
        // environment.
        return Map.of("passed", true, "simulation", "Mocked sandbox result for REST client");
    }

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, Object> getActivePolicies() {
        log.info("[ISE:REST] Fetching active authorization policies");
        try {
            return restClient.get()
                    .uri("/ers/config/authorizationpolicy")
                    .retrieve()
                    .body(Map.class);
        } catch (Exception e) {
            log.error("[ISE:REST] Failed to fetch policies: {}", e.getMessage());
            return Map.of("error", e.getMessage());
        }
    }
}
