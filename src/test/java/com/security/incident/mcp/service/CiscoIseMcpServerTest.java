package com.security.incident.mcp.service;

import com.security.incident.mcp.model.LogEntry;
import com.security.incident.mcp.model.LogEntry.EventType;
import com.security.incident.mcp.model.LogEntry.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class CiscoIseMcpServerTest {

    private CiscoIseMcpServer mcpServer;

    @Mock
    private CiscoIseClient iseClient;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Manually inject the mock via the constructor wrapped in Optional
        mcpServer = new CiscoIseMcpServer(Optional.of(iseClient));
    }

    @Test
    void testGetSecurityLogs() {
        // Arrange
        List<LogEntry> simulatedLogs = generateSimulatedLogs(5);
        when(iseClient.getSecurityLogs(5, "ALL")).thenReturn(simulatedLogs);

        // Act
        List<LogEntry> logs = mcpServer.getSecurityLogs(5, "ALL");

        // Assert
        assertNotNull(logs);
        assertEquals(5, logs.size());
        assertEquals("EVT-9000", logs.get(0).eventId());
    }

    @Test
    void testGetEndpointStatus() {
        // Arrange
        String ip = "1.2.3.4";
        Map<String, Object> simulatedStatus = Map.of(
                "ip_address", ip,
                "mac_address", deterministicMac(ip),
                "threat_score", 45);
        when(iseClient.getEndpointStatus(ip)).thenReturn(simulatedStatus);

        // Act
        Map<String, Object> status = mcpServer.getEndpointStatus(ip);

        // Assert
        assertNotNull(status);
        assertEquals(ip, status.get("ip_address"));
        assertEquals(45, status.get("threat_score"));
    }

    // ── Transferred Simulation Logic (now available to tests) ────────────────

    private static final Set<String> THREAT_INTEL_IPS = Set.of(
            "185.220.101.47", "198.199.67.82", "103.21.244.0", "45.33.32.156");

    public List<LogEntry> generateSimulatedLogs(int count) {
        List<LogEntry> logs = new ArrayList<>();
        Random rng = new Random(42);

        List<String> ipPool = List.of(
                "185.220.101.47", "198.199.67.82", "10.0.1.50",
                "192.168.10.5", "172.16.44.23", "10.10.20.88",
                "103.21.244.0", "192.168.1.102", "172.16.0.55");

        EventType[] types = EventType.values();
        Severity[] severities = { Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL, Severity.HIGH };

        for (int i = 0; i < count; i++) {
            String ip = ipPool.get(rng.nextInt(ipPool.size()));
            boolean isThreat = THREAT_INTEL_IPS.contains(ip);

            EventType type = isThreat
                    ? (rng.nextBoolean() ? EventType.BRUTE_FORCE : EventType.LATERAL_MOVEMENT)
                    : types[rng.nextInt(types.length)];

            Severity sev = isThreat ? Severity.CRITICAL : severities[rng.nextInt(severities.length)];
            int attempts = isThreat ? (50 + rng.nextInt(200)) : (rng.nextInt(8));

            logs.add(new LogEntry(
                    "EVT-" + (9000 + i),
                    Instant.now().minus(i * 2L, ChronoUnit.MINUTES),
                    ip,
                    "10.0.0.1",
                    type,
                    isThreat ? "unknown" : "user" + rng.nextInt(100) + "@corp.local",
                    deterministicMac(ip),
                    "GigabitEthernet1/" + rng.nextInt(48),
                    isThreat ? "5400.1 Authentication failed" : null,
                    attempts,
                    sev,
                    String.format("[ISE] %s from %s – %d attempts – %s", type, ip, attempts, sev)));
        }
        return logs;
    }

    public String deterministicMac(String ip) {
        int hash = Math.abs(ip.hashCode());
        return String.format("AA:BB:%02X:%02X:%02X:%02X",
                (hash >> 24) & 0xFF, (hash >> 16) & 0xFF,
                (hash >> 8) & 0xFF, hash & 0xFF);
    }
}
