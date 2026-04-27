package com.security.incident.config;

import com.security.incident.mcp.service.CiscoIseMcpServer;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.SimpleLoggerAdvisor;
import org.springframework.ai.mcp.SyncMcpToolCallbackProvider;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * Spring AI Configuration
 *
 * Key wiring:
 *  1. CiscoIseMcpServer tools (@Tool methods) → MethodToolCallbackProvider
 *  2. ChatClient.Builder gets those tools registered as function callbacks
 *  3. Each Agent gets its own ChatClient configured with the MCP tools
 *
 * How MCP works here:
 *  - CiscoIseMcpServer is exposed as an MCP server via the
 *    spring-ai-mcp-server-spring-boot-starter (stdio transport by default)
 *  - The @Tool methods are auto-discovered and registered
 *  - Agents use ToolCallbackProvider to make the same tools available
 *    to the ChatClient for in-process tool calling (avoids need for separate process)
 */
@Configuration
public class AgentConfig {

    /**
     * Registers the @Tool-annotated methods from CiscoIseMcpServer
     * as Spring AI tool callbacks that the ChatClient can invoke.
     */
    @Bean
    public ToolCallbackProvider ciscoIseTools(CiscoIseMcpServer mcpServer) {
        return MethodToolCallbackProvider.builder()
            .toolObjects(mcpServer)   // scans for @Tool annotations
            .build();
    }

    /**
     * Base ChatClient.Builder pre-configured with:
     *  – MCP tools (Cisco ISE simulation)
     *  – Request/response logging advisor
     *  – Default system context for all agents
     */
    @Bean
    @Primary
    public ChatClient.Builder chatClientBuilder(
            org.springframework.ai.chat.model.ChatModel chatModel,
            ToolCallbackProvider ciscoIseTools) {

        return ChatClient.builder(chatModel)
            .defaultTools(ciscoIseTools)              // attach MCP tools
            .defaultAdvisors(new SimpleLoggerAdvisor()); // log all LLM I/O
    }
}
