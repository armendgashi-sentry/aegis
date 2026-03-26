/**
 * MCP (Model Context Protocol) adapter for Aegis.
 *
 * Guards MCP tool calls by checking them through Aegis before execution.
 *
 * @example
 * ```ts
 * import { AegisClient } from "@aegis/sdk";
 * import { createMcpGuard } from "@aegis/sdk/adapters/mcp";
 *
 * const client = new AegisClient();
 * const guard = createMcpGuard(client);
 *
 * // In your MCP server's tools/call handler:
 * server.setRequestHandler("tools/call", async (request) => {
 *   const verdict = await guard.checkToolCall(request.params);
 *   if (verdict.decision === "deny") {
 *     return { content: [{ type: "text", text: `Blocked: ${verdict.reason}` }] };
 *   }
 *   // ... proceed with tool execution
 * });
 * ```
 */

import type { AegisClient } from "../client.js";
import type { Verdict } from "../types.js";

/** MCP tool call parameters (subset of the MCP protocol). */
export interface McpToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface McpGuard {
  /** Check an MCP tool call against Aegis policies. */
  checkToolCall(params: McpToolCallParams): Promise<Verdict>;

  /** Tools that are always allowed without checking. */
  allowList: Set<string>;

  /** Tools that are always denied. */
  denyList: Set<string>;
}

export interface McpGuardOptions {
  /** Tool names that are always allowed without Aegis check. */
  allowList?: string[];
  /** Tool names that are always denied. */
  denyList?: string[];
  /** Fields to extract commands from (default: ["command", "cmd"]). */
  commandFields?: string[];
}

/**
 * Create a guard for MCP tool calls.
 *
 * Extracts shell commands from tool arguments and evaluates them
 * through Aegis. Supports allow/deny lists for known tool names.
 */
export function createMcpGuard(
  client: AegisClient,
  options: McpGuardOptions = {}
): McpGuard {
  const allowSet = new Set(options.allowList ?? []);
  const denySet = new Set(options.denyList ?? []);
  const commandFields = options.commandFields ?? ["command", "cmd"];

  return {
    allowList: allowSet,
    denyList: denySet,

    async checkToolCall(params: McpToolCallParams): Promise<Verdict> {
      // Check static lists first
      if (allowSet.has(params.name)) {
        return {
          decision: "allow",
          reason: `Tool "${params.name}" is in the allow list`,
          source: "sdk:mcp:allowlist",
        };
      }

      if (denySet.has(params.name)) {
        return {
          decision: "deny",
          reason: `Tool "${params.name}" is in the deny list`,
          source: "sdk:mcp:denylist",
        };
      }

      const args = params.arguments ?? {};

      // Try to extract a command
      for (const field of commandFields) {
        const val = args[field];
        if (typeof val === "string") {
          return client.evaluateShell({
            command: val,
            toolName: params.name,
          });
        }
      }

      // Try HTTP-like fields
      const method = typeof args.method === "string" ? args.method : null;
      const url = typeof args.url === "string" ? args.url : null;

      if (method && url) {
        return client.evaluateHttp({
          method,
          url,
          headers: args.headers as Record<string, string> | undefined,
          body: typeof args.body === "string" ? args.body : undefined,
        });
      }

      // No recognizable command — allow
      return {
        decision: "allow",
        reason: `No command found in tool "${params.name}" arguments`,
        source: "sdk:mcp",
      };
    },
  };
}
