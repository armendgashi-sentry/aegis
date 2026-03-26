/**
 * Vercel AI SDK adapter for Aegis.
 *
 * Wraps tool calls with Aegis guardrails so that shell/command-execution
 * tools are checked before the AI model's tool call is executed.
 *
 * @example
 * ```ts
 * import { AegisClient } from "@aegis/sdk";
 * import { createAegisToolGuard } from "@aegis/sdk/adapters/vercel-ai";
 *
 * const client = new AegisClient();
 * const guard = createAegisToolGuard(client);
 *
 * // Before executing a tool call from the model:
 * const verdict = await guard.checkToolCall("shell", { command: "nmap -sV target" });
 * if (verdict.decision === "deny") {
 *   // Return error to model instead of executing
 * }
 * ```
 */

import type { AegisClient } from "../client.js";
import type { Verdict } from "../types.js";

export interface AegisToolGuard {
  /** Check a tool call against Aegis policies. */
  checkToolCall(
    toolName: string,
    args: Record<string, unknown>
  ): Promise<Verdict>;
}

/**
 * Create a tool guard for Vercel AI SDK tool calls.
 *
 * Inspects tool arguments for `command` fields and evaluates them
 * through Aegis. Non-command tools are auto-allowed.
 */
export function createAegisToolGuard(client: AegisClient): AegisToolGuard {
  return {
    async checkToolCall(
      toolName: string,
      args: Record<string, unknown>
    ): Promise<Verdict> {
      // Check for shell-like tool calls
      const command =
        typeof args.command === "string"
          ? args.command
          : typeof args.cmd === "string"
            ? args.cmd
            : null;

      if (command) {
        return client.evaluateShell({ command, toolName });
      }

      // Check for HTTP-like tool calls
      const method =
        typeof args.method === "string" ? args.method : null;
      const url = typeof args.url === "string" ? args.url : null;

      if (method && url) {
        return client.evaluateHttp({
          method,
          url,
          headers: args.headers as Record<string, string> | undefined,
          body: typeof args.body === "string" ? args.body : undefined,
        });
      }

      // Unknown tool type — allow by default
      return {
        decision: "allow",
        reason: "Non-command tool call — not evaluated",
        source: "sdk:vercel-ai",
      };
    },
  };
}
