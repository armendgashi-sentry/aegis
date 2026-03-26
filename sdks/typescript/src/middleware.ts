import { AegisClient } from "./client.js";
import { AegisBlocked } from "./errors.js";
import type { AegisClientOptions, Verdict } from "./types.js";

/**
 * Wrap a tool function with Aegis guardrails.
 *
 * Before the tool runs, the command is checked through Aegis.
 * If denied, throws `AegisBlocked`.
 *
 * @example
 * ```ts
 * import { guardedTool, AegisClient } from "@aegis/sdk";
 *
 * const client = new AegisClient();
 *
 * const safeExec = guardedTool(
 *   async (cmd: string) => { ... },
 *   { client, extractCommand: (cmd) => cmd }
 * );
 *
 * await safeExec("ls -la"); // checked then executed
 * ```
 */
export function guardedTool<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => TReturn | Promise<TReturn>,
  options: {
    client: AegisClient;
    extractCommand: (...args: TArgs) => string;
    toolName?: string;
  }
): (...args: TArgs) => Promise<TReturn> {
  const { client, extractCommand, toolName } = options;

  return async (...args: TArgs): Promise<TReturn> => {
    const command = extractCommand(...args);
    const verdict = await client.evaluateShell({
      command,
      toolName: toolName ?? "shell",
    });

    if (verdict.decision === "deny") {
      throw new AegisBlocked(verdict);
    }

    return fn(...args);
  };
}

/**
 * Create a guard function that checks commands before execution.
 *
 * @example
 * ```ts
 * const guard = createGuard({ client });
 * const verdict = await guard("rm -rf /");
 * // verdict.decision === "deny"
 * ```
 */
export function createGuard(
  options: { client: AegisClient; toolName?: string }
): (command: string) => Promise<Verdict> {
  const { client, toolName } = options;
  return (command: string) =>
    client.evaluateShell({ command, toolName: toolName ?? "shell" });
}

/**
 * Options for the HTTP request guard middleware.
 */
export interface HttpGuardOptions {
  client: AegisClient;
  onDeny?: (verdict: Verdict, req: { method: string; url: string }) => void;
}

/**
 * Create an HTTP request guard that can be used as middleware.
 *
 * Returns a function that checks requests against Aegis policies.
 * Compatible with any HTTP framework via the simple request interface.
 *
 * @example
 * ```ts
 * // Express-style middleware
 * const guard = createHttpGuard({ client });
 *
 * app.use(async (req, res, next) => {
 *   const verdict = await guard(req.method, `${req.protocol}://${req.hostname}${req.url}`);
 *   if (verdict.decision === "deny") {
 *     return res.status(403).json({ error: verdict.reason });
 *   }
 *   next();
 * });
 * ```
 */
export function createHttpGuard(
  options: HttpGuardOptions
): (
  method: string,
  url: string,
  headers?: Record<string, string>,
  body?: string
) => Promise<Verdict> {
  const { client } = options;
  return (
    method: string,
    url: string,
    headers?: Record<string, string>,
    body?: string
  ) => client.evaluateHttp({ method, url, headers, body });
}
