import type {
  AegisClientOptions,
  AuditEntry,
  EvalHttpOptions,
  EvalShellOptions,
  FileDiff,
  LogEntriesOptions,
  LogFile,
  SecretStatus,
  SnapshotInfo,
  Stats,
  Verdict,
} from "./types.js";
import { AegisConnectionError, AegisError } from "./errors.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:19002";
const DEFAULT_TIMEOUT = 5000;

/**
 * Client for the Aegis web API.
 *
 * @example
 * ```ts
 * const client = new AegisClient();
 * const verdict = await client.evaluateShell({ command: "nmap -sV 10.0.0.1" });
 * if (verdict.decision === "deny") {
 *   console.log(`Blocked: ${verdict.reason}`);
 * }
 * ```
 */
export class AegisClient {
  private readonly baseUrl: string;
  private readonly timeout: number;

  constructor(options: AegisClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.timeout = options.timeout ?? DEFAULT_TIMEOUT;
  }

  // -- internal helpers -----------------------------------------------------

  private async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    let url = `${this.baseUrl}${path}`;
    if (params) {
      const qs = new URLSearchParams(params).toString();
      if (qs) url += `?${qs}`;
    }

    let resp: Response;
    try {
      resp = await fetch(url, {
        method: "GET",
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (err) {
      throw new AegisConnectionError(
        `Cannot connect to Aegis at ${this.baseUrl}: ${err}`
      );
    }

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new AegisError(`Aegis API error ${resp.status}: ${text}`);
    }

    return resp.json() as Promise<T>;
  }

  private async post<T>(path: string, body?: unknown): Promise<T> {
    let resp: Response;
    try {
      resp = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body ?? {}),
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (err) {
      throw new AegisConnectionError(
        `Cannot connect to Aegis at ${this.baseUrl}: ${err}`
      );
    }

    if (!resp.ok) {
      const text = await resp.text().catch(() => "");
      throw new AegisError(`Aegis API error ${resp.status}: ${text}`);
    }

    return resp.json() as Promise<T>;
  }

  // -- health / stats -------------------------------------------------------

  /** Check if Aegis is running. */
  async health(): Promise<{ status: string }> {
    return this.get("/api/health");
  }

  /** Get aggregate request statistics. */
  async stats(): Promise<Stats> {
    return this.get("/api/stats");
  }

  // -- evaluate -------------------------------------------------------------

  /** Check a shell command against Aegis policies. */
  async evaluateShell(options: EvalShellOptions): Promise<Verdict> {
    return this.post<Verdict>("/api/evaluate/shell", {
      command: options.command,
      tool_name: options.toolName ?? "shell",
      ...(options.cwd ? { cwd: options.cwd } : {}),
    });
  }

  /** Check an HTTP request against Aegis policies. */
  async evaluateHttp(options: EvalHttpOptions): Promise<Verdict> {
    return this.post<Verdict>("/api/evaluate/http", {
      method: options.method,
      url: options.url,
      ...(options.headers ? { headers: options.headers } : {}),
      ...(options.body ? { body: options.body } : {}),
    });
  }

  // -- secrets --------------------------------------------------------------

  /** Get secrets configuration status (no secret values exposed). */
  async secretsStatus(): Promise<SecretStatus> {
    return this.get("/api/secrets/status");
  }

  // -- snapshots ------------------------------------------------------------

  /** Create a filesystem snapshot. */
  async createSnapshot(root?: string): Promise<SnapshotInfo> {
    return this.post<SnapshotInfo>("/api/snapshot/create", root ? { root } : {});
  }

  /** Get the diff between a snapshot and the current filesystem state. */
  async snapshotDiff(snapshotId: string): Promise<FileDiff> {
    return this.get(`/api/snapshot/${snapshotId}/diff`);
  }

  /** Rollback the filesystem to a previous snapshot. */
  async snapshotRollback(snapshotId: string): Promise<boolean> {
    const data = await this.post<{ ok?: boolean }>(
      `/api/snapshot/${snapshotId}/rollback`
    );
    return Boolean(data.ok);
  }

  /** Accept changes and commit a snapshot. */
  async snapshotCommit(
    snapshotId: string,
    message?: string
  ): Promise<boolean> {
    const data = await this.post<{ ok?: boolean }>(
      `/api/snapshot/${snapshotId}/commit`,
      message ? { message } : {}
    );
    return Boolean(data.ok);
  }

  // -- audit logs -----------------------------------------------------------

  /** List available audit log files. */
  async logs(): Promise<LogFile[]> {
    const data = await this.get<{ logs: LogFile[] }>("/api/logs");
    return data.logs ?? [];
  }

  /** Read entries from an audit log file. */
  async logEntries(options: LogEntriesOptions): Promise<AuditEntry[]> {
    const params: Record<string, string> = { file: options.file };
    if (options.limit !== undefined) params.limit = String(options.limit);
    if (options.decision) params.decision = options.decision;
    const data = await this.get<{ entries: AuditEntry[] }>(
      "/api/logs/entries",
      params
    );
    return data.entries ?? [];
  }
}
