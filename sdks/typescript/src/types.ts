/** Aegis policy decision. */
export type Decision = "allow" | "deny";

/** Result of an Aegis policy evaluation. */
export interface Verdict {
  decision: Decision;
  reason: string;
  source: string;
}

/** A single audit log entry. */
export interface AuditEntry {
  id: string;
  timestamp: string;
  decision: Decision;
  reason: string;
  source: string;
  method: string;
  url: string;
  host: string;
  layer: string;
  headers?: Record<string, string>;
  body?: string;
  content_type?: string;
  secrets_applied?: SecretApplied[];
}

/** Secret injection metadata (values are masked). */
export interface SecretApplied {
  rule_name: string;
  header: string;
  masked_value: string;
}

/** Information about a filesystem snapshot. */
export interface SnapshotInfo {
  id: string;
  method: string;
  root: string;
  timestamp: string;
  branch?: string;
}

/** Filesystem diff relative to a snapshot. */
export interface FileDiff {
  added: string[];
  modified: string[];
  deleted: string[];
  summary: string;
}

/** Secrets configuration status (no secret values exposed). */
export interface SecretStatus {
  enabled: boolean;
  rules: Record<string, unknown>[];
  strip_env_count: number;
}

/** Aggregate request statistics. */
export interface Stats {
  total: number;
  allowed: number;
  denied: number;
  version: string;
  status: string;
}

/** Audit log file metadata. */
export interface LogFile {
  name: string;
  path: string;
  size: number;
  session: string;
  current: boolean;
}

/** Options for creating an AegisClient. */
export interface AegisClientOptions {
  /** Base URL for the Aegis web API. Default: http://127.0.0.1:19002 */
  baseUrl?: string;
  /** Request timeout in milliseconds. Default: 5000 */
  timeout?: number;
}

/** Options for evaluating a shell command. */
export interface EvalShellOptions {
  command: string;
  toolName?: string;
  cwd?: string;
}

/** Options for evaluating an HTTP request. */
export interface EvalHttpOptions {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}

/** Options for reading audit log entries. */
export interface LogEntriesOptions {
  file: string;
  limit?: number;
  decision?: "allow" | "deny";
}
