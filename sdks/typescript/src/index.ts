// Core client
export { AegisClient } from "./client.js";

// Types
export type {
  AegisClientOptions,
  AuditEntry,
  Decision,
  EvalHttpOptions,
  EvalShellOptions,
  FileDiff,
  LogEntriesOptions,
  LogFile,
  SecretApplied,
  SecretStatus,
  SnapshotInfo,
  Stats,
  Verdict,
} from "./types.js";

// Errors
export { AegisBlocked, AegisConnectionError, AegisError } from "./errors.js";

// Middleware / guards
export { createGuard, createHttpGuard, guardedTool } from "./middleware.js";
export type { HttpGuardOptions } from "./middleware.js";
