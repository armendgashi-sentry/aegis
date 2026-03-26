import type { Verdict } from "./types.js";

/** Base error for all Aegis SDK errors. */
export class AegisError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AegisError";
  }
}

/** Raised when an action is blocked by Aegis policy. */
export class AegisBlocked extends AegisError {
  public readonly verdict: Verdict;

  constructor(verdict: Verdict) {
    super(`Blocked by Aegis: ${verdict.reason} [${verdict.source}]`);
    this.name = "AegisBlocked";
    this.verdict = verdict;
  }
}

/** Raised when the Aegis API is unreachable. */
export class AegisConnectionError extends AegisError {
  constructor(message: string) {
    super(message);
    this.name = "AegisConnectionError";
  }
}
