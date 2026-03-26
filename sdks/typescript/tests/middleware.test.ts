import { describe, it, expect, vi } from "vitest";
import { AegisClient } from "../src/client.js";
import { AegisBlocked } from "../src/errors.js";
import { guardedTool, createGuard, createHttpGuard } from "../src/middleware.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function jsonResponse(data: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

describe("guardedTool", () => {
  it("allows and executes when verdict is allow", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "allow", reason: "safe", source: "policy" })
    );

    const client = new AegisClient();
    const fn = vi.fn().mockReturnValue("output");

    const guarded = guardedTool(fn, {
      client,
      extractCommand: (cmd: string) => cmd,
    });

    const result = await guarded("ls -la");
    expect(result).toBe("output");
    expect(fn).toHaveBeenCalledWith("ls -la");
  });

  it("throws AegisBlocked when verdict is deny", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        decision: "deny",
        reason: "blocked: rm -rf",
        source: "builtin:shell",
      })
    );

    const client = new AegisClient();
    const fn = vi.fn();

    const guarded = guardedTool(fn, {
      client,
      extractCommand: (cmd: string) => cmd,
    });

    await expect(guarded("rm -rf /tmp")).rejects.toThrow(AegisBlocked);
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("createGuard", () => {
  it("returns verdict for command", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "deny", reason: "blocked", source: "shell" })
    );

    const client = new AegisClient();
    const guard = createGuard({ client });
    const verdict = await guard("rm -rf /");
    expect(verdict.decision).toBe("deny");
  });
});

describe("createHttpGuard", () => {
  it("checks HTTP requests through Aegis", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "allow", reason: "in scope", source: "policy" })
    );

    const client = new AegisClient();
    const guard = createHttpGuard({ client });
    const verdict = await guard("GET", "https://app.acme.com/api");
    expect(verdict.decision).toBe("allow");
  });
});
