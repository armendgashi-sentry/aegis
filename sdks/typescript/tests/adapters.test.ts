import { describe, it, expect, vi, beforeEach } from "vitest";
import { AegisClient } from "../src/client.js";
import { createAegisToolGuard } from "../src/adapters/vercel-ai.js";
import { createMcpGuard } from "../src/adapters/mcp.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

beforeEach(() => {
  mockFetch.mockReset();
});

function jsonResponse(data: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

describe("Vercel AI adapter", () => {
  it("checks shell-like tool calls", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "deny", reason: "blocked", source: "shell" })
    );

    const client = new AegisClient();
    const guard = createAegisToolGuard(client);
    const verdict = await guard.checkToolCall("shell", { command: "rm -rf /" });
    expect(verdict.decision).toBe("deny");
  });

  it("checks HTTP-like tool calls", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "allow", reason: "safe", source: "http" })
    );

    const client = new AegisClient();
    const guard = createAegisToolGuard(client);
    const verdict = await guard.checkToolCall("http_request", {
      method: "GET",
      url: "https://app.acme.com/api",
    });
    expect(verdict.decision).toBe("allow");
  });

  it("auto-allows non-command tools", async () => {
    const client = new AegisClient();
    const guard = createAegisToolGuard(client);
    const verdict = await guard.checkToolCall("calculator", { expression: "2+2" });
    expect(verdict.decision).toBe("allow");
    expect(mockFetch).not.toHaveBeenCalled();
  });
});

describe("MCP adapter", () => {
  it("checks shell commands from MCP tool calls", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ decision: "deny", reason: "blocked", source: "shell" })
    );

    const client = new AegisClient();
    const guard = createMcpGuard(client);
    const verdict = await guard.checkToolCall({
      name: "run_command",
      arguments: { command: "rm -rf /" },
    });
    expect(verdict.decision).toBe("deny");
  });

  it("respects allow list", async () => {
    const client = new AegisClient();
    const guard = createMcpGuard(client, { allowList: ["read_file"] });
    const verdict = await guard.checkToolCall({
      name: "read_file",
      arguments: { path: "/etc/passwd" },
    });
    expect(verdict.decision).toBe("allow");
    expect(verdict.source).toContain("allowlist");
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it("respects deny list", async () => {
    const client = new AegisClient();
    const guard = createMcpGuard(client, { denyList: ["dangerous_tool"] });
    const verdict = await guard.checkToolCall({
      name: "dangerous_tool",
      arguments: {},
    });
    expect(verdict.decision).toBe("deny");
    expect(verdict.source).toContain("denylist");
  });

  it("allows tools with no recognized arguments", async () => {
    const client = new AegisClient();
    const guard = createMcpGuard(client);
    const verdict = await guard.checkToolCall({
      name: "get_weather",
      arguments: { city: "NYC" },
    });
    expect(verdict.decision).toBe("allow");
  });
});
