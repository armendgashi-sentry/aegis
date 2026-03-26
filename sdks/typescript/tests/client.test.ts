import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AegisClient } from "../src/client.js";
import { AegisConnectionError, AegisError } from "../src/errors.js";

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function jsonResponse(data: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(JSON.stringify(data)),
  } as Response;
}

describe("AegisClient", () => {
  let client: AegisClient;

  beforeEach(() => {
    client = new AegisClient({ baseUrl: "http://localhost:19002" });
    mockFetch.mockReset();
  });

  // -- health / stats -------------------------------------------------------

  describe("health", () => {
    it("returns status ok", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));
      const result = await client.health();
      expect(result).toEqual({ status: "ok" });
      expect(mockFetch).toHaveBeenCalledWith(
        "http://localhost:19002/api/health",
        expect.objectContaining({ method: "GET" })
      );
    });
  });

  describe("stats", () => {
    it("returns aggregate stats", async () => {
      const data = { total: 100, allowed: 80, denied: 20, version: "0.1.0", status: "running" };
      mockFetch.mockResolvedValueOnce(jsonResponse(data));
      const result = await client.stats();
      expect(result.total).toBe(100);
      expect(result.allowed).toBe(80);
      expect(result.denied).toBe(20);
    });
  });

  // -- evaluate -------------------------------------------------------------

  describe("evaluateShell", () => {
    it("returns allow for safe commands", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ decision: "allow", reason: "safe", source: "policy" })
      );
      const verdict = await client.evaluateShell({ command: "nmap -sV 10.0.0.1" });
      expect(verdict.decision).toBe("allow");
      expect(verdict.reason).toBe("safe");
    });

    it("returns deny for dangerous commands", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          decision: "deny",
          reason: "blocked pattern: rm -rf",
          source: "builtin:shell",
        })
      );
      const verdict = await client.evaluateShell({ command: "rm -rf /tmp" });
      expect(verdict.decision).toBe("deny");
    });

    it("sends tool_name and cwd", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ decision: "allow", reason: "", source: "" })
      );
      await client.evaluateShell({
        command: "ls",
        toolName: "Bash",
        cwd: "/home/user",
      });
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.tool_name).toBe("Bash");
      expect(body.cwd).toBe("/home/user");
    });
  });

  describe("evaluateHttp", () => {
    it("returns deny for blocked methods", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          decision: "deny",
          reason: "DELETE blocked",
          source: "builtin:http",
        })
      );
      const verdict = await client.evaluateHttp({
        method: "DELETE",
        url: "https://app.acme.com/api/users/1",
      });
      expect(verdict.decision).toBe("deny");
    });

    it("sends headers and body", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ decision: "allow", reason: "", source: "" })
      );
      await client.evaluateHttp({
        method: "POST",
        url: "https://app.acme.com/api",
        headers: { "content-type": "application/json" },
        body: '{"q":"test"}',
      });
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.headers["content-type"]).toBe("application/json");
      expect(body.body).toBe('{"q":"test"}');
    });
  });

  // -- secrets --------------------------------------------------------------

  describe("secretsStatus", () => {
    it("returns secret config status", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ enabled: true, rules: [{ name: "github" }], strip_env_count: 3 })
      );
      const status = await client.secretsStatus();
      expect(status.enabled).toBe(true);
      expect(status.rules).toHaveLength(1);
      expect(status.strip_env_count).toBe(3);
    });
  });

  // -- snapshots ------------------------------------------------------------

  describe("createSnapshot", () => {
    it("returns snapshot info", async () => {
      const snap = { id: "abc123", method: "git", root: "/project", timestamp: "2026-01-01T00:00:00Z" };
      mockFetch.mockResolvedValueOnce(jsonResponse(snap));
      const result = await client.createSnapshot();
      expect(result.id).toBe("abc123");
      expect(result.method).toBe("git");
    });
  });

  describe("snapshotDiff", () => {
    it("returns file diff", async () => {
      const diff = { added: ["new.txt"], modified: ["README.md"], deleted: [], summary: "2 files changed" };
      mockFetch.mockResolvedValueOnce(jsonResponse(diff));
      const result = await client.snapshotDiff("abc123");
      expect(result.added).toContain("new.txt");
      expect(result.modified).toContain("README.md");
    });
  });

  describe("snapshotRollback", () => {
    it("returns true on success", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      const result = await client.snapshotRollback("abc123");
      expect(result).toBe(true);
    });
  });

  describe("snapshotCommit", () => {
    it("sends commit message", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));
      await client.snapshotCommit("abc123", "accept changes");
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.message).toBe("accept changes");
    });
  });

  // -- audit logs -----------------------------------------------------------

  describe("logs", () => {
    it("returns log file list", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          logs: [
            { name: "aegis-2026-01-01.jsonl", path: "/logs/aegis-2026-01-01.jsonl", size: 1024, session: "2026-01-01", current: true },
          ],
        })
      );
      const logs = await client.logs();
      expect(logs).toHaveLength(1);
      expect(logs[0].current).toBe(true);
    });
  });

  describe("logEntries", () => {
    it("returns audit entries", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({
          entries: [
            { id: "1", timestamp: "2026-01-01T00:00:00Z", decision: "deny", reason: "blocked", source: "shell", method: "shell", url: "", host: "", layer: "shell" },
          ],
        })
      );
      const entries = await client.logEntries({ file: "/logs/test.jsonl", limit: 10 });
      expect(entries).toHaveLength(1);
      expect(entries[0].decision).toBe("deny");
    });
  });

  // -- error handling -------------------------------------------------------

  describe("error handling", () => {
    it("throws AegisConnectionError on network failure", async () => {
      mockFetch.mockRejectedValueOnce(new TypeError("fetch failed"));
      await expect(client.health()).rejects.toThrow(AegisConnectionError);
    });

    it("throws AegisError on non-OK response", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ error: "not found" }, 404));
      await expect(client.snapshotDiff("nonexistent")).rejects.toThrow(AegisError);
    });
  });
});
