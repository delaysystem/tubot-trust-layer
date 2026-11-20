import { describe, it, expect } from "bun:test";
import {
  cacheDelete,
  cacheGet,
  cachePut,
  detectCacheKey,
  moderateCacheKey,
  pruneCache,
  rehydrateSpans,
  sha256Hex,
  stripSpanText,
  stripVerdict,
} from "./cache";
import { initDatabase } from "./storage";

/** Minimal Map-backed D1 mock supporting the cache statements. */
function createMockD1() {
  const rows = new Map<string, { value: string; created_at: number; expires_at: number }>();
  const db = {
    rows,
    prepare(query: string) {
      const q = query;
      return {
        _params: [] as any[],
        bind(...values: any[]) {
          this._params = values;
          return this;
        },
        async first() {
          if (q.includes("FROM trust_cache WHERE key = ?")) {
            const row = rows.get(this._params[0]);
            return row ? { value: row.value, expires_at: row.expires_at } : null;
          }
          return null;
        },
        async run() {
          if (q.startsWith("INSERT OR REPLACE INTO trust_cache")) {
            const [key, value, created_at, expires_at] = this._params;
            rows.set(key, { value, created_at, expires_at });
            return { meta: { changes: 1 } };
          }
          if (q.startsWith("DELETE FROM trust_cache WHERE key = ?")) {
            const gone = rows.delete(this._params[0]) ? 1 : 0;
            return { meta: { changes: gone } };
          }
          if (q.startsWith("DELETE FROM trust_cache WHERE expires_at < ?")) {
            let gone = 0;
            for (const [k, v] of rows) {
              if (v.expires_at < this._params[0]) {
                rows.delete(k);
                gone++;
              }
            }
            return { meta: { changes: gone } };
          }
          return { meta: { changes: 0 } }; // CREATE TABLE / INDEX no-ops
        },
      };
    },
  };
  return db as unknown as D1Database & { rows: typeof rows };
}

describe("trust result cache", () => {
  it("hashes stably to 64 hex chars", async () => {
    const a = await sha256Hex("hello");
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(await sha256Hex("hello")).toBe(a);
    expect(await sha256Hex("hello!")).not.toBe(a);
  });

  it("keys every behavior-affecting detect option", async () => {
    const base = await detectCacheKey("text", undefined);
    expect(await detectCacheKey("text", undefined)).toBe(base);
    expect(await detectCacheKey("other", undefined)).not.toBe(base);
    expect(await detectCacheKey("text", { enabledTypes: ["EMAIL"] })).not.toBe(base);
    expect(await detectCacheKey("text", { useLlama: false })).not.toBe(base);
    expect(await detectCacheKey("text", { useClef: false })).not.toBe(base);
    expect(await detectCacheKey("text", { clefThreshold: 0.1 })).not.toBe(base);
    expect(await detectCacheKey("text", { regexOnly: true })).not.toBe(base);
    // Equivalent options share entries.
    expect(await detectCacheKey("text", { enabledTypes: ["EMAIL", "PHONE"] })).toBe(
      await detectCacheKey("text", { enabledTypes: ["PHONE", "EMAIL"] })
    );
  });

  it("keys every behavior-affecting moderate option", async () => {
    const base = await moderateCacheKey("text", undefined);
    expect(await moderateCacheKey("text", undefined)).toBe(base);
    expect(await moderateCacheKey("other", undefined)).not.toBe(base);
    expect(await moderateCacheKey("text", { mode: "warn" })).not.toBe(base);
    expect(await moderateCacheKey("text", { heuristicOnly: true })).not.toBe(base);
    expect(await moderateCacheKey("text", { allowedCategories: ["S7"] })).not.toBe(base);
    expect(await moderateCacheKey("text", { useClef: false })).not.toBe(base);
  });

  it("round-trips values and honors TTL", async () => {
    const db = createMockD1();
    await initDatabase(db);
    expect(await cacheGet(db, "missing")).toBeNull();
    await cachePut(db, "k", "v", 60000, 1000);
    expect(await cacheGet(db, "k", 2000)).toBe("v");
    expect(await cacheGet(db, "k", 61001)).toBeNull();
    expect((db as any).rows.has("k")).toBe(false); // expired rows are deleted
  });

  it("prunes only expired rows and reports the count", async () => {
    const db = createMockD1();
    await cachePut(db, "old", "v", 1000, 1000);
    await cachePut(db, "new", "v", 60000, 1000);
    expect(await pruneCache(db, 5000)).toBe(1);
    expect(await cacheGet(db, "new", 5000)).toBe("v");
    await cacheDelete(db, "new");
    expect(await cacheGet(db, "new", 5000)).toBeNull();
  });

  it("strips span text and rehydrates offsets losslessly", () => {
    const text = "mail amy@example.com now";
    const at = text.indexOf("amy@example.com");
    const stripped = stripSpanText([
      { text: "amy@example.com", type: "EMAIL", start: at, end: at + 15, confidence: 0.99, source: "regex" },
    ]);
    expect(JSON.stringify(stripped)).not.toContain("amy@example.com");
    const spans = rehydrateSpans(text, stripped);
    expect(spans).toHaveLength(1);
    expect(spans[0]).toMatchObject({ text: "amy@example.com", type: "EMAIL", start: at, end: at + 15 });
  });

  it("rejects corrupt cached spans", () => {
    const text = "hello";
    for (const bad of [
      [{ type: "EMAIL", start: 0, end: 99, source: "regex" }],
      [{ type: "EMAIL", start: 3, end: 2, source: "regex" }],
      [{ type: "EMAIL", start: -1, end: 2, source: "regex" }],
      [{ type: 42, start: 0, end: 2, source: "regex" }],
      "not-an-array",
    ]) {
      expect(() => rehydrateSpans(text, bad as any)).toThrow();
    }
  });

  it("strips verdicts to PII-free fields", () => {
    const verdict = stripVerdict({
      safe: false,
      flagged: true,
      action: "block",
      categories: ["Hate Speech"],
      categoryCodes: ["S10"],
      findings: [{ source: "clef-flash", code: "S10", category: "Hate Speech", severity: "high" }],
      executionTimeMs: 123,
      models: ["@cf/cloudflare/clef-flash"],
    });
    expect(verdict).toEqual({
      safe: false,
      flagged: true,
      action: "block",
      categories: ["Hate Speech"],
      categoryCodes: ["S10"],
      findings: [{ source: "clef-flash", code: "S10", category: "Hate Speech", severity: "high" }],
    });
  });
});
