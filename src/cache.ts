/**
 * PII-free result cache for detect/moderate (D1-backed).
 *
 * Why: provider legs (Workers AI NER, guard, clef-flash) stall for seconds
 * under load, and identical texts are re-scanned across sessions, turns,
 * and lanes. A cache hit answers in milliseconds without touching inference.
 *
 * Privacy: keys are one-way SHA-256 hashes of the canonical request; values
 * store span OFFSETS only (text is re-sliced from the request at lookup, so
 * a cache row is meaningless without the exact input text). Moderation values
 * hold verdicts/categories only, never input text. No tenant identifiers are
 * stored: identical text yields identical spans/verdicts regardless of tenant.
 *
 * Correctness: the key covers every option that can change the output
 * (normalized to effective values), values carry a TTL, and CACHE_VERSION
 * must be bumped whenever scoring logic, models, or default thresholds change.
 */

import { CLEF_SCREEN_THRESHOLD } from "./clef";
import type { DetectedSpan, DetectOptions, PiiType } from "./detector";
import type { ModerateOptions, ModerateResult } from "./moderator";

export const CACHE_VERSION = "v1";
export const CACHE_TTL_MS = 7 * 24 * 3600 * 1000;

export const CACHE_SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS trust_cache (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
)`,
  `CREATE INDEX IF NOT EXISTS idx_trust_cache_expires ON trust_cache(expires_at)`,
];

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sortedJoin(types: readonly string[] | undefined): string {
  return types ? [...types].sort().join(",") : "*";
}

/** Effective detect behavior, normalized so equivalent options share entries. */
export function detectCacheParts(text: string, options?: DetectOptions): unknown[] {
  return [
    CACHE_VERSION,
    "detect",
    text,
    sortedJoin(options?.enabledTypes as readonly string[] | undefined),
    !options?.regexOnly && (options?.useLlama ?? options?.useGranite ?? true),
    options?.useClef !== false,
    options?.clefThreshold ?? CLEF_SCREEN_THRESHOLD,
  ];
}

export function moderateCacheParts(text: string, options?: ModerateOptions): unknown[] {
  return [
    CACHE_VERSION,
    "moderate",
    text,
    options?.mode ?? "block",
    options?.heuristicOnly === true,
    sortedJoin(options?.allowedCategories),
    options?.useClef !== false,
  ];
}

export async function detectCacheKey(text: string, options?: DetectOptions): Promise<string> {
  return `${CACHE_VERSION}:detect:${await sha256Hex(JSON.stringify(detectCacheParts(text, options)))}`;
}

export async function moderateCacheKey(text: string, options?: ModerateOptions): Promise<string> {
  return `${CACHE_VERSION}:moderate:${await sha256Hex(JSON.stringify(moderateCacheParts(text, options)))}`;
}

export async function cacheGet(db: D1Database, key: string, now = Date.now()): Promise<string | null> {
  const row = await db
    .prepare(`SELECT value, expires_at FROM trust_cache WHERE key = ?`)
    .bind(key)
    .first<{ value: string; expires_at: number }>();
  if (!row) return null;
  if (row.expires_at <= now) {
    await db.prepare(`DELETE FROM trust_cache WHERE key = ?`).bind(key).run();
    return null;
  }
  return row.value;
}

export async function cachePut(
  db: D1Database,
  key: string,
  value: string,
  ttlMs: number = CACHE_TTL_MS,
  now = Date.now()
): Promise<void> {
  await db
    .prepare(
      `INSERT OR REPLACE INTO trust_cache (key, value, created_at, expires_at) VALUES (?, ?, ?, ?)`
    )
    .bind(key, value, now, now + ttlMs)
    .run();
}

export async function cacheDelete(db: D1Database, key: string): Promise<void> {
  await db.prepare(`DELETE FROM trust_cache WHERE key = ?`).bind(key).run();
}

export async function pruneCache(db: D1Database, now = Date.now()): Promise<number> {
  const result = await db.prepare(`DELETE FROM trust_cache WHERE expires_at < ?`).bind(now).run();
  return result.meta?.changes ?? 0;
}

export interface CachedSpan {
  type: PiiType;
  start: number;
  end: number;
  confidence?: number;
  source: DetectedSpan["source"];
}

/** Strips span text (PII) before storage; offsets rehydrate it at lookup. */
export function stripSpanText(spans: DetectedSpan[]): CachedSpan[] {
  return spans.map((s) => ({
    type: s.type,
    start: s.start,
    end: s.end,
    ...(s.confidence !== undefined ? { confidence: s.confidence } : {}),
    source: s.source,
  }));
}

/** Re-slices span text from the request; throws on corrupt entries (caller treats as miss). */
export function rehydrateSpans(text: string, cached: CachedSpan[]): DetectedSpan[] {
  if (!Array.isArray(cached)) throw new Error("corrupt cache entry");
  return cached.map((s) => {
    if (
      !s ||
      typeof s !== "object" ||
      typeof s.type !== "string" ||
      !Number.isInteger(s.start) ||
      !Number.isInteger(s.end) ||
      s.start < 0 ||
      s.end > text.length ||
      s.start >= s.end ||
      typeof s.source !== "string"
    ) {
      throw new Error("corrupt cache entry");
    }
    return {
      text: text.slice(s.start, s.end),
      type: s.type,
      start: s.start,
      end: s.end,
      ...(typeof s.confidence === "number" ? { confidence: s.confidence } : {}),
      source: s.source,
    };
  });
}

export interface CachedVerdict {
  safe: boolean;
  flagged: boolean;
  action: ModerateResult["action"];
  categories: string[];
  categoryCodes: string[];
  findings: ModerateResult["findings"];
}

/** Verdicts carry no input text; safe to store verbatim (minus timing/attribution). */
export function stripVerdict(result: ModerateResult): CachedVerdict {
  return {
    safe: result.safe,
    flagged: result.flagged,
    action: result.action,
    categories: [...result.categories],
    categoryCodes: [...result.categoryCodes],
    findings: JSON.parse(JSON.stringify(result.findings)),
  };
}
