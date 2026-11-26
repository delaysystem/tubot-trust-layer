import {
  deriveKey,
  encryptPii,
  decryptPii,
  encryptRecordMap,
  decryptRecordMap,
  generateEncryptionKey,
} from "./crypto";
import {
  blockSpans,
  detectPii,
  detectPiiInner,
  type DetectedSpan,
  type PiiType,
  type DetectOptions,
} from "./detector";
import {
  maskText,
  unmaskText,
  type MaskOptions,
  type MaskResult,
  type UnmaskResult,
} from "./masker";
import {
  initDatabase,
  storeVaultRecord,
  getVaultRecord,
  getTokens,
  deleteVaultRecord,
  pruneExpiredRecords,
  type VaultRecord,
  type TokenRecord,
} from "./storage";
import {
  moderateInput,
  type ModerateResult,
  type ModerateOptions,
} from "./moderator";
import { GEMINI_MODEL_ID } from "./gemini";
import { TRUST_LAYER_TOOLS } from "./tools";
import {
  cacheDelete,
  cacheGet,
  cachePut,
  detectCacheKey,
  moderateCacheKey,
  pruneCache,
  rehydrateSpans,
  stripSpanText,
  stripVerdict,
  type CachedVerdict,
} from "./cache";

// Safe dynamic imports for Cloudflare Workers runtime vs Bun testing
let DurableObjectClass: any;
let WorkerEntrypointClass: any;

try {
  // @ts-ignore
  const cf = await import("cloudflare:workers");
  DurableObjectClass = cf.DurableObject;
  WorkerEntrypointClass = cf.WorkerEntrypoint;
} catch {
  DurableObjectClass = class {
    ctx: any;
    env: any;
    constructor(ctx?: any, env?: any) {
      this.ctx = ctx;
      this.env = env;
    }
  };
  WorkerEntrypointClass = class {
    ctx: any;
    env: any;
    constructor(ctx?: any, env?: any) {
      this.ctx = ctx;
      this.env = env;
    }
  };
}

export interface MaskApiRequest {
  text: string;
  key?: string;
  tenantId?: string;
  entities?: PiiType[];
  format?: "numbered" | "uuid" | "custom";
  ttlSeconds?: number;
  vaultId?: string;
  useGranite?: boolean;
  useLlama?: boolean;
  regexOnly?: boolean;
  /** False forces the legacy Llama engines instead of clef-flash. */
  useClef?: boolean;
  /** True answers from local layers when every AI engine fails (degraded:true) instead of 503. */
  allowDegraded?: boolean;
  moderate?: boolean;
  moderationMode?: "block" | "warn";
  allowedCategories?: string[];
}

export interface MaskApiResponse {
  success: boolean;
  maskedText: string;
  key: string;
  vaultId: string;
  tokens: Array<{ token: string; type: PiiType }>;
  piiDetectedCount: number;
  executionTimeMs: number;
  moderation?: ModerateResult;
}

export interface UnmaskApiRequest {
  text: string;
  key: string;
  vaultId?: string;
  tenantId?: string;
}

export interface UnmaskApiResponse {
  success: boolean;
  unmaskedText: string;
  restoredCount: number;
  restoredTokens: string[];
  executionTimeMs: number;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Encryption-Key",
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      ...CORS_HEADERS,
      ...SECURITY_HEADERS,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function errorResponse(message: string, status = 400): Response {
  return json({ success: false, error: message }, status);
}

/**
 * D1-cached detection. Identical requests answer in milliseconds without
 * inference; the cache is auxiliary — any cache/D1 failure bypasses to a
 * direct call, while detection errors (413/503) still propagate. Degraded
 * (local-only) results are never cached: only full-fidelity entries are stored.
 */
const L1_CACHE_TTL_MS = 5 * 60 * 1000;
const L1_CACHE_MAX_ENTRIES = 512;
const l1CacheByDb = new WeakMap<D1Database, Map<string, { value: string; expiresAt: number }>>();

function l1CacheGet(db: D1Database, key: string): string | null {
  const map = l1CacheByDb.get(db);
  const hit = map?.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= Date.now()) {
    map!.delete(key);
    return null;
  }
  return hit.value;
}

function l1CacheSet(db: D1Database, key: string, value: string): void {
  let map = l1CacheByDb.get(db);
  if (!map) {
    map = new Map();
    l1CacheByDb.set(db, map);
  }
  if (!map.has(key) && map.size >= L1_CACHE_MAX_ENTRIES) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
  map.set(key, { value, expiresAt: Date.now() + L1_CACHE_TTL_MS });
}

async function cachedDetect(
  env: Env,
  text: string,
  options?: DetectOptions
): Promise<{ spans: DetectedSpan[]; count: number; models: string[]; cached?: boolean; degraded?: boolean }> {
  const direct = async () => {
    // The Gemini leg always uses the server key; caller-supplied keys are ignored.
    const { spans, meta } = await detectPiiInner(text, requestAi(env), { ...options, geminiKey: env.GOOGLE_API_KEY });
    return { spans, count: spans.length, models: meta.models, ...(meta.degraded ? { degraded: true as const } : {}) };
  };
  if (!env.DB) return direct();
  let key: string;
  try {
    key = await detectCacheKey(text, options);
    const l1Hit = l1CacheGet(env.DB, key);
    if (l1Hit) {
      try {
        const spans = rehydrateSpans(text, JSON.parse(l1Hit).spans);
        return { spans, count: spans.length, models: [], cached: true };
      } catch {
        l1CacheByDb.get(env.DB)?.delete(key);
      }
    }
    await initDatabase(env.DB);
    const hit = await cacheGet(env.DB, key);
    if (hit) {
      try {
        const spans = rehydrateSpans(text, JSON.parse(hit).spans);
        l1CacheSet(env.DB, key, hit);
        return { spans, count: spans.length, models: [], cached: true };
      } catch {
        await cacheDelete(env.DB, key).catch(() => null);
      }
    }
  } catch {
    return direct();
  }
  const result = await direct();
  if (!result.degraded) {
    const serialized = JSON.stringify({ spans: stripSpanText(result.spans) });
    l1CacheSet(env.DB, key!, serialized);
    await cachePut(env.DB, key!, serialized).catch(() => null);
  }
  return result;
}

/**
 * D1-cached moderation. Same auxiliary-cache contract as cachedDetect;
 * degraded (heuristic-only) verdicts are never cached.
 */
async function cachedModerate(
  env: Env,
  text: string,
  options?: ModerateOptions
): Promise<ModerateResult> {
  const direct = () => moderateInput(text, requestAi(env), { ...options, geminiKey: env.GOOGLE_API_KEY });
  if (!env.DB) return direct();
  const started = performance.now();
  let key: string;
  try {
    key = await moderateCacheKey(text, options);
    const l1Hit = l1CacheGet(env.DB, key);
    if (l1Hit) {
      try {
        const verdict = JSON.parse(l1Hit) as CachedVerdict;
        if (verdict && typeof verdict === "object" && typeof verdict.safe === "boolean" && Array.isArray(verdict.findings)) {
          return {
            ...verdict,
            executionTimeMs: Math.max(0, Math.round((performance.now() - started) * 100) / 100),
            models: [],
            cached: true,
          };
        }
      } catch {
        l1CacheByDb.get(env.DB)?.delete(key);
      }
    }
    await initDatabase(env.DB);
    const hit = await cacheGet(env.DB, key);
    if (hit) {
      const verdict = JSON.parse(hit) as CachedVerdict;
      if (
        verdict &&
        typeof verdict === "object" &&
        typeof verdict.safe === "boolean" &&
        Array.isArray(verdict.findings)
      ) {
        l1CacheSet(env.DB, key, hit);
        return {
          ...verdict,
          executionTimeMs: Math.max(0, Math.round((performance.now() - started) * 100) / 100),
          models: [],
          cached: true,
        };
      }
      await cacheDelete(env.DB, key).catch(() => null);
    }
  } catch {
    return direct();
  }
  const result = await direct();
  if (!result.degraded) {
    const serialized = JSON.stringify(stripVerdict(result));
    l1CacheSet(env.DB, key!, serialized);
    await cachePut(env.DB, key!, serialized).catch(() => null);
  }
  return result;
}

function requestAi(env: Env): Env["AI"] {
  return env.AI;
}

/** Health-probe AI budget: the probe must answer promptly for load balancers,
 * so past this the provider counts as unavailable. Origin: FLK-09
 * (pre-existing 8s behavior, now named); the timed-out probe aborts so the
 * loser stops before its next model round instead of running on. */
const HEALTH_PROBE_TIMEOUT_MS = 8000;

/**
 * Live health probe. Key presence says nothing about provider
 * reachability, so this runs one tiny gemini moderation call and one
 * `SELECT 1` against D1. The probe never throws: a failing provider
 * surfaces as `ai: "unavailable"` with `status: "degraded"`, telling
 * callers degraded mode is the only working path.
 */
async function healthReport(env: Env) {
  // Workers AI disabled: Tier-2 health is the Gemini leg (or local-only
  // degradation), never the vestigial AI binding. Always probe; a missing
  // key fails fast (no model round) and reports unavailable/degraded.
  let ai: "ok" | "unavailable" | "unbound" = "unavailable";
  let aiLatencyMs: number | null = null;
  {
    const started = performance.now();
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        moderateInput("ok", requestAi(env), { signal: ctrl.signal, geminiKey: env.GOOGLE_API_KEY }),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            // Cancel the loser: its next stage check throws instead of
            // spending another model round on an answer nobody waits for.
            ctrl.abort();
            reject(new Error("probe timeout"));
          }, HEALTH_PROBE_TIMEOUT_MS);
        }),
      ]);
      ai = "ok";
      aiLatencyMs = Math.round((performance.now() - started) * 100) / 100;
    } catch {
      ai = "unavailable";
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
  let db: "ok" | "unavailable" | "unbound" = env.DB ? "unavailable" : "unbound";
  if (env.DB) {
    try {
      await env.DB.prepare("SELECT 1").first();
      db = "ok";
    } catch {
      db = "unavailable";
    }
  }
  return {
    status: ai === "unavailable" ? "degraded" : "healthy",
    service: "tubot-trust-layer",
    layers: ["regex", "rust-wasm-pii", "openredaction", "gemini-ner", "residual-scan", "result-cache"],
    models: {
      pii: GEMINI_MODEL_ID,
      moderation: GEMINI_MODEL_ID,
    },
    fallbackModels: {
      pii: "local-layers",
      moderation: "local-layers",
    },
    degradedFallback: "local-layers",
    model: GEMINI_MODEL_ID,
    hasD1: !!env.DB,
    hasAI: !!env.AI,
    hasGemini: !!env.GOOGLE_API_KEY,
    ai,
    aiLatencyMs,
    db,
  };
}

/**
 * Core Masking Workflow
 */
export async function executeMasking(
  env: Env,
  request: MaskApiRequest
): Promise<MaskApiResponse> {
  const startTime = performance.now();

  if (!request.text || typeof request.text !== "string") {
    throw new Error("Missing or invalid 'text' field in request body.");
  }

  if (new TextEncoder().encode(request.text).length > 16384) throw Object.assign(new Error("PII input exceeds 16 KiB"), { status: 413 });
  if (!env.DB) throw Object.assign(new Error("D1 binding unavailable"), { status: 503 });
  const localSpans = await detectPii(request.text, undefined, { enabledTypes: request.entities, regexOnly: true });
  // Linear single-pass blocking (was O(spans x textLen) slice-concat). Origin: COST-01.
  const moderationText = blockSpans(request.text, localSpans);

  // Ensure D1 database schema is ready
  if (env.DB) {
    await initDatabase(env.DB);
  }

  // 0 & 1. Run Input Moderation and PII Detection in parallel to halve latency;
  // if moderation blocks, discard detection and reject immediately with 422.
  let moderationResult: ModerateResult | undefined;
  const detectOpts: DetectOptions = {
    enabledTypes: request.entities,
    useLlama: request.useLlama,
    useGranite: request.regexOnly ? false : request.useGranite !== false,
    regexOnly: request.regexOnly,
    useClef: request.useClef,
    allowDegraded: request.allowDegraded,
  };
  let spans: DetectedSpan[];
  if (request.moderate !== false) {
    if (!env.AI) throw Object.assign(new Error("Workers AI binding unavailable"), { status: 503 });
    const allowedCategories = request.allowedCategories ?? [
      "S7",
      "Privacy Violations",
    ];
    const [modRes, detectRes] = await Promise.all([
      cachedModerate(env, moderationText, {
        mode: request.moderationMode || "block",
        allowedCategories,
        useClef: request.useClef,
        allowDegraded: request.allowDegraded,
      }),
      cachedDetect(env, request.text, detectOpts).catch((err) => ({ __detectError: err as Error })),
    ]);
    moderationResult = modRes;
    if (moderationResult.action === "block") {
      const categoryList = moderationResult.categories.join(", ") || "Hazard Detected";
      const error: any = new Error(
        `Input blocked by Moderation Shield [${categoryList}]: potential security exploit or safety violation detected.`
      );
      error.status = 422;
      error.moderation = moderationResult;
      throw error;
    }
    if ("__detectError" in detectRes) throw detectRes.__detectError;
    spans = detectRes.spans;
  } else {
    spans = (await cachedDetect(env, request.text, detectOpts)).spans;
  }

  // If no PII detected, return original text
  if (spans.length === 0) {
    const elapsed = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      success: true,
      maskedText: request.text,
      key: request.key || "",
      vaultId: request.vaultId || "",
      tokens: [],
      piiDetectedCount: 0,
      executionTimeMs: elapsed,
      moderation: moderationResult,
    };
  }

  // 2. Perform Masking and token substitution
  const maskResult = maskText(request.text, spans, {
    format: request.format || "numbered",
    vaultId: request.vaultId,
  });

  // Verify the final output locally before persisting or returning it.
  let verificationText = maskResult.maskedText;
  for (const token of Object.keys(maskResult.tokenMap)) verificationText = verificationText.replaceAll(token, "█".repeat(token.length));
  const residual = await detectPii(verificationText, undefined, { enabledTypes: request.entities, regexOnly: true });
  if (residual.length) throw Object.assign(new Error("Residual PII detected after masking"), { status: 503 });

  // 3. Prepare Encryption Key
  const rawKey = request.key?.trim() || (await generateEncryptionKey());
  const derived = await deriveKey(rawKey);

  // 4. Encrypt tokens for D1 storage
  const now = Date.now();
  const ttlMs = request.ttlSeconds ? request.ttlSeconds * 1000 : null;
  const expiresAt = ttlMs ? now + ttlMs : null;

  const plainRecordMap: Record<string, string> = {};
  const tokenRecords: TokenRecord[] = [];
  const tokenList: Array<{ token: string; type: PiiType }> = [];
  const detectedTypes = new Set<string>();

  const tenantId = typeof request.tenantId === "string" ? request.tenantId.trim().slice(0, 128) : "";
  for (const [token, meta] of Object.entries(maskResult.tokenMap)) {
    plainRecordMap[token] = meta.value;
    tokenList.push({ token, type: meta.type });
    detectedTypes.add(meta.type);

    // Encrypt individual token for point lookups
    const encryptedToken = await encryptPii(meta.value, derived.key);
    tokenRecords.push({
      tokenId: token,
      vaultId: maskResult.vaultId,
      tenantId,
      piiType: meta.type,
      iv: encryptedToken.iv,
      encryptedValue: encryptedToken.ciphertext,
      createdAt: now,
      expiresAt,
    });
  }

  // Encrypt the full vault record dictionary
  const encryptedMap = await encryptRecordMap(plainRecordMap, derived.key);
  const vaultRecord: VaultRecord = {
    vaultId: maskResult.vaultId,
    tenantId,
    salt: derived.salt || null,
    iv: encryptedMap.iv,
    encryptedData: encryptedMap.encryptedData,
    piiTypes: Array.from(detectedTypes),
    itemCount: tokenRecords.length,
    createdAt: now,
    expiresAt,
  };

  // 5. Store in D1
  if (env.DB) {
    await storeVaultRecord(env.DB, vaultRecord, tokenRecords);
  }

  const elapsed = Math.round((performance.now() - startTime) * 100) / 100;
  return {
    success: true,
    maskedText: maskResult.maskedText,
    key: rawKey,
    vaultId: maskResult.vaultId,
    tokens: tokenList,
    piiDetectedCount: tokenRecords.length,
    executionTimeMs: elapsed,
    moderation: moderationResult,
  };
}

/**
 * Core Unmasking Workflow
 */
export async function executeUnmasking(
  env: Env,
  request: UnmaskApiRequest
): Promise<UnmaskApiResponse> {
  const startTime = performance.now();

  if (!request.text || typeof request.text !== "string") {
    throw new Error("Missing or invalid 'text' field in request body.");
  }
  if (!request.key || typeof request.key !== "string") {
    throw new Error("Missing required 'key' field for unmasking.");
  }

  if (env.DB) {
    await initDatabase(env.DB);
  }

  const tenantId = typeof request.tenantId === "string" ? request.tenantId.trim().slice(0, 128) : "";
  const candidateTokens =
    request.text.match(/\[(?:PII:)?[A-Z_]+(?:_\d+|:[a-f0-9-]+)?\]/g) || [];

  if (candidateTokens.length === 0 && !request.vaultId) {
    const elapsed = Math.round((performance.now() - startTime) * 100) / 100;
    return {
      success: true,
      unmaskedText: request.text,
      restoredCount: 0,
      restoredTokens: [],
      executionTimeMs: elapsed,
    };
  }

  let plainMap: Record<string, string> = {};

  // Method A: Vault ID lookup (fastest single-query batch decrypt)
  if (request.vaultId && env.DB) {
    const vault = await getVaultRecord(env.DB, request.vaultId, tenantId);
    if (vault) {
      if (vault.expiresAt && vault.expiresAt < Date.now()) {
        throw new Error(
          `Vault record '${request.vaultId}' has expired and cannot be unmasked.`
        );
      }

      try {
        const derived = await deriveKey(request.key, vault.salt || undefined);
        plainMap = await decryptRecordMap(
          vault.encryptedData,
          vault.iv,
          derived.key
        );
      } catch (err: any) {
        throw new Error(
          "Decryption failed. The provided key is invalid or the data was corrupted."
        );
      }
    }
  }

  // Method B: Token-based lookup scoped strictly by tenantId and each token's own vault
  if (Object.keys(plainMap).length === 0 && candidateTokens.length > 0 && env.DB) {
    const tokens = await getTokens(env.DB, candidateTokens, tenantId);
    if (tokens.length > 0) {
      const saltKeys = new Map<string, CryptoKey>();
      for (const token of tokens) {
        if (token.expiresAt && token.expiresAt < Date.now()) continue;
        try {
          let key = saltKeys.get(token.vaultId);
          if (!key) {
            const vault = await getVaultRecord(env.DB, token.vaultId, tenantId);
            key = (await deriveKey(request.key, vault?.salt || undefined)).key;
            saltKeys.set(token.vaultId, key);
          }
          const decrypted = await decryptPii(
            token.encryptedValue,
            token.iv,
            key
          );
          plainMap[token.tokenId] = decrypted;
        } catch {
          // Skip on wrong key / mismatched vault
        }
      }
    }
  }

  const unmaskResult = unmaskText(request.text, plainMap);
  const elapsed = Math.round((performance.now() - startTime) * 100) / 100;

  return {
    success: true,
    unmaskedText: unmaskResult.unmaskedText,
    restoredCount: unmaskResult.restoredCount,
    restoredTokens: unmaskResult.restoredTokens,
    executionTimeMs: elapsed,
  };
}

/**
 * Cloudflare Worker Service Binding Entrypoint
 * Allows zero-overhead RPC calls from other workers (tubot-brain, tubot-gateway, etc.)
 */
export class TrustLayerWorkerEntrypoint extends WorkerEntrypointClass {
  constructor(ctx?: any, env?: any) {
    super(ctx, env);
  }

  async mask(request: MaskApiRequest): Promise<MaskApiResponse> {
    return executeMasking(this.env as Env, request);
  }

  async unmask(request: UnmaskApiRequest): Promise<UnmaskApiResponse> {
    return executeUnmasking(this.env as Env, request);
  }

  async detect(
    text: string,
    options?: DetectOptions
  ): Promise<{ spans: DetectedSpan[]; count: number; models: string[]; cached?: boolean; degraded?: boolean }> {
    return cachedDetect(this.env as Env, text, options);
  }

  async moderate(
    text: string,
    options?: ModerateOptions
  ): Promise<ModerateResult> {
    return cachedModerate(this.env as Env, text, options);
  }
}

/**
 * Cloudflare Durable Object class for stateful Trust Layer workflows
 */
export class MyDurableObject extends DurableObjectClass {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
  }

  async mask(request: MaskApiRequest): Promise<MaskApiResponse> {
    return executeMasking(this.env as Env, request);
  }

  async unmask(request: UnmaskApiRequest): Promise<UnmaskApiResponse> {
    return executeUnmasking(this.env as Env, request);
  }

  async detect(
    text: string,
    options?: DetectOptions
  ): Promise<{ spans: DetectedSpan[]; count: number; models: string[]; cached?: boolean; degraded?: boolean }> {
    return cachedDetect(this.env as Env, text, options);
  }

  async moderate(
    text: string,
    options?: ModerateOptions
  ): Promise<ModerateResult> {
    return cachedModerate(this.env as Env, text, options);
  }

  async sayHello(name: string): Promise<string> {
    return `TuBot Trust Layer ready for ${name}`;
  }
}

/**
 * Standard HTTP Fetch Handler
 */
export const httpHandler = {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    // 1. CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS,
      });
    }

    const url = new URL(request.url);
    const pathname = url.pathname.replace(/\/+$/, "") || "/";

    // 2. Health & Status
    if (request.method === "GET" && (pathname === "/health" || pathname === "/status")) {
      return json({ ...(await healthReport(env)), timestamp: new Date().toISOString() });
    }

    // 3. AI Agent Tool Schemas
    if (request.method === "GET" && pathname === "/tool-definitions") {
      return json({
        tools: TRUST_LAYER_TOOLS,
      });
    }

    const protectedRoute = ["/moderate", "/v1/moderate", "/mask", "/v1/mask", "/detect", "/v1/detect", "/unmask", "/v1/unmask", "/vault/delete", "/prune"].includes(pathname) || pathname.startsWith("/vault/");
    if (protectedRoute) {
      const expected = env.API_TOKEN;
      const supplied = request.headers.get("Authorization")?.match(/^Bearer ([^\s]+)$/i)?.[1];
      if (!expected || !supplied) return errorResponse("Unauthorized", 401);
      const encoder = new TextEncoder();
      const [a, b] = await Promise.all([expected, supplied].map(v => crypto.subtle.digest("SHA-256", encoder.encode(v))));
      const left = new Uint8Array(a), right = new Uint8Array(b);
      let difference = 0;
      for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
      if (difference) return errorResponse("Unauthorized", 401);
    }

    // 4. POST /moderate (Input Moderation & Exploit Shield)
    if (request.method === "POST" && (pathname === "/moderate" || pathname === "/v1/moderate")) {
      try {
        const body = (await request.json().catch(() => ({}))) as {
          text: string;
          mode?: "block" | "warn";
          useClef?: boolean;
          allowDegraded?: boolean;
        };
        if (!body.text || typeof body.text !== "string") {
          return errorResponse("Missing or invalid 'text' field in request body.", 400);
        }
        if (!env.AI) return errorResponse("Workers AI binding unavailable", 503);
        const result = await cachedModerate(env, body.text, {
          mode: body.mode || "block",
          useClef: body.useClef,
          allowDegraded: body.allowDegraded,
        });
        const status = result.action === "block" ? 422 : 200;
        return json(result, status);
      } catch (err: any) {
        return errorResponse(err?.message || "Moderation error", err?.status || 500);
      }
    }

    // 5. POST /mask
    if (request.method === "POST" && (pathname === "/mask" || pathname === "/v1/mask")) {
      try {
        const body = (await request.json().catch(() => ({}))) as MaskApiRequest;
        const result = await executeMasking(env, body);
        return json(result);
      } catch (err: any) {
        const status = err?.status || (err?.message?.includes("Moderation Shield") ? 422 : 400);
        return json(
          {
            success: false,
            error: err?.message || "Internal masking error",
            moderation: err?.moderation,
          },
          status
        );
      }
    }

    // 5. POST /unmask
    if (request.method === "POST" && (pathname === "/unmask" || pathname === "/v1/unmask")) {
      try {
        const body = (await request.json().catch(() => ({}))) as UnmaskApiRequest;
        const result = await executeUnmasking(env, body);
        return json(result);
      } catch (err: any) {
        const message = err?.message || "Internal unmasking error";
        const status = message.includes("expired")
          ? 410
          : message.includes("Decryption failed")
          ? 401
          : 400;
        return errorResponse(message, status);
      }
    }

    // 6. POST /detect (dry-run detection preview)
    if (request.method === "POST" && (pathname === "/detect" || pathname === "/v1/detect")) {
      try {
        const body = (await request.json().catch(() => ({}))) as {
          text: string;
          entities?: PiiType[];
          useGranite?: boolean;
          useLlama?: boolean;
          regexOnly?: boolean;
          useClef?: boolean;
          clefThreshold?: number;
          allowDegraded?: boolean;
        };
        if (!body.text || typeof body.text !== "string") {
          return errorResponse("Missing 'text' field in request body.", 400);
        }

        const start = performance.now();
        const result = await cachedDetect(env, body.text, {
          enabledTypes: body.entities,
          useLlama: body.useLlama,
          useGranite: body.regexOnly ? false : body.useGranite !== false,
          regexOnly: body.regexOnly,
          useClef: body.useClef,
          clefThreshold: body.clefThreshold,
          allowDegraded: body.allowDegraded,
        });
        const elapsed = Math.round((performance.now() - start) * 100) / 100;

        return json({
          success: true,
          spans: result.spans,
          count: result.count,
          models: result.models,
          ...(result.cached === true ? { cached: true } : {}),
          ...(result.degraded === true ? { degraded: true } : {}),
          executionTimeMs: elapsed,
        });
      } catch (err: any) {
        return errorResponse(err?.message || "Detection error", err?.status || 400);
      }
    }

    // 7. DELETE /vault/:vaultId
    if (
      (request.method === "DELETE" && pathname.startsWith("/vault/")) ||
      (request.method === "POST" && pathname === "/vault/delete")
    ) {
      try {
        let vaultId = "";
        if (pathname.startsWith("/vault/")) {
          vaultId = pathname.replace(/^\/vault\//, "");
        } else {
          const body = (await request.json().catch(() => ({}))) as { vaultId: string };
          vaultId = body.vaultId;
        }

        if (!vaultId) {
          return errorResponse("Missing vaultId to delete", 400);
        }

        if (!env.DB) {
          return errorResponse("D1 database binding DB not found", 500);
        }

        const deleted = await deleteVaultRecord(env.DB, vaultId);
        return json({ success: true, vaultId, deleted });
      } catch (err: any) {
        return errorResponse(err?.message || "Delete error", 500);
      }
    }

    // 8. POST /prune
    if (request.method === "POST" && pathname === "/prune") {
      try {
        if (!env.DB) {
          return errorResponse("D1 database binding DB not found", 500);
        }
        const pruned = await pruneExpiredRecords(env.DB);
        const cachePruned = await pruneCache(env.DB);
        return json({ success: true, prunedCount: pruned, cachePrunedCount: cachePruned });
      } catch (err: any) {
        return errorResponse(err?.message || "Prune error", 500);
      }
    }

    // 9. Static Assets (UI in public/index.html)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return errorResponse("Not Found", 404);
  },
} satisfies ExportedHandler<Env>;

/** Default service bindings expose the same authorized RPC methods as the named entrypoint. */
export default class TrustLayer extends TrustLayerWorkerEntrypoint {
  async fetch(request: Request): Promise<Response> {
    return httpHandler.fetch(request, this.env as Env, this.ctx as ExecutionContext);
  }
}
