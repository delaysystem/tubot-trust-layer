import {
  deriveKey,
  encryptPii,
  decryptPii,
  encryptRecordMap,
  decryptRecordMap,
  generateEncryptionKey,
} from "./crypto";
import {
  detectPii,
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
import { TRUST_LAYER_TOOLS } from "./tools";

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
  entities?: PiiType[];
  format?: "numbered" | "uuid" | "custom";
  ttlSeconds?: number;
  vaultId?: string;
  useGranite?: boolean;
  useLlama?: boolean;
  regexOnly?: boolean;
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

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: {
      ...CORS_HEADERS,
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

function errorResponse(message: string, status = 400): Response {
  return json({ success: false, error: message }, status);
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
  let moderationText = request.text;
  for (const span of localSpans) moderationText = moderationText.slice(0, span.start) + "█".repeat(span.end - span.start) + moderationText.slice(span.end);

  // Ensure D1 database schema is ready
  if (env.DB) {
    await initDatabase(env.DB);
  }

  // 0. Input Moderation & Exploit Shield (Tier 1 Heuristics + Tier 2 Llama Guard 3)
  let moderationResult: ModerateResult | undefined;
  if (request.moderate !== false) {
    if (!env.AI) throw Object.assign(new Error("Workers AI binding unavailable"), { status: 503 });
    // Legitimate inputs sent to a PII masking service naturally contain personal details (names, emails, phones).
    // Meta Llama Guard 3 flags personal details as S7 (Privacy Violations).
    // During PII masking, S7 is permitted by default so that data can be encrypted and protected,
    // while strictly enforcing cyberattacks (S13), prompt injections & system manipulation (S14),
    // violent crimes (S1), indiscriminate weapons (S9), hate speech (S10), etc.
    const allowedCategories = request.allowedCategories ?? [
      "S7",
      "Privacy Violations",
    ];

    moderationResult = await moderateInput(moderationText, env.AI, {
      mode: request.moderationMode || "block",
      allowedCategories,
    });

    if (moderationResult.action === "block") {
      const categoryList = moderationResult.categories.join(", ") || "Hazard Detected";
      const error: any = new Error(
        `Input blocked by Moderation Shield [${categoryList}]: potential security exploit or safety violation detected.`
      );
      error.status = 422;
      error.moderation = moderationResult;
      throw error;
    }
  }

  // 1. Detect PII using Llama + Rust/Wasm + OpenRedaction + Regex
  const spans = await detectPii(request.text, env.AI, {
    enabledTypes: request.entities,
    useLlama: request.useLlama,
    useGranite: request.regexOnly ? false : request.useGranite !== false,
    regexOnly: request.regexOnly,
  });

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

  for (const [token, meta] of Object.entries(maskResult.tokenMap)) {
    plainRecordMap[token] = meta.value;
    tokenList.push({ token, type: meta.type });
    detectedTypes.add(meta.type);

    // Encrypt individual token for point lookups
    const encryptedToken = await encryptPii(meta.value, derived.key);
    tokenRecords.push({
      tokenId: token,
      vaultId: maskResult.vaultId,
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

  const candidateTokens =
    request.text.match(/\[(?:PII:)?[A-Z_]+(?:_\d+|:[a-f0-9]+)?\]/g) || [];

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
    const vault = await getVaultRecord(env.DB, request.vaultId);
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

  // Method B: Token-based lookup for any remaining or standalone tokens
  if (Object.keys(plainMap).length === 0 && candidateTokens.length > 0 && env.DB) {
    const tokens = await getTokens(env.DB, candidateTokens);
    if (tokens.length > 0) {
      // Find vault salt if applicable
      const firstVaultId = tokens[0].vaultId;
      const vault = await getVaultRecord(env.DB, firstVaultId);
      const derived = await deriveKey(request.key, vault?.salt || undefined);

      for (const token of tokens) {
        if (token.expiresAt && token.expiresAt < Date.now()) continue;
        try {
          const decrypted = await decryptPii(
            token.encryptedValue,
            token.iv,
            derived.key
          );
          plainMap[token.tokenId] = decrypted;
        } catch {
          // Skip or throw on failure
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
  ): Promise<{ spans: DetectedSpan[]; count: number }> {
    const spans = await detectPii(text, (this.env as Env).AI, options);
    return { spans, count: spans.length };
  }

  async moderate(
    text: string,
    options?: ModerateOptions
  ): Promise<ModerateResult> {
    return moderateInput(text, (this.env as Env).AI, options);
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
  ): Promise<{ spans: DetectedSpan[]; count: number }> {
    const spans = await detectPii(text, (this.env as Env).AI, options);
    return { spans, count: spans.length };
  }

  async moderate(
    text: string,
    options?: ModerateOptions
  ): Promise<ModerateResult> {
    return moderateInput(text, (this.env as Env).AI, options);
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
      return json({
        status: "healthy",
        service: "tubot-trust-layer",
        layers: ["regex", "rust-wasm-pii", "openredaction", "llama", "residual-scan"],
        models: {
          pii: "@cf/meta/llama-3.1-8b-instruct-fp8",
          moderation: "@cf/meta/llama-guard-3-8b",
        },
        model: "@cf/meta/llama-3.1-8b-instruct-fp8",
        hasD1: !!env.DB,
        hasAI: !!env.AI,
        timestamp: new Date().toISOString(),
      });
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
          heuristicOnly?: boolean;
          allowedCategories?: string[];
        };
        if (!body.text || typeof body.text !== "string") {
          return errorResponse("Missing or invalid 'text' field in request body.", 400);
        }
        if (!env.AI && !body.heuristicOnly) return errorResponse("Workers AI binding unavailable", 503);
        const result = await moderateInput(body.text, env.AI, {
          mode: body.mode || "block",
          heuristicOnly: body.heuristicOnly,
          allowedCategories: body.allowedCategories,
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
        };
        if (!body.text || typeof body.text !== "string") {
          return errorResponse("Missing 'text' field in request body.", 400);
        }

        const start = performance.now();
        const spans = await detectPii(body.text, env.AI, {
          enabledTypes: body.entities,
          useLlama: body.useLlama,
          useGranite: body.regexOnly ? false : body.useGranite !== false,
          regexOnly: body.regexOnly,
        });
        const elapsed = Math.round((performance.now() - start) * 100) / 100;

        return json({
          success: true,
          spans,
          count: spans.length,
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
        return json({ success: true, prunedCount: pruned });
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
