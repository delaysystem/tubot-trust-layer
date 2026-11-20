import { mergeAndDeduplicateSpans, type DetectedSpan, type PiiType } from "./detector";

export interface MaskOptions {
  format?: "numbered" | "uuid" | "custom"; // default: "numbered" -> [NAME_1], [EMAIL_1]
  vaultId?: string;
  customPrefix?: string; // e.g. "PII"
}

export interface MaskResult {
  maskedText: string;
  tokenMap: Record<string, { value: string; type: PiiType }>;
  spans: DetectedSpan[];
  vaultId: string;
}

export interface UnmaskResult {
  unmaskedText: string;
  restoredCount: number;
  restoredTokens: string[];
}

/**
 * Maps PiiType to a human-readable token tag name.
 * e.g. PERSON -> NAME, EMAIL -> EMAIL, PHONE -> PHONE.
 */
function toTokenTagName(type: PiiType): string {
  switch (type) {
    case "PERSON":
      return "NAME";
    case "CREDIT_CARD":
      return "CREDIT_CARD";
    case "IP_ADDRESS":
      return "IP_ADDRESS";
    default:
      return type;
  }
}

/**
 * Computes a deterministic 6-character hex hash for custom token formatting.
 */
function deterministicShortHash(val: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < val.length; i++) {
    hash ^= val.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(6, "0").slice(0, 6);
}

/**
 * Escapes regex special characters in a string.
 */
function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Masks detected PII spans in the input text with deterministic token tags.
 * Replaces text spans in reverse offset order (from end to start) to prevent offset corruption.
 */
export function maskText(
  text: string,
  spans: DetectedSpan[],
  options?: MaskOptions
): MaskResult {
  const format = options?.format ?? "numbered";
  const vaultId = options?.vaultId ?? crypto.randomUUID();
  const customPrefix = options?.customPrefix;

  // Filter valid spans within text bounds
  const validSpans = mergeAndDeduplicateSpans(spans, text);

  // Sort ascending by start offset to assign token numbers in natural reading order
  const ascendingSpans = [...validSpans].sort(
    (a, b) => a.start - b.start || a.end - b.end
  );

  // Deduplicate overlapping spans if any slipped through
  const nonOverlapping: DetectedSpan[] = [];
  for (const span of ascendingSpans) {
    const overlaps = nonOverlapping.some(
      (s) => Math.max(s.start, span.start) < Math.min(s.end, span.end)
    );
    if (!overlaps) {
      nonOverlapping.push(span);
    }
  }

  // Token assignment cache (ensures identical value+type gets the same token)
  const tokenMap: Record<string, { value: string; type: PiiType }> = {};
  const valueTypeToToken = new Map<string, string>();
  const counters: Record<string, number> = {};
  const spanToToken = new Map<DetectedSpan, string>();

  for (const span of nonOverlapping) {
    const tag = toTokenTagName(span.type);
    const cacheKey = `${span.type}:::${span.text}`;

    let token = valueTypeToToken.get(cacheKey);
    if (!token) {
      if (format === "custom") {
        const prefix = customPrefix || "PII";
        const hash = deterministicShortHash(span.text);
        token = `[${prefix}:${tag}:${hash}]`;
      } else if (format === "uuid") {
        const id = crypto.randomUUID();
        token = customPrefix
          ? `[${customPrefix}:${tag}:${id}]`
          : `[${tag}_${id}]`;
      } else {
        // format === "numbered"
        const nextCount = (counters[tag] = (counters[tag] || 0) + 1);
        token = customPrefix
          ? `[${customPrefix}_${tag}_${nextCount}]`
          : `[${tag}_${nextCount}]`;
      }

      valueTypeToToken.set(cacheKey, token);
      tokenMap[token] = { value: span.text, type: span.type };
    }

    spanToToken.set(span, token);
  }

  // Sort spans descending by start offset for in-place reverse replacement
  const descendingSpans = [...nonOverlapping].sort(
    (a, b) => b.start - a.start || b.end - a.end
  );

  let maskedText = text;
  for (const span of descendingSpans) {
    const token = spanToToken.get(span);
    if (token) {
      maskedText =
        maskedText.substring(0, span.start) +
        token +
        maskedText.substring(span.end);
    }
  }

  return {
    maskedText,
    tokenMap,
    spans: nonOverlapping,
    vaultId,
  };
}

/**
 * Restores original PII in masked text using the provided token map.
 * Supports both plain string maps `Record<string, string>` and rich maps `Record<string, { value: string }>`.
 */
export function unmaskText(
  maskedText: string,
  tokenMap: Record<string, string | { value: string; type?: PiiType }>
): UnmaskResult {
  const tokenKeys = Object.keys(tokenMap);
  if (tokenKeys.length === 0 || !maskedText) {
    return {
      unmaskedText: maskedText,
      restoredCount: 0,
      restoredTokens: [],
    };
  }

  // Sort token keys descending by length so longer tokens match first
  tokenKeys.sort((a, b) => b.length - a.length);

  const pattern = new RegExp(tokenKeys.map(escapeRegExp).join("|"), "g");
  const restoredTokensSet = new Set<string>();
  let restoredCount = 0;

  const unmaskedText = maskedText.replace(pattern, (match) => {
    const entry = tokenMap[match];
    if (entry === undefined) {
      return match;
    }
    restoredTokensSet.add(match);
    restoredCount++;
    return typeof entry === "string" ? entry : entry.value;
  });

  return {
    unmaskedText,
    restoredCount,
    restoredTokens: Array.from(restoredTokensSet),
  };
}
