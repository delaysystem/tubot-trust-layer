/**
 * Cloudflare Clef-flash decision-model client for the trust layer.
 *
 * Clef-flash (@cf/cloudflare/clef-flash) is a 9B decision model: it takes a
 * state plus a schema of typed yes/no (`noul`) questions and returns a
 * probability per question in one forward pass, without generating text.
 * That makes it an order of magnitude faster than the generative Llama
 * models previously used for moderation (llama-guard-3-8b) and semantic PII
 * NER (llama-3.1-8b-instruct-fp8).
 *
 * Design: clef-flash is the primary engine; the legacy Llama paths remain
 * as automatic fallbacks. Any transport error OR malformed/partial answer
 * set resolves to `null` so callers fall back instead of failing open.
 * API contract: https://developers.cloudflare.com/workers-ai/models/clef-flash/
 */

export const CLEF_FLASH_MODEL_ID = "@cf/cloudflare/clef-flash";
export const CLEF_FLASH_MODEL_SELECTOR = "clef-flash";

/** Moderate: flag a category when P(yes) >= threshold. Precision matters
 * here (a false block breaks UX); the heuristic tier already catches
 * deterministic attacks, so use the neutral 0.5 cutoff. */
export const CLEF_MODERATE_THRESHOLD = 0.5;

/** Detect: run the (slow, precise) NER fallback when P(yes) >= threshold.
 * Recall matters here (a miss leaks PII to downstream models), so bias
 * toward running NER. Calibrated 2026-10-15 against the live recall eval:
 * bare placenames ("Ohio" in "Born 1990-04-12 in Ohio.") score ADDRESS in
 * [0.25, 0.3) while clean chat texts score < 0.1 on all types, so 0.2
 * catches the weak positives with margin while keeping clean-text skips. */
export const CLEF_SCREEN_THRESHOLD = 0.2;

export interface ClefNoulQuestion {
  type: "noul";
  instructions: string;
  criteria?: {
    true: string;
    false: string;
  };
}

export interface ClefNoulAnswer {
  type: "noul";
  noul: number;
}

export interface ClefDecideResult {
  /** Probability per asked question id, in [0, 1]. */
  probabilities: Record<string, number>;
  /** Raw model payload, for debugging only. Never log the state. */
  rawResponse: unknown;
  inputTokens?: number;
  outputTokens?: number;
}

interface AiRunner {
  run(model: string, input: unknown): Promise<unknown>;
}

/**
 * Runs one clef-flash decision round over `state` with the given yes/no
 * questions. Returns `null` when the call fails or the answer set is
 * incomplete/malformed, so the caller can fall back to the legacy engine.
 */
export async function clefDecide(
  ai: AiRunner,
  state: string,
  questions: Record<string, ClefNoulQuestion>
): Promise<ClefDecideResult | null> {
  const ids = Object.keys(questions);
  if (ids.length === 0 || ids.length > 64) {
    return null;
  }

  let raw: unknown;
  try {
    raw = await ai.run(CLEF_FLASH_MODEL_ID, {
      model: CLEF_FLASH_MODEL_SELECTOR,
      state,
      questions,
    });
  } catch {
    return null;
  }

  return parseClefAnswers(raw, ids);
}

/**
 * Strictly validates a clef-flash payload. Every asked question id must
 * have a well-formed noul answer with a finite probability in [0, 1];
 * anything else returns null (caller falls back to the legacy engine).
 */
export function parseClefAnswers(
  raw: unknown,
  ids: string[]
): ClefDecideResult | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const root = raw as Record<string, unknown>;
  // Tolerate the REST envelope shape ({ result: {...} }) as well as the
  // direct ai.run() shape.
  const answers =
    (root.answers as Record<string, unknown> | undefined) ??
    ((root.result as Record<string, unknown> | undefined)?.answers as
      | Record<string, unknown>
      | undefined);
  if (!answers || typeof answers !== "object") {
    return null;
  }

  const probabilities: Record<string, number> = {};
  for (const id of ids) {
    const answer = answers[id] as
      | Partial<ClefNoulAnswer>
      | undefined;
    if (
      !answer ||
      typeof answer !== "object" ||
      answer.type !== "noul" ||
      typeof answer.noul !== "number" ||
      !Number.isFinite(answer.noul) ||
      answer.noul < 0 ||
      answer.noul > 1
    ) {
      return null;
    }
    probabilities[id] = answer.noul;
  }

  const usage = (root.usage ?? (root.result as Record<string, unknown> | undefined)?.usage) as
    | { input_tokens?: unknown; output_tokens?: unknown }
    | undefined;
  return {
    probabilities,
    rawResponse: raw,
    inputTokens:
      typeof usage?.input_tokens === "number" ? usage.input_tokens : undefined,
    outputTokens:
      typeof usage?.output_tokens === "number" ? usage.output_tokens : undefined,
  };
}
