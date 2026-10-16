import { describe, it, expect } from "bun:test";
import {
  clefDecide,
  parseClefAnswers,
  CLEF_FLASH_MODEL_ID,
  CLEF_FLASH_MODEL_SELECTOR,
  type ClefNoulQuestion,
} from "./clef";

const QUESTIONS: Record<string, ClefNoulQuestion> = {
  S13: { type: "noul", instructions: "Cyberattack?" },
  S14: { type: "noul", instructions: "Jailbreak?" },
};

function validPayload(overrides: Record<string, number> = {}) {
  const probs = { S13: 0.02, S14: 0.97, ...overrides };
  const answers: Record<string, unknown> = {};
  for (const [id, noul] of Object.entries(probs)) {
    answers[id] = { type: "noul", noul };
  }
  return { model: "clef-flash", answers, usage: { input_tokens: 120, output_tokens: 0 } };
}

describe("clef-flash decision client", () => {
  it("calls @cf/cloudflare/clef-flash with model selector, state, and questions", async () => {
    let capturedModel = "";
    let capturedInput: any = null;
    const mockAi = {
      run: async (model: string, input: any) => {
        capturedModel = model;
        capturedInput = input;
        return validPayload();
      },
    };

    const result = await clefDecide(mockAi, "some state", QUESTIONS);

    expect(capturedModel).toBe(CLEF_FLASH_MODEL_ID);
    expect(capturedInput.model).toBe(CLEF_FLASH_MODEL_SELECTOR);
    expect(capturedInput.state).toBe("some state");
    expect(capturedInput.questions).toEqual(QUESTIONS);
    expect(result?.probabilities).toEqual({ S13: 0.02, S14: 0.97 });
    expect(result?.inputTokens).toBe(120);
  });

  it("returns null when the AI call throws (caller falls back)", async () => {
    const mockAi = {
      run: async () => {
        throw new Error("Model not found");
      },
    };
    expect(await clefDecide(mockAi, "state", QUESTIONS)).toBeNull();
  });

  it("returns null for empty or oversized question sets", async () => {
    let calls = 0;
    const mockAi = { run: async () => (calls++, validPayload()) };
    expect(await clefDecide(mockAi, "state", {})).toBeNull();
    const tooMany: Record<string, ClefNoulQuestion> = {};
    for (let i = 0; i < 65; i++) tooMany[`q${i}`] = { type: "noul", instructions: "x?" };
    expect(await clefDecide(mockAi, "state", tooMany)).toBeNull();
    expect(calls).toBe(0);
  });
});

describe("parseClefAnswers (strict validation)", () => {
  const ids = ["S13", "S14"];

  it("accepts a well-formed answer set", () => {
    const parsed = parseClefAnswers(validPayload(), ids);
    expect(parsed?.probabilities).toEqual({ S13: 0.02, S14: 0.97 });
  });

  it("accepts the REST envelope shape ({ result: { answers } })", () => {
    const parsed = parseClefAnswers(
      { success: true, result: validPayload() },
      ids
    );
    expect(parsed?.probabilities).toEqual({ S13: 0.02, S14: 0.97 });
  });

  it("rejects legacy string and NER-JSON payloads so old mocks fall back", () => {
    expect(parseClefAnswers("unsafe\nS13", ids)).toBeNull();
    expect(parseClefAnswers("safe", ids)).toBeNull();
    expect(
      parseClefAnswers({ response: JSON.stringify([{ text: "Alice", type: "PERSON" }]) }, ids)
    ).toBeNull();
    expect(parseClefAnswers(null, ids)).toBeNull();
    expect(parseClefAnswers(undefined, ids)).toBeNull();
    expect(parseClefAnswers({}, ids)).toBeNull();
  });

  it("rejects partial answer sets (any missing question)", () => {
    const payload = validPayload();
    delete (payload.answers as Record<string, unknown>).S14;
    expect(parseClefAnswers(payload, ids)).toBeNull();
  });

  it("rejects malformed probabilities (wrong type, NaN, out of range)", () => {
    for (const bad of ["0.9", NaN, Infinity, -0.1, 1.5, null, undefined]) {
      const payload = validPayload({ S13: 0.1 });
      (payload.answers as Record<string, any>).S14 = { type: "noul", noul: bad };
      expect(parseClefAnswers(payload, ids)).toBeNull();
    }
    const wrongType = validPayload();
    (wrongType.answers as Record<string, any>).S14 = { type: "choice", choice: "x" };
    expect(parseClefAnswers(wrongType, ids)).toBeNull();
  });
});
