import { afterEach, describe, expect, it } from "bun:test";
import { GEMINI_MODEL_ID, geminiNerScan, geminiSafetyScan } from "./gemini";

const realFetch = globalThis.fetch;

function mockFetchOnce(handler: (url: string, init: any) => unknown) {
  globalThis.fetch = (async (url: any, init: any) => handler(String(url), init)) as any;
}

function geminiOk(text: string) {
  return {
    ok: true,
    json: async () => ({ candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }] }),
  };
}

afterEach(() => {
  globalThis.fetch = realFetch;
});

describe("geminiSafetyScan", () => {
  it("parses a safe verdict", async () => {
    mockFetchOnce(() => geminiOk('{"safe": true, "codes": []}'));
    await expect(geminiSafetyScan("hello world", "k")).resolves.toEqual({ safe: true, categoryCodes: [] });
  });

  it("parses an unsafe verdict with normalized codes", async () => {
    mockFetchOnce(() => geminiOk('{"safe": false, "codes": ["s10", "S10", "S7"]}'));
    await expect(geminiSafetyScan("hate", "k")).resolves.toEqual({ safe: false, categoryCodes: ["S10", "S7"] });
  });

  it("returns safe without calling for blank text", async () => {
    let calls = 0;
    mockFetchOnce(() => { calls++; return geminiOk("{}"); });
    await expect(geminiSafetyScan("  ", "k")).resolves.toEqual({ safe: true, categoryCodes: [] });
    expect(calls).toBe(0);
  });

  it("throws 503-shaped on transport and model failures", async () => {
    const cases: Array<() => unknown> = [
      () => { throw new Error("down"); },
      () => ({ ok: false, status: 429, json: async () => ({}) }),
      () => ({ ok: true, json: async () => ({ promptFeedback: { blockReason: "SAFETY" } }) }),
      () => ({ ok: true, json: async () => ({ candidates: [] }) }),
      () => geminiOk("not json"),
      () => geminiOk('{"safe": "yes", "codes": []}'),
      () => geminiOk('{"safe": false, "codes": ["S99"]}'),
      () => geminiOk('{"safe": true, "codes": ["S10"]}'),
    ];
    for (const handler of cases) {
      mockFetchOnce(handler);
      const err = await geminiSafetyScan("hello", "k").then(
        () => null,
        (e) => e
      );
      expect(err?.status).toBe(503);
    }
  });

  it("posts to the flash model with the api key header", async () => {
    let seen: any = null;
    mockFetchOnce((url, init) => {
      seen = { url, init };
      return geminiOk('{"safe": true, "codes": []}');
    });
    await geminiSafetyScan("hello", "secret-key");
    expect(seen.url).toContain(GEMINI_MODEL_ID);
    expect(seen.init.headers["x-goog-api-key"]).toBe("secret-key");
    expect(seen.init.method).toBe("POST");
  });
});

describe("geminiNerScan", () => {
  it("parses an entity list", async () => {
    mockFetchOnce(() => geminiOk('[{"text": "Jane Doe", "type": "PERSON"}]'));
    await expect(geminiNerScan("contact Jane Doe", "k")).resolves.toEqual([{ text: "Jane Doe", type: "PERSON" }]);
  });

  it("returns [] without calling for blank text", async () => {
    let calls = 0;
    mockFetchOnce(() => { calls++; return geminiOk("[]"); });
    await expect(geminiNerScan("  ", "k")).resolves.toEqual([]);
    expect(calls).toBe(0);
  });

  it("throws 503-shaped on malformed output", async () => {
    for (const text of ["not json", '{"a": 1}', '[{"text": "x"}]', '[{"type": "PERSON"}]', '[null]']) {
      mockFetchOnce(() => geminiOk(text));
      const err = await geminiNerScan("hello", "k").then(
        () => null,
        (e) => e
      );
      expect(err?.status).toBe(503);
    }
  });
});
