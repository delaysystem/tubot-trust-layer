/// <reference types="bun-types" />
import { afterEach, describe, expect, it } from "bun:test";
import {
  buildClefPresenceQuestions,
  clefPresenceScreen,
  detectPii,
  detectPiiInner,
  graniteScan,
  isValidIpv6,
  isValidSsn,
  luhnCheck,
  mergeAndDeduplicateSpans,
  regexScan,
  type DetectedSpan,
  type PiiType,
} from "./detector";

describe("Luhn Algorithm (Credit Cards)", () => {
  it("validates legitimate credit card numbers", () => {
    // Visa test card
    expect(luhnCheck("4242 4242 4242 4242")).toBe(true);
    // Mastercard test card
    expect(luhnCheck("5555 5555 5555 4444")).toBe(true);
    // Amex test card
    expect(luhnCheck("3782 822463 10005")).toBe(true);
    // Continuous digits
    expect(luhnCheck("4242424242424242")).toBe(true);
  });

  it("rejects invalid credit card numbers (negative test cases)", () => {
    // Checksum invalid (last digit 3 instead of 2)
    expect(luhnCheck("4242 4242 4242 4243")).toBe(false);
    // All zeros
    expect(luhnCheck("0000 0000 0000 0000")).toBe(false);
    // Too short
    expect(luhnCheck("1234 5678 90")).toBe(false);
    // Too long
    expect(luhnCheck("1234 5678 9012 3456 7890 1234")).toBe(false);
    // Random numbers
    expect(luhnCheck("1234 5678 9012 3456")).toBe(false);
  });
});

describe("SSN Validation", () => {
  it("validates legitimate SSNs", () => {
    expect(isValidSsn("123-45-6789")).toBe(true);
    expect(isValidSsn("789-12-3456")).toBe(true);
  });

  it("rejects invalid SSN patterns", () => {
    expect(isValidSsn("000-12-3456")).toBe(false); // area 000
    expect(isValidSsn("666-12-3456")).toBe(false); // area 666
    expect(isValidSsn("900-12-3456")).toBe(false); // area 900+
    expect(isValidSsn("123-00-4567")).toBe(false); // group 00
    expect(isValidSsn("123-45-0000")).toBe(false); // serial 0000
  });
});

describe("IPv6 Validation", () => {
  it("validates valid IPv6 strings", () => {
    expect(isValidIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true);
    expect(isValidIpv6("2001:db8::1")).toBe(true);
    expect(isValidIpv6("::1")).toBe(true);
  });

  it("rejects invalid IPv6 strings", () => {
    expect(isValidIpv6("12:30")).toBe(false); // time
    expect(isValidIpv6("192.168.1.1")).toBe(false); // ipv4
    expect(isValidIpv6(":::")).toBe(false);
    expect(isValidIpv6("2001:db8::1::2")).toBe(false); // double ::
  });
});

describe("Deterministic Regex Pre-Scanner", () => {
  it("detects RFC 5322 compliant emails", () => {
    const text =
      "Please email alice@example.com or bob.builder+tag@company.co.uk for support.";
    const spans = regexScan(text, ["EMAIL"]);

    expect(spans).toHaveLength(2);
    expect(spans[0].type).toBe("EMAIL");
    expect(spans[0].text).toBe("alice@example.com");
    expect(spans[1].type).toBe("EMAIL");
    expect(spans[1].text).toBe("bob.builder+tag@company.co.uk");
  });

  it("detects North American and international phone numbers", () => {
    const text =
      "Call me at (555) 234-5678 or UK line +44 20 7946 0958 or +1-555-867-5309. Date is 2026-09-24.";
    const spans = regexScan(text, ["PHONE"]);

    const matchedTexts = spans.map((s) => s.text);
    expect(matchedTexts).toContain("(555) 234-5678");
    expect(matchedTexts).toContain("+44 20 7946 0958");
    expect(matchedTexts).toContain("+1-555-867-5309");
    // Ensure date 2026-09-24 is not detected as phone
    expect(matchedTexts).not.toContain("2026-09-24");
  });

  it("detects formatted SSNs and contextual 9-digit SSNs", () => {
    const text =
      "Alice SSN: 123-45-6789. Bob's social security number is 123456789. Order #987654321.";
    const spans = regexScan(text, ["SSN"]);

    const matchedTexts = spans.map((s) => s.text);
    expect(matchedTexts).toContain("123-45-6789");
    expect(matchedTexts).toContain("123456789");
    // Unrelated 9-digit number without SSN context should not be matched
    expect(matchedTexts).not.toContain("987654321");
  });

  it("detects credit cards with Luhn validation", () => {
    const text =
      "Valid Visa: 4242-4242-4242-4242. Valid MC: 5555 5555 5555 4444. Fake: 4242-4242-4242-4243.";
    const spans = regexScan(text, ["CREDIT_CARD"]);

    expect(spans).toHaveLength(2);
    expect(spans[0].text).toBe("4242-4242-4242-4242");
    expect(spans[1].text).toBe("5555 5555 5555 4444");
  });

  it("detects IPv4 and IPv6 addresses", () => {
    const text =
      "Servers at 192.168.1.100 and 10.0.0.1 and 2001:db8::1. Version v1.2.3.4 is running.";
    const spans = regexScan(text, ["IP_ADDRESS"]);

    const matchedTexts = spans.map((s) => s.text);
    expect(matchedTexts).toContain("192.168.1.100");
    expect(matchedTexts).toContain("10.0.0.1");
    expect(matchedTexts).toContain("2001:db8::1");
    expect(matchedTexts).not.toContain("v1.2.3.4");
  });

  it("detects various developer secrets and tokens", () => {
    const text = `
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.abcdef1234567890
ghp_1234567890abcdefghijklmnopqrstuvwxyzAB
sk-proj-abc1234567890def1234567890
AKIAIOSFODNN7EXAMPLE
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3fakekey...
-----END RSA PRIVATE KEY-----
    `;
    const spans = regexScan(text, ["SECRET"]);
    const types = spans.map((s) => s.type);

    expect(spans.length).toBe(5);
    expect(types.every((t) => t === "SECRET")).toBe(true);

    const texts = spans.map((s) => s.text);
    expect(texts.some((t) => t.startsWith("eyJ"))).toBe(true);
    expect(
      texts.includes("ghp_1234567890abcdefghijklmnopqrstuvwxyzAB")
    ).toBe(true);
    expect(texts.includes("sk-proj-abc1234567890def1234567890")).toBe(true);
    expect(texts.includes("AKIAIOSFODNN7EXAMPLE")).toBe(true);
    expect(texts.some((t) => t.includes("BEGIN RSA PRIVATE KEY"))).toBe(true);
  });

  it("respects enabledTypes filter", () => {
    const text = "Email: test@example.com, Phone: 555-234-5678, IP: 192.168.1.1";
    const emailOnly = regexScan(text, ["EMAIL"]);
    expect(emailOnly).toHaveLength(1);
    expect(emailOnly[0].type).toBe("EMAIL");

    const phoneOnly = regexScan(text, ["PHONE"]);
    expect(phoneOnly).toHaveLength(1);
    expect(phoneOnly[0].type).toBe("PHONE");
  });
});

describe("Llama Semantic Scanner", () => {
  it("parses clean JSON array output from Llama", async () => {
    const mockAi: any = {
      run: async (model: string, input: any) => {
        expect(model).toBe("@cf/meta/llama-3.1-8b-instruct-fp8");
        return {
          response: JSON.stringify([
            { text: "Sarah Connor", type: "PERSON" },
            { text: "Cyberdyne Systems", type: "ORG" },
            { text: "Los Angeles, CA", type: "ADDRESS" },
            { text: "1984-05-12", type: "DOB" },
          ]),
        };
      },
    };

    const text =
      "Sarah Connor worked at Cyberdyne Systems in Los Angeles, CA. Born on 1984-05-12.";
    const spans = await graniteScan(text, mockAi);

    expect(spans).toHaveLength(4);
    expect(spans.find((s) => s.type === "PERSON")?.text).toBe("Sarah Connor");
    expect(spans.find((s) => s.type === "ORG")?.text).toBe("Cyberdyne Systems");
    expect(spans.find((s) => s.type === "ADDRESS")?.text).toBe(
      "Los Angeles, CA"
    );
    expect(spans.find((s) => s.type === "DOB")?.text).toBe("1984-05-12");
  });

  it("handles markdown code fences and extraneous text gracefully", async () => {
    const mockAi: any = {
      run: async () => ({
        response: `Here is the detected PII:
\`\`\`json
[
  { "text": "John Doe", "type": "PERSON" }
]
\`\`\`
Hope this helps!`,
      }),
    };

    const text = "Welcome John Doe to the team.";
    const spans = await graniteScan(text, mockAi);

    expect(spans).toHaveLength(1);
    expect(spans[0].text).toBe("John Doe");
    expect(spans[0].type).toBe("PERSON");
    expect(spans[0].start).toBe(8);
    expect(spans[0].end).toBe(16);
  });

  it("rejects if AI fails", async () => {
    const failingAi: any = {
      run: async () => {
        throw new Error("Workers AI rate limit");
      },
    };

    await expect(graniteScan("Some text", failingAi)).rejects.toThrow("Semantic PII detection unavailable");
  });

  it("skips malformed and ungrounded entities without discarding valid spans", async () => {
    const mockAi: any = {
      run: async () => ({
        response: JSON.stringify([
          { text: "John Doe", type: "PERSON" },
          { text: "Nobody Here", type: "PERSON" },
          { text: "John Doe", type: "BOGUS" },
          { text: "   ", type: "PERSON" },
          null,
        ]),
      }),
    };

    const spans = await graniteScan("Hello John Doe.", mockAi);
    expect(spans).toHaveLength(1);
    expect(spans[0].text).toBe("John Doe");
    expect(spans[0].type).toBe("PERSON");
  });

  it("ignores bare identifiers while keeping natural-language names", async () => {
    const mockAi: any = {
      run: async () => ({
        response: JSON.stringify([
          { text: "John Doe", type: "PERSON" },
          { text: "topicCandidates", type: "ORG" },
          { text: "en", type: "PERSON" },
        ]),
      }),
    };

    const spans = await graniteScan("Hello John Doe.\ntopicCandidates\nen", mockAi);
    expect(spans).toHaveLength(1);
    expect(spans[0].text).toBe("John Doe");
  });
});

describe("Span Resolver & Merger", () => {
  it("deduplicates identical spans and sorts descending by start offset", () => {
    const text = "Alice is at alice@example.com and Bob is at bob@example.com.";
    const spans: DetectedSpan[] = [
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 12,
        end: 29,
        source: "regex",
      },
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 12,
        end: 29,
        source: "regex",
      },
      {
        text: "bob@example.com",
        type: "EMAIL",
        start: 44,
        end: 59,
        source: "regex",
      },
    ];

    const merged = mergeAndDeduplicateSpans(spans, text);
    expect(merged).toHaveLength(2);
    // Crucial requirement: sorted descending by start offset!
    expect(merged[0].start).toBe(44);
    expect(merged[1].start).toBe(12);
  });

  it("prefers regex for structural types over Granite", () => {
    const text = "Contact alice@example.com now.";
    const spans: DetectedSpan[] = [
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 8,
        end: 25,
        source: "regex",
        confidence: 0.99,
      },
      {
        text: "alice",
        type: "PERSON",
        start: 8,
        end: 13,
        source: "granite",
        confidence: 0.85,
      },
    ];

    const merged = mergeAndDeduplicateSpans(spans, text);
    expect(merged).toHaveLength(1);
    expect(merged[0].type).toBe("EMAIL");
    expect(merged[0].source).toBe("regex");
  });

  it("prefers Granite for semantic types when overlapping with weak matches", () => {
    const text = "Contact John Smith at Acme.";
    const spans: DetectedSpan[] = [
      {
        text: "John Smith",
        type: "PERSON",
        start: 8,
        end: 18,
        source: "granite",
        confidence: 0.9,
      },
    ];

    const merged = mergeAndDeduplicateSpans(spans, text);
    expect(merged).toHaveLength(1);
    expect(merged[0].type).toBe("PERSON");
    expect(merged[0].text).toBe("John Smith");
  });

  it("trims overlapping semantic spans instead of widening deterministic ones", () => {
    const text = "My email is alice@example.com. Thanks!";
    const spans: DetectedSpan[] = [
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 12,
        end: 29,
        source: "regex",
        confidence: 0.99,
      },
      {
        text: "My email is alice@example.com. Thanks!",
        type: "EMAIL",
        start: 0,
        end: 38,
        source: "llama",
        confidence: 0.9,
      },
    ];

    const merged = mergeAndDeduplicateSpans(spans, text);
    const exact = merged.find((s) => s.start === 12 && s.end === 29);
    expect(exact?.type).toBe("EMAIL");
    expect(exact?.source).toBe("regex");
    expect(exact?.text).toBe("alice@example.com");
    // Residue keeps coverage outside the deterministic span, still descending.
    expect(merged[0].start).toBeGreaterThanOrEqual(merged[1].start);
    for (const span of merged) expect(span.text).toBe(text.slice(span.start, span.end));
  });
});

describe("detectPii (Integration)", () => {
  it("combines local scanners and Llama", async () => {
    const mockAi: any = {
      run: async () => ({
        response: JSON.stringify([{ text: "Dr. Evelyn Reed", type: "PERSON" }]),
      }),
    };

    const text = "Dr. Evelyn Reed can be reached at evelyn@clinic.org.";
    const spans = await detectPii(text, mockAi);

    expect(spans).toHaveLength(2);
    const types = spans.map((s) => s.type);
    expect(types).toContain("PERSON");
    expect(types).toContain("EMAIL");
    // Verify descending sort order
    expect(spans[0].start).toBeGreaterThan(spans[1].start);
  });

  it("supports regexOnly option", async () => {
    let aiCalled = false;
    const mockAi: any = {
      run: async () => {
        aiCalled = true;
        return { response: "[]" };
      },
    };

    const text = "Contact user@example.com.";
    const spans = await detectPii(text, mockAi, { regexOnly: true });

    expect(aiCalled).toBe(false);
    expect(spans).toHaveLength(1);
    expect(spans[0].type).toBe("EMAIL");
  });
});

function screenPayload(high: Record<string, number> = {}, types: string[] = ["PERSON", "ADDRESS", "ORG", "DOB"]) {
  const answers: Record<string, unknown> = {};
  for (const type of types) {
    answers[type] = { type: "noul", noul: high[type] ?? 0.02 };
  }
  return { model: "clef-flash", answers, usage: { input_tokens: 90, output_tokens: 0 } };
}

describe("Clef-flash presence screen (clefPresenceScreen)", () => {
  it("builds one yes/no question per requested semantic type", () => {
    const questions = buildClefPresenceQuestions(["PERSON", "DOB", "EMAIL"]);
    expect(Object.keys(questions).sort()).toEqual(["DOB", "PERSON"]);
    for (const q of Object.values(questions)) {
      expect(q.type).toBe("noul");
      expect(q.instructions.length).toBeGreaterThan(0);
    }
  });

  it("returns flagged types at or above threshold", async () => {
    const mockAi: any = {
      run: async () => screenPayload({ PERSON: 0.91, ORG: 0.4 }),
    };
    const flagged = await clefPresenceScreen("Alice works at Acme", mockAi, ["PERSON", "ADDRESS", "ORG", "DOB"]);
    expect(flagged?.sort()).toEqual(["ORG", "PERSON"]);
  });

  it("returns null when Workers AI throws or answers are malformed", async () => {
    const throwing: any = {
      run: async () => {
        throw new Error("Model not found");
      },
    };
    expect(await clefPresenceScreen("text", throwing, ["PERSON"])).toBeNull();

    const malformed: any = { run: async () => ({ response: "[]" }) };
    expect(await clefPresenceScreen("text", malformed, ["PERSON"])).toBeNull();
  });

  it("returns [] without calling AI when no semantic types are requested", async () => {
    let calls = 0;
    const mockAi: any = {
      run: async () => {
        calls++;
        return screenPayload();
      },
    };
    expect(await clefPresenceScreen("text", mockAi, ["EMAIL"])).toEqual([]);
    expect(calls).toBe(0);
  });
});

describe("detectPii clef-flash gating", () => {
  it("skips the NER call entirely when the screen finds nothing", async () => {
    const calls: string[] = [];
    const mockAi: any = {
      run: async (model: string) => {
        calls.push(model);
        if (model === "@cf/cloudflare/clef-flash") return screenPayload();
        throw new Error("NER must not be called");
      },
    };

    const spans = await detectPii("Reach me at user@example.com please.", mockAi);

    expect(calls).toEqual(["@cf/cloudflare/clef-flash"]);
    expect(spans.map((s) => s.type)).toEqual(["EMAIL"]);
  });

  it("runs full NER when the screen flags and keeps deterministic spans", async () => {
    const calls: Array<{ model: string; input: any }> = [];
    const mockAi: any = {
      run: async (model: string, input: any) => {
        calls.push({ model, input });
        if (model === "@cf/cloudflare/clef-flash") return screenPayload({ PERSON: 0.88 });
        return { response: JSON.stringify([{ text: "Dr. Evelyn Reed", type: "PERSON" }]) };
      },
    };

    const text = "Dr. Evelyn Reed can be reached at evelyn@clinic.org.";
    const spans = await detectPii(text, mockAi);

    expect(calls.map((c) => c.model)).toEqual([
      "@cf/cloudflare/clef-flash",
      "@cf/meta/llama-3.1-8b-instruct-fp8",
    ]);
    // The screen runs on the same protected text as NER: known PII masked.
    expect(calls[0].input.state).not.toContain("evelyn@clinic.org");
    expect(calls[0].input.state.length).toBe(text.length);
    expect(calls[1].input.messages[1].content).not.toContain("evelyn@clinic.org");
    const types = spans.map((s) => s.type);
    expect(types).toContain("PERSON");
    expect(types).toContain("EMAIL");
  });

  it("falls back to full legacy NER when the screen is unavailable", async () => {
    const calls: string[] = [];
    const mockAi: any = {
      run: async (model: string) => {
        calls.push(model);
        if (model === "@cf/cloudflare/clef-flash") throw new Error("503");
        return { response: JSON.stringify([{ text: "Alice", type: "PERSON" }]) };
      },
    };

    const spans = await detectPii("hello Alice", mockAi);

    expect(calls).toEqual(["@cf/cloudflare/clef-flash", "@cf/meta/llama-3.1-8b-instruct-fp8"]);
    expect(spans.map((s) => s.type)).toContain("PERSON");
  });

  it("forces legacy always-run NER when useClef: false", async () => {
    const calls: string[] = [];
    const mockAi: any = {
      run: async (model: string) => {
        calls.push(model);
        return { response: "[]" };
      },
    };

    await detectPii("nothing sensitive here", mockAi, { useClef: false });

    expect(calls).toEqual(["@cf/meta/llama-3.1-8b-instruct-fp8"]);
  });

  it("resolves legacy-shaped AI responses through the NER fallback path", async () => {
    // Old mocks answer every model with NER JSON: the screen sees a
    // malformed payload and the full legacy NER path produces the spans.
    const mockAi: any = {
      run: async () => ({
        response: JSON.stringify([{ text: "Dr. Evelyn Reed", type: "PERSON" }]),
      }),
    };
    const spans = await detectPii("Dr. Evelyn Reed can be reached at evelyn@clinic.org.", mockAi);
    const types = spans.map((s) => s.type);
    expect(types).toContain("PERSON");
    expect(types).toContain("EMAIL");
  });

  it("honors a custom clefThreshold instead of the default", async () => {
    const mockAi: any = {
      run: async (model: string) => {
        if (model === "@cf/cloudflare/clef-flash") return screenPayload({ PERSON: 0.15 });
        return { response: JSON.stringify([{ text: "Alice", type: "PERSON" }]) };
      },
    };
    // Default threshold (0.2): 0.15 does not flag -> NER skipped.
    const skipped = await detectPiiInner("hello Alice", mockAi);
    expect(skipped.meta.models).toEqual(["@cf/cloudflare/clef-flash"]);
    expect(skipped.spans.map((s) => s.type)).not.toContain("PERSON");
    // Lower threshold (0.1): 0.15 flags -> full NER runs.
    const flagged = await detectPiiInner("hello Alice", mockAi, { clefThreshold: 0.1 });
    expect(flagged.meta.models).toEqual([
      "@cf/cloudflare/clef-flash",
      "@cf/meta/llama-3.1-8b-instruct-fp8",
    ]);
    expect(flagged.spans.map((s) => s.type)).toContain("PERSON");
  });

  it("falls back to the default threshold for invalid clefThreshold values", async () => {
    const mockAi: any = {
      run: async (model: string) => {
        if (model === "@cf/cloudflare/clef-flash") return screenPayload({ PERSON: 0.15 });
        return { response: "[]" };
      },
    };
    for (const clefThreshold of [0, 1, -0.5, 99, NaN]) {
      const result = await detectPiiInner("hello Alice", mockAi, { clefThreshold });
      // Invalid -> default 0.2 -> 0.15 does not flag -> NER skipped.
      expect(result.meta.models).toEqual(["@cf/cloudflare/clef-flash"]);
    }
  });

  it("reports models: [] when no semantic types are requested", async () => {
    let calls = 0;
    const mockAi: any = {
      run: async () => {
        calls++;
        return screenPayload();
      },
    };
    const result = await detectPiiInner("user@example.com", mockAi, { enabledTypes: ["EMAIL"] });
    expect(calls).toBe(0);
    expect(result.meta.models).toEqual([]);
    expect(result.spans.map((s) => s.type)).toEqual(["EMAIL"]);
  });

  it("reports models accurately across all engine paths", async () => {
    // Skip path: screen clears -> [clef].
    const skipAi: any = {
      run: async (model: string) => {
        if (model !== "@cf/cloudflare/clef-flash") throw new Error("NER must not run");
        return screenPayload();
      },
    };
    expect((await detectPiiInner("nothing here", skipAi)).meta.models).toEqual([
      "@cf/cloudflare/clef-flash",
    ]);
    // Legacy-forced path: [llama].
    const legacyAi: any = { run: async () => ({ response: "[]" }) };
    expect((await detectPiiInner("nothing here", legacyAi, { useClef: false })).meta.models).toEqual([
      "@cf/meta/llama-3.1-8b-instruct-fp8",
    ]);
    // Local-only path: [].
    expect((await detectPiiInner("nothing here", legacyAi, { regexOnly: true })).meta.models).toEqual([]);
  });
});

describe("detectPiiInner degraded fallback (allowDegraded)", () => {
  const down: any = {
    run: async () => {
      throw new Error("503 Service Unavailable");
    },
  };

  it("throws 503 by default when NER is unavailable", async () => {
    await expect(detectPiiInner("contact Jane Doe", down)).rejects.toThrow();
  });

  it("returns local-layer spans with degraded:true when allowDegraded", async () => {
    const { spans, meta } = await detectPiiInner("email me at jane@example.com", down, {
      allowDegraded: true,
    });
    expect(meta.degraded).toBe(true);
    expect(spans.some((s) => s.type === "EMAIL" && s.text === "jane@example.com")).toBe(true);
  });

  it("fails on misconfiguration even when allowDegraded (degrade on provider failure only)", async () => {
    await expect(detectPiiInner("contact Jane Doe", null as any, { allowDegraded: true })).rejects.toThrow();
  });
});

describe("detectPiiInner gemini cross-provider leg", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });
  const geminiOk = (text: string) => ({
    ok: true,
    json: async () => ({ candidates: [{ content: { parts: [{ text }] }, finishReason: "STOP" }] }),
  });
  const down: any = {
    run: async () => {
      throw new Error("503 Service Unavailable");
    },
  };

  it("falls over to Gemini NER when Workers AI NER fails", async () => {
    globalThis.fetch = (async () => geminiOk('[{"text": "Jane Doe", "type": "PERSON"}]')) as any;
    const { spans, meta } = await detectPiiInner("contact Jane Doe", down, { geminiKey: "k" });
    expect(meta.degraded ?? false).toBe(false);
    expect(meta.models).toContain("gemini-3.5-flash-lite");
    const person = spans.find((s) => s.type === "PERSON");
    expect(person?.text).toBe("Jane Doe");
    expect(person?.source).toBe("gemini");
  });

  it("degrades only when Gemini also fails and allowDegraded is set", async () => {
    globalThis.fetch = (async () => ({ ok: false, status: 500, json: async () => ({}) })) as any;
    const degraded = await detectPiiInner("contact Jane Doe", down, { geminiKey: "k", allowDegraded: true });
    expect(degraded.meta.degraded).toBe(true);
    expect(degraded.meta.models).toContain("gemini-3.5-flash-lite");
    await expect(detectPiiInner("contact Jane Doe", down, { geminiKey: "k" })).rejects.toThrow();
  });

  it("never calls Gemini when Workers AI NER answers", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      return geminiOk("[]");
    }) as any;
    const workingAi: any = { run: async () => ({ response: "[]" }) };
    const { meta } = await detectPiiInner("nothing here", workingAi, { useClef: false, geminiKey: "k" });
    expect(meta.models).toEqual(["@cf/meta/llama-3.1-8b-instruct-fp8"]);
    expect(calls).toBe(0);
  });
});
