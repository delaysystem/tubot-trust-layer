/// <reference types="bun-types" />
import { describe, expect, it } from "bun:test";
import { type DetectedSpan } from "./detector";
import { maskText, unmaskText } from "./masker";

describe("maskText", () => {
  it("masks entities with default numbered format ([NAME_1], [EMAIL_1], etc.)", () => {
    const text =
      "Hello Alice, please email me at alice@example.com or call 555-234-5678.";
    const spans: DetectedSpan[] = [
      { text: "Alice", type: "PERSON", start: 6, end: 11, source: "granite" },
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 32,
        end: 49,
        source: "regex",
      },
      {
        text: "555-234-5678",
        type: "PHONE",
        start: 58,
        end: 70,
        source: "regex",
      },
    ];

    const result = maskText(text, spans);

    expect(result.maskedText).toBe(
      "Hello [NAME_1], please email me at [EMAIL_1] or call [PHONE_1]."
    );
    expect(result.tokenMap["[NAME_1]"]).toEqual({
      value: "Alice",
      type: "PERSON",
    });
    expect(result.tokenMap["[EMAIL_1]"]).toEqual({
      value: "alice@example.com",
      type: "EMAIL",
    });
    expect(result.tokenMap["[PHONE_1]"]).toEqual({
      value: "555-234-5678",
      type: "PHONE",
    });
    expect(typeof result.vaultId).toBe("string");
    expect(result.vaultId.length).toBeGreaterThan(0);
  });

  it("handles coreference: reuses the same token for identical entities", () => {
    const text =
      "Alice met Bob. Alice gave Bob her file, and Alice was happy.";
    const spans: DetectedSpan[] = [
      { text: "Alice", type: "PERSON", start: 0, end: 5, source: "granite" },
      { text: "Bob", type: "PERSON", start: 10, end: 13, source: "granite" },
      { text: "Alice", type: "PERSON", start: 15, end: 20, source: "granite" },
      { text: "Bob", type: "PERSON", start: 26, end: 29, source: "granite" },
      { text: "Alice", type: "PERSON", start: 44, end: 49, source: "granite" },
    ];

    const result = maskText(text, spans);

    expect(result.maskedText).toBe(
      "[NAME_1] met [NAME_2]. [NAME_1] gave [NAME_2] her file, and [NAME_1] was happy."
    );
    expect(Object.keys(result.tokenMap)).toHaveLength(2);
    expect(result.tokenMap["[NAME_1]"]).toEqual({
      value: "Alice",
      type: "PERSON",
    });
    expect(result.tokenMap["[NAME_2]"]).toEqual({
      value: "Bob",
      type: "PERSON",
    });
  });

  it("supports custom token format [PII:NAME:hash]", () => {
    const text = "Contact Alice at alice@example.com.";
    const spans: DetectedSpan[] = [
      { text: "Alice", type: "PERSON", start: 8, end: 13, source: "granite" },
      {
        text: "alice@example.com",
        type: "EMAIL",
        start: 17,
        end: 34,
        source: "regex",
      },
    ];

    const result = maskText(text, spans, {
      format: "custom",
      customPrefix: "PII",
      vaultId: "vault-12345",
    });

    expect(result.vaultId).toBe("vault-12345");
    expect(result.maskedText).toMatch(
      /Contact \[PII:NAME:[0-9a-f]{6}\] at \[PII:EMAIL:[0-9a-f]{6}\]\./
    );
    const tokens = Object.keys(result.tokenMap);
    expect(tokens).toHaveLength(2);
  });

  it("supports UUID token format", () => {
    const text = "Server at 192.168.1.1.";
    const spans: DetectedSpan[] = [
      {
        text: "192.168.1.1",
        type: "IP_ADDRESS",
        start: 10,
        end: 21,
        source: "regex",
      },
    ];

    const result = maskText(text, spans, { format: "uuid" });
    expect(result.maskedText).toMatch(
      /Server at \[IP_ADDRESS_[0-9a-fA-F-]{36}\]\./
    );
  });

  it("safely handles reverse offset replacement without offset drift", () => {
    // Spans in reverse or disordered input
    const text = "First 111-22-3333 then 444-55-6666.";
    const spans: DetectedSpan[] = [
      {
        text: "444-55-6666",
        type: "SSN",
        start: 23,
        end: 34,
        source: "regex",
      },
      {
        text: "111-22-3333",
        type: "SSN",
        start: 6,
        end: 17,
        source: "regex",
      },
    ];

    const result = maskText(text, spans);
    expect(result.maskedText).toBe("First [SSN_1] then [SSN_2].");
  });
});

describe("unmaskText", () => {
  it("performs complete roundtrip with plain string tokenMap", () => {
    const originalText =
      "Report from John Doe (john@acme.com), phone +1-555-0199, SSN: 123-45-6789.";
    const spans: DetectedSpan[] = [
      { text: "John Doe", type: "PERSON", start: 12, end: 20, source: "granite" },
      {
        text: "john@acme.com",
        type: "EMAIL",
        start: 22,
        end: 35,
        source: "regex",
      },
      {
        text: "+1-555-0199",
        type: "PHONE",
        start: 44,
        end: 55,
        source: "regex",
      },
      {
        text: "123-45-6789",
        type: "SSN",
        start: 62,
        end: 73,
        source: "regex",
      },
    ];

    const maskResult = maskText(originalText, spans);

    // Convert to plain Record<string, string>
    const plainMap: Record<string, string> = {};
    for (const [token, data] of Object.entries(maskResult.tokenMap)) {
      plainMap[token] = data.value;
    }

    const unmasked = unmaskText(maskResult.maskedText, plainMap);

    expect(unmasked.unmaskedText).toBe(originalText);
    expect(unmasked.restoredCount).toBe(4);
    expect(unmasked.restoredTokens).toHaveLength(4);
  });

  it("performs complete roundtrip directly with MaskResult.tokenMap", () => {
    const originalText =
      "Credit card 4242-4242-4242-4242 charged for user@test.com.";
    const spans: DetectedSpan[] = [
      {
        text: "4242-4242-4242-4242",
        type: "CREDIT_CARD",
        start: 12,
        end: 31,
        source: "regex",
      },
      {
        text: "user@test.com",
        type: "EMAIL",
        start: 44,
        end: 57,
        source: "regex",
      },
    ];

    const maskResult = maskText(originalText, spans);
    const unmasked = unmaskText(maskResult.maskedText, maskResult.tokenMap);

    expect(unmasked.unmaskedText).toBe(originalText);
    expect(unmasked.restoredCount).toBe(2);
  });

  it("preserves surrounding markdown, punctuation, and formatting", () => {
    const originalText = `### Customer Overview
- **Name:** Alice Smith
- **Email:** <alice.smith@hospital.org>
- **Notes:** (High-priority case!)`;

    const aliceIdx = originalText.indexOf("Alice Smith");
    const emailIdx = originalText.indexOf("alice.smith@hospital.org");

    const spans: DetectedSpan[] = [
      {
        text: "Alice Smith",
        type: "PERSON",
        start: aliceIdx,
        end: aliceIdx + "Alice Smith".length,
        source: "granite",
      },
      {
        text: "alice.smith@hospital.org",
        type: "EMAIL",
        start: emailIdx,
        end: emailIdx + "alice.smith@hospital.org".length,
        source: "regex",
      },
    ];

    const maskResult = maskText(originalText, spans);
    const unmasked = unmaskText(maskResult.maskedText, maskResult.tokenMap);

    expect(unmasked.unmaskedText).toBe(originalText);
  });

  it("handles repeated tokens and tracks restored count accurately", () => {
    const maskedText = "[NAME_1] sent [NAME_1] a message: [NAME_1] is ready.";
    const tokenMap = {
      "[NAME_1]": "Eve",
    };

    const result = unmaskText(maskedText, tokenMap);
    expect(result.unmaskedText).toBe("Eve sent Eve a message: Eve is ready.");
    expect(result.restoredCount).toBe(3);
    expect(result.restoredTokens).toEqual(["[NAME_1]"]);
  });

  it("handles empty tokenMap or text safely", () => {
    expect(unmaskText("No tokens here", {})).toEqual({
      unmaskedText: "No tokens here",
      restoredCount: 0,
      restoredTokens: [],
    });

    expect(unmaskText("", { "[NAME_1]": "Alice" })).toEqual({
      unmaskedText: "",
      restoredCount: 0,
      restoredTokens: [],
    });
  });
});
