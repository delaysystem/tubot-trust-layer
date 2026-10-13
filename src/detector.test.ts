/// <reference types="bun-types" />
import { describe, expect, it } from "bun:test";
import {
  detectPii,
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
