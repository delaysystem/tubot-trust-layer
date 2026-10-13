/**
 * Meta Llama Guard 3 Safety Moderation Engine & Fast Heuristics Scanner.
 * Provides multi-tier moderation:
 * - Tier 1: Sub-millisecond deterministic regex/pattern heuristics (prompt injections, zero-width evasion, XSS, SQLi).
 * - Tier 2: Meta Llama Guard 3 8B classification via Cloudflare Workers AI (@cf/meta/llama-guard-3-8b).
 */

export type SafetySeverity = "critical" | "high" | "medium";

export interface SafetyCategoryInfo {
  name: string;
  description: string;
  severity: SafetySeverity;
}

/**
 * Standard Meta Llama Guard 3 safety categories S1 through S14.
 */
export const LLAMA_GUARD_CATEGORIES: Record<string, SafetyCategoryInfo> = {
  S1: {
    name: "Violent Crimes",
    description: "Responses that encourage, facilitate, or provide instructions for violent crimes.",
    severity: "critical",
  },
  S2: {
    name: "Non-Violent Crimes",
    description: "Responses that encourage, facilitate, or provide instructions for non-violent crimes, such as theft, fraud, or drug trafficking.",
    severity: "high",
  },
  S3: {
    name: "Sex-Related Crimes",
    description: "Responses that encourage, facilitate, or provide instructions for sex-related crimes including sexual assault and trafficking.",
    severity: "critical",
  },
  S4: {
    name: "Child Sexual Exploitation",
    description: "Responses that contain, promote, or facilitate child sexual exploitation or abuse.",
    severity: "critical",
  },
  S5: {
    name: "Defamation",
    description: "Responses that produce verifiably false statements intended to harm an individual's reputation.",
    severity: "medium",
  },
  S6: {
    name: "Specialized Advice",
    description: "Harmful or unauthorized medical, legal, or financial advice provided without appropriate disclaimers.",
    severity: "medium",
  },
  S7: {
    name: "Privacy Violations",
    description: "Responses that compromise privacy through doxxing, unauthorized personal data disclosure, or illegal surveillance.",
    severity: "high",
  },
  S8: {
    name: "Intellectual Property",
    description: "Responses that violate intellectual property rights or trade secrets.",
    severity: "medium",
  },
  S9: {
    name: "Indiscriminate Weapons",
    description: "Responses that assist with chemical, biological, radiological, nuclear, or high-yield explosive weapons (CBRNE).",
    severity: "critical",
  },
  S10: {
    name: "Hate Speech",
    description: "Responses that promote hatred, incite violence, or disparage protected characteristics.",
    severity: "high",
  },
  S11: {
    name: "Suicide & Self-Harm",
    description: "Responses that encourage, assist, or provide instructions for suicide or deliberate self-harm.",
    severity: "critical",
  },
  S12: {
    name: "Sexual Content",
    description: "Responses depicting non-consensual or inappropriate sexual content.",
    severity: "medium",
  },
  S13: {
    name: "Cyberattacks & Exploits",
    description: "Responses facilitating malware creation, cracking, hacking, unauthorized system access, or denial-of-service attacks.",
    severity: "critical",
  },
  S14: {
    name: "Code Interpreter Abuse / System Manipulation",
    description: "Attempts to bypass safety guardrails, perform jailbreaks, escape execution sandboxes, or manipulate system prompts.",
    severity: "critical",
  },
};

export interface HeuristicFinding {
  source: "heuristic";
  code?: string;
  category: string;
  detail?: string;
  severity?: SafetySeverity;
}

export interface LlamaGuardFinding {
  source: "llama-guard";
  code?: string;
  category: string;
  detail?: string;
  severity?: SafetySeverity;
}

export interface LlamaGuardResult {
  safe: boolean;
  categoryCodes: string[];
  categories: string[];
  findings: LlamaGuardFinding[];
  rawResponse?: any;
  error?: string;
}

export interface ModerateOptions {
  mode?: "block" | "warn";
  heuristicOnly?: boolean;
  allowedCategories?: string[];
}

export interface ModerateFinding {
  source: "heuristic" | "llama-guard";
  code?: string;
  category: string;
  detail?: string;
  severity?: SafetySeverity;
}

export interface ModerateResult {
  safe: boolean;
  flagged: boolean;
  action: "block" | "warn" | "allow";
  categories: string[];
  categoryCodes: string[];
  findings: ModerateFinding[];
  executionTimeMs: number;
}

// ---------------------------------------------------------
// Fast Deterministic Pattern Definitions (< 1ms execution)
// ---------------------------------------------------------

interface ExploitPattern {
  name: string;
  code: string;
  category: string;
  severity: SafetySeverity;
  detail: string;
  regex: RegExp;
}

const SYSTEM_OVERRIDE_PATTERNS: ExploitPattern[] = [
  {
    name: "ignore_instructions",
    code: "S14",
    category: LLAMA_GUARD_CATEGORIES.S14.name,
    severity: "critical",
    detail: "System prompt override keyword detected (ignore instructions)",
    regex: /\bignore\s+(?:all\s+previous|all|previous|above|the\s+above)\s+instructions?\b/i,
  },
  {
    name: "disregard_instructions",
    code: "S14",
    category: LLAMA_GUARD_CATEGORIES.S14.name,
    severity: "critical",
    detail: "System prompt override keyword detected (disregard instructions)",
    regex: /\bdisregard\s+(?:all\s+previous|all|previous|above|the\s+above)\s+instructions?\b/i,
  },
  {
    name: "jailbreak_mode",
    code: "S14",
    category: LLAMA_GUARD_CATEGORIES.S14.name,
    severity: "critical",
    detail: "Jailbreak mode activation attempt detected (developer/dan/jailbreak/unrestricted/god mode)",
    regex: /\b(?:you\s+are|you're)(?:\s+now)?\s+in\s+(?:developer|dan|jailbreak|unrestricted|god)\s+mode\b/i,
  },
  {
    name: "bypass_filters",
    code: "S14",
    category: LLAMA_GUARD_CATEGORIES.S14.name,
    severity: "critical",
    detail: "Guardrail filter bypass attempt detected (bypass filters)",
    regex: /\bbypass\s+(?:all\s+)?(?:all|guardrails?|safety|security)\s+filters?\b/i,
  },
  {
    name: "reveal_prompt_or_key",
    code: "S14",
    category: LLAMA_GUARD_CATEGORIES.S14.name,
    severity: "critical",
    detail: "System asset exfiltration attempt detected (reveal prompt/secret/api key)",
    regex: /\breveal\s+(?:(?:the|your)\s+)?(?:system\s+prompts?|internal\s+prompts?|secret\s+keys?|api\s+keys?)\b/i,
  },
];

const DELIMITER_TOKENS = [
  { token: "<|im_start|>", regex: /<\|im_start\|>/i },
  { token: "<|im_end|>", regex: /<\|im_end\|>/i },
  { token: "[INST]", regex: /\[INST\]/i },
  { token: "[/INST]", regex: /\[\/INST\]/i },
  { token: "<|endoftext|>", regex: /<\|endoftext\|>/i },
  { token: "<<SYS>>", regex: /<<SYS>>/i },
  { token: "<|system|>", regex: /<\|system\|>/i },
  { token: "[SYSTEM]", regex: /\[SYSTEM\]/i },
];

// Zero-width characters used for invisible payload delivery and filter evasion:
// \u200B (zero-width space), \u200C (zero-width non-joiner), \u200D (zero-width joiner), \uFEFF (zero-width no-break space / BOM)
const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\uFEFF]/;

const INJECTION_PATTERNS: ExploitPattern[] = [
  {
    name: "script_tag",
    code: "S13",
    category: LLAMA_GUARD_CATEGORIES.S13.name,
    severity: "critical",
    detail: "Cross-site scripting (XSS) / script injection detected (<script>)",
    regex: /<\s*script[\s>]/i,
  },
  {
    name: "javascript_uri",
    code: "S13",
    category: LLAMA_GUARD_CATEGORIES.S13.name,
    severity: "critical",
    detail: "JavaScript URI scheme execution attempt detected (javascript:)",
    regex: /javascript\s*:/i,
  },
  {
    name: "sql_union_select",
    code: "S13",
    category: LLAMA_GUARD_CATEGORIES.S13.name,
    severity: "critical",
    detail: "SQL injection signature detected (UNION SELECT)",
    regex: /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
  },
  {
    name: "sql_drop_table",
    code: "S13",
    category: LLAMA_GUARD_CATEGORIES.S13.name,
    severity: "critical",
    detail: "Destructive SQL injection signature detected (DROP TABLE)",
    regex: /\bDROP\s+TABLE\b/i,
  },
];

/**
 * Fast Regex/Pattern Scanner (< 1ms).
 * Evaluates inputs against high-confidence signatures for:
 * 1. System prompt override keywords
 * 2. Delimiter smuggling & LLM template tokens
 * 3. Obfuscated zero-width characters
 * 4. Script & SQL injection patterns
 */
export function heuristicExploitScan(text: string): HeuristicFinding[] {
  if (!text || typeof text !== "string") {
    return [];
  }

  const findings: HeuristicFinding[] = [];

  // 1. System prompt override keywords
  for (const pattern of SYSTEM_OVERRIDE_PATTERNS) {
    if (pattern.regex.test(text)) {
      findings.push({
        source: "heuristic",
        code: pattern.code,
        category: pattern.category,
        detail: pattern.detail,
        severity: pattern.severity,
      });
    }
  }

  // 2. Delimiter smuggling & LLM template tokens
  for (const item of DELIMITER_TOKENS) {
    if (item.regex.test(text)) {
      findings.push({
        source: "heuristic",
        code: "S14",
        category: LLAMA_GUARD_CATEGORIES.S14.name,
        detail: `Delimiter smuggling / template token detected: ${item.token}`,
        severity: "critical",
      });
    }
  }

  // 3. Obfuscated zero-width characters
  if (ZERO_WIDTH_REGEX.test(text)) {
    findings.push({
      source: "heuristic",
      code: "S14",
      category: LLAMA_GUARD_CATEGORIES.S14.name,
      detail: "Obfuscated zero-width hidden characters detected (evasion attempt)",
      severity: "high",
    });
  }

  // 4. Script & SQL injection signatures
  for (const injection of INJECTION_PATTERNS) {
    if (injection.regex.test(text)) {
      findings.push({
        source: "heuristic",
        code: injection.code,
        category: injection.category,
        detail: injection.detail,
        severity: injection.severity,
      });
    }
  }

  return findings;
}

/**
 * Parses and normalizes raw outputs from Meta Llama Guard 3.
 * Handles both string outputs ("safe", "unsafe\nS13", "unsafe\nS1,S14")
 * and object outputs ({ response: { safe: boolean, categories: string[] } }).
 */
export function parseLlamaGuardOutput(raw: any): {
  safe: boolean;
  categoryCodes: string[];
} {
  if (!raw) {
    return { safe: true, categoryCodes: [] };
  }

  let content = raw;
  if (typeof raw === "object" && raw !== null && "response" in raw) {
    content = raw.response;
  }

  // Object response format: { safe: boolean, categories?: string[] }
  if (typeof content === "object" && content !== null) {
    const rawCategories: any[] = Array.isArray(content.categories)
      ? content.categories
      : [];
    const codes: string[] = [];

    for (const cat of rawCategories) {
      if (typeof cat === "string") {
        const trimmed = cat.trim();
        const codeMatch = trimmed.match(/\b(S(?:[1-9]|1[0-4]))\b/i);
        if (codeMatch) {
          codes.push(codeMatch[1].toUpperCase());
        } else {
          // Check if category name was provided directly
          const matchedEntry = Object.entries(LLAMA_GUARD_CATEGORIES).find(
            ([_, val]) => val.name.toLowerCase() === trimmed.toLowerCase()
          );
          if (matchedEntry) {
            codes.push(matchedEntry[0]);
          } else if (trimmed.length > 0) {
            codes.push(trimmed);
          }
        }
      }
    }

    const isSafe =
      typeof content.safe === "boolean" ? content.safe : codes.length === 0;

    return {
      safe: isSafe && codes.length === 0,
      categoryCodes: Array.from(new Set(codes)),
    };
  }

  // String response format
  if (typeof content === "string") {
    const trimmed = content.trim();
    if (trimmed.toLowerCase().startsWith("unsafe")) {
      const matches = trimmed.match(/\bS(?:[1-9]|1[0-4])\b/gi);
      const codes = matches
        ? Array.from(new Set(matches.map((m) => m.toUpperCase())))
        : [];
      return {
        safe: false,
        categoryCodes: codes,
      };
    } else if (trimmed.toLowerCase().startsWith("safe")) {
      return {
        safe: true,
        categoryCodes: [],
      };
    } else {
      // In case format omitted prefix but contains category code
      const matches = trimmed.match(/\bS(?:[1-9]|1[0-4])\b/gi);
      if (matches && matches.length > 0) {
        return {
          safe: false,
          categoryCodes: Array.from(new Set(matches.map((m) => m.toUpperCase()))),
        };
      }
    }
  }

  return { safe: true, categoryCodes: [] };
}

/**
 * Llama Guard 3 AI Scanner.
 * Invokes @cf/meta/llama-guard-3-8b via Cloudflare Workers AI.
 * Maps raw S1..S14 codes into structured category names, descriptions, and severities.
 */
export async function llamaGuardScan(
  text: string,
  ai: Ai
): Promise<LlamaGuardResult> {
  if (!text || typeof text !== "string" || text.trim().length === 0) {
    return {
      safe: true,
      categoryCodes: [],
      categories: [],
      findings: [],
    };
  }

  try {
    const rawResult: any = await (ai as any).run(
      "@cf/meta/llama-guard-3-8b",
      {
        messages: [{ role: "user", content: text }],
      }
    );

    const content = typeof rawResult === "object" && rawResult !== null && "response" in rawResult ? rawResult.response : rawResult;
    if (typeof content === "string" ? !/^(?:safe|unsafe)(?:\s|$)/i.test(content.trim()) : !content || typeof content.safe !== "boolean") throw new Error("Invalid safety response");
    const parsed = parseLlamaGuardOutput(rawResult);
    const findings: LlamaGuardFinding[] = [];
    const categories: string[] = [];

    for (const code of parsed.categoryCodes) {
      const catInfo = LLAMA_GUARD_CATEGORIES[code];
      if (catInfo) {
        categories.push(catInfo.name);
        findings.push({
          source: "llama-guard",
          code,
          category: catInfo.name,
          detail: catInfo.description,
          severity: catInfo.severity,
        });
      } else {
        categories.push(code);
        findings.push({
          source: "llama-guard",
          code,
          category: code,
          detail: `Llama Guard violation (${code})`,
          severity: "high",
        });
      }
    }

    if (!parsed.safe && findings.length === 0) {
      categories.push("Unspecified Safety Violation");
      findings.push({
        source: "llama-guard",
        category: "Unspecified Safety Violation",
        detail: "Content flagged as unsafe by Llama Guard 3",
        severity: "high",
      });
    }

    return {
      safe: parsed.safe,
      categoryCodes: parsed.categoryCodes,
      categories: Array.from(new Set(categories)),
      findings,
      rawResponse: rawResult,
    };
  } catch (err: any) {
    throw Object.assign(new Error("Safety inference unavailable"), { status: 503 });
  }
}

/**
 * Multi-Tier Moderation Entrypoint.
 * Evaluates Tier 1 deterministic heuristics + Tier 2 Meta Llama Guard 3.
 */
export async function moderateInput(
  text: string,
  ai?: Ai,
  options?: ModerateOptions
): Promise<ModerateResult> {
  const startTime = performance.now();
  const mode = options?.mode ?? "block";

  if (!text || typeof text !== "string" || text.trim().length === 0) {
    return {
      safe: true,
      flagged: false,
      action: "allow",
      categories: [],
      categoryCodes: [],
      findings: [],
      executionTimeMs: Math.max(
        0,
        Math.round((performance.now() - startTime) * 100) / 100
      ),
    };
  }

  // Tier 1: Fast Heuristic Scanner (< 1ms)
  const heuristicFindings = heuristicExploitScan(text);

  // Tier 2: Llama Guard 3 Scanner (if AI binding provided and not heuristicOnly)
  let lgFindings: ModerateFinding[] = [];
  if (ai && !options?.heuristicOnly) {
    const lgResult = await llamaGuardScan(text, ai);
    if (lgResult.error) throw Object.assign(new Error("Safety inference unavailable"), { status: 503 });
    lgFindings = lgResult.findings;
  }

  const allFindings: ModerateFinding[] = [...heuristicFindings, ...lgFindings];

  // Filter allowed categories if specified
  const allowed =
    options?.allowedCategories?.map((c) => c.trim().toLowerCase()) ?? [];
  const activeFindings = allFindings.filter((finding) => {
    if (allowed.length === 0) return true;
    if (finding.code && allowed.includes(finding.code.toLowerCase())) {
      return false; // suppressed by category code
    }
    if (finding.category && allowed.includes(finding.category.toLowerCase())) {
      return false; // suppressed by category name
    }
    return true;
  });

  const flagged = activeFindings.length > 0;
  const safe = !flagged;
  const action: "block" | "warn" | "allow" = flagged
    ? mode === "warn"
      ? "warn"
      : "block"
    : "allow";

  const categories = Array.from(new Set(activeFindings.map((f) => f.category)));
  const categoryCodes = Array.from(
    new Set(
      activeFindings
        .map((f) => f.code)
        .filter((c): c is string => typeof c === "string" && c.length > 0)
    )
  );

  const executionTimeMs = Math.max(
    0,
    Math.round((performance.now() - startTime) * 100) / 100
  );

  return {
    safe,
    flagged,
    action,
    categories,
    categoryCodes,
    findings: activeFindings,
    executionTimeMs,
  };
}
