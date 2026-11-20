/**
 * Standard Tool Definitions for TuBot Trust Layer PII Masking & Unmasking.
 * Compatible with OpenAI Function Calling, Anthropic Tool Use, and Salesforce Agentforce.
 */

export const MASK_PII_TOOL = {
  name: "mask_pii",
  description:
    "Detects Personally Identifiable Information (PII) using Llama 3.1 8B + Rust/Wasm + OpenRedaction AI and high-speed regex, encrypts the sensitive values into Cloudflare D1 with AES-256-GCM, and returns masked text with replacement tokens and a client-held decryption key.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The plaintext input containing sensitive personal information to be masked.",
      },
      key: {
        type: "string",
        description:
          "Optional user-provided 256-bit AES key (base64) or passphrase. If omitted, a cryptographically secure 256-bit key is generated and returned.",
      },
      entities: {
        type: "array",
        items: {
          type: "string",
          enum: [
            "EMAIL",
            "PHONE",
            "SSN",
            "CREDIT_CARD",
            "IP_ADDRESS",
            "SECRET",
            "PERSON",
            "ADDRESS",
            "ORG",
            "DOB",
            "FINANCIAL",
            "CUSTOM",
          ],
        },
        description: "Optional list of entity categories to mask. Defaults to all detected types.",
      },
      format: {
        type: "string",
        enum: ["numbered", "uuid", "custom"],
        description: "Token format for replacement. 'numbered' (e.g. [NAME_1]) is recommended for LLM prompts.",
        default: "numbered",
      },
      ttlSeconds: {
        type: "integer",
        description: "Optional expiration TTL in seconds for the stored encrypted vault record.",
      },
      vaultId: {
        type: "string",
        description: "Optional session or vault identifier to associate with the masked record.",
      },
    },
    required: ["text"],
  },
} as const;

export const UNMASK_PII_TOOL = {
  name: "unmask_pii",
  description:
    "Restores original sensitive values into masked text by fetching encrypted ciphertext from Cloudflare D1 and decrypting it with the client-held AES-256-GCM key.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The masked text containing replacement tokens (e.g. [NAME_1], [EMAIL_1]).",
      },
      key: {
        type: "string",
        description: "The 256-bit AES-GCM decryption key or passphrase returned during the masking step.",
      },
      vaultId: {
        type: "string",
        description: "Optional vault identifier returned during masking to accelerate lookup.",
      },
    },
    required: ["text", "key"],
  },
} as const;

export const DETECT_PII_TOOL = {
  name: "detect_pii",
  description:
    "Preview Personally Identifiable Information (PII) detected in text using Llama 3.1 8B + Rust/Wasm + OpenRedaction and regex without encrypting or persisting to D1.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The text to scan for sensitive information.",
      },
      entities: {
        type: "array",
        items: {
          type: "string",
        },
        description: "Optional list of entity categories to filter by.",
      },
    },
    required: ["text"],
  },
} as const;

export const MODERATE_CONTENT_TOOL = {
  name: "moderate_content",
  description:
    "Inspects text and prompts for security exploits, prompt injections, jailbreaks, malicious payloads, cyberattacks, and content safety violations using fast Clef-flash decision screening with Meta Llama Guard 3 fallback and heuristic exploit filters.",
  parameters: {
    type: "object",
    properties: {
      text: {
        type: "string",
        description: "The prompt or message text to moderate.",
      },
      mode: {
        type: "string",
        enum: ["block", "warn"],
        description:
          "Enforcement mode: 'block' rejects unsafe content, 'warn' flags without blocking.",
        default: "block",
      },
      categories: {
        type: "array",
        items: {
          type: "string",
        },
        description: "Specific safety categories to enforce.",
      },
    },
    required: ["text"],
  },
} as const;

export const TRUST_LAYER_TOOLS = [
  MASK_PII_TOOL,
  UNMASK_PII_TOOL,
  DETECT_PII_TOOL,
  MODERATE_CONTENT_TOOL,
] as const;

