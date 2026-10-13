// Use the package’s CJS lite export: its ESM bundle initializes Node createRequire at module scope.
// Wrangler bundles this statically; optional NER and hosted/document backends remain disabled.
import type { LiteOpenRedaction as Redactor } from "@openredaction/core/lite";
const { LiteOpenRedaction } = require("@openredaction/core/lite") as { LiteOpenRedaction: typeof Redactor };
import type { DetectedSpan, PiiType } from "./detector";

function mapType(type: string): PiiType | undefined {
  if (type === "EMAIL") return "EMAIL";
  if (type.startsWith("PHONE_")) return "PHONE";
  if (["SSN", "ITIN"].includes(type)) return "SSN";
  if (type === "CREDIT_CARD") return "CREDIT_CARD";
  if (["IPV4", "IPV6"].includes(type)) return "IP_ADDRESS";
  if (type === "URL_WITH_AUTH" || /(?:API_KEY|TOKEN|PRIVATE_KEY|PASSWORD|SECRET)/.test(type)) return "SECRET";
  if (type === "IBAN" || /^(?:BANK_ACCOUNT|SORT_CODE|ROUTING_NUMBER|IFSC|CLABE|BSB_AU|SWIFT)/.test(type)) return "FINANCIAL";
  if (type === "DATE_OF_BIRTH") return "DOB";
  if (/^(?:ADDRESS_|POSTCODE_|ZIP_CODE_)/.test(type)) return "ADDRESS";
  if (/^(?:PASSPORT_|NATIONAL_INSURANCE_|NHS_NUMBER|DRIVING_LICENSE_|TAX_ID|SIN_CA|MEDICAL_RECORD_NUMBER|PATIENT_ID)/.test(type)) return "CUSTOM";
  return undefined;
}

export async function openRedactionScan(text: string, enabledTypes?: PiiType[]): Promise<DetectedSpan[]> {
  // Request-local instance. Disable caches, logging, metrics and learned tenant state.
  const patterns = new LiteOpenRedaction({ includeNames: false }).getPatterns();
  const redactor = new LiteOpenRedaction({
    patterns: [...new Set(patterns.filter((p) => mapType(p.type)).map((p) => p.type))],
    includeNames: false, enableContextAnalysis: true, enableCache: false,
    enableAuditLog: false, enableMetrics: false, debug: false,
  });
  try {
    const result = await redactor.detect(text);
    return result.detections.flatMap((d) => {
      const type = mapType(d.type);
      if (!type || (enabledTypes && !enabledTypes.includes(type))) return [];
      const [start, end] = d.position;
      if (text.slice(start, end) !== d.value) throw new Error("Invalid local PII span");
      return [{ text: d.value, type, start, end, confidence: d.confidence, source: "openredaction" as const }];
    });
  } catch {
    throw Object.assign(new Error("Local PII detection unavailable"), { status: 503 });
  }
}
