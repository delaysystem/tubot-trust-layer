import wasmSource from "./wasm/pii_engine.wasm";
import type { DetectedSpan, PiiType } from "./detector";

// A `.wasm` import is a compiled Module under Workers, but Bun's test loader
// can surface raw bytes or a filesystem path instead. Accept all three so the
// scanner runs unchanged in every environment.
const ModuleCtor = WebAssembly.Module as unknown as new (bytes: BufferSource) => WebAssembly.Module;
function loadWasmModule(): WebAssembly.Module {
  if (wasmSource instanceof WebAssembly.Module) return wasmSource;
  if (typeof wasmSource === "string") {
    const fs = require("node:fs");
    return new ModuleCtor(fs.readFileSync(wasmSource));
  }
  return new ModuleCtor(wasmSource as unknown as BufferSource);
}
const module = loadWasmModule();

type Exports = { memory: WebAssembly.Memory; pii_alloc(n: number): number;
  pii_free(p: number, n: number): void; pii_scan(p: number, n: number): number;
  pii_free_result(p: number): void };

export function wasmScan(text: string, enabledTypes?: PiiType[]): DetectedSpan[] {
  if (!text) return [];
  const input = new TextEncoder().encode(text);
  if (input.length > 65536) throw Object.assign(new Error("PII input exceeds 64 KiB"), { status: 413 });
  // Each request owns its instance; no tenant text or memory survives in a shared instance.
  const instance = new WebAssembly.Instance(module, {});
  const wasm = instance.exports as unknown as Exports;
  const ptr = wasm.pii_alloc(input.length);
  if (!ptr) throw new Error("PII allocation failed");
  let output = 0;
  try {
    new Uint8Array(wasm.memory.buffer, ptr, input.length).set(input);
    output = wasm.pii_scan(ptr, input.length);
    if (!output) throw new Error("PII analysis failed");
    const bytes = new Uint8Array(wasm.memory.buffer);
    const end = bytes.indexOf(0, output);
    if (end < output) throw new Error("Invalid PII result");
    const detections = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(output, end)));
    if (!Array.isArray(detections)) throw new Error("PII analysis failed");
    return detections.filter((d) => !enabledTypes || enabledTypes.includes(d.type)).map((d) => {
      if (!Number.isInteger(d.start) || !Number.isInteger(d.end) || d.start < 0 || d.end > text.length || d.end <= d.start) throw new Error("Invalid PII span");
      return { ...d, text: text.slice(d.start, d.end), source: "wasm" };
    });
  } finally {
    input.fill(0);
    if (output) wasm.pii_free_result(output);
    wasm.pii_free(ptr, input.length);
    // No full-memory wipe (was O(memory) per request): this instance is
    // request-local and discarded after the scan, so nothing can observe its
    // heap afterwards; the Rust side already volatile-wipes the input
    // (pii_free) and result (pii_free_result) buffers, the only tenant bytes
    // addressable through the exports. Origin: COST-17.
  }
}
