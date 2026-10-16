import { describe, expect, test } from "bun:test";
import { detectPii, llamaScan, mergeAndDeduplicateSpans, type DetectedSpan } from "./detector";
import { wasmScan } from "./wasm-scanner";
import { openRedactionScan } from "./openredaction-scanner";
import { maskText, unmaskText } from "./masker";
import { httpHandler as worker } from "./index";

describe("layered PII protection", () => {
  test("real Wasm detects financial identifiers and preserves Unicode offsets", () => {
    const text = "🔐 漢字 user@example.com IBAN GB82 WEST 1234 5698 7654 32";
    const spans = wasmScan(text);
    expect(spans.some(s => s.type === "FINANCIAL")).toBe(true);
    expect(spans.find(s => s.type === "EMAIL")?.start).toBe(text.indexOf("user@"));
    for (const span of spans) expect(text.slice(span.start,span.end)).toBe(span.text);
    const masked = maskText(text, mergeAndDeduplicateSpans(spans,text));
    expect(unmaskText(masked.maskedText,masked.tokenMap).unmaskedText).toBe(text);
  });
  test("OpenRedaction adds UK national insurance coverage", async () => {
    const spans = await openRedactionScan("National Insurance AB123456C");
    expect(spans.some(s => s.type === "CUSTOM" && s.text === "AB123456C")).toBe(true);
  });
  test("known structured PII is removed before any inference call", async () => {
    const text = "🔐 Alice wrote to alice@clinic.org and Alice replied.";
    const models:string[]=[];
    const ai:any={run:async(model:string,input:any)=>{
      models.push(model);
      if(model==="@cf/cloudflare/clef-flash"){
        expect(input.state).not.toContain("alice@clinic.org");
        expect(input.state.length).toBe(text.length);
        return {model:"clef-flash",answers:{PERSON:{type:"noul",noul:0.95},ADDRESS:{type:"noul",noul:0.01},ORG:{type:"noul",noul:0.02},DOB:{type:"noul",noul:0.01}},usage:{input_tokens:80,output_tokens:0}};
      }
      expect(model).toBe("@cf/meta/llama-3.1-8b-instruct-fp8");
      expect(input.messages[1].content).not.toContain("alice@clinic.org");
      expect(input.messages[1].content.length).toBe(text.length);
      return {response:'[{"text":"Alice","type":"PERSON"}]'};
    }};
    const masked=maskText(text,await detectPii(text,ai));
    expect(models).toEqual(["@cf/cloudflare/clef-flash","@cf/meta/llama-3.1-8b-instruct-fp8"]);
    expect(masked.maskedText).not.toContain("Alice");
    expect(masked.maskedText).not.toContain("alice@clinic.org");
    expect(unmaskText(masked.maskedText,masked.tokenMap).unmaskedText).toBe(text);
  });
  test("deterministic spans keep exact boundaries while semantic residue keeps coverage", () => {
    // Unioning would widen the exact EMAIL match to the whole sentence and
    // destroy the precision downstream masking depends on; residues keep it.
    const text="abcdefghijklmnop";
    const spans:DetectedSpan[]=[{text:"",start:4,end:10,type:"EMAIL",source:"regex"},{text:"",start:0,end:6,type:"PERSON",source:"llama"},{text:"",start:9,end:16,type:"ADDRESS",source:"llama"}];
    const merged=mergeAndDeduplicateSpans(spans,text);
    expect(merged.find(s=>s.source==="regex")).toMatchObject({start:4,end:10,type:"EMAIL",text:"efghij"});
    expect(merged).toHaveLength(3);
    expect(maskText(text,spans).maskedText).toBe("[NAME_1][EMAIL_1][ADDRESS_1]");
    expect(mergeAndDeduplicateSpans([{...spans[0],end:999}],text)).toEqual([]);
  });
  test("upstream errors and empty responses fail closed", async () => {
    await expect(llamaScan("hello",{run:async()=>({response:""})} as any)).rejects.toThrow("Semantic PII detection unavailable");
    await expect(detectPii("hello")).rejects.toThrow("Workers AI binding unavailable");
    await expect(detectPii("x".repeat(16385),undefined,{regexOnly:true})).rejects.toThrow("16 KiB");
  });
  test("chatty no-entity replies resolve to no semantic spans", async () => {
    // Small models chat instead of emitting [] when nothing matches; that
    // carries no spans and must not discard deterministic detections.
    const spans=await llamaScan("hello",{run:async()=>({response:"No PII found in the text."})} as any);
    expect(spans).toEqual([]);
  });
  test("hallucinated and mistyped entities are skipped without discarding grounded spans", async () => {
    // A single bad entity must not discard deterministic detections computed
    // before inference ran; transport and round failures still reject above.
    const spans=await llamaScan("hello Alice",{run:async()=>({response:'[{"text":"Alice","type":"PERSON"},{"text":"Imaginary Person","type":"PERSON"},{"text":"hello","type":"UNKNOWN"}]'})} as any);
    expect(spans).toHaveLength(1);
    expect(spans[0]).toMatchObject({text:"Alice",type:"PERSON",start:6,end:11});
  });
  test("local only policy still uses all deterministic layers and honors type filters",async()=>{
    const text="National Insurance AB123456C user@clinic.org";
    const spans=await detectPii(text,undefined,{regexOnly:true});
    expect(spans.some(s=>s.type==="CUSTOM")).toBe(true);
    const filtered=await detectPii(text,undefined,{regexOnly:true,enabledTypes:["EMAIL"]});
    expect(filtered.map(s=>s.type)).toEqual(["EMAIL"]);
  });
  test("independent Wasm requests retain no prior tenant detections",()=>{
    wasmScan("user@example.com");
    expect(wasmScan("nothing sensitive here")).toEqual([]);
  });
  test("HTTP rejects absent, incorrect and unconfigured credentials", async()=>{
    for(const [env,authorization] of [[{API_TOKEN:"expected"},""],[{API_TOKEN:"expected"},"Bearer wrong"],[{},"Bearer expected"]] as const){
      const response=await worker.fetch(new Request("https://trust.internal/detect",{method:"POST",headers:{Authorization:authorization},body:'{"text":"hello"}'}),env as Env,{} as any);
      expect(response.status).toBe(401);
    }
  });
});
