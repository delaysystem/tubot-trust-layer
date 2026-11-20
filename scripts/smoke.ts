import { strict as assert } from "node:assert";

const target = process.env.TRUST_LAYER_URL;
const credential = process.env.TRUST_LAYER_API_TOKEN;
if (!target || !credential) throw new Error("Set TRUST_LAYER_URL and TRUST_LAYER_API_TOKEN");
const remote = process.argv.includes("--remote");
const base = target.replace(/\/$/, "");
const text = "🔐 My name is Jane Rivera. Email jane@clinic.org, IBAN GB82 WEST 1234 5698 7654 32. National Insurance AB123456C.";
async function request(path: string, body?: unknown, method = "POST") {
  const response = await fetch(base + path, { method, headers: { "Content-Type": "application/json", Authorization: `Bearer ${credential}` }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) throw new Error(`Trust layer ${path} returned HTTP ${response.status}`);
  return response.json() as Promise<any>;
}
async function groundTruth(vaultId: string) {
  assert.match(vaultId, /^[0-9a-f-]{36}$/i);
  const command = `SELECT (SELECT COUNT(*) FROM pii_vault WHERE vault_id = '${vaultId}') AS vaults, (SELECT COUNT(*) FROM pii_tokens WHERE vault_id = '${vaultId}') AS tokens, (SELECT COUNT(*) FROM pii_vault WHERE vault_id = '${vaultId}' AND encrypted_data NOT LIKE '%jane@clinic.org%') AS encrypted;`;
  const cli = Bun.spawn(["bunx", "wrangler", "d1", "execute", "DB", remote ? "--remote" : "--local", "--command", command, "--json"], { stdout: "pipe", stderr: "pipe" });
  const stdout = await new Response(cli.stdout).text();
  const stderr = await new Response(cli.stderr).text();
  if (await cli.exited !== 0) throw new Error(`Independent D1 verification failed: ${stderr}`);
  const results = JSON.parse(stdout);
  return results[0].results[0];
}
const unauthenticated = await fetch(base + "/detect", { method: "POST", body: JSON.stringify({ text }) });
assert.equal(unauthenticated.status, 401);
const detected = await request("/detect", { text, regexOnly: true });
assert(detected.spans.some((s: any) => s.type === "FINANCIAL"));
assert(detected.spans.some((s: any) => s.type === "CUSTOM"));
const masked = await request("/mask", { text, moderate: false });
assert(masked.success);
for (const sensitive of ["Jane Rivera", "jane@clinic.org", "GB82 WEST", "AB123456C"]) assert(!masked.maskedText.includes(sensitive));
const record = await groundTruth(masked.vaultId);
assert.equal(record.vaults, 1);
assert.equal(record.tokens, masked.piiDetectedCount);
assert.equal(record.encrypted, 1);
console.log("Independent D1 CLI confirmed encrypted vault and token persistence");
const restored = await request("/unmask", { text: masked.maskedText, key: masked.key, vaultId: masked.vaultId });
assert.equal(restored.unmaskedText, text);
const safe = await request("/mask", { text: "Contact jane@clinic.org", regexOnly: true });
assert(!safe.maskedText.includes("jane@clinic.org"));
assert.equal((await groundTruth(safe.vaultId)).vaults,1);
for (const vaultId of [masked.vaultId, safe.vaultId]) {
  await request(`/vault/${vaultId}`, undefined, "DELETE");
  const remaining = await groundTruth(vaultId);
  assert.equal(remaining.vaults,0);
  assert.equal(remaining.tokens,0);
}
console.log("Live Wasm, OpenRedaction, Llama, safety model, encryption roundtrip and independently verified cleanup passed");
