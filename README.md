# Trust layer PII masking

Masking runs the existing validated regex scanner, Rust `pii` 0.1.0 compiled to WebAssembly, and the local `@openredaction/core` 1.1.5 scanner. The local layers complement each other: secrets, payment checksums, spaced IBANs, national and medical identifiers, and contact information. A curated OpenRedaction pattern allowlist avoids treating every number, domain, or URL as PII. Financial identifiers map to `FINANCIAL`; national and medical identifiers map to `CUSTOM`.

Locally detected spans are blocked with equal-length characters before Workers AI inference using `@cf/meta/llama-3.1-8b-instruct-fp8`. Llama extracts names, organizations, addresses, and dates of birth. Exact substrings, schema validation, and overlap unions preserve offsets and cover the entire detected range. A final local scan checks the masked result, excluding generated placeholders, before encrypted D1 persistence. Known structural PII is also blocked before the existing safety model runs.

Each Wasm invocation owns its instance; input and linear memory are erased afterward. OpenRedaction instances are request-local with caching, audit logging, metrics, and debug logging disabled. No raw model responses or upstream PII errors are logged. Detection and safety inference errors reject masking with HTTP 503. Inputs exceeding 16 KiB are rejected with HTTP 413. These layers reduce exposure; semantic detection remains probabilistic and a local residual scan cannot prove that all PII was found.

`regexOnly: true` disables semantic inference but retains all three local scanners. `useLlama: false` does the same; `useGranite` remains a legacy alias. `entities` applies to every layer and intentionally limits protection to those categories. Clients should omit it for full configured coverage. Decryption continues to require the client-held encryption key.

HTTP operations require `Authorization: Bearer <API_TOKEN>`. Missing configuration or invalid credentials return HTTP 401. Configure the secret using `bunx wrangler secret put API_TOKEN`; the UI accepts the credential in memory. Worker RPC is authorized through Cloudflare service bindings. Service credentials are for authorized backend callers, not a replacement for tenant authentication in the calling gateway. Health, tool schemas, and static UI remain public.

Builds require Rust with the `wasm32-unknown-unknown` target. All commands use Bun:

- `bun run build:wasm` builds the locked crate and copies the artifact.
- `bun run test` builds Wasm and runs integration and regression tests.
- `bun run test:rust` runs the Rust scanner tests.
- `bun run typecheck` checks TypeScript.
- `bun run deploy` runs Wrangler, which rebuilds Wasm automatically.

The checked-in Wasm binary is reproducible from the crate and Cargo lockfile. For live tests, configure `TRUST_LAYER_URL` and `TRUST_LAYER_API_TOKEN`. Independently query D1 with Wrangler after test mutations rather than trusting API success alone.

Sources: [pii](https://docs.rs/pii/0.1.0/pii/), [OpenRedaction](https://github.com/sam247/openredaction), [Workers Wasm](https://developers.cloudflare.com/workers/runtime-apis/webassembly/), [Workers AI model](https://developers.cloudflare.com/workers-ai/models/llama-3.1-8b-instruct-fp8/).
