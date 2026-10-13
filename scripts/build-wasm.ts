export {};
const command = Bun.spawn(["cargo", "build", "--locked", "--manifest-path", "crates/pii_engine/Cargo.toml", "--target", "wasm32-unknown-unknown", "--release"], { stdout: "inherit", stderr: "inherit" });
if (await command.exited !== 0) process.exit(1);
const source = await Bun.file("crates/pii_engine/target/wasm32-unknown-unknown/release/trust_pii_engine.wasm").bytes();
const destination = Bun.file("src/wasm/pii_engine.wasm");
if (!await destination.exists() || !Buffer.from(await destination.bytes()).equals(source)) await Bun.write(destination,source);
