export {};
const test = Bun.spawn(["cargo", "test", "--locked", "--manifest-path", "crates/pii_engine/Cargo.toml"], { stdout: "inherit", stderr: "inherit" });
process.exit(await test.exited);
