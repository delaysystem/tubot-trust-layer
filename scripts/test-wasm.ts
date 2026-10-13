import { plugin } from "bun";
plugin({ name: "wasm-test-loader", setup(build) {
  build.onLoad({ filter: /\.wasm$/ }, async ({ path }) => ({
    exports: { default: new (WebAssembly.Module as unknown as { new(bytes: ArrayBuffer): WebAssembly.Module })(await Bun.file(path).arrayBuffer()) }, loader: "object",
  }));
}});
