import { plugin } from "bun";
import { resolve } from "node:path";

// Workers imports `.wasm` as a compiled WebAssembly.Module. Bun's `loader:
// "object"` cannot preserve the module's internal slot across the loader
// boundary, so generate a JS shim that compiles the bytes in the importing
// module's own realm instead.
plugin({ name: "wasm-test-loader", setup(build) {
  build.onResolve({ filter: /\.wasm$/ }, (args) => ({
    path: resolve(args.resolveDir, args.path),
    namespace: "wasm-test",
  }));
  build.onLoad({ filter: /.*/, namespace: "wasm-test" }, ({ path }) => ({
    contents: `const bytes = await Bun.file(${JSON.stringify(path)}).arrayBuffer();
export default new WebAssembly.Module(bytes);`,
    loader: "js",
  }));
}});
