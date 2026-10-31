// Copies the built UI into the Python package so `strxeye serve` can serve
// it. The target folder is generated; it is git-ignored but included in
// wheels via [tool.hatch.build] artifacts in pyproject.toml.
import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "../dist");
const target = resolve(here, "../../../src/strxeye/web");

if (!existsSync(resolve(dist, "index.html"))) {
  console.error("dist/index.html not found; run `npm run build` first");
  process.exit(1);
}
rmSync(target, { recursive: true, force: true });
cpSync(dist, target, { recursive: true });
console.log(`Copied ${dist} -> ${target}`);
