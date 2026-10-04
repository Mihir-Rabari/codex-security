import { readdir, rm } from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";

const root = path.resolve(import.meta.dirname, "..");
const tests = path.join(root, "tests");
const files = await readdir(tests, { recursive: true });
await Promise.all(
  files
    .filter((file) => file.endsWith(".js"))
    .map((file) => rm(path.join(tests, file))),
);

await build({
  entryPoints: files
    .filter((file) => file.endsWith(".ts"))
    .map((file) => path.join(tests, file)),
  outbase: tests,
  outdir: tests,
  format: "esm",
  platform: "node",
  target: "node22.13",
});

await build({
  entryPoints: (await readdir(path.join(root, "scripts")))
    .filter((file) => file.endsWith(".mts") && !file.endsWith(".d.mts"))
    .map((file) => path.join(root, "scripts", file)),
  outdir: path.join(root, "scripts"),
  outExtension: { ".js": ".mjs" },
  format: "esm",
  platform: "node",
  target: "node22.13",
});
