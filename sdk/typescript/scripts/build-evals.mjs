import { readdir, rm } from "node:fs/promises";
import path from "node:path";
import { build } from "esbuild";

const root = path.resolve(import.meta.dirname, "../../../evals");
const directories = [
  "deep-reducer",
  "secret-discovery",
  "triage-finding/assertions",
  "triage-finding/scripts",
  "triage-finding/sastbench/assertions",
  "triage-finding/sastbench/scripts",
];
const files = (
  await Promise.all(
    directories.map(async (directory) =>
      (await readdir(path.join(root, directory))).map((file) =>
        path.join(root, directory, file),
      ),
    ),
  )
).flat();
await Promise.all(
  files
    .filter((file) => file.endsWith(".mjs") || file.endsWith(".js"))
    .map((file) => rm(file)),
);
for (const [extension, format, output] of [
  [".mts", "esm", ".mjs"],
  [".ts", "cjs", ".js"],
]) {
  await build({
    entryPoints: files.filter((file) => file.endsWith(extension)),
    outbase: root,
    outdir: root,
    outExtension: { ".js": output },
    format,
    platform: "node",
    target: "node22.13",
  });
}
