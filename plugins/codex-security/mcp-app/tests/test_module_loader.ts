import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { importSource } from "./import-module.ts";

test("loads modules and relative dependencies from paths containing spaces", async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), "test module paths "));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(
    path.join(root, "dependency.ts"),
    "export const value: number = 42;",
  );
  await writeFile(path.join(root, "note.md"), "Résumé with spaces");
  const entry = path.join(root, "entry.ts");
  await writeFile(
    entry,
    'export { value } from "./dependency.ts"; export { default as note } from "./note.md";',
  );
  const module = await importSource(fileURLToPath(pathToFileURL(entry)), {
    loader: { ".md": "text" },
  });
  assert.equal(module.value, 42);
  assert.equal(module.note, "Résumé with spaces");
});
