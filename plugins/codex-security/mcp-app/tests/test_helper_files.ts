import assert from "node:assert/strict";
import { mkdir, rm, symlink } from "node:fs/promises";
import { join, win32 } from "node:path";
import { after, test } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";

const { resolvedPathText } = (await importSource(
  "src/helpers/helper-files.ts",
  {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  },
)) as typeof import("../src/helpers/helper-files.ts");
const directories = createTemporaryDirectories(true);
after(() => directories.cleanup());

test("resolved text preserves ordinary paths, aliases, and missing suffixes", async () => {
  const root = await directories.create("helper-path-");
  const target = join(root, "target");
  const alias = join(root, "alias");
  await mkdir(target);
  await symlink(
    target,
    alias,
    process.platform === "win32" ? "junction" : "dir",
  );
  assert.equal(resolvedPathText(target), target);
  assert.equal(resolvedPathText(alias), target);
  assert.equal(
    resolvedPathText(join(alias, "missing"), false),
    join(target, "missing"),
  );
  assert.throws(
    () => resolvedPathText(join(alias, "missing")),
    /ENOENT|filesystem error/u,
  );
});

test(
  "Windows resolution keeps an explicitly requested namespace",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await directories.create("helper-namespace-");
    const namespaced = win32.toNamespacedPath(root);
    assert.equal(resolvedPathText(namespaced), namespaced);
    assert.equal(
      resolvedPathText(join(namespaced, "missing"), false),
      join(namespaced, "missing"),
    );
  },
);

test(
  "Windows display spelling still identifies a raw target through a junction",
  { skip: process.platform !== "win32" },
  async () => {
    const root = await directories.create("helper-raw-path-");
    const ordinary = join(root, "target");
    const raw = `${win32.toNamespacedPath(ordinary)}. `;
    const alias = join(root, "alias");
    await mkdir(ordinary);
    await mkdir(raw);
    try {
      await symlink(raw, alias, "junction");
      const display = resolvedPathText(alias);
      // An ordinary alias must never select the neighboring trimmed directory.
      assert.notEqual(display, ordinary);
      assert.equal(resolvedPathText(win32.toNamespacedPath(display)), raw);
    } finally {
      await rm(alias, { recursive: true, force: true });
      await rm(raw, { recursive: true, force: true });
    }
  },
);
