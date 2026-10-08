import assert from "node:assert/strict";
import { test } from "node:test";
import { importSource } from "./import-module.ts";

const { projectAncestors } = (await importSource(
  "src/helpers/config-preflight.ts",
  { define: { "process.platform": '"win32"' } },
)) as typeof import("../src/helpers/config-preflight.ts");

test("Windows project discovery stops at ordinary and extended share roots", () => {
  for (const prefix of ["\\\\", "\\\\?\\UNC\\"]) {
    const share = `${prefix}server\\share`;
    const ancestors = [...projectAncestors(`${share}\\folder\\child`)];
    assert.deepEqual(ancestors, [
      `${share}\\folder\\child`,
      `${share}\\folder`,
      `${share}\\`,
    ]);
    assert.deepEqual([...projectAncestors(`${share}\\`)], [`${share}\\`]);
  }
});

test("Windows project discovery retains drive roots and raw path units", () => {
  for (const root of ["C:\\", "\\\\?\\C:\\"]) {
    assert.deepEqual(
      [...projectAncestors(`${root}folder-\udfff\\child`)],
      [`${root}folder-\udfff\\child`, `${root}folder-\udfff`, root],
    );
  }
});
