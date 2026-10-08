import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { importSource } from "./import-module.ts";
import { windowsFileSystem } from "../../native/windows-files.mjs";
import type { WindowsBinding } from "../../native/windows-binding.mjs";

for (const [name, reparseTag, surrogate] of [
  ["cloud directory", 0x9000001a, false],
  ["directory junction", 0xa0000003, true],
  ["symbolic link", 0xa000000c, true],
] as const)
  test(`Windows metadata identifies ${name} without treating every reparse point as a link`, () => {
    const binding = {
      windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
      openWindowsFile: () => ({
        error: 0,
        handle: {
          attributes: () => ({ error: 0, attributes: 0x410, reparseTag }),
          fileType: () => ({ error: 0, value: 1 }),
          close: () => 0,
        },
      }),
    } as unknown as WindowsBinding;
    const info = windowsFileSystem(binding).stat(
      Buffer.from("C:\\fixture", "utf16le"),
      false,
    );
    assert.equal(info.isReparsePoint(), true);
    assert.equal(info.isNameSurrogate(), surrogate);
    if (!surrogate) assert.equal(info.isDirectory(), true);
  });

test("POSIX file identities retain all 64 inode bits", async () => {
  const original = fs.statSync;
  fs.statSync = ((path, options) => {
    if (!["left", "right"].includes(String(path)))
      return original(path, options);
    const ino = String(path) === "left" ? 9007199254740992n : 9007199254740993n;
    return options?.bigint ? { dev: 1n, ino } : { dev: 1, ino: Number(ino) };
  }) as typeof fs.statSync;
  syncBuiltinESMExports();
  try {
    const { sameFile } = await importSource("src/helpers/inventory-paths.ts", {
      define: {
        "process.platform": '"linux"',
        "import.meta.url": JSON.stringify(
          new URL(
            "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
            import.meta.url,
          ).href,
        ),
      },
    });
    assert.equal(sameFile("left", "right"), false);
    assert.equal(sameFile("left", "left"), true);
  } finally {
    fs.statSync = original;
    syncBuiltinESMExports();
  }
});
