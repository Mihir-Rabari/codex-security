import assert from "node:assert/strict";
import { test } from "node:test";
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
