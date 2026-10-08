import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { importSource } from "./import-module.ts";
import type { WindowsBinding } from "../../native/windows-binding.mjs";

const { windowsFileSystem } = (await importSource(
  "../native/windows-files.mts",
)) as typeof import("../../native/windows-files.mjs");

for (const platform of ["linux", "win32"]) {
  test(`Git paths retain platform byte encoding on ${platform}`, async () => {
    const { decodeGitPath, encodeGitPath } = await importSource(
      "src/helpers/inventory-git.ts",
      {
        define: {
          "process.platform": JSON.stringify(platform),
          "import.meta.url": JSON.stringify(
            new URL(
              "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
              import.meta.url,
            ).href,
          ),
        },
      },
    );
    const bytes = Buffer.concat([
      Buffer.from("résumé/😀/high-"),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from("/low-"),
      Buffer.from([0xed, 0xbf, 0xbf]),
      Buffer.from("\0ordinary\0"),
    ]);
    const text =
      platform === "win32"
        ? "résumé/😀/high-\ud800/low-\udfff\0ordinary\0"
        : "résumé/😀/high-\udced\udca0\udc80/low-\udced\udcbf\udcbf\0ordinary\0";
    assert.equal(decodeGitPath(bytes), text);
    assert.deepEqual(encodeGitPath(text), bytes);
  });
}

const { sampleFile, createSourceSampler, PREVIEW_READ_BYTES } =
  await importSource("src/helpers/source-preview.ts", {
    define: {
      "import.meta.url": JSON.stringify(
        new URL(
          "../../../../sdk/typescript/_bundled_plugin/mcp/helpers.mjs",
          import.meta.url,
        ).href,
      ),
    },
  });

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

test(
  "short file reads preserve the complete preview prefix and UTF-16 units",
  { skip: process.platform === "win32" },
  () => {
    const root = fs.mkdtempSync(join(tmpdir(), "inventory-short-read-"));
    const file = join(root, "source");
    const original = fs.readSync;
    let calls = 0;
    fs.readSync = ((descriptor, buffer, offset, length, position) =>
      original(
        descriptor,
        buffer,
        offset,
        Math.min(length, [1, 3, 5, 4096][calls++ % 4]!),
        position,
      )) as typeof fs.readSync;
    syncBuiltinESMExports();
    try {
      const utf16 = Buffer.concat([
        Buffer.from([0xff, 0xfe]),
        Buffer.from("Ā source\n".repeat(8000), "utf16le"),
      ]);
      for (const data of [
        Buffer.alloc(0),
        Buffer.from([0xff]),
        Buffer.from([0xff, 0xfe]),
        Buffer.from([0xff, 0xfe, 0]),
        Buffer.from([0xfe, 0xff, 0]),
        Buffer.from("source\n".repeat(12000)),
        utf16,
        Buffer.from(utf16).swap16(),
      ]) {
        fs.writeFileSync(file, data);
        calls = 0;
        const [sample, binary] = sampleFile(file);
        assert.equal(binary, false);
        assert.deepEqual(sample, data.subarray(0, PREVIEW_READ_BYTES));
        fs.writeFileSync(file, Buffer.concat([data, Buffer.from([0, 0])]));
        calls = 0;
        assert.equal(sampleFile(file)[1], true);
      }
    } finally {
      fs.readSync = original;
      syncBuiltinESMExports();
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);

test("Windows short file reads preserve previews across split BOMs and units", () => {
  const text = Buffer.concat([
    Buffer.from([0xff, 0xfe]),
    Buffer.from("Ā source\n".repeat(8000), "utf16le"),
  ]);
  for (const source of [Buffer.alloc(0), Buffer.from([0xff, 0xfe, 0]), text])
    for (const binary of [false, true]) {
      const data = binary
        ? Buffer.concat([source, Buffer.from([0, 0])])
        : source;
      let cursor = 0,
        calls = 0,
        closes = 0;
      const native = {
        windowsAbsolutePath: (value: Buffer) => ({ error: 0, value }),
        openWindowsFile: () => ({
          error: 0,
          handle: {
            read: (buffer: Buffer, offset: number, length: number) => {
              const count = Math.min(
                length,
                data.length - cursor,
                [1, 3, 5, 4096][calls++ % 4]!,
              );
              data.copy(buffer, offset, cursor, cursor + count);
              cursor += count;
              return { error: 0, value: count };
            },
            close: () => {
              closes++;
              return 0;
            },
          },
        }),
      } as unknown as WindowsBinding;
      const sampler = createSourceSampler();
      assert.equal(sampler.consume(Buffer.alloc(0)), true);
      windowsFileSystem(native).readChunks(
        Buffer.from("C:\\fixture", "utf16le"),
        sampler.consume,
      );
      assert.deepEqual(sampler.finish(), [
        binary ? Buffer.alloc(0) : source.subarray(0, PREVIEW_READ_BYTES),
        binary,
      ]);
      assert.equal(closes, 1);
    }
});
