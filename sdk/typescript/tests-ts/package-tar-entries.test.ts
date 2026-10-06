import { describe, expect, test } from "bun:test";
import {
  archive,
  blockSize,
  octal,
  tarRecord,
} from "./package-tar-fixtures.js";

type PlainTarEntry = {
  path: string;
  size: number;
};

type PackageTarEntries = {
  plainTarEntries: (archiveBytes: Buffer) => PlainTarEntry[];
};

const { plainTarEntries } = (await import(
  new URL("../scripts/package-tar-entries.mjs", import.meta.url).href
)) as PackageTarEntries;

const invalidTarEntryError = "npm tarball contains an invalid tar entry.";
const internalReferenceError = "npm tarball contains an internal reference.";

describe("plain npm tar entries", () => {
  test.each([" ", " \0", "\0"])(
    "accepts package size fields ending in %j",
    (terminator) => {
      expect(
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("readme"), {
              name: "package/README.md",
              sizeField: octal(6, 12, terminator),
            }),
          ),
        ),
      ).toEqual([{ path: "package/README.md", size: 6 }]);
    },
  );

  test.each([0, 0x30])(
    "accepts regular typeflag %i and prefix paths",
    (type) => {
      const prefix = `package/${"nested/".repeat(13)}deep`;
      const longPath = `${prefix}/README.md`;
      expect(longPath.length).toBeGreaterThan(100);

      const bytes = archive(
        tarRecord(Buffer.from("license"), { name: "package/LICENSE", type }),
        tarRecord(Buffer.from("readme"), { name: "README.md", prefix, type }),
      );

      expect(plainTarEntries(bytes)).toEqual([
        { path: "package/LICENSE", size: 7 },
        { path: longPath, size: 6 },
      ]);
    },
  );

  test("rejects every unsupported tar entry type", () => {
    for (const type of [
      0x31, 0x32, 0x33, 0x34, 0x36, 0x44, 0x4b, 0x4c, 0x53, 0x67, 0x78,
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              type,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("accepts an empty size field for an empty file", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.alloc(0), {
            name: "package/README.md",
            sizeField: Buffer.alloc(12),
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 0 }]);
  });

  test("rejects invalid or binary size encodings", () => {
    const base256 = Buffer.alloc(12);
    base256[0] = 0x80;
    base256[11] = 1;
    for (const sizeField of [base256, Buffer.from("00000000008\0")]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              sizeField,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("rejects alternate ustar signatures", () => {
    for (const options of [
      { magic: "ustar " },
      { magic: "ustar\0", version: " \0" },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("x"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(invalidTarEntryError);
    }
  });

  test("scans complete header text fields", () => {
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("clean"), {
            name: "package/README.md",
            user: "public\0go/example",
          }),
        ),
      ),
    ).toThrow(internalReferenceError);
  });

  test("scans complete raw headers", () => {
    for (const options of [
      {
        deviceNumbers: Buffer.concat([
          Buffer.from("go/example"),
          Buffer.alloc(6),
        ]),
      },
      { reserved: Buffer.from("go/example") },
    ]) {
      expect(() =>
        plainTarEntries(
          archive(
            tarRecord(Buffer.from("clean"), {
              name: "package/README.md",
              ...options,
            }),
          ),
        ),
      ).toThrow(internalReferenceError);
    }
  });

  test("accepts explicit empty directory members", () => {
    expect(
      plainTarEntries(
        archive(tarRecord(Buffer.alloc(0), { name: "package/", type: 0x35 })),
      ),
    ).toEqual([{ path: "package/", size: 0 }]);
    expect(() =>
      plainTarEntries(
        archive(tarRecord(Buffer.from("x"), { name: "package/", type: 0x35 })),
      ),
    ).toThrow(invalidTarEntryError);
  });

  test("accepts GNU headers without treating timestamps as a path prefix", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("readme"), {
            name: "package/README.md",
            magic: "ustar ",
            version: " \0",
            prefix: "00000000000",
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
  });

  test("accepts padding, optional end markers, and zero blocks between files", () => {
    const record = tarRecord(Buffer.from("x"), { name: "package/README.md" });
    record[record.length - 1] = 1;
    const secondRecord = tarRecord(Buffer.from("y"), {
      name: "package/LICENSE",
    });

    expect(plainTarEntries(record)).toEqual([
      { path: "package/README.md", size: 1 },
    ]);
    for (const zeroBlocks of [1, 2]) {
      expect(
        plainTarEntries(
          Buffer.concat([
            record,
            Buffer.alloc(blockSize * zeroBlocks),
            secondRecord,
          ]),
        ),
      ).toEqual([
        { path: "package/README.md", size: 1 },
        { path: "package/LICENSE", size: 1 },
      ]);
    }
  });

  test("still scans padding and rejects partial blocks or truncated contents", () => {
    const record = tarRecord(Buffer.from("x"), { name: "package/README.md" });
    const paddingMarker = Buffer.from(record);
    paddingMarker.write("go/example", blockSize + 1);
    expect(() => plainTarEntries(paddingMarker)).toThrow(
      internalReferenceError,
    );
    for (const bytes of [
      Buffer.concat([archive(record), Buffer.alloc(1)]),
      record.subarray(0, blockSize),
    ]) {
      expect(() => plainTarEntries(bytes)).toThrow(invalidTarEntryError);
    }
  });
});
