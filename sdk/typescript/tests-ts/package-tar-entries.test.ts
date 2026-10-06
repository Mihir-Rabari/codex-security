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

function paxRecords(attributes: Record<string, string>): Buffer {
  return Buffer.concat(
    Object.entries(attributes).map(([key, value]) => {
      const record = ` ${key}=${value}\n`;
      let length = Buffer.byteLength(record) + 1;
      while (length !== Buffer.byteLength(record) + String(length).length)
        length = Buffer.byteLength(record) + String(length).length;
      return Buffer.from(`${length}${record}`);
    }),
  );
}

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

  test("rejects unsupported entry types and malformed extended headers", () => {
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

  test.each([0x78, 0x67])("accepts POSIX pax metadata typeflag %i", (type) => {
    const attributes = paxRecords({ ctime: "0.123456789" });
    expect(
      plainTarEntries(
        archive(
          tarRecord(attributes, { name: "package/PaxHeaders/README.md", type }),
          tarRecord(Buffer.from("readme"), { name: "package/README.md" }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
  });

  test("uses local pax paths and sizes and clears them after their member", () => {
    const path = `package/${"nested/".repeat(16)}README.md`;
    expect(
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ path, size: "6" }), {
            name: "package/PaxHeaders/README.md",
            type: 0x78,
          }),
          tarRecord(Buffer.from("readme"), {
            name: "placeholder",
            sizeField: octal(0, 12),
          }),
          tarRecord(Buffer.from("license"), { name: "package/LICENSE" }),
        ),
      ),
    ).toEqual([
      { path, size: 6 },
      { path: "package/LICENSE", size: 7 },
    ]);
  });

  test("retains global pax attributes and honors local overrides", () => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ path: "package/README.md" }), {
            name: "GlobalHead",
            type: 0x67,
          }),
          tarRecord(Buffer.from("readme"), { name: "placeholder" }),
          tarRecord(paxRecords({ path: "package/LICENSE" }), {
            name: "package/PaxHeaders/LICENSE",
            type: 0x78,
          }),
          tarRecord(Buffer.from("license"), { name: "placeholder" }),
        ),
      ),
    ).toEqual([
      { path: "package/README.md", size: 6 },
      { path: "package/LICENSE", size: 7 },
    ]);
  });

  test("scans the complete pax metadata payload", () => {
    expect(() =>
      plainTarEntries(
        archive(
          tarRecord(paxRecords({ comment: "go/example" }), {
            name: "package/PaxHeaders/README.md",
            type: 0x78,
          }),
          tarRecord(Buffer.from("readme"), { name: "package/README.md" }),
        ),
      ),
    ).toThrow(internalReferenceError);
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

  test.each([0, 0x30])("accepts basic V7 regular typeflag %i", (type) => {
    expect(
      plainTarEntries(
        archive(
          tarRecord(Buffer.from("readme"), {
            name: "package/README.md",
            type,
            magic: "\0".repeat(6),
            version: "\0\0",
          }),
        ),
      ),
    ).toEqual([{ path: "package/README.md", size: 6 }]);
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
    for (const trailingBytes of [1, 511]) {
      expect(
        plainTarEntries(
          Buffer.concat([archive(record), Buffer.alloc(trailingBytes)]),
        ),
      ).toEqual([{ path: "package/README.md", size: 1 }]);
    }
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
      Buffer.concat([archive(record), Buffer.from([1])]),
      record.subarray(0, blockSize),
    ]) {
      expect(() => plainTarEntries(bytes)).toThrow(invalidTarEntryError);
    }
  });
});
