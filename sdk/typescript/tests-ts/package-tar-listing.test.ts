import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, test } from "bun:test";
import {
  archive,
  octal,
  paxRecords,
  tarRecord,
} from "./package-tar-fixtures.js";

const { assertTarListingSizes, regularTarListingLines } = (await import(
  new URL("../scripts/package-tar-listing.mjs", import.meta.url).href
)) as {
  regularTarListingLines: (listing: string) => string[];
  assertTarListingSizes: (lines: string[], maximum: number) => number[];
};
const { packageDistFiles } = (await import(
  new URL("../scripts/package-dist-files.mjs", import.meta.url).href
)) as { packageDistFiles: readonly string[] };
const pluginContract = {
  externalOwnedExact: [".codex-plugin/plugin.json"],
  shippedExact: ["scripts/launch_codex_security_mcp"],
};

function packageTar({
  trailingZeroBytes = 0,
  sizeTerminator = " ",
  type = 0x30,
  compatibleLayout = false,
  rootDirectoryMode = 0o755,
  readmeMode = 0o644,
  mtime = 0,
  readmeSparse,
}: {
  trailingZeroBytes?: number;
  sizeTerminator?: string;
  type?: number;
  compatibleLayout?: boolean;
  rootDirectoryMode?: number;
  readmeMode?: number;
  mtime?: number;
  readmeSparse?: "0.0" | "1.0";
} = {}): Buffer {
  const executablePaths = [
    "package/bin/codex-security.mjs",
    "package/_bundled_plugin/scripts/launch_codex_security_mcp",
  ];
  const paths = [
    "package/package.json",
    "package/README.md",
    "package/docs/cli.md",
    "package/docs/findings-service.md",
    "package/docs/dedupe-records.md",
    "package/schemas/project-config.schema.json",
    "package/LICENSE",
    ...executablePaths,
    ...packageDistFiles,
    "package/_bundled_plugin/.codex-plugin/plugin.json",
  ];
  const records = paths.map((path) => {
    if (path === "package/README.md" && readmeSparse !== undefined) {
      const contents = Buffer.alloc(512, 0x78);
      const map = Buffer.alloc(512);
      map.write("1\n512\n512\n");
      const attributes: Record<string, string> =
        readmeSparse === "0.0"
          ? {
              "GNU.sparse.size": "1024",
              "GNU.sparse.numblocks": "1",
              "GNU.sparse.map": "512,512",
            }
          : {
              "GNU.sparse.major": "1",
              "GNU.sparse.minor": "0",
              "GNU.sparse.name": path,
              "GNU.sparse.realsize": "1024",
            };
      return Buffer.concat([
        tarRecord(paxRecords(attributes), {
          name: "PaxHeaders/readme",
          type: 0x78,
        }),
        tarRecord(
          readmeSparse === "0.0" ? contents : Buffer.concat([map, contents]),
          {
            name:
              readmeSparse === "0.0" ? path : "package/GNUSparseFile.1/readme",
          },
        ),
      ]);
    }
    const contents =
      path === "package/package.json"
        ? Buffer.from(
            JSON.stringify({
              license: "Apache-2.0",
              name: "@openai/codex-security",
            }),
          )
        : path.endsWith(".json") || path.endsWith(".map")
          ? Buffer.from("{}\n")
          : Buffer.from("fixture\n");
    const record = tarRecord(contents, {
      name: path,
      type,
      mtime,
      mode: executablePaths.includes(path)
        ? 0o755
        : path === "package/README.md"
          ? readmeMode
          : 0o644,
      sizeField: octal(contents.length, 12, sizeTerminator),
      ...(compatibleLayout ? { magic: "ustar ", version: " \0" } : {}),
    });
    if (compatibleLayout) record[record.length - 1] = 1;
    return record;
  });
  if (compatibleLayout) {
    const directories = new Set<string>();
    for (const path of paths) {
      const parts = path.split("/");
      for (let index = 1; index < parts.length; index++) {
        directories.add(`${parts.slice(0, index).join("/")}/`);
      }
    }
    return Buffer.concat([
      ...[...directories].map((name) =>
        tarRecord(Buffer.alloc(0), {
          name,
          type: 0x35,
          mode: name === "package/" ? rootDirectoryMode : 0o755,
        }),
      ),
      ...records.flatMap((record) => [Buffer.alloc(512), record]),
    ]);
  }
  return archive(...records, Buffer.alloc(trailingZeroBytes));
}

function commandPath(command: string): string {
  const lookup = spawnSync(
    process.platform === "win32" ? "where.exe" : "which",
    [command],
    { encoding: "utf8", windowsHide: true },
  );
  if (lookup.error !== undefined) throw lookup.error;
  const path = lookup.stdout.split(/\r?\n/u).find(Boolean);
  if (lookup.status !== 0 || path === undefined) {
    throw new Error(`Could not resolve ${command}.`);
  }
  return path;
}

describe("npm package tar listings", () => {
  test("accepts regular entries with Unix or Windows line endings", () => {
    const file = "-rw-r--r-- package/package.json";
    const directory = "drwxr-xr-x package/dist/";

    expect(regularTarListingLines(`${file}\n${directory}\n`)).toEqual([
      file,
      directory,
    ]);
    expect(regularTarListingLines(`${file}\r\n${directory}\r\n`)).toEqual([
      file,
      directory,
    ]);
  });

  test.each([
    "-rw-r--r-- 0/0        33554433 1970-01-01 00:00 package/README.md",
    "-rw-r--r--  0 0      0    33554433 Jan  1  1970 package/README.md",
  ])("bounds native sparse logical sizes before extraction: %s", (line) => {
    expect(() => assertTarListingSizes([line], 32 * 1024 * 1024)).toThrow(
      "npm tarball contains an invalid tar entry",
    );
    const bounded = line.replace("33554433", "33554432");
    expect(() =>
      assertTarListingSizes([bounded], 32 * 1024 * 1024),
    ).not.toThrow();
    expect(() =>
      assertTarListingSizes([bounded, bounded], 32 * 1024 * 1024),
    ).toThrow();
  });

  test("retains bounded logical sparse sizes in listing order", () => {
    expect(
      assertTarListingSizes(
        [
          "drwxr-xr-x 0/0 0 1970-01-01 00:00 package/",
          "-rw-r--r-- 0/0 1024 1970-01-01 00:00 package/README.md",
          "-rw-r--r--  0 0 0 512 Jan  1 1970 package/LICENSE",
        ],
        1536,
      ),
    ).toEqual([0, 1024, 512]);
  });

  test("rejects symbolic links and other non-regular entries", () => {
    expect(() =>
      regularTarListingLines("lrwxrwxrwx package/link -> target\r\n"),
    ).toThrow("npm tarball contains a non-regular entry");
  });

  test.each([false, true])(
    "rejects invalid package paths before Brotli expansion, complete=%p",
    (complete) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-path-order-"));
      try {
        const archivePath = join(root, "unexpected-brotli.tgz");
        writeFileSync(
          archivePath,
          gzipSync(
            Buffer.concat([
              ...(complete ? [packageTar()] : []),
              tarRecord(Buffer.from("Malformed compressed bytes."), {
                name: "package/unexpected.br",
              }),
            ]),
          ),
        );
        const contractPath = join(root, "plugin contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          { cwd: root, encoding: "utf8", timeout: 30_000, windowsHide: true },
        );
        expect(result.status).toBe(1);
        expect(result.stderr).toContain(
          complete
            ? "unexpected file: package/unexpected.br"
            : "missing package/package.json",
        );
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test("accepts equivalent bounded gzip representations", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-gzip-test-"));
    try {
      const tarBytes = packageTar({ trailingZeroBytes: 31 * 1024 * 1024 });
      const archives = [
        ["default", gzipSync(tarBytes)],
        ["level-0", gzipSync(tarBytes, { level: 0 })],
        ["sparse-0.0", gzipSync(packageTar({ readmeSparse: "0.0" }))],
        ["sparse-1.0", gzipSync(packageTar({ readmeSparse: "1.0" }))],
        ["npm-size-field", gzipSync(packageTar({ sizeTerminator: " \0" }))],
        ["nul-regular-file", gzipSync(packageTar({ type: 0 }))],
        [
          "future-timestamps",
          gzipSync(
            packageTar({ mtime: Math.floor(Date.now() / 1000) + 365 * 86400 }),
          ),
        ],
        ["unreadable-readme", gzipSync(packageTar({ readmeMode: 0 }))],
        ["posix-size-field", gzipSync(packageTar({ sizeTerminator: "\0" }))],
        [
          "compatible-tar-layout",
          gzipSync(packageTar({ compatibleLayout: true })),
        ],
        [
          "read-only-directories",
          gzipSync(
            packageTar({ compatibleLayout: true, rootDirectoryMode: 0o555 }),
          ),
        ],
      ] as const;
      expect(archives[0][1].length).toBeLessThan(1024 * 1024);
      expect(archives[1][1].length).toBeGreaterThan(31 * 1024 * 1024);

      const contractPath = join(root, "plugin contract.json");
      writeFileSync(contractPath, JSON.stringify(pluginContract));
      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      for (const [representation, contents] of archives) {
        const archivePath = join(root, `${representation}.tgz`);
        writeFileSync(archivePath, contents);
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            encoding: "utf8",
            env: environment,
            timeout: 30_000,
            windowsHide: true,
          },
        );
        expect({
          representation,
          status: result.status,
          stderr: result.stderr,
        }).toEqual({ representation, status: 0, stderr: "" });
      }
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });

  test.each([0x78, 0x67])(
    "preserves inherited character locale for Unicode pax owners, type=%i",
    (type) => {
      const root = mkdtempSync(join(tmpdir(), "codex-package-owner-test-"));
      try {
        const archivePath = join(root, "unicode owner.tgz");
        writeFileSync(
          archivePath,
          gzipSync(
            Buffer.concat([
              tarRecord(
                paxRecords({
                  uname: "Synthetic é owner",
                  gname: "Synthetic é group",
                }),
                { name: "OwnerHead", type },
              ),
              packageTar(),
            ]),
          ),
        );
        const contractPath = join(root, "plugin contract.json");
        writeFileSync(contractPath, JSON.stringify(pluginContract));
        const environment: NodeJS.ProcessEnv = { ...process.env };
        delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
        if (process.platform !== "win32")
          environment["LC_ALL"] =
            process.platform === "darwin" ? "en_US.UTF-8" : "C.UTF-8";
        const result = spawnSync(
          commandPath("node"),
          [
            fileURLToPath(
              new URL("../scripts/check-package.mjs", import.meta.url),
            ),
            archivePath,
            contractPath,
          ],
          {
            cwd: root,
            env: environment,
            encoding: "utf8",
            timeout: 30_000,
            windowsHide: true,
          },
        );
        expect({ status: result.status, stderr: result.stderr }).toEqual({
          status: 0,
          stderr: "",
        });
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );

  test("streams each archive without resolving tar from its directory", () => {
    const root = mkdtempSync(join(tmpdir(), "codex-package-tar-test-"));
    try {
      const archiveDirectory = join(
        root,
        process.platform === "win32" ? "package archive" : "D: package archive",
      );
      mkdirSync(archiveDirectory, { recursive: true });
      const archivePath = join(
        archiveDirectory,
        process.platform === "win32"
          ? "-fixture package.tgz"
          : "-fixture: package.tgz",
      );
      const contractPath = join(root, "plugin contract.json");
      const logPath = join(root, "tar calls.jsonl");
      const adjacentTarMarker = join(root, "archive tar ran");
      const tarBytes = packageTar({
        compatibleLayout: true,
        rootDirectoryMode: 0o555,
        readmeMode: 0,
      });
      const archiveContents = gzipSync(tarBytes, { level: 0 });
      writeFileSync(archivePath, archiveContents);
      writeFileSync(contractPath, JSON.stringify(pluginContract));

      const nodePath = commandPath("node");
      const environment: NodeJS.ProcessEnv = { ...process.env };
      delete environment["CODEX_SECURITY_EXPECTED_GIT_HEAD"];
      environment["PATH"] = `.${delimiter}${process.env["PATH"] ?? ""}`;
      const extractionDirectory = join(root, "extraction");
      mkdirSync(extractionDirectory, { mode: 0o700 });
      for (const variable of ["TMPDIR", "TMP", "TEMP"]) {
        environment[variable] = extractionDirectory;
      }
      if (process.platform === "win32") {
        for (const name of ["tar.com", "tar.exe"]) {
          writeFileSync(join(archiveDirectory, name), "not an executable");
        }
      } else {
        const adjacentTar = join(archiveDirectory, "tar");
        writeFileSync(
          adjacentTar,
          `#!/usr/bin/env node
require("node:fs").writeFileSync(process.env.ADJACENT_TAR_MARKER, "ran");
process.exit(99);
`,
        );
        chmodSync(adjacentTar, 0o755);

        const proxySource = `#!/usr/bin/env node
const { spawnSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const { appendFileSync, readFileSync } = require("node:fs");
const input = readFileSync(0);
appendFileSync(
  process.env.TAR_PROXY_LOG,
  JSON.stringify({
    args: process.argv.slice(2),
    cwd: process.cwd(),
    inputLength: input.length,
    inputSha256: createHash("sha256").update(input).digest("hex"),
  }) + "\\n",
);
const result = spawnSync(process.env.REAL_TAR, process.argv.slice(2), {
  env: process.env,
  input,
  stdio: ["pipe", "inherit", "inherit"],
  windowsHide: true,
});
if (result.error !== undefined) throw result.error;
if (result.status === 0 && process.argv.includes("-xzf") && process.env.TAR_PROXY_FAIL_EXTRACT) {
  process.stderr.write("synthetic extraction failure\\n");
  process.exit(23);
}
process.exit(result.status ?? 1);
`;
        const proxyPath = join(root, "tar");
        writeFileSync(proxyPath, proxySource);
        chmodSync(proxyPath, 0o755);
        environment["ADJACENT_TAR_MARKER"] = adjacentTarMarker;
        environment["REAL_TAR"] = commandPath("tar");
        environment["TAR_PROXY_LOG"] = logPath;
      }

      const result = spawnSync(
        nodePath,
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: environment,
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect(existsSync(adjacentTarMarker)).toBe(false);
      expect({ status: result.status, stderr: result.stderr }).toEqual({
        status: 0,
        stderr: "",
      });
      expect(readdirSync(extractionDirectory)).toEqual([]);
      if (process.platform === "win32") return;

      const calls = readFileSync(logPath, "utf8")
        .trim()
        .split(/\r?\n/u)
        .map(
          (line) =>
            JSON.parse(line) as {
              args: string[];
              cwd: string;
              inputLength: number;
              inputSha256: string;
            },
        );
      const archiveSha256 = createHash("sha256")
        .update(archiveContents)
        .digest("hex");
      expect(calls).toHaveLength(3);
      for (const call of calls) {
        expect(call.args.filter((arg) => arg === "-")).toEqual(["-"]);
        expect(call.args).not.toContain(archivePath);
        expect(realpathSync(call.cwd)).toBe(realpathSync(root));
        expect(call.inputLength).toBe(archiveContents.length);
        expect(call.inputSha256).toBe(archiveSha256);
      }
      expect(calls[0]?.args).toEqual(["--ignore-zeros", "-tzf", "-"]);
      expect(calls[1]?.args).toEqual([
        "--ignore-zeros",
        "--numeric-owner",
        "-tvzf",
        "-",
      ]);
      expect(calls[2]?.args.slice(0, 10)).toEqual([
        "--ignore-zeros",
        "-m",
        "--keep-old-files",
        "--no-same-owner",
        "--no-same-permissions",
        "--no-acls",
        "--no-xattrs",
        "-xzf",
        "-",
        "-C",
      ]);

      environment["TAR_PROXY_FAIL_EXTRACT"] = "true";
      const failed = spawnSync(
        nodePath,
        [
          fileURLToPath(
            new URL("../scripts/check-package.mjs", import.meta.url),
          ),
          archivePath,
          contractPath,
        ],
        {
          cwd: root,
          encoding: "utf8",
          env: environment,
          timeout: 30_000,
          windowsHide: true,
        },
      );
      expect(failed.status).not.toBe(0);
      expect(failed.stderr).toContain("synthetic extraction failure");
      expect(readdirSync(extractionDirectory)).toEqual([]);
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
});
