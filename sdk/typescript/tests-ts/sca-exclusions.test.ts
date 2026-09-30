import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { runOsvScan } from "../src/sca-osv.js";

const temporaryDirectories: string[] = [];
afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function scan(
  stderr: string,
  allExcluded = false,
  retainedLocal = false,
) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "sca-exclusions-")));
  temporaryDirectories.push(root);
  const repository = join(root, "repository");
  const output = join(root, "output");
  await mkdir(repository);
  await writeFile(
    join(repository, "package-lock.json"),
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "node_modules/@synthetic/local": {
          version: "1.0.0",
          resolved: "file:../synthetic-local.tgz",
        },
        ...(!allExcluded
          ? { "node_modules/synthetic-registry": { version: "2.0.0" } }
          : {}),
      },
    }),
  );
  await writeFile(
    join(repository, "osv-scanner.toml"),
    '[[PackageOverrides]]\nname="@synthetic/local"\nignore=true\n',
  );
  return runOsvScan(
    { repositoryPath: repository, outputDir: output },
    {
      executable: process.execPath,
      runProcess: async (_executable, argv) =>
        argv[0] === "--version"
          ? { stdout: "osv-scanner version: 2.6.0", stderr: "", exitCode: 0 }
          : {
              stdout: JSON.stringify({
                results: allExcluded
                  ? []
                  : [
                      {
                        source: { path: "package-lock.json" },
                        packages: [
                          {
                            package: {
                              name: "synthetic-registry",
                              version: "2.0.0",
                              ecosystem: "npm",
                            },
                          },
                          ...(retainedLocal
                            ? [
                                {
                                  package: {
                                    name: "@synthetic/local",
                                    version: "1.0.0",
                                    ecosystem: "npm",
                                  },
                                },
                              ]
                            : []),
                        ],
                      },
                    ],
              }),
              stderr,
              exitCode: 0,
            },
    },
  );
}

test.each([false, true])(
  "effective local package exclusions preserve complete coverage when all excluded: %s",
  async (allExcluded) => {
    const result = await scan(
      "Package npm/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
      allExcluded,
    );
    expect(result.status).toBe("completed");
    expect(result.coverage.status).toBe("complete");
    expect(result.coverage.unresolvedPackages).toBe(0);
    expect(result.components).toHaveLength(allExcluded ? 0 : 1);
    expect(result.coverage.configFiles).toHaveLength(1);
    expect(
      result.coverage.limitations.some((line) =>
        line.includes("suppressed counts"),
      ),
    ).toBe(true);
  },
);

test.each([
  ["absent receipt", ""],
  [
    "different package",
    "Package npm/@synthetic/local-other/1.0.0 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "different version",
    "Package npm/@synthetic/local/1.0.1 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "different ecosystem",
    "Package Go/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
  ],
  [
    "advisory-only exclusion",
    "Filtered 1 ignored vulnerability/s from the scan.\n",
  ],
])(
  "%s does not establish that a local package was excluded",
  async (_label, stderr) => {
    const result = await scan(stderr);
    expect(result.status).toBe("partial");
    expect(result.coverage.unresolvedPackages).toBe(1);
  },
);

test("a retained local tuple remains unresolved when another occurrence was excluded", async () => {
  const result = await scan(
    "Package npm/@synthetic/local/1.0.0 has been filtered out because: synthetic exclusion\n",
    false,
    true,
  );
  expect(result.components).toHaveLength(2);
  expect(result.coverage.unresolvedPackages).toBe(1);
  expect(result.status).toBe("partial");
});
