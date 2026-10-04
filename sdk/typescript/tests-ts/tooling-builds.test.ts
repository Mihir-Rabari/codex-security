import { execFile } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, test } from "bun:test";

const execFileAsync = promisify(execFile);
const repositoryRoot = fileURLToPath(new URL("../../../", import.meta.url));
const mcpRoot = "plugins/codex-security/mcp-app";
const outputPath = (source: string) =>
  source.replace(/\.mts$/, ".mjs").replace(/\.ts$/, ".js");

for (const fixture of [
  {
    name: "MCP tests",
    script: `${mcpRoot}/scripts/build_tests.mjs`,
    directories: [`${mcpRoot}/tests`, `${mcpRoot}/scripts`],
    renamed: `${mcpRoot}/tests/test_removed.ts`,
    deleted: `${mcpRoot}/tests/nested/removed.ts`,
    retained: [
      `${mcpRoot}/tests/test_kept.ts`,
      `${mcpRoot}/scripts/reporter.mts`,
    ],
    untouched: `${mcpRoot}/scripts/bootstrap.mjs`,
  },
  {
    name: "eval tooling",
    script: "sdk/typescript/scripts/build-evals.mjs",
    directories: [
      "evals/deep-reducer",
      "evals/secret-discovery",
      "evals/triage-finding/assertions",
      "evals/triage-finding/scripts",
      "evals/triage-finding/sastbench/assertions",
      "evals/triage-finding/sastbench/scripts",
    ],
    renamed: "evals/secret-discovery/test_removed.mts",
    deleted: "evals/triage-finding/scripts/test_removed.ts",
    retained: [
      "evals/deep-reducer/run.mts",
      "evals/triage-finding/assertions/kept.ts",
    ],
    untouched: "evals/triage-finding/fixtures/repo/src/server.js",
  },
]) {
  test(`${fixture.name} rebuild removes outputs for renamed and deleted sources`, async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-tooling-build-"));
    try {
      for (const directory of fixture.directories) {
        await mkdir(join(root, directory), { recursive: true });
      }
      await symlink(
        fileURLToPath(new URL("../node_modules", import.meta.url)),
        join(root, "node_modules"),
        "junction",
      );
      const script = join(root, fixture.script);
      await mkdir(dirname(script), { recursive: true });
      await copyFile(join(repositoryRoot, fixture.script), script);
      for (const source of [
        fixture.renamed,
        fixture.deleted,
        ...fixture.retained,
      ]) {
        const file = join(root, source);
        await mkdir(dirname(file), { recursive: true });
        await writeFile(file, 'export const value: string = "fixture";\n');
      }
      const untouched = join(root, fixture.untouched);
      await mkdir(dirname(untouched), { recursive: true });
      await writeFile(untouched, "// fixture source\n");
      const node = Bun.which("node");
      expect(node).not.toBeNull();
      await execFileAsync(node!, [script]);
      for (const source of [fixture.renamed, fixture.deleted]) {
        expect(
          await readFile(join(root, outputPath(source)), "utf8"),
        ).toContain("fixture");
      }

      const renamed = fixture.renamed.replace("removed", "renamed");
      await rename(join(root, fixture.renamed), join(root, renamed));
      await rm(join(root, fixture.deleted));
      await execFileAsync(node!, [script]);

      for (const source of [fixture.renamed, fixture.deleted]) {
        expect(await Bun.file(join(root, outputPath(source))).exists()).toBe(
          false,
        );
      }
      for (const source of [renamed, ...fixture.retained]) {
        expect(
          await readFile(join(root, outputPath(source)), "utf8"),
        ).toContain("fixture");
      }
      expect(await readFile(untouched, "utf8")).toBe("// fixture source\n");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
