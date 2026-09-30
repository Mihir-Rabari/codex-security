import { execFile as execFileCallback, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";

const execFile = promisify(execFileCallback);
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test.each([true, false])(
  "scoped Git inventory matches indexed prefixes by filesystem identity, same directory: %s",
  async (sameDirectory) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "sca-git-scope-")),
    );
    directories.push(root);
    const repository = join(root, "repository");
    const selected = join(repository, "SRC");
    const indexed = join(repository, "src");
    await mkdir(selected, { recursive: true });
    await writeFile(join(repository, ".gitignore"), "*\n");
    await writeFile(
      join(selected, "package-lock.json"),
      JSON.stringify({ lockfileVersion: 3, packages: {} }),
    );
    await execFile("git", ["init", "--quiet", repository]);
    const { stdout } = await execFile("git", [
      "-C",
      repository,
      "hash-object",
      "-w",
      "--",
      join(selected, "package-lock.json"),
    ]);
    await execFile("git", [
      "-C",
      repository,
      "update-index",
      "--add",
      "--cacheinfo",
      "100644",
      stdout.trim(),
      "src/package-lock.json",
    ]);
    // Model the filesystem identity lookup at the portable boundary. The Git index
    // and ignored working-tree lockfile are real; no application code is executed.
    // The second case represents distinct case-sensitive directories.
    const other = join(root, "distinct-directory");
    await mkdir(other);
    const script = `
    import { mock } from "bun:test";
    import * as filesystem from "node:fs/promises";
    const [selected, indexed, other, sameDirectory, module] = process.argv.slice(1);
    const nativeStat = filesystem.stat;
    mock.module("node:fs/promises", () => ({
      ...filesystem,
      stat(path, options) {
        return nativeStat(path === indexed ? (sameDirectory === "true" ? selected : other) : path, options);
      },
    }));
    const { discoverScaInputs } = await import(module);
    const result = await discoverScaInputs(selected);
    console.log(JSON.stringify(result));
  `;
    const child = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        selected,
        indexed,
        other,
        String(sameDirectory),
        pathToFileURL(join(import.meta.dir, "../src/sca-osv.ts")).href,
      ],
      { encoding: "utf8" },
    );
    expect(child.stderr).toBe("");
    expect(child.status).toBe(0);
    const result = JSON.parse(child.stdout);
    expect(
      result.inputs.map((input: { path: string; status: string }) => [
        input.path,
        input.status,
      ]),
    ).toEqual(sameDirectory ? [["package-lock.json", "scanned"]] : []);
    expect(result.diagnostics).toEqual([]);
  },
);
