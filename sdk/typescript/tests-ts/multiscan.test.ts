import { createCliTest, captureCli } from "./support/cli-run.js";
import { gitText } from "./support/shell.js";
import { parseJsonLines, readJsonLines } from "./support/json.js";
import { resolving } from "./support/promises.js";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  access,
  appendFile,
  chmod,
  cp,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import * as filesystem from "node:fs/promises";
import { hostname, homedir } from "node:os";
import { basename, dirname, join, posix, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, spyOn, test, mock } from "bun:test";
import { zipSync } from "fflate";
import Papa from "papaparse";
import { main } from "../src/cli.js";
import { loadContract } from "../src/contract.js";
import * as contract from "../src/contract.js";
import { writeThreatModel } from "../src/artifact-export.js";
import { PYTHON } from "./support/security-policy.js";
import { ScanCostLimitExceededError } from "../src/errors.js";
import type { ScanResult } from "../src/result.js";
import { buildGitHubCredentialArgs, runMultiscan } from "../src/multiscan.js";
import { normalizeTarget } from "../src/targets.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import { DiffTarget } from "../src/targets.js";
import { prepareOutputDir } from "../src/runtime.js";
import * as runtime from "../src/runtime.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting, throwing } from "./support/errors.js";

type MultiscanOptions = Parameters<typeof runMultiscan>[0];
type SecurityClient = ReturnType<MultiscanOptions["createSecurity"]>;

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-multiscan-",
);
const testPosix = process.platform === "win32" ? test.skip : test;

const fixtureRoots = new Set<string>();
afterEach(async () => {
  await cleanup();
  fixtureRoots.clear();
});

async function fixture(): Promise<{
  root: string;
  input: string;
  output: string;
}> {
  const root = await temporaryDirectory();
  fixtureRoots.add(root);
  return {
    root,
    input: join(root, "repositories.csv"),
    output: join(root, "results"),
  };
}

function git(repository: string, ...args: string[]): string {
  return gitText(["-C", repository, ...args], {
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

async function repository(
  root: string,
  name: string,
): Promise<{ path: string; revision: string }> {
  const path = join(root, name);
  await mkdir(join(path, "src"), { recursive: true });
  await writeFile(
    join(path, "src", "app.ts"),
    `export const name = "${name}";\n`,
  );
  git(path, "init", "-q");
  git(path, "add", ".");
  git(
    path,
    "-c",
    "user.name=Multiscan Test",
    "-c",
    "user.email=multiscan@example.test",
    "commit",
    "-qm",
    "initial",
  );
  return { path, revision: git(path, "rev-parse", "HEAD") };
}

async function completedScan(
  outputDir: string,
  completeness: "complete" | "partial" | "unknown" = "complete",
  targetRoot?: string,
): Promise<ScanResult> {
  await mkdir(outputDir, { recursive: true, mode: 0o700 });
  await chmod(outputDir, 0o700);
  await cp(join(PLUGIN_ROOT, "examples", "completed-scan"), outputDir, {
    recursive: true,
  });
  await writeFile(join(outputDir, "report.md"), "# Scan report\n");
  const manifestPath = join(outputDir, "scan-manifest.json");
  const findingsPath = join(outputDir, "findings.json");
  const coveragePath = join(outputDir, "coverage.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanResult["manifest"];
  const findings = JSON.parse(
    await readFile(findingsPath, "utf8"),
  ) as ScanResult["findings"];
  const coverage = JSON.parse(
    await readFile(coveragePath, "utf8"),
  ) as ScanResult["coverage"];
  const id = basename(dirname(outputDir));
  const campaignRoot = dirname(dirname(dirname(outputDir)));
  const fixtureRoot = [...fixtureRoots].find((root) =>
    outputDir.startsWith(root + sep),
  );
  const inventory =
    fixtureRoot === undefined
      ? undefined
      : await readFile(join(fixtureRoot, "repositories.csv"), "utf8").catch(
          () => undefined,
        );
  if (inventory !== undefined) {
    const task = Papa.parse<Record<string, string>>(inventory, {
      header: true,
      skipEmptyLines: true,
    }).data.find((entry) => entry["id"] === id);
    if (task !== undefined) {
      manifest.scan.target.kind = "git_revision";
      manifest.scan.target.targetId = `target_sha256_${createHash("sha256")
        .update(
          `local-workspace\0${targetRoot ?? join(campaignRoot, "checkouts", id)}`,
        )
        .digest("hex")}`;
      manifest.scan.target.displayName = basename(
        targetRoot ?? join(campaignRoot, "checkouts", id),
      );
      manifest.scan.target.revision = task["revision"]!;
      delete manifest.scan.target.snapshotDigest;
      const scope = task["scope"]?.trim();
      let normalizedScope = scope ? posix.normalize(scope) : ".";
      if (scope) {
        const checkout = join(campaignRoot, "checkouts", id);
        const canonicalScope = await realpath(join(checkout, scope)).catch(
          () => undefined,
        );
        if (canonicalScope !== undefined) {
          normalizedScope =
            relative(await realpath(checkout), canonicalScope)
              .split(sep)
              .join("/") || ".";
        }
      }
      const includePaths = [normalizedScope];
      manifest.scan.scope.includePaths = includePaths;
      coverage.includePaths = includePaths;
      coverage.mode = scope
        ? "scoped_path"
        : task["mode"]?.trim() === "deep"
          ? "deep_repository"
          : "repository";
      coverage.inventoryStrategy = scope ? "scoped_path" : "repository";
    }
  }
  for (const finding of findings.findings) {
    const fingerprint = `codex-security/v1:sha256:${createHash("sha256")
      .update(
        [
          "codex-security/v1",
          manifest.scan.target.targetId,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? "",
        ].join("\0"),
      )
      .digest("hex")}`;
    finding.fingerprints.primary = fingerprint;
    finding.findingId = `csf_${createHash("sha256")
      .update(fingerprint)
      .digest("hex")
      .slice(0, 24)}`;
    finding.occurrenceId = `occ_${createHash("sha256")
      .update([manifest.scan.id, fingerprint].join("\0"))
      .digest("hex")
      .slice(0, 24)}`;
  }
  coverage.completeness = completeness;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
  await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
  await reseal(outputDir);
  return { manifest, coverage: { completeness } } as ScanResult;
}

async function reseal(outputDir: string): Promise<void> {
  const path = join(outputDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8")) as {
    scan: { artifacts: Array<{ path: string; sha256: string }> };
  };
  for (const artifact of manifest.scan.artifacts) {
    artifact.sha256 = createHash("sha256")
      .update(await readFile(join(outputDir, artifact.path)))
      .digest("hex");
  }
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
}

const completeRun: SecurityClient["run"] = async (
  _repository,
  scanOptions = {},
) => {
  return await completedScan(scanOptions.outputDir!);
};

const completeRunWithoutAwait: SecurityClient["run"] = async (
  _repository,
  scanOptions = {},
) => {
  return completedScan(scanOptions.outputDir!);
};

function client<Run extends SecurityClient["run"]>(
  run: Run,
  close: SecurityClient["close"] = async () => {},
): SecurityClient & { run: Run } {
  return { run, close };
}

function options(
  paths: { input: string; output: string },
  security: SecurityClient,
  overrides: Partial<MultiscanOptions> = {},
): MultiscanOptions {
  return {
    inputPath: paths.input,
    outputDir: paths.output,
    workers: 1,
    mode: "standard",
    maxAttempts: 2,
    config: {},
    createSecurity: () => security,
    ...overrides,
  };
}

const results = readJsonLines<Record<string, unknown>>;

describe("multiscan", () => {
  test.each([false, true])(
    "only links current models from failed child runs with recovery=%p",
    async (recovery) => {
      const paths = await fixture();
      const source = await repository(paths.root, "model-source");
      await writeFile(
        paths.input,
        `id,repository,revision\ncurrent,${source.path},${source.revision}\nstale,${source.path},${source.revision}\n`,
      );
      if (recovery)
        await runMultiscan(
          options(
            paths,
            client(async () => {
              throw new Error("Synthetic interruption before checkpoint");
            }),
            { maxAttempts: 1, config: { pythonPath: PYTHON } },
          ),
        );
      const checkouts: string[] = [];
      const python = spyOn(runtime, "resolvePluginPython");
      let summary;
      try {
        summary = await runMultiscan(
          options(
            paths,
            client(async (checkout, scanOptions = {}) => {
              checkouts.push(checkout);
              const directory = scanOptions.outputDir!;
              await mkdir(directory, { recursive: true });
              const manifest = {
                documentType: "codex-security.policy-draft",
                status: "threat_model_ready",
                threatModel: {
                  format: "markdown",
                  content: "# Earlier model\n",
                },
              };
              await writeFile(
                join(directory, "policy-draft.json"),
                JSON.stringify(manifest),
              );
              await writeThreatModel(directory, { pythonPath: PYTHON });
              if (directory.includes("stale")) {
                manifest.threatModel.content = "# Updated model\n";
                await writeFile(
                  join(directory, "policy-draft.json"),
                  JSON.stringify(manifest),
                );
              }
              throw new Error("Synthetic child failure after checkpoint");
            }),
            {
              maxAttempts: 1,
              config: { pythonPath: PYTHON },
              ...(recovery ? { recoverScan: async () => undefined } : {}),
            },
          ),
        );
        expect(checkouts).toHaveLength(2);
        for (const checkout of checkouts) {
          expect(python).toHaveBeenCalledWith(
            expect.objectContaining({
              configuredPath: PYTHON,
              protectedRoot: checkout,
            }),
          );
          if (recovery)
            expect((await lstat(checkout)).isDirectory()).toBe(true);
          else await expect(lstat(checkout)).rejects.toThrow();
        }
      } finally {
        python.mockRestore();
      }
      const rows = (await results(summary.resultsPath)).reverse();
      expect(
        rows.find((row) => row["id"] === "current")?.["threatModelPath"],
      ).toBeString();
      expect(
        rows.find((row) => row["id"] === "stale")?.["threatModelPath"],
      ).toBeUndefined();
    },
  );

  test("prepares shared prompt files once while missing sources remain row failures", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "prompt-source");
    const prompt = join(paths.root, "shared-prompt.md");
    await writeFile(prompt, "Review synthetic boundaries.");
    await writeFile(
      paths.input,
      `id,repository,revision\nmissing,${join(paths.root, "absent")},${source.revision}\nfirst,${source.path},${source.revision}\nsecond,${source.path},${source.revision}\n`,
    );
    let scans = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_checkout, scanOptions = {}) => {
          expect(scanOptions.scanPrompt).toBe("Review synthetic boundaries.");
          expect(scanOptions.scanPromptFile).toBeUndefined();
          if (scans++ === 0) await rm(prompt);
          return await completedScan(scanOptions.outputDir!);
        }),
        { maxAttempts: 1, scanPromptFile: prompt },
      ),
    );
    expect(scans).toBe(2);
    expect(summary).toMatchObject({ total: 3, completed: 2, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "missing", status: "failed" },
      { id: "first", status: "completed" },
      { id: "second", status: "completed" },
    ]);
  });

  test.each([DiffTarget.refs({ base: "HEAD~1" }), DiffTarget.workingTree()])(
    "rejects unsupported bulk diff scopes before preparing a campaign: %j",
    async (target) => {
      const paths = await fixture();
      const source = await repository(paths.root, "configured-scope");
      await writeFile(
        paths.input,
        `id,repository,revision\nexample,${source.path},${source.revision}\n`,
      );
      const createSecurity = mock(() => {
        return security;
      });
      const security = client(
        rejecting("The unsupported target must not reach a scan."),
      );
      await expect(
        runMultiscan(
          options(paths, security, {
            scanOptionsByMode: { standard: { target } },
            createSecurity,
          }),
        ),
      ).rejects.toThrow(
        "Bulk scans do not support diff or working-tree scopes",
      );
      expect(createSecurity).not.toHaveBeenCalled();
      await expect(access(paths.output)).rejects.toMatchObject({
        code: "ENOENT",
      });
    },
  );

  test("canceled recovery retains the new checkout and attempt without appending a failure receipt", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "cancel-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Stopped")), { maxAttempts: 1 }),
    );
    const before = await readFile(join(paths.output, "results.jsonl"), "utf8");
    const controller = new AbortController();
    let retained = "";
    await expect(
      runMultiscan(
        options(
          paths,
          client(async (checkout, scan = {}) => {
            retained = checkout;
            await writeFile(join(scan.outputDir!, "checkpoint"), "keep");
            controller.abort(new Error("Interrupted recovery"));
            controller.signal.throwIfAborted();
            throw new Error("Unreachable");
          }),
          { recoverScan: async () => undefined, signal: controller.signal },
        ),
      ),
    ).rejects.toThrow("Interrupted recovery");
    expect(await readFile(join(retained, "src", "app.ts"), "utf8")).toContain(
      "cancel-recovery",
    );
    expect(
      await readFile(
        join(paths.output, "artifacts", "repo", "attempt-2", "checkpoint"),
        "utf8",
      ),
    ).toBe("keep");
    expect(await readFile(join(paths.output, "results.jsonl"), "utf8")).toBe(
      before,
    );
  });

  test("occupied bulk attempts preserve the original checkout and recommend bulk recovery", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "occupied");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const scanDir = join(paths.output, "artifacts", "repo", "attempt-1");
    const checkout = join(paths.output, "checkouts", "repo");
    await mkdir(scanDir, { recursive: true, mode: 0o700 });
    await mkdir(checkout, { recursive: true });
    await writeFile(join(scanDir, "checkpoint"), "keep");
    await writeFile(join(checkout, "source"), "keep checkout");
    const error = capture();
    const output = capture();
    const deps = dependencies();
    const code = await main(
      [
        "bulk-scan",
        paths.input,
        "--output-dir",
        paths.output,
        "--max-attempts",
        "3",
        "--json",
      ],
      output.stream,
      error.stream,
      {
        ...deps,
        createSecurity: (config) => ({
          ...deps.createSecurity(config),
          run: async (_repo, scan = {}) => {
            await prepareOutputDir(scan.outputDir, "repo");
            return completedScan(scan.outputDir!);
          },
        }),
      },
    );
    expect(code).toBe(2);
    expect(error.text()).toContain("--recover");
    expect(error.text()).not.toContain("--archive-existing");
    const receipts = await results(JSON.parse(output.text()).resultsPath);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]).toMatchObject({
      status: "failed",
      attempt: 1,
      error: expect.stringContaining("--recover"),
    });
    expect(await readFile(join(checkout, "source"), "utf8")).toBe(
      "keep checkout",
    );
    expect(await readFile(join(scanDir, "checkpoint"), "utf8")).toBe("keep");
    await expect(prepareOutputDir(scanDir, "repo")).rejects.toThrow(
      "--archive-existing",
    );
  });

  test("CLI escapes bulk failure controls while preserving the saved receipt", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "failure");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const failure = "Bulk failed: token=SYNTHETIC_VALUE\u001b[2J\ncontinued";
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    expect(
      await runCli(
        [
          "bulk-scan",
          paths.input,
          "--output-dir",
          paths.output,
          "--max-attempts",
          "1",
          "--json",
        ],
        {
          ...deps,
          createSecurity: (config) => ({
            ...deps.createSecurity(config),
            run: rejecting(failure),
          }),
        },
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(
      "Bulk failed: token=SYNTHETIC_VALUE [2J continued\n",
    );
    expect(stderr.text()).not.toContain("\u001b");
    expect(await results(JSON.parse(stdout.text()).resultsPath)).toMatchObject([
      { status: "failed", error: failure },
    ]);
  });

  test("recovery skips untouched rows and saves an interrupted ledger tail before appending", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "tail");
    const tasks = ["failed", "untouched"].map((id) => ({
      id,
      repository: source.path,
      revision: source.revision,
      mode: "standard",
    }));
    await writeFile(
      paths.input,
      `id,repository,revision\n${tasks.map((task) => `${task.id},${task.repository},${task.revision}`).join("\n")}\n`,
    );
    await mkdir(paths.output);
    await writeFile(
      join(paths.output, "manifest.json"),
      JSON.stringify({ version: 1, tasks }, null, 2) + "\n",
    );
    const tail = '{"id":"failed","status":';
    const original =
      JSON.stringify({
        ...tasks[0],
        status: "failed",
        attempt: 1,
        outputDir: join(paths.output, "artifacts", "failed", "attempt-1"),
      }) + "\n";
    await writeFile(join(paths.output, "results.jsonl"), original + tail);
    const runs = mock(completeRunWithoutAwait);
    const result = await runMultiscan(
      options(paths, client(runs), { recoverScan: async () => undefined }),
    );
    expect(result).toMatchObject({
      total: 2,
      completed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(runs.mock.calls.length).toBe(1);
    expect(
      (await readFile(result.resultsPath, "utf8")).startsWith(original),
    ).toBe(true);
    const backup = (await readdir(paths.output)).find((name) =>
      name.startsWith("results.jsonl.interrupted-"),
    );
    expect(backup).toBeDefined();
    expect(await readFile(join(paths.output, backup!), "utf8")).toBe(tail);
  });

  test("recovery preserves occupied attempts and checkouts while retrying only failed repositories", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "recovery");
    await writeFile(
      paths.input,
      `id,repository,revision,mode\nfailed,${source.path},${source.revision},deep\ndone,${source.path},${source.revision},deep\n`,
    );
    const failedDir = join(paths.output, "artifacts", "failed", "attempt-1");
    const first = await runMultiscan(
      options(
        paths,
        client(async (_repo, scan = {}) => {
          if (scan.outputDir === failedDir) throw new Error("Interrupted scan");
          return completedScan(scan.outputDir!, "partial");
        }),
        { maxAttempts: 1 },
      ),
    );
    const before = await readFile(first.resultsPath, "utf8");
    const orphan = join(paths.output, "artifacts", "failed", "attempt-5");
    const checkout = join(paths.output, "checkouts", "failed");
    await mkdir(orphan, { recursive: true });
    await mkdir(checkout, { recursive: true });
    await writeFile(join(orphan, "checkpoint"), "keep checkpoint");
    await writeFile(join(checkout, "source"), "keep checkout");
    const inode = (await lstat(checkout)).ino;
    const resumed = mock(resolving<undefined, [string]>(undefined));
    const runs = mock<SecurityClient["run"]>(async (repo, scan = {}) => {
      expect(repo).not.toBe(checkout);
      expect(git(repo, "rev-parse", "HEAD")).toBe(source.revision);
      expect(scan.mode).toBe("deep");
      expect(scan.outputDir).toBe(
        join(paths.output, "artifacts", "failed", "attempt-6"),
      );
      return completedScan(scan.outputDir!);
    });
    const result = await runMultiscan(
      options(paths, client(runs), {
        maxAttempts: 1,
        recoverScan: resumed,
      }),
    );
    expect(result).toMatchObject({
      completed: 1,
      incomplete: 1,
      failed: 0,
      skipped: 1,
    });
    expect(runs.mock.calls.length).toBe(1);
    expect(resumed.mock.calls.map(([value]) => value)).toEqual([orphan]);
    expect((await lstat(checkout)).ino).toBe(inode);
    expect(await readFile(join(checkout, "source"), "utf8")).toBe(
      "keep checkout",
    );
    expect(await readFile(join(orphan, "checkpoint"), "utf8")).toBe(
      "keep checkpoint",
    );
    expect(
      (await readFile(result.resultsPath, "utf8")).startsWith(before),
    ).toBe(true);
    expect((await results(result.resultsPath)).at(-1)).toMatchObject({
      id: "failed",
      attempt: 6,
      status: "completed",
    });
  });

  test.each([
    [false, "checkouts"],
    [true, "checkouts"],
    [false, "recovery-checkouts"],
    [true, "recovery-checkouts"],
  ] as const)(
    "recovery records the original attempt with failure=%p and retained %s",
    async (failure, layout) => {
      const paths = await fixture();
      const source = await repository(paths.root, "retained");
      await writeFile(
        paths.input,
        `id,repository,revision\nretained,${source.path},${source.revision}\n`,
      );
      await runMultiscan(
        options(paths, client(rejecting("Stopped")), { maxAttempts: 1 }),
      );
      const dir = join(paths.output, "artifacts", "retained", "attempt-1");
      await mkdir(dir, { recursive: true });
      await writeFile(join(dir, "checkpoint"), "keep");
      const checkout = join(
        paths.output,
        layout,
        "retained",
        ...(layout === "recovery-checkouts" ? ["attempt-1"] : []),
      );
      await mkdir(checkout, { recursive: true });
      await writeFile(join(checkout, "source"), "keep checkout");
      const recoverScan = mock(async (scanDir: string) => {
        expect(scanDir).toBe(dir);
        if (failure) throw new Error("Resume transport failed");
        return completedScan(scanDir, "complete", checkout);
      });
      const runs = mock(completeRunWithoutAwait);
      const python = spyOn(runtime, "resolvePluginPython");
      let summary;
      try {
        summary = await runMultiscan(
          options(paths, client(runs), {
            maxAttempts: 3,
            config: { pythonPath: PYTHON },
            recoverScan,
          }),
        );
        expect(python).toHaveBeenCalledWith(
          expect.objectContaining({
            configuredPath: PYTHON,
            protectedRoot: checkout,
          }),
        );
      } finally {
        python.mockRestore();
      }
      expect(await readFile(join(checkout, "source"), "utf8")).toBe(
        "keep checkout",
      );
      expect(runs.mock.calls.length).toBe(0);
      expect(recoverScan).toHaveBeenCalledTimes(1);
      expect(summary.failed).toBe(failure ? 1 : 0);
      expect(summary.completed).toBe(failure ? 0 : 1);
      expect((await results(summary.resultsPath)).at(-1)).toMatchObject({
        attempt: 1,
        outputDir: dir,
        status: failure ? "failed" : "completed",
      });
      expect(await readFile(join(dir, "checkpoint"), "utf8")).toBe("keep");
      if (!failure) {
        expect(await runMultiscan(options(paths, client(runs)))).toMatchObject({
          completed: 1,
          skipped: 1,
          failed: 0,
        });
        expect(runs).toHaveBeenCalledTimes(0);
        expect(recoverScan).toHaveBeenCalledTimes(1);
      }
    },
  );

  test.each(["high", "low"] as const)(
    "recovery applies the campaign severity policy to %s findings and retains the outcome",
    async (severity) => {
      const paths = await fixture();
      const source = await repository(paths.root, "policy-recovery");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const configured = options(paths, client(rejecting("Interrupted scan")), {
        maxAttempts: 1,
        scanPrompt: "Shared scan instructions.",
        scanOptionsByMode: { standard: { failureSeverity: "high" } },
      });
      await runMultiscan(configured);
      await mkdir(join(paths.output, "artifacts", "repo", "attempt-1"), {
        recursive: true,
      });
      const result = await runMultiscan({
        ...configured,
        recoverScan: async (scanDir, prompts) => {
          expect(prompts.scanPrompt).toBe("Shared scan instructions.");
          await completedScan(scanDir);
          const recovered = fakeResult([severity]);
          return {
            coverage: recovered.coverage,
            cost: recovered.cost,
            findings: recovered.findings,
          };
        },
      });
      expect(result).toMatchObject({
        completed: 1,
        failed: 0,
        policyFailed: severity === "high",
      });
      expect((await results(result.resultsPath)).at(-1)).toMatchObject({
        attempt: 1,
        policyFailed: severity === "high",
      });
      expect(await runMultiscan(configured)).toMatchObject({
        completed: 1,
        skipped: 1,
        policyFailed: severity === "high",
      });
    },
  );

  test("bulk recovery requires an existing campaign and a CSV", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "missing-campaign");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    for (const args of [
      ["--recover"],
      [paths.input, "--output-dir", paths.output, "--recover"],
    ]) {
      const error = captureCli(main, "stderr");
      const code = await error.run(["bulk-scan", ...args], dependencies());
      expect(code).toBe(2);
      expect(error.text()).toMatch(/recovery requires/i);
    }
  });

  test("scopes GitHub CLI credentials to the discovered GitHub host", () => {
    expect(buildGitHubCredentialArgs(undefined)).toEqual([]);
    expect(buildGitHubCredentialArgs("github.com")).toEqual([
      "-c",
      "credential.https://github.com.helper=",
      "-c",
      "credential.https://github.com.helper=!gh auth git-credential",
    ]);
    expect(buildGitHubCredentialArgs("github.acme.example")).toEqual([
      "-c",
      "credential.https://github.acme.example.helper=",
      "-c",
      "credential.https://github.acme.example.helper=!gh auth git-credential",
    ]);
    for (const host of [
      "github.com/another-owner",
      "user@github.com",
      "github.com?token=secret",
      "github.com#fragment",
    ]) {
      expect(() => buildGitHubCredentialArgs(host)).toThrow(
        "GitHub credential host is invalid",
      );
    }
  });

  test("uses GitHub credentials for discovered checkouts without changing global Git configuration", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "github-credentials");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const configured = gitText(
      [
        ...buildGitHubCredentialArgs("github.acme.example"),
        "config",
        "--get-all",
        "credential.https://github.acme.example.helper",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    expect(configured.trim()).toBe("!gh auth git-credential");

    const summary = await runMultiscan(
      options(paths, client(completeRun), {
        githubHost: "github.acme.example",
      }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
  });

  test("parses quoted CSV fields, embedded delimiters, and Windows line endings", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "comma, quoted");
    await writeFile(
      paths.input,
      `\uFEFF"id","repository","revision","scope","mode","prompt","notes"\r\n"payments","${source.path}","${source.revision}","src","deep","Focus on authentication, authorization.","contains ""quotes"""\r\n\r\n`,
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.target).toEqual(["src"]);
          expect(scanOptions.mode).toBe("deep");
          expect(scanOptions.scanPrompt).toBe(
            "Review boundaries.\n\nFocus on authentication, authorization.",
          );
          expect(scanOptions.postScanPrompt).toBe("Draft confirmed fixes.");
          expect(scanOptions.maxCostUsd).toBe(12.5);
          return await completedScan(scanOptions.outputDir!);
        }),
        {
          scanPrompt: "Review boundaries.",
          postScanPrompt: "Draft confirmed fixes.",
          maxCostUsd: 12.5,
          scanOptionsByMode: {
            deep: { target: DiffTarget.workingTree() },
          },
        },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "payments", repository: source.path },
    ]);
    expect(
      JSON.parse(await readFile(join(paths.output, "manifest.json"), "utf8")),
    ).toMatchObject({
      scanPrompt: "Review boundaries.",
      postScanPrompt: "Draft confirmed fixes.",
      maxCostUsd: 12.5,
      tasks: [
        { id: "payments", prompt: "Focus on authentication, authorization." },
      ],
    });
  });

  test("records each completed scan's cost in the resumable ledger", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "priced");
    await writeFile(
      paths.input,
      `id,repository,revision\npriced,${source.path},${source.revision}\n`,
    );
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    };

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) =>
          Object.assign(await completedScan(scanOptions.outputDir!), { cost }),
        ),
      ),
    );

    expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "priced", status: "completed", coverage: "complete", cost },
    ]);
  });

  test("records an exhausted repository budget without retrying the scan", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "over-budget");
    await writeFile(
      paths.input,
      `id,repository,revision\nover-budget,${source.path},${source.revision}\n`,
    );
    const cost = {
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 25.25,
    };
    const attempts = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        throw new ScanCostLimitExceededError(25, cost, scanOptions.outputDir!);
      },
    );

    const summary = await runMultiscan(
      options(paths, client(attempts), { maxAttempts: 3, maxCostUsd: 25 }),
    );

    expect(attempts.mock.calls.length).toBe(1);
    expect(summary).toMatchObject({ completed: 0, failed: 1 });
    expect(await results(summary.resultsPath)).toMatchObject([
      { id: "over-budget", status: "failed", attempt: 1, cost },
    ]);
  });

  test("forwards a bulk CLI cost limit and rejects zero", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const { runCli } = createCliTest(main);

    let scanOptions: unknown;

    expect(
      await runCli(
        [
          "bulk-scan",
          "repositories.csv",
          "--output-dir",
          "results",
          "--max-cost",
          "12.5",
          "--json",
        ],
        dependencies({
          currentDirectory: paths.root,
          onTurn: (_repository, options) => (scanOptions = options),
        }),
      ),
    ).toBe(0);
    expect(scanOptions).toMatchObject({ maxCostUsd: 12.5 });

    const invalid = captureCli(main, "stderr");
    expect(
      await invalid.run(
        ["bulk-scan", "--max-cost=0"],
        dependencies({ currentDirectory: paths.root }),
      ),
    ).toBe(2);
    expect(invalid.text()).toContain("expected number to be >0");
  });

  test("surfaces optional post-scan warnings without failing completed scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "follow-up-warning");
    await writeFile(
      paths.input,
      `id,repository,revision\nfollow-up-warning,${source.path},${source.revision}\n`,
    );
    const progress: Parameters<
      NonNullable<MultiscanOptions["onProgress"]>
    >[0][] = [];

    const warnings = [
      "Could not run post-scan instructions.",
      "Repository changed during the scan.",
    ];
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          for (const warning of warnings) scanOptions.onWarning?.(warning);
          return await completedScan(scanOptions.outputDir!);
        }),
        { onProgress: (event) => progress.push(event) },
      ),
    );

    expect(summary).toMatchObject({
      completed: 1,
      incomplete: 0,
      failed: 0,
      warnings: [
        {
          repository: "follow-up-warning",
          warnings,
        },
      ],
    });
    expect(progress).toContainEqual({
      repository: "follow-up-warning",
      attempt: 1,
      status: "started",
      warning: "Could not run post-scan instructions.",
    });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "follow-up-warning",
        status: "completed",
        warnings,
      },
    ]);

    const resumedProgress: typeof progress = [];
    const resumed = await runMultiscan(
      options(
        paths,
        client(async () => Promise.reject(new Error("must not rerun"))),
        {
          onProgress: (event) => resumedProgress.push(event),
        },
      ),
    );

    expect(resumed).toEqual({ ...summary, skipped: 1 });
    for (const warning of warnings) {
      expect(resumedProgress).toContainEqual({
        repository: "follow-up-warning",
        attempt: 1,
        status: "completed",
        warning,
      });
    }
  });

  test.each([false, true])(
    "continues scanning when a progress observer fails %p",
    async (asynchronous) => {
      const paths = await fixture();
      const source = await repository(paths.root, "observer-failure");
      await writeFile(
        paths.input,
        `id,repository,revision\nobserver-failure,${source.path},${source.revision}\n`,
      );
      const attempts = mock<SecurityClient["run"]>(
        async (_repository, scanOptions = {}) => {
          scanOptions.onWarning?.("Optional post-scan warning.");
          return await completedScan(scanOptions.outputDir!);
        },
      );
      const progress: string[] = [];

      const summary = await runMultiscan(
        options(paths, client(attempts), {
          onProgress: (event) => {
            progress.push(event.warning ?? event.status);
            const error = new Error("Optional progress observer failed.");
            if (asynchronous) return Promise.reject(error);
            throw error;
          },
        }),
      );

      expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
      expect(attempts.mock.calls.length).toBe(1);
      expect(progress).toEqual([
        "started",
        "Optional post-scan warning.",
        "completed",
      ]);
      expect(await results(summary.resultsPath)).toMatchObject([
        { id: "observer-failure", status: "completed", attempt: 1 },
      ]);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "retains sealed %s coverage without retries or multiplied costs",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, completeness);
      await writeFile(
        paths.input,
        `id,repository,revision\nsealed,${source.path},${source.revision}\n`,
      );
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 12.5,
      };
      const progress: Parameters<
        NonNullable<MultiscanOptions["onProgress"]>
      >[0][] = [];
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return Object.assign(
          await completedScan(scanOptions.outputDir!, completeness),
          { cost },
        );
      });

      const summary = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          onProgress: (event) => progress.push(event),
        }),
      );

      expect(attempts).toBe(1);
      expect(summary).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 0,
      });
      const outputDir = join(paths.output, "artifacts", "sealed", "attempt-1");
      const warning = `Scan coverage is ${completeness}; results may be incomplete.`;
      const receipts = await results(summary.resultsPath);
      expect(receipts).toMatchObject([
        {
          id: "sealed",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          outputDir,
          coverage: completeness,
          cost,
          warning,
        },
      ]);
      expect(
        receipts.reduce(
          (total, receipt) =>
            total + (receipt["cost"] as typeof cost).estimatedUsd,
          0,
        ),
      ).toBe(cost.estimatedUsd);
      await Promise.all(
        [
          "scan-manifest.json",
          "findings.json",
          "coverage.json",
          "report.md",
        ].map((name) => access(join(outputDir, name))),
      );
      expect(progress).toMatchObject([
        { repository: "sealed", status: "started", attempt: 1 },
        {
          repository: "sealed",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          warning,
        },
      ]);

      const resumed = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          onProgress: throwing("Optional progress observer failed."),
        }),
      );
      expect(resumed).toMatchObject({
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(attempts).toBe(1);
      expect(await results(resumed.resultsPath)).toHaveLength(1);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "resumes legacy sealed %s coverage without rerunning or duplicating cost",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, `legacy-${completeness}`);
      await writeFile(
        paths.input,
        `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
      );
      const outputDir = join(paths.output, "artifacts", "legacy", "attempt-1");
      await completedScan(outputDir, completeness);
      const cost = {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 200,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 231.73,
      };
      const receipt = {
        id: "legacy",
        repository: source.path,
        revision: source.revision,
        mode: "standard",
        status: "failed",
        attempt: 1,
        outputDir,
        cost,
        error: "Multiscan repository coverage is incomplete.",
      };
      await writeFile(
        join(paths.output, "results.jsonl"),
        `${JSON.stringify(receipt)}\n`,
      );
      const progress: Parameters<
        NonNullable<MultiscanOptions["onProgress"]>
      >[0][] = [];
      const security = client(mock(completeRun));

      const summary = await runMultiscan(
        options(paths, security, {
          maxAttempts: 3,
          onProgress: (event) => progress.push(event),
        }),
      );

      expect(summary).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(security.run.mock.calls.length).toBe(0);
      expect(progress).toEqual([
        {
          repository: "legacy",
          status: "completed_with_incomplete_coverage",
          attempt: 1,
          warning: `Scan coverage is ${completeness}; results may be incomplete.`,
        },
      ]);
      expect(await results(summary.resultsPath)).toEqual([receipt]);

      await runMultiscan(options(paths, security, { maxAttempts: 3 }));
      expect(security.run.mock.calls.length).toBe(0);
      expect(await results(summary.resultsPath)).toEqual([receipt]);
    },
  );

  test.each([
    ["operational failures", "partial", "Worker exited unexpectedly.", false],
    [
      "complete coverage",
      "complete",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "malformed coverage",
      "malformed",
      "Multiscan repository coverage is incomplete.",
      false,
    ],
    [
      "missing artifacts",
      "partial",
      "Multiscan repository coverage is incomplete.",
      true,
    ],
  ] as const)(
    "continues retrying legacy %s",
    async (_scenario, completeness, error, missingArtifact) => {
      const paths = await fixture();
      const source = await repository(paths.root, "legacy-retry");
      await writeFile(
        paths.input,
        `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
      );
      const outputDir = join(paths.output, "artifacts", "legacy", "attempt-1");
      await completedScan(outputDir);
      await writeFile(
        join(outputDir, "coverage.json"),
        completeness === "malformed"
          ? "{\n"
          : `${JSON.stringify({ completeness })}\n`,
      );
      if (missingArtifact) await rm(join(outputDir, "report.md"));
      await writeFile(
        join(paths.output, "results.jsonl"),
        `${JSON.stringify({
          id: "legacy",
          repository: source.path,
          revision: source.revision,
          mode: "standard",
          status: "failed",
          attempt: 1,
          outputDir,
          error,
        })}\n`,
      );
      const attempts = mock(completeRun);

      const summary = await runMultiscan(options(paths, client(attempts)));

      expect(summary).toMatchObject({
        completed: 1,
        incomplete: 0,
        failed: 0,
        skipped: 0,
      });
      expect(attempts.mock.calls.length).toBe(1);
      expect(await results(summary.resultsPath)).toMatchObject([
        { status: "failed", attempt: 1, error },
        { status: "completed", attempt: 2, coverage: "complete" },
      ]);
    },
  );

  test.each(["partial", "unknown"] as const)(
    "keeps sealed %s-coverage CLI runs fail-closed without retrying",
    async (completeness) => {
      const paths = await fixture();
      const source = await repository(paths.root, "sample");
      await writeFile(
        paths.input,
        `id,repository,revision\nsample,${source.path},${source.revision}\n`,
      );
      const outputDir = join(paths.output, "artifacts", "sample", "attempt-1");
      const result = fakeResult([], completeness);
      const { stdout, stderr, runCli } = createCliTest(main);

      const onRun = mock();
      const arguments_ = [
        "bulk-scan",
        "repositories.csv",
        "--output-dir",
        "results",
        "--max-attempts",
        "3",
        "--json",
      ];
      const clientDependencies = dependencies({
        currentDirectory: paths.root,
        result,
        onRun,
      });
      const createSecurity = clientDependencies.createSecurity;
      clientDependencies.createSecurity = (config) => {
        const security = createSecurity(config);
        return {
          ...security,
          run: async (repository, scan = {}) => {
            const completed = await completedScan(
              scan.outputDir!,
              completeness,
            );
            result.manifest.scan.target = completed.manifest.scan.target;
            return security.run(repository, scan);
          },
        };
      };

      expect(await runCli(arguments_, clientDependencies)).toBe(2);
      expect(onRun).toHaveBeenCalledTimes(1);
      expect(JSON.parse(stdout.text())).toMatchObject({
        total: 1,
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 0,
      });
      const warning = `Scan coverage is ${completeness}; results may be incomplete.`;
      expect(stderr.text()).toContain(
        "sample completed_with_incomplete_coverage (attempt 1)",
      );
      expect(stderr.text()).toContain(warning);
      expect(stderr.text()).not.toContain("attempt 2");
      expect(await results(join(paths.output, "results.jsonl"))).toMatchObject([
        {
          status: "completed_with_incomplete_coverage",
          coverage: completeness,
          outputDir,
        },
      ]);

      const resumedOutput = capture();
      const resumedError = capture();
      expect(
        await main(
          arguments_,
          resumedOutput.stream,
          resumedError.stream,
          clientDependencies,
        ),
      ).toBe(2);
      expect(JSON.parse(resumedOutput.text())).toMatchObject({
        completed: 0,
        incomplete: 1,
        failed: 0,
        skipped: 1,
      });
      expect(resumedError.text()).toContain(warning);
      expect(onRun).toHaveBeenCalledTimes(1);
    },
  );

  test("retries incomplete scans that are missing required artifacts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "missing-artifact");
    await writeFile(
      paths.input,
      `id,repository,revision\nmissing,${source.path},${source.revision}\n`,
    );

    const attempts = mock<SecurityClient["run"]>(
      async (_repository, scanOptions = {}) => {
        const result = await completedScan(
          scanOptions.outputDir!,
          attempts.mock.calls.length === 1 ? "partial" : "complete",
        );
        if (attempts.mock.calls.length === 1) {
          await rm(join(scanOptions.outputDir!, "report.md"));
        }
        return result;
      },
    );
    const summary = await runMultiscan(options(paths, client(attempts)));

    expect(attempts.mock.calls.length).toBe(2);
    expect(summary).toMatchObject({ completed: 1, incomplete: 0, failed: 0 });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "missing",
        status: "failed",
        attempt: 1,
        coverage: "partial",
        error: "Multiscan scan output is missing required artifacts.",
      },
      { id: "missing", status: "completed", attempt: 2, coverage: "complete" },
    ]);
  });

  test("rejects malformed CSV and duplicate headers before starting scans", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "csv");
    const invalid = [
      `id,repository,revision\npayments,"${source.path},${source.revision}\n`,
      `id,repository,revision,id\npayments,${source.path},${source.revision},again\n`,
      `id,repository,revision\npayments,${source.path}\n`,
    ];
    const scans = mock(completeRun);

    for (const input of invalid) {
      await writeFile(paths.input, input);
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        /CSV/,
      );
    }

    expect(scans.mock.calls.length).toBe(0);
  });

  test("rejects task IDs that collide with Windows path names", async () => {
    const paths = await fixture();
    const scans = mock(completeRun);
    for (const id of ["task.", "CON", "nul.txt", "COM1", "LPT9.log"]) {
      await writeFile(
        paths.input,
        `id,repository,revision\n${id},./repository,${"0".repeat(40)}\n`,
      );

      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "safe, unique path names",
      );
    }

    expect(scans.mock.calls.length).toBe(0);
  });

  test("materializes the pinned commit, applies row options, and removes its checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "payments");
    await writeFile(
      join(source.path, "src", "app.ts"),
      "export const changed = true;\n",
    );
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "later",
    );
    await writeFile(
      paths.input,
      `id,repository,revision,scope,mode\npayments,${source.path},${source.revision},src,deep\n`,
    );

    const run = mock<SecurityClient["run"]>(async (path, scanOptions = {}) => {
      expect(git(path, "rev-parse", "HEAD")).toBe(source.revision);
      expect(await readFile(join(path, "src", "app.ts"), "utf8")).toContain(
        'name = "payments"',
      );
      expect(scanOptions.target).toEqual(["src"]);
      expect(scanOptions.mode).toBe("deep");
      expect(scanOptions.outputDir).toBe(
        join(paths.output, "artifacts", "payments", "attempt-1"),
      );
      return await completedScan(scanOptions.outputDir!);
    });
    const observeClosed = mock(async () => {});
    const summary = await runMultiscan(
      options(paths, client(run, observeClosed)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0, skipped: 0 });
    expect(observeClosed).toHaveBeenCalledTimes(1);
    await expect(access(run.mock.lastCall?.[0] ?? "")).rejects.toThrow();
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "payments",
        repository: source.path,
        revision: source.revision,
        scope: "src",
        mode: "deep",
        status: "completed",
        attempt: 1,
      },
    ]);
  });

  test("limits simultaneous checkouts to the requested worker count", async () => {
    const paths = await fixture();
    const knowledgeBasePaths = [
      join(paths.root, "architecture.md"),
      "shared/threat-model.md",
    ];
    const sources = await Promise.all(
      ["one", "two", "three"].map((name) => repository(paths.root, name)),
    );
    await writeFile(
      paths.input,
      `id,repository,revision\n${sources
        .map(
          (source, index) => `${index + 1},${source.path},${source.revision}`,
        )
        .join("\n")}\n`,
    );

    let active = 0;
    let maximum = 0;
    const createSecurity = mock(() => {
      let running = false;
      return client(async (repository, scanOptions) => {
        if (running) {
          throw new Error("A scan is already running for this client.");
        }
        running = true;
        try {
          return await security.run(repository, scanOptions);
        } finally {
          running = false;
        }
      }, close);
    });
    const close = mock(async () => {});
    const simultaneous = Promise.withResolvers<void>();
    const security = client(async (_repository, scanOptions = {}) => {
      expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
      active += 1;
      maximum = Math.max(maximum, active);
      if (active === 2) simultaneous.resolve();
      await simultaneous.promise;
      active -= 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const summary = await runMultiscan(
      options(paths, security, {
        workers: 2,
        knowledgeBasePaths,
        createSecurity,
      }),
    );

    expect(maximum).toBe(2);
    expect(createSecurity).toHaveBeenCalledTimes(2);
    expect(close).toHaveBeenCalledTimes(2);
    expect(summary).toMatchObject({ total: 3, completed: 3, failed: 0 });
    expect(await results(summary.resultsPath)).toHaveLength(3);
  });

  test("rejects another supervisor and recovers a crashed owner's checkout", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "exclusive");
    await writeFile(
      paths.input,
      `id,repository,revision\nexclusive,${source.path},${source.revision}\n`,
    );
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    const security = client(async (_repository, scanOptions = {}) => {
      running.resolve();
      await finish.promise;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = runMultiscan(options(paths, security));
    await running.promise;
    try {
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      expect(JSON.parse(await readFile(ownerPath, "utf8"))).toMatchObject({
        pid: process.pid,
        ownerId: expect.any(String),
        hostname: hostname(),
        processStartedAt: expect.any(Number),
      });
      if (process.platform !== "win32") {
        expect((await lstat(lock)).mode & 0o777).toBe(0o700);
        expect((await lstat(ownerPath)).mode & 0o777).toBe(0o600);
      }
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        /running|locked|supervisor/iu,
      );
    } finally {
      finish.resolve();
      await first;
    }

    const [receipt] = await results(join(paths.output, "results.jsonl"));
    await rm(join(receipt!["outputDir"] as string, "report.md"));
    const lock = join(paths.output, ".lock");
    await mkdir(lock);
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
    );
    const checkout = join(paths.output, "checkouts", "exclusive");
    await mkdir(checkout);

    const recovered = await runMultiscan(options(paths, security));
    expect(recovered).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(await results(recovered.resultsPath)).toEqual([receipt!]);
    await access(join(receipt!["outputDir"] as string, "report.md"));
    expect(await readdir(join(paths.output, "checkouts"))).toEqual([]);
    await expect(access(lock)).rejects.toThrow();
  });

  test("recovers a legacy supervisor lock when this live PID was reused", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-pid-reuse");
    await writeFile(
      paths.input,
      `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });
    const beforeProcessStarted = new Date(performance.timeOrigin - 60_000);
    await utimes(ownerPath, beforeProcessStarted, beforeProcessStarted);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
    expect(
      (await readdir(paths.output)).some((name) =>
        name.startsWith(".lock.stale-"),
      ),
    ).toBe(false);
  });

  test("preserves an active legacy supervisor lock", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\nlegacy,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(ownerPath, JSON.stringify({ pid: process.pid }), {
      mode: 0o600,
    });

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toEqual({
      pid: process.pid,
    });
  });

  for (const previousHostname of [hostname(), "previous-container"]) {
    test(`recovers an expired supervisor lease from ${previousHostname === hostname() ? "a reused live PID" : "a replacement container"}`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "expired-supervisor");
      await writeFile(
        paths.input,
        `id,repository,revision\nexpired,${source.path},${source.revision}\n`,
      );
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      await mkdir(lock, { recursive: true, mode: 0o700 });
      await writeFile(
        ownerPath,
        JSON.stringify({
          pid: process.pid,
          ownerId: "previous-supervisor",
          hostname: previousHostname,
          processStartedAt: performance.timeOrigin - 60_000,
        }),
        { mode: 0o600 },
      );
      const expired = new Date(Date.now() - 120_000);
      await utimes(ownerPath, expired, expired);

      const summary = await runMultiscan(
        options(paths, client(completeRunWithoutAwait)),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(lock)).rejects.toThrow();
    });
  }

  test("does not reclaim a live supervisor in another container", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "remote-supervisor");
    await writeFile(
      paths.input,
      `id,repository,revision\nremote,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      ownerPath,
      JSON.stringify({
        pid: 999_999_999,
        ownerId: "live-remote-supervisor",
        hostname: "another-container",
        processStartedAt: performance.timeOrigin,
      }),
      { mode: 0o600 },
    );

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect(JSON.parse(await readFile(ownerPath, "utf8"))).toMatchObject({
      ownerId: "live-remote-supervisor",
    });
  });

  test("recovers interrupted lock creation without an owner record", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "interrupted-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\ninterrupted,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    const expired = new Date(Date.now() - 120_000);
    await utimes(lock, expired, expired);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("preserves a supervisor lock while its owner record is being created", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "initializing-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\ninitializing,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });

    await expect(
      runMultiscan(options(paths, client(completeRunWithoutAwait))),
    ).rejects.toThrow("A multiscan supervisor is already running.");
    expect((await lstat(lock)).isDirectory()).toBe(true);
  });

  test("recovers an interrupted stale-lock recovery claim", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "interrupted-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\ninterrupted,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const recoveryPath = join(lock, ".recovering");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
      {
        mode: 0o600,
      },
    );
    await writeFile(recoveryPath, "", { mode: 0o600 });
    const expired = new Date(Date.now() - 120_000);
    await utimes(recoveryPath, expired, expired);

    const summary = await runMultiscan(
      options(paths, client(completeRunWithoutAwait)),
    );

    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    await expect(access(lock)).rejects.toThrow();
  });

  test("allows only one supervisor to recover an abandoned lock", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "recovery-race");
    await writeFile(
      paths.input,
      `id,repository,revision\nrace,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    await mkdir(lock, { recursive: true, mode: 0o700 });
    await writeFile(
      join(lock, "owner.json"),
      JSON.stringify({ pid: 999_999_999 }),
      {
        mode: 0o600,
      },
    );
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    let active = 0;
    let maximum = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      active += 1;
      maximum = Math.max(maximum, active);
      running.resolve();
      await finish.promise;
      active -= 1;
      return completedScan(scanOptions.outputDir!);
    });
    const contenders = Promise.allSettled([
      runMultiscan(options(paths, security)),
      runMultiscan(options(paths, security)),
    ]);

    await running.promise;
    finish.resolve();
    const outcomes = await contenders;

    expect(maximum).toBe(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "rejected"),
    ).toHaveLength(1);
  });

  test("never removes a replacement owner's lock during interrupted cleanup", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "replacement-owner");
    await writeFile(
      paths.input,
      `id,repository,revision\nreplacement,${source.path},${source.revision}\n`,
    );
    const running = Promise.withResolvers<void>();
    const finish = Promise.withResolvers<void>();
    const first = runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          running.resolve();
          await finish.promise;
          return completedScan(scanOptions.outputDir!);
        }),
      ),
    );
    await running.promise;
    const lock = join(paths.output, ".lock");
    const abandoned = join(paths.output, ".lock.stale-interrupted");
    await rename(lock, abandoned);
    await mkdir(lock, { mode: 0o700 });
    const replacement = {
      pid: process.pid,
      ownerId: "replacement-supervisor",
      hostname: hostname(),
      processStartedAt: performance.timeOrigin,
    };
    await writeFile(join(lock, "owner.json"), JSON.stringify(replacement), {
      mode: 0o600,
    });

    finish.resolve();
    await first;

    expect(
      JSON.parse(await readFile(join(lock, "owner.json"), "utf8")),
    ).toEqual(replacement);
  });

  test("removes an empty supervisor lock when owner creation fails", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "owner-creation-failure");
    await writeFile(
      paths.input,
      `id,repository,revision\nfailure,${source.path},${source.revision}\n`,
    );
    const lock = join(paths.output, ".lock");
    const ownerPath = join(lock, "owner.json");
    const originalWriteFile = filesystem.writeFile;
    const writeOwner = spyOn(filesystem, "writeFile").mockImplementation(
      async (path, data, options) => {
        if (String(path) !== ownerPath) {
          return await originalWriteFile(path, data, options);
        }
        writeOwner.mockRestore();
        throw Object.assign(new Error("could not publish lock owner"), {
          code: "EACCES",
        });
      },
    );
    const security = client(completeRunWithoutAwait);

    try {
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        "could not publish lock owner",
      );
      await expect(access(lock)).rejects.toThrow();
      await expect(
        runMultiscan(options(paths, security)),
      ).resolves.toMatchObject({ completed: 1 });
    } finally {
      writeOwner.mockRestore();
    }
  });

  test.each([false, true])(
    "never removes a replacement lock when owner creation fails (owner published: %p)",
    async (ownerPublished) => {
      if (
        runTestInSubprocess(
          import.meta.path,
          `never removes a replacement lock when owner creation fails (owner published: ${ownerPublished})`,
        )
      ) {
        return;
      }
      const paths = await fixture();
      const source = await repository(paths.root, "owner-creation-race");
      await writeFile(
        paths.input,
        `id,repository,revision\nrace,${source.path},${source.revision}\n`,
      );
      const lock = join(paths.output, ".lock");
      const ownerPath = join(lock, "owner.json");
      const replacement = JSON.stringify({
        pid: process.pid,
        ownerId: "replacement-supervisor",
        hostname: hostname(),
        processStartedAt: performance.timeOrigin,
      });
      const createdInode = 2n ** 60n;
      const replacementInode = createdInode + 1n;
      expect(Number(createdInode)).toBe(Number(replacementInode));
      let replaced = false;
      const originalLstat = filesystem.lstat;
      const originalWriteFile = filesystem.writeFile;
      const readLock = spyOn(filesystem, "lstat").mockImplementation((async (
        ...args: Parameters<typeof filesystem.lstat>
      ) => {
        const metadata = await originalLstat(...args);
        if (String(args[0]) === lock) {
          const inode = replaced ? replacementInode : createdInode;
          metadata.ino =
            typeof metadata.ino === "bigint" ? inode : Number(inode);
        }
        return metadata;
      }) as typeof filesystem.lstat);
      const writeOwner = spyOn(filesystem, "writeFile").mockImplementation(
        async (path, data, options) => {
          if (String(path) !== ownerPath) {
            return await originalWriteFile(path, data, options);
          }
          writeOwner.mockRestore();
          await rename(lock, join(paths.output, ".lock.stale-owner-creation"));
          await mkdir(lock, { mode: 0o700 });
          replaced = true;
          if (ownerPublished) {
            await originalWriteFile(ownerPath, replacement, { mode: 0o600 });
          }
          throw Object.assign(new Error("replacement already owns the lock"), {
            code: "EEXIST",
          });
        },
      );

      try {
        await expect(
          runMultiscan(options(paths, client(completeRunWithoutAwait))),
        ).rejects.toThrow("replacement already owns the lock");
        await access(lock);
        if (ownerPublished) {
          expect(await readFile(ownerPath, "utf8")).toBe(replacement);
        }
      } finally {
        writeOwner.mockRestore();
        readLock.mockRestore();
      }
    },
  );

  test("retries a failed attempt and records both durable receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retry");
    const failure = "temporary failure: token=SYNTHETIC_MULTISCAN_TOKEN";
    const knowledgeBasePaths = ["architecture.md"];
    await writeFile(
      paths.input,
      `id,repository,revision\nretry,${source.path},${source.revision}\n`,
    );

    let attempts = 0;
    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          expect(scanOptions.knowledgeBasePaths).toEqual(knowledgeBasePaths);
          attempts += 1;
          if (attempts === 1) {
            scanOptions.onWarning?.("Warning from the failed attempt.");
            throw new Error(failure);
          }
          return await completedScan(scanOptions.outputDir!);
        }),
        { knowledgeBasePaths },
      ),
    );

    expect(attempts).toBe(2);
    expect(summary).toMatchObject({ completed: 1, failed: 0 });
    expect(summary).not.toHaveProperty("warnings");
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "retry",
        status: "failed",
        attempt: 1,
        error: failure,
        warnings: ["Warning from the failed attempt."],
      },
      { id: "retry", status: "completed", attempt: 2 },
    ]);
  });

  test("rescans corrupt, modified, and mismatched sealed repository artifacts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume-integrity");
    await writeFile(
      paths.input,
      `id,repository,revision\nresume-integrity,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const foreignPaths = await fixture();
    await writeFile(
      foreignPaths.input,
      `id,repository,revision\nresume-integrity,${source.path},${source.revision}\n`,
    );
    const foreign = await runMultiscan(
      options(
        foreignPaths,
        client(async (_repository, scanOptions = {}) =>
          completedScan(scanOptions.outputDir!),
        ),
      ),
    );
    const [foreignReceipt] = await results(foreign.resultsPath);
    const [firstReceipt] = await results(first.resultsPath);
    expect(foreignReceipt!["targetId"]).not.toBe(firstReceipt!["targetId"]);

    const modify = async (
      outputDir: string,
      name: string,
      update: (
        document: Record<string, unknown> & {
          scan?: ScanResult["manifest"]["scan"];
        },
      ) => void,
    ): Promise<void> => {
      const path = join(outputDir, name);
      const document = JSON.parse(await readFile(path, "utf8")) as Record<
        string,
        unknown
      > & { scan?: ScanResult["manifest"]["scan"] };
      update(document);
      await writeFile(path, `${JSON.stringify(document, null, 2)}\n`);
      await reseal(outputDir);
    };
    await modify(
      firstReceipt!["outputDir"] as string,
      "scan-manifest.json",
      (manifest) => {
        manifest.scan!.producer.version = "0.0.1";
      },
    );
    expect(await runMultiscan(options(paths, security))).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    const corruptions: Array<(outputDir: string) => Promise<void>> = [
      ...(["failed", "canceled", "interrupted"] as const).map(
        (status) => async (outputDir: string) => {
          await modify(outputDir, "scan-manifest.json", (manifest) => {
            manifest.scan!.status = status;
          });
          await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
        },
      ),
      async (outputDir) => {
        await writeFile(
          join(outputDir, "scan-manifest.json"),
          "{broken json\n",
        );
      },
      async (outputDir) => {
        await writeFile(join(outputDir, "findings.json"), "{}\n");
        await reseal(outputDir);
      },
      async (outputDir) => {
        await appendFile(join(outputDir, "coverage.json"), "\n");
      },
      (outputDir) =>
        modify(outputDir, "coverage.json", (coverage) => {
          coverage["completeness"] = "partial";
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.revision = "0".repeat(40);
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.displayName = "another-repository";
        }),
      async (outputDir) => {
        await cp(foreignReceipt!["outputDir"] as string, outputDir, {
          recursive: true,
          force: true,
        });
        const contract = await loadContract(outputDir, {
          pluginRoot: PLUGIN_ROOT,
        });
        expect(contract.manifest.scan.target.targetId).toBe(
          foreignReceipt!["targetId"] as string,
        );
      },
      async (outputDir) => {
        const receipts = await results(first.resultsPath);
        receipts.at(-1)!["targetId"] = foreignReceipt!["targetId"];
        await writeFile(
          first.resultsPath,
          `${receipts.map((receipt) => JSON.stringify(receipt)).join("\n")}\n`,
        );
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.producer.name = "another-security-plugin";
        });
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.kind = "directory_snapshot";
          manifest.scan!.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
        }),
      (outputDir) =>
        modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.target.snapshotDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
        }),
      (outputDir) =>
        modify(outputDir, "coverage.json", (coverage) => {
          coverage["mode"] = "deep_repository";
        }),
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.scope.includePaths = ["another-scope"];
        });
        await modify(outputDir, "coverage.json", (coverage) => {
          coverage["includePaths"] = ["another-scope"];
        });
      },
      async (outputDir) => {
        await modify(outputDir, "scan-manifest.json", (manifest) => {
          manifest.scan!.scope.excludePaths = ["src"];
        });
        await modify(outputDir, "coverage.json", (coverage) => {
          coverage["excludePaths"] = ["src"];
        });
        await loadContract(outputDir, { pluginRoot: PLUGIN_ROOT });
      },
    ];

    for (const corrupt of corruptions) {
      const previous = join(
        paths.output,
        "artifacts",
        "resume-integrity",
        `attempt-${attempts}`,
      );
      await corrupt(previous);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        failed: 0,
        skipped: 0,
      });
      await access(previous);
    }

    expect(attempts).toBe(corruptions.length + 1);
    expect(await results(join(paths.output, "results.jsonl"))).toHaveLength(
      corruptions.length + 1,
    );
  });

  test.each([
    "forged campaign target identity",
    "forged resolved repository scope",
    "forged lexical symlink scope",
    "forged worktree snapshot digest",
    "deferred complete coverage",
    "follow-up complete coverage",
    "unsealed canonical findings",
    "unsealed canonical coverage",
    "duplicate coverage surface identities",
    "duplicate finding identities",
    "reversed finding line range",
    "duplicate evidence identifiers",
    "dangling root-cause evidence",
    "dangling validation evidence",
    "dangling attack-path evidence",
  ] as const)("rescans sealed artifacts with %s", async (corruption) => {
    if (corruption === "forged lexical symlink scope") {
      const count = Number(process.env["GIT_CONFIG_COUNT"] ?? "0");
      if (
        runTestInSubprocess(
          fileURLToPath(import.meta.url),
          `rescans sealed artifacts with ${corruption}`,
          {
            ...process.env,
            GIT_CONFIG_COUNT: String(count + 1),
            [`GIT_CONFIG_KEY_${count}`]: "core.symlinks",
            [`GIT_CONFIG_VALUE_${count}`]: "true",
          },
        )
      )
        return;
    }
    const paths = await fixture();
    const source = await repository(paths.root, "sealed-resume-integrity");
    let revision = source.revision;
    if (corruption === "forged lexical symlink scope") {
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add scoped directory alias",
      );
      revision = git(source.path, "rev-parse", "HEAD");
    }
    const inventory =
      corruption === "forged resolved repository scope"
        ? `id,repository,revision,scope\nsealed-resume,${source.path},${revision},src\n`
        : corruption === "forged lexical symlink scope"
          ? `id,repository,revision,scope\nsealed-resume,${source.path},${revision},alias\n`
          : `id,repository,revision\nsealed-resume,${source.path},${revision}\n`;
    await writeFile(paths.input, inventory);
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    let pluginRoot = PLUGIN_ROOT;
    if (
      corruption === "deferred complete coverage" ||
      corruption === "follow-up complete coverage" ||
      corruption === "unsealed canonical findings" ||
      corruption === "unsealed canonical coverage"
    ) {
      pluginRoot = join(paths.root, "custom-plugin");
      await mkdir(pluginRoot);
      await cp(
        join(PLUGIN_ROOT, ".codex-plugin"),
        join(pluginRoot, ".codex-plugin"),
        { recursive: true },
      );
      await cp(join(PLUGIN_ROOT, "schemas"), join(pluginRoot, "schemas"), {
        recursive: true,
      });
      const coverageSchema =
        corruption === "deferred complete coverage" ||
        corruption === "follow-up complete coverage";
      const schemaPath = join(
        pluginRoot,
        "schemas",
        coverageSchema ? "coverage.schema.json" : "scan-manifest.schema.json",
      );
      const schema = JSON.parse(await readFile(schemaPath, "utf8")) as {
        allOf?: unknown;
        properties?: { scan?: { allOf?: unknown } };
      };
      if (coverageSchema) delete schema.allOf;
      else delete schema.properties?.scan?.allOf;
      await writeFile(schemaPath, `${JSON.stringify(schema, null, 2)}\n`);
    }
    const campaign = options(
      paths,
      security,
      pluginRoot === PLUGIN_ROOT ? {} : { config: { pluginPath: pluginRoot } },
    );
    const first = await runMultiscan(campaign);
    const [receipt] = await results(first.resultsPath);
    const outputDir = receipt!["outputDir"] as string;

    if (corruption === "forged campaign target identity") {
      const foreignPaths = await fixture();
      await writeFile(foreignPaths.input, inventory);
      const foreign = await runMultiscan(
        options(
          foreignPaths,
          client(async (_repository, scanOptions = {}) =>
            completedScan(scanOptions.outputDir!),
          ),
        ),
      );
      const [foreignReceipt] = await results(foreign.resultsPath);
      await cp(foreignReceipt!["outputDir"] as string, outputDir, {
        recursive: true,
        force: true,
      });
      receipt!["targetId"] = foreignReceipt!["targetId"];
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (
      corruption === "forged resolved repository scope" ||
      corruption === "forged lexical symlink scope"
    ) {
      const manifestPath = join(outputDir, "scan-manifest.json");
      const manifest = JSON.parse(
        await readFile(manifestPath, "utf8"),
      ) as ScanResult["manifest"];
      const forgedScope =
        corruption === "forged lexical symlink scope" ? "alias" : ".";
      manifest.scan.scope.includePaths = [forgedScope];
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      const coveragePath = join(outputDir, "coverage.json");
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as ScanResult["coverage"];
      coverage.includePaths = [forgedScope];
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
      receipt!["resolvedScope"] = forgedScope;
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (corruption === "forged worktree snapshot digest") {
      const manifestPath = join(outputDir, "scan-manifest.json");
      const manifest = JSON.parse(
        await readFile(manifestPath, "utf8"),
      ) as ScanResult["manifest"];
      const forgedDigest = `codex-security-snapshot/v1:sha256:${"0".repeat(64)}`;
      manifest.scan.target.kind = "git_worktree";
      manifest.scan.target.snapshotDigest = forgedDigest;
      await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
      receipt!["snapshotDigest"] = forgedDigest;
      await writeFile(first.resultsPath, `${JSON.stringify(receipt)}\n`);
    } else if (
      corruption === "duplicate finding identities" ||
      corruption === "reversed finding line range" ||
      corruption === "duplicate evidence identifiers" ||
      corruption === "dangling root-cause evidence" ||
      corruption === "dangling validation evidence" ||
      corruption === "dangling attack-path evidence"
    ) {
      const findingsPath = join(outputDir, "findings.json");
      const findings = JSON.parse(
        await readFile(findingsPath, "utf8"),
      ) as ScanResult["findings"];
      const finding = findings.findings[0]!;
      if (corruption === "duplicate finding identities") {
        findings.findings.push(structuredClone(finding));
      } else if (corruption === "reversed finding line range") {
        finding.locations[0]!.endLine = finding.locations[0]!.startLine - 1;
      } else if (corruption === "duplicate evidence identifiers") {
        const evidence = {
          id: "source-evidence",
          label: "Source evidence",
          path: "src/extract.py",
          startLine: 41,
          endLine: 44,
          code: "extract()",
          explanation: "Source evidence",
        };
        finding.codeEvidence = [evidence, structuredClone(evidence)];
      } else if (corruption === "dangling root-cause evidence") {
        finding.rootCause = {
          summary: "Missing source evidence.",
          evidenceRefs: ["missing-evidence"],
        };
      } else if (corruption === "dangling validation evidence") {
        finding.validation = { evidenceRefs: ["missing-evidence"] };
      } else {
        finding.attackPath = { evidenceRefs: ["missing-evidence"] };
      }
      await writeFile(findingsPath, `${JSON.stringify(findings, null, 2)}\n`);
    } else if (
      corruption === "deferred complete coverage" ||
      corruption === "follow-up complete coverage" ||
      corruption === "duplicate coverage surface identities"
    ) {
      const coveragePath = join(outputDir, "coverage.json");
      const coverage = JSON.parse(
        await readFile(coveragePath, "utf8"),
      ) as ScanResult["coverage"];
      if (corruption === "deferred complete coverage") {
        coverage.deferred.push({
          id: "unreviewed-surface",
          reason: "Review remains incomplete.",
        });
      } else if (corruption === "follow-up complete coverage") {
        coverage.surfaces[0]!.disposition = "needs_follow_up";
      } else {
        coverage.surfaces.push(structuredClone(coverage.surfaces[0]!));
      }
      await writeFile(coveragePath, `${JSON.stringify(coverage, null, 2)}\n`);
    }

    const manifestPath = join(outputDir, "scan-manifest.json");
    const manifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as ScanResult["manifest"];
    if (corruption === "unsealed canonical findings") {
      manifest.scan.artifacts = manifest.scan.artifacts.filter(
        (artifact) => artifact.path !== "findings.json",
      );
    } else if (corruption === "unsealed canonical coverage") {
      manifest.scan.artifacts = manifest.scan.artifacts.filter(
        (artifact) => artifact.path !== "coverage.json",
      );
    }
    manifest.scan.artifacts.push({
      path: "report.md",
      sha256: "0".repeat(64),
      mediaType: "text/markdown",
    });
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    await reseal(outputDir);
    const sealedManifest = JSON.parse(
      await readFile(manifestPath, "utf8"),
    ) as ScanResult["manifest"];
    expect(
      await contract.hasSealedReport(outputDir, sealedManifest),
    ).toBeTrue();

    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      failed: 0,
      skipped: 0,
    });
    expect(attempts).toBe(2);
  });

  test.each([
    ["scoped", "src", "standard"],
    ["trailing-scope", "src/", "standard"],
    ["root-scope", "./", "standard"],
    ["deep", "", "deep"],
  ] as const)(
    "resumes current and legacy sealed %s scans matching the requested mode and scope",
    async (id, scope, mode) => {
      const paths = await fixture();
      const source = await repository(paths.root, id);
      await writeFile(
        paths.input,
        `id,repository,revision,scope,mode\n${id},${source.path},${source.revision},${scope},${mode}\n`,
      );
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(scanOptions.outputDir!);
      });

      const first = await runMultiscan(options(paths, security));
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });

      const [legacy] = await results(first.resultsPath);
      delete legacy!["targetId"];
      delete legacy!["resolvedScope"];
      const ledger = `${JSON.stringify(legacy)}\n`;
      await writeFile(first.resultsPath, ledger);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
      expect(attempts).toBe(1);
    },
  );

  testPosix(
    "resumes a sealed scope reached through an in-repository symlink",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "symlink-scope");
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add scoped directory alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nsymlink-scope,${source.path},${revision},alias\n`,
      );
      let attempts = 0;
      const security = client(async (_repository, scanOptions = {}) => {
        attempts += 1;
        return await completedScan(scanOptions.outputDir!);
      });

      const first = await runMultiscan(options(paths, security));
      expect(await results(first.resultsPath)).toMatchObject([
        { status: "completed", scope: "alias", resolvedScope: "src" },
      ]);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(attempts).toBe(1);

      const [legacy] = await results(first.resultsPath);
      delete legacy!["resolvedScope"];
      await writeFile(first.resultsPath, `${JSON.stringify(legacy)}\n`);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(attempts).toBe(2);
    },
  );

  test("validates resumed artifacts with a configured plugin archive", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "custom-plugin");
    await writeFile(
      paths.input,
      `id,repository,revision\ncustom,${source.path},${source.revision}\n`,
    );
    const pluginPath = join(paths.root, "plugin.zip");
    const entries: Record<string, Uint8Array> = {};
    for (const path of [
      ".codex-plugin/plugin.json",
      "schemas/scan-manifest.schema.json",
      "schemas/findings.schema.json",
      "schemas/coverage.schema.json",
    ]) {
      entries[`release/${path}`] = await readFile(join(PLUGIN_ROOT, path));
    }
    await writeFile(pluginPath, zipSync(entries));
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const campaign = options(paths, security, { config: { pluginPath } });

    await runMultiscan(campaign);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(attempts).toBe(1);
    expect(
      (await readdir(paths.output)).some((name) =>
        name.startsWith(".resume-plugin-"),
      ),
    ).toBe(false);
  });

  test("resumes complete bundles, repairs missing reports, and rejects manifest drift", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "resume");
    const csv = `id,repository,revision\nresume,${source.path},${source.revision}\n`;
    await writeFile(paths.input, csv);
    const security = client(mock(completeRun));

    const initial = await runMultiscan(options(paths, security));
    await appendFile(initial.resultsPath, '{"id":"interrupted"');
    const resumed = await runMultiscan(options(paths, security));
    expect(resumed).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    for (const prompts of [
      { scanPrompt: "Review different boundaries." },
      { postScanPrompt: "Draft confirmed fixes." },
      { maxCostUsd: 12.5 },
    ]) {
      await expect(
        runMultiscan(options(paths, security, prompts)),
      ).rejects.toThrow("manifest does not match");
    }
    expect(security.run.mock.calls.length).toBe(1);

    const [receipt] = await results(initial.resultsPath);
    const outputDir = receipt!["outputDir"] as string;
    const reportPath = join(outputDir, "report.md");
    const report = await readFile(reportPath);
    const canonicalPaths = [
      "scan-manifest.json",
      "findings.json",
      "coverage.json",
    ].map((name) => join(outputDir, name));
    const canonical = await Promise.all(
      canonicalPaths.map((path) => readFile(path)),
    );
    const ledger = await readFile(initial.resultsPath, "utf8");
    await rm(reportPath);
    const repaired = await runMultiscan(options(paths, security));
    expect(repaired).toMatchObject({ completed: 1, failed: 0, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    expect(await readFile(reportPath)).toEqual(report);
    expect(
      await Promise.all(canonicalPaths.map((path) => readFile(path))),
    ).toEqual(canonical);
    expect(await readFile(repaired.resultsPath, "utf8")).toBe(ledger);

    await writeFile(paths.input, csv.replace("resume,", "changed,"));
    await expect(runMultiscan(options(paths, security))).rejects.toThrow(
      "manifest does not match",
    );
    expect(security.run.mock.calls.length).toBe(1);
  });

  test("skips sealed report recovery and preserves earned receipts on recovery failure", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "report-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nreport-recovery,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const ledger = await readFile(first.resultsPath, "utf8");
    const resolvePython = spyOn(
      runtime,
      "resolvePluginPythonCommand",
    ).mockRejectedValue(
      new Error("Python unavailable: sk-proj-SYNTHETIC_REPORT_RECOVERY_123"),
    );
    try {
      const reportSealed = spyOn(contract, "hasSealedReport").mockResolvedValue(
        true,
      );
      try {
        await expect(
          runMultiscan(options(paths, security)),
        ).resolves.toMatchObject({ completed: 1, failed: 0, skipped: 1 });
        expect(reportSealed).toHaveBeenCalledTimes(1);
        expect(resolvePython).not.toHaveBeenCalled();
        expect(attempts).toBe(1);
        expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
      } finally {
        reportSealed.mockRestore();
      }
      await expect(runMultiscan(options(paths, security))).rejects.toThrow(
        "Multiscan report recovery is required: Python unavailable: sk-proj-SYNTHETIC_REPORT_RECOVERY_123",
      );
      expect(resolvePython).toHaveBeenCalledWith(
        expect.objectContaining({
          protectedRoot: join(paths.output, "checkouts", "report-recovery"),

          environment: runtime.pluginHelperEnvironment(process.env),
        }),
      );
      expect(attempts).toBe(1);
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
    } finally {
      resolvePython.mockRestore();
    }
  });

  test("preserves cancellation during report recovery", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "cancel-report-recovery");
    await writeFile(
      paths.input,
      `id,repository,revision\nreport-recovery,${source.path},${source.revision}\n`,
    );
    let attempts = 0;
    const security = client(async (_repository, scanOptions = {}) => {
      attempts += 1;
      return await completedScan(scanOptions.outputDir!);
    });
    const first = await runMultiscan(options(paths, security));
    const ledger = await readFile(first.resultsPath, "utf8");
    const controller = new AbortController();
    const reason = new Error("Report recovery cancelled.");
    const resolvePython = spyOn(
      runtime,
      "resolvePluginPythonCommand",
    ).mockImplementation(async () => {
      controller.abort(reason);
      throw reason;
    });
    try {
      await expect(
        runMultiscan(options(paths, security, { signal: controller.signal })),
      ).rejects.toBe(reason);
      expect(attempts).toBe(1);
      expect(await readFile(first.resultsPath, "utf8")).toBe(ledger);
    } finally {
      resolvePython.mockRestore();
    }
  });

  test.skipIf(process.platform !== "win32")(
    "resumes campaigns across Windows repository path aliases",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "resume-alias");
      const inventory = (repositoryPath: string) =>
        `id,repository,revision\nresume,${repositoryPath},${source.revision}\n`;
      const security = client(mock(completeRun));

      await writeFile(paths.input, inventory(source.path));
      await runMultiscan(options(paths, security));
      await writeFile(paths.input, inventory(source.path.toUpperCase()));

      expect(await runMultiscan(options(paths, security))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(security.run.mock.calls.length).toBe(1);
    },
  );

  test("ignores repository-local Git shims while preserving credential configuration", async () => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        "ignores repository-local Git shims while preserving credential configuration",
      )
    )
      return;
    const paths = await fixture();
    const source = await repository(paths.root, "private");
    await writeFile(
      paths.input,
      `id,repository,revision\nprivate,${source.path},${source.revision}\n`,
    );
    const shimDirectory = join(paths.root, "node_modules", ".bin");
    const leakedCredential = join(paths.root, "leaked-credential");
    await mkdir(shimDirectory, { recursive: true });
    await writeFile(
      join(shimDirectory, "git"),
      `#!/bin/sh\nprintf '%s' "$GIT_CONFIG_VALUE_0" > "${leakedCredential}"\nexit 1\n`,
      { mode: 0o700 },
    );
    const previousDirectory = process.cwd();
    const environment = new Map(
      [
        "PATH",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
      ].map((name) => [name, process.env[name]] as const),
    );

    try {
      process.chdir(paths.root);
      process.env["PATH"] =
        `${shimDirectory}${process.platform === "win32" ? ";" : ":"}${environment.get("PATH") ?? ""}`;
      process.env["GIT_CONFIG_COUNT"] = "1";
      process.env["GIT_CONFIG_KEY_0"] = "multiscan.credential";
      process.env["GIT_CONFIG_VALUE_0"] = "SYNTHETIC_GIT_CREDENTIAL";

      const summary = await runMultiscan(
        options(
          paths,
          client(async (checkout, scanOptions = {}) => {
            const trustedGit = await resolveTrustedExecutable(
              "git",
              { ...process.env, PATH: environment.get("PATH") ?? "" },
              paths.root,
            );
            if (trustedGit === null) {
              throw new Error("Git is not available on a trusted PATH.");
            }
            const credential = execFileSync(
              trustedGit.executable,
              ["-C", checkout, "config", "--get", "multiscan.credential"],
              {
                encoding: "utf8",
                env: trustedGit.environment,
                stdio: ["ignore", "pipe", "pipe"],
              },
            ).trim();
            expect(credential).toBe("SYNTHETIC_GIT_CREDENTIAL");
            return await completedScan(scanOptions.outputDir!);
          }),
        ),
      );

      expect(summary).toMatchObject({ completed: 1, failed: 0 });
      await expect(access(leakedCredential)).rejects.toThrow();
    } finally {
      process.chdir(previousDirectory);
      for (const [name, value] of environment) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("removes mixed-case repository Git variables before cloning", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "isolated");
    const trace = join(paths.root, "git-events.jsonl");
    await writeFile(
      paths.input,
      `id,repository,revision\nisolated,${source.path},${source.revision}\n`,
    );
    const repositoryVariables = [
      "Git_Dir",
      "gIt_Work_Tree",
      "Git_Index_File",
      "gIt_Object_Directory",
      "Git_Alternate_Object_Directories",
    ];
    const previous = new Map(
      [...repositoryVariables, "GIT_TRACE2_EVENT", "GIT_TRACE2_ENV_VARS"].map(
        (name) => [name, process.env[name]] as const,
      ),
    );

    try {
      for (const name of repositoryVariables) {
        process.env[name] = join(paths.root, `missing-${name}`);
      }
      process.env["GIT_TRACE2_EVENT"] = trace;
      process.env["GIT_TRACE2_ENV_VARS"] = repositoryVariables.join(",");

      const summary = await runMultiscan(
        options(paths, client(completeRunWithoutAwait)),
      );
      expect(summary).toMatchObject({ completed: 1, failed: 0 });

      const leakedVariables = parseJsonLines<{
        event: string;
        param?: string;
        value?: string;
      }>(await readFile(trace, "utf8")).filter(
        (event) =>
          event.event === "def_param" &&
          repositoryVariables.includes(event.param ?? "") &&
          event.value === join(paths.root, `missing-${event.param}`),
      );
      expect(leakedVariables).toEqual([]);
    } finally {
      for (const [name, value] of previous) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("rejects output-directory symlinks before deleting external checkouts", async () => {
    for (const directory of ["", "checkouts", "artifacts"]) {
      const paths = await fixture();
      const source = await repository(paths.root, "victim");
      await writeFile(
        paths.input,
        `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
      );
      const external = join(paths.root, "external");
      const preserved = join(external, "victim", "keep.txt");
      await mkdir(join(external, "victim"), { recursive: true });
      await writeFile(preserved, "preserved\n");
      if (directory) await mkdir(paths.output, { mode: 0o700 });
      await symlink(
        external,
        directory ? join(paths.output, directory) : paths.output,
      );

      const scans = mock(completeRun);
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "symbolic links",
      );
      expect(scans.mock.calls.length).toBe(0);
      expect(await readFile(preserved, "utf8")).toBe("preserved\n");
    }
  });

  test("rejects linked task artifact directories without touching external files", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "victim");
    await writeFile(
      paths.input,
      `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
    );
    const external = join(paths.root, "external");
    await mkdir(external);
    await writeFile(join(external, "preserved.txt"), "preserved\n");
    await mkdir(join(paths.output, "artifacts"), {
      recursive: true,
      mode: 0o700,
    });
    await symlink(
      external,
      join(paths.output, "artifacts", "victim"),
      process.platform === "win32" ? "junction" : "dir",
    );

    const scans = mock(completeRun);
    const summary = await runMultiscan(
      options(paths, client(scans), { maxAttempts: 1 }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 0, failed: 1 });
    expect(scans.mock.calls.length).toBe(0);
    expect((await results(summary.resultsPath))[0]?.["error"]).toContain(
      "symbolic links",
    );
    expect(await readdir(external)).toEqual(["preserved.txt"]);
    expect(await readFile(join(external, "preserved.txt"), "utf8")).toBe(
      "preserved\n",
    );
  });

  test("rejects linked task artifacts before accepting completed receipts", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "victim");
    await writeFile(
      paths.input,
      `id,repository,revision\nvictim,${source.path},${source.revision}\n`,
    );
    const external = join(paths.root, "external");
    await completedScan(join(external, "attempt-1"));
    await mkdir(join(paths.output, "artifacts"), {
      recursive: true,
      mode: 0o700,
    });
    await symlink(
      external,
      join(paths.output, "artifacts", "victim"),
      process.platform === "win32" ? "junction" : "dir",
    );
    await writeFile(
      join(paths.output, "results.jsonl"),
      `${JSON.stringify({
        id: "victim",
        repository: source.path,
        revision: source.revision,
        mode: "standard",
        status: "completed",
        attempt: 1,
        outputDir: join(paths.output, "artifacts", "victim", "attempt-1"),
      })}\n`,
    );

    const scans = mock(completeRun);
    await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
      "symbolic links",
    );
    expect(scans.mock.calls.length).toBe(0);
    expect(await readdir(external)).toEqual(["attempt-1"]);
  });

  test("rejects an output directory replaced during preparation when numeric identities collide", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "output-identity-race");
    await writeFile(
      paths.input,
      `id,repository,revision\nrace,${source.path},${source.revision}\n`,
    );
    await mkdir(paths.output, { mode: 0o700 });
    const originalLstat = filesystem.lstat;
    const canonicalOutput = await realpath(paths.output);
    const firstExactIdentity = BigInt(Number.MAX_SAFE_INTEGER) + 1n;
    let outputInspections = 0;
    const inspectOutput = spyOn(filesystem, "lstat").mockImplementation(
      async (path, options) => {
        const stats = await originalLstat(path, options as never);
        if (String(path) !== paths.output && String(path) !== canonicalOutput) {
          return stats as never;
        }
        const exactIdentity =
          firstExactIdentity + (outputInspections++ === 0 ? 0n : 1n);
        return Object.assign(
          Object.create(Object.getPrototypeOf(stats)),
          stats,
          {
            ino:
              typeof stats.ino === "bigint"
                ? exactIdentity
                : Number(exactIdentity),
          },
        ) as never;
      },
    );
    const scans = mock(completeRun);

    try {
      await expect(runMultiscan(options(paths, client(scans)))).rejects.toThrow(
        "changed during preparation",
      );
      expect(scans.mock.calls.length).toBe(0);
    } finally {
      inspectOutput.mockRestore();
    }
  });

  testPosix(
    "rejects other-user-writable campaigns while preserving readable existing campaigns",
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "sample");
      await writeFile(
        paths.input,
        `id,repository,revision\nsample,${source.path},${source.revision}\n`,
      );
      await mkdir(paths.output, { mode: 0o755 });
      const security = client(mock(completeRun));

      for (const mode of [0o770, 0o777]) {
        await chmod(paths.output, mode);
        await expect(runMultiscan(options(paths, security))).rejects.toThrow(
          "must not be group- or world-writable",
        );
        expect(security.run.mock.calls.length).toBe(0);
      }

      await chmod(paths.output, 0o755);
      expect(await runMultiscan(options(paths, security))).toMatchObject({
        total: 1,
        completed: 1,
        failed: 0,
      });
      expect(security.run.mock.calls.length).toBe(1);
    },
  );

  testPosix("rejects campaigns beneath an unsafe shared parent", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const parent = join(paths.root, "shared");
    await mkdir(parent, { mode: 0o777 });
    await chmod(parent, 0o777);
    const scans = mock(completeRun);

    await expect(
      runMultiscan(
        options(paths, client(scans), { outputDir: join(parent, "results") }),
      ),
    ).rejects.toThrow(
      "must not be group- or world-writable without the sticky bit",
    );
    expect(scans.mock.calls.length).toBe(0);
  });

  test("preserves trusted user-selected campaign parent aliases", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const canonicalParent = join(paths.root, "campaigns");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent, { mode: 0o700 });
    await symlink(
      canonicalParent,
      linkedParent,
      process.platform === "win32" ? "junction" : "dir",
    );
    const output = join(linkedParent, "results");
    const security = client(mock(completeRun));

    const summary = await runMultiscan(
      options(paths, security, { outputDir: output }),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(summary.resultsPath).toBe(join(output, "results.jsonl"));
    const [receipt] = await results(summary.resultsPath);
    expect(receipt?.["outputDir"]).toBe(
      join(canonicalParent, "results", "artifacts", "sample", "attempt-1"),
    );
    await writeFile(
      summary.resultsPath,
      `${JSON.stringify({
        ...receipt,
        outputDir: join(output, "artifacts", "sample", "attempt-1"),
      })}\n`,
    );
    expect(
      await runMultiscan(options(paths, security, { outputDir: output })),
    ).toMatchObject({ completed: 1, skipped: 1 });
    expect(security.run.mock.calls.length).toBe(1);
    expect(await readdir(join(canonicalParent, "results"))).toContain(
      "results.jsonl",
    );
  });

  test("keeps campaign operations on their validated canonical directory", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "sample");
    await writeFile(
      paths.input,
      `id,repository,revision\nsample,${source.path},${source.revision}\n`,
    );
    const canonicalParent = join(paths.root, "campaigns");
    const redirectedParent = join(paths.root, "redirected");
    const linkedParent = join(paths.root, "linked-campaigns");
    await mkdir(canonicalParent, { mode: 0o700 });
    await mkdir(join(redirectedParent, "results"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      join(redirectedParent, "results", "preserved.txt"),
      "preserved\n",
    );
    await symlink(
      canonicalParent,
      linkedParent,
      process.platform === "win32" ? "junction" : "dir",
    );
    const output = join(linkedParent, "results");

    const summary = await runMultiscan(
      options(
        paths,
        client(async (_repository, scanOptions = {}) => {
          await rename(linkedParent, join(paths.root, "previous-alias"));
          await symlink(
            redirectedParent,
            linkedParent,
            process.platform === "win32" ? "junction" : "dir",
          );
          return await completedScan(scanOptions.outputDir!);
        }),
        { outputDir: output },
      ),
    );

    expect(summary).toMatchObject({ total: 1, completed: 1, failed: 0 });
    expect(summary.resultsPath).toBe(
      join(canonicalParent, "results", "results.jsonl"),
    );
    expect(await readdir(join(redirectedParent, "results"))).toEqual([
      "preserved.txt",
    ]);
  });

  test("rejects unsafe input without starting scans or exposing URL credentials", async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "safe");
    const secret = "MULTISCAN_CREDENTIAL_SHOULD_NOT_APPEAR";
    const invalid = [
      {
        name: "task-id",
        row: `../escape,${source.path},${source.revision},.`,
      },
      ...[
        "CON",
        "con.txt",
        "NUL",
        "AUX.txt",
        "PRN",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9.txt",
        "report.",
      ].map((id) => ({
        name: `task-id-${id}`,
        row: `${id},${source.path},${source.revision},.`,
      })),
      {
        name: "windows-alias",
        row: `report,${source.path},${source.revision},.\nreport.,${source.path},${source.revision},.`,
      },
      {
        name: "scope",
        row: `safe,${source.path},${source.revision},../outside`,
      },
      ...(process.platform === "win32"
        ? [
            {
              name: "windows-qualified-scope",
              row: `safe,${source.path},${source.revision},src:stream`,
            },
          ]
        : []),
      {
        name: "revision",
        row: `safe,${source.path},HEAD,.`,
      },
      {
        name: "duplicate-id",
        row: `safe,${source.path},${source.revision},.\nsafe,${source.path},${source.revision},.`,
      },
      {
        name: "credentials",
        row: `safe,https://user:${secret}@example.test/private.git,${source.revision},.`,
      },
    ];
    const security = client(mock(completeRun));

    for (const entry of invalid) {
      await writeFile(
        paths.input,
        `id,repository,revision,scope\n${entry.row}\n`,
      );
      const output = join(paths.root, entry.name);
      const error = await runMultiscan(
        options(paths, security, { outputDir: output }),
      ).then(
        () => null,
        (reason: unknown) => reason,
      );
      expect(error).toBeInstanceOf(Error);
      expect(String(error)).not.toContain(secret);
    }

    expect(security.run.mock.calls.length).toBe(0);
  });

  test("records incomplete coverage separately and still finishes other repositories", async () => {
    const paths = await fixture();
    const incomplete = await repository(paths.root, "incomplete");
    const complete = await repository(paths.root, "complete");
    await writeFile(
      paths.input,
      [
        "id,repository,revision",
        `incomplete,${incomplete.path},${incomplete.revision}`,
        `complete,${complete.path},${complete.revision}`,
        "",
      ].join("\n"),
    );

    const summary = await runMultiscan(
      options(
        paths,
        client(async (checkout, scanOptions = {}) =>
          completedScan(
            scanOptions.outputDir!,
            (await readFile(join(checkout, "src", "app.ts"), "utf8")).includes(
              'name = "incomplete"',
            )
              ? "partial"
              : "complete",
          ),
        ),
        { maxAttempts: 3 },
      ),
    );

    expect(summary).toMatchObject({
      total: 2,
      completed: 1,
      incomplete: 1,
      failed: 0,
    });
    expect(await results(summary.resultsPath)).toMatchObject([
      {
        id: "incomplete",
        status: "completed_with_incomplete_coverage",
        attempt: 1,
        coverage: "partial",
      },
      { id: "complete", status: "completed", attempt: 1, coverage: "complete" },
    ]);
  });
});

test("qualified campaign reuses a completed recovery checkout", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "recovery-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  await runMultiscan(
    options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
  );
  const originalCheckout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, originalCheckout);
  const originalIdentity = await lstat(originalCheckout);
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => completedScan(settings.outputDir!, "complete", checkout),
  );
  const campaign = options(paths, client(runs), {
    recoverScan: async () => undefined,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(runs).toHaveBeenCalledTimes(1);
  const retainedIdentity = await lstat(originalCheckout);
  expect([retainedIdentity.dev, retainedIdentity.ino]).toEqual([
    originalIdentity.dev,
    originalIdentity.ino,
  ]);
});

for (const count of [1, 2]) {
  test(`qualified campaign accepts ${count} referenced legacy evidence entries`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const first = await runMultiscan(campaign);
    const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
    const path = join(dir, "findings.json");
    const saved = JSON.parse(
      await readFile(path, "utf8"),
    ) as ScanResult["findings"];
    saved.findings[0]!.code_evidence = Array.from({ length: count }, () => ({
      id: "saved-evidence",
      code: "extract()",
    }));
    saved.findings[0]!.rootCause = {
      summary: "Existing source evidence",
      evidenceRefs: ["saved-evidence"],
    };
    await writeFile(path, JSON.stringify(saved));
    await reseal(dir);
    expect(
      (await loadContract(dir, { pluginRoot: PLUGIN_ROOT })).findings
        .findings[0]!.code_evidence,
    ).toEqual(saved.findings[0]!.code_evidence);
    const bytes = await readFile(path);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
    expect(await readFile(path)).toEqual(bytes);
  });
}

for (const target of [["src"], ["src", "src/app.ts"]]) {
  test(`qualified campaign retains configured scopes ${target.join(",")}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "configured-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        expect(settings.target).toEqual(target);
        const result = await completedScan(
          settings.outputDir!,
          "complete",
          checkout,
        );
        result.manifest.scan.scope.includePaths = target;
        const coveragePath = join(settings.outputDir!, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.includePaths = target;
        coverage.mode = "scoped_path";
        coverage.inventoryStrategy = "scoped_path";
        await writeFile(coveragePath, JSON.stringify(coverage));
        await writeFile(
          join(settings.outputDir!, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        await reseal(settings.outputDir!);
        return result;
      },
    );
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target } },
    });
    await runMultiscan(campaign);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const orphaned of [false, true]) {
  testPosix(
    `qualified campaign retains resolved scope after ${orphaned ? "orphaned" : "recorded"} recovery`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "resolved-source");
      await symlink("src", join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "Add directory alias",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nRepo,${source.path},${revision},alias\n`,
      );
      const interrupted = client(async (checkout: string, settings = {}) => {
        await completedScan(settings.outputDir!, "partial", checkout);
        throw new Error("Interrupted after saved progress");
      });
      const initial = await runMultiscan(
        options(paths, interrupted, { maxAttempts: 1 }),
      );
      if (orphaned) await writeFile(initial.resultsPath, "");
      const recoverScan = mock(async (dir: string) => {
        const result = await completedScan(dir);
        result.manifest.scan.scope.includePaths = ["src"];
        await writeFile(
          join(dir, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        const coveragePath = join(dir, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        coverage.includePaths = ["src"];
        await writeFile(coveragePath, JSON.stringify(coverage));
        await reseal(dir);
        return {
          coverage: result.coverage,
          cost: null,
          findings: (await loadContract(dir, { pluginRoot: PLUGIN_ROOT }))
            .findings,
        };
      });
      const runs = mock(completeRun);
      const recovered = await runMultiscan(
        options(paths, client(runs), { recoverScan }),
      );
      expect((await results(recovered.resultsPath)).at(-1)).toMatchObject({
        status: "completed",
        resolvedScope: "src",
      });
      expect(await runMultiscan(options(paths, client(runs)))).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(0);
    },
  );
}

test("qualified campaign keeps a recorded checkout while rejecting a failed sealed attempt", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "retained-checkout-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  let checkout = "";
  await runMultiscan(
    options(
      paths,
      client(async (root, settings = {}) => {
        checkout = root;
        await completedScan(settings.outputDir!, "complete", root);
        throw new Error("Synthetic interruption after saved artifacts");
      }),
      { maxAttempts: 1 },
    ),
  );
  // Restore the owned fixture checkout that an interrupted process would retain.
  git(paths.root, "clone", "--quiet", source.path, checkout);
  const before = await lstat(checkout);
  let preserved = false;
  const runs = mock(completeRun);
  const recoverScan = mock(async (dir: string) => {
    const current = await lstat(checkout).catch(() => undefined);
    preserved = current?.dev === before.dev && current?.ino === before.ino;
    return completedScan(dir, "complete", checkout);
  });
  expect(
    await runMultiscan(options(paths, client(runs), { recoverScan })),
  ).toMatchObject({ completed: 1, failed: 0 });
  expect(preserved).toBe(true);
  expect(runs).toHaveBeenCalledTimes(0);
  expect(recoverScan).toHaveBeenCalledTimes(1);
});

test("qualified campaign replays warnings only from accepted saved attempts", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "saved-warning-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const warning = "Synthetic saved-attempt warning";
  let attempts = 0;
  const security = client(async (_root, settings = {}) => {
    attempts += 1;
    if (attempts === 1) settings.onWarning?.(warning);
    return completedScan(settings.outputDir!);
  });
  const campaign = options(paths, security);
  const first = await runMultiscan(campaign);
  expect(first.warnings).toEqual([{ repository: "repo", warnings: [warning] }]);
  const acceptedProgress: string[] = [];
  expect(
    await runMultiscan({
      ...campaign,
      onProgress: (event) => {
        if (event.warning) acceptedProgress.push(event.warning);
      },
    }),
  ).toMatchObject({
    skipped: 1,
    warnings: [{ repository: "repo", warnings: [warning] }],
  });
  expect(acceptedProgress).toEqual([warning]);
  const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
  await appendFile(join(dir, "findings.json"), " ");
  const freshProgress: string[] = [];
  const fresh = await runMultiscan({
    ...campaign,
    onProgress: (event) => {
      if (event.warning) freshProgress.push(event.warning);
    },
  });
  expect(fresh).toMatchObject({ completed: 1, skipped: 0 });
  expect(fresh).not.toHaveProperty("warnings");
  expect(freshProgress).toEqual([]);
  expect(attempts).toBe(2);
});

test("qualified campaign preserves a completed receipt when scope checkout fails", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "unavailable-scoped-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), { maxAttempts: 1 });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  await expect(runMultiscan(campaign)).rejects.toThrow();
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

test("qualified campaign resumes an absolute configured scope inside its checkout", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "absolute-scope-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const requested = join(paths.output, "checkouts", "repo", "src");
  const runs = mock(
    async (
      checkout: string,
      settings: Parameters<SecurityClient["run"]>[1] = {},
    ) => {
      expect((await normalizeTarget(checkout, settings.target!)).paths).toEqual(
        ["src"],
      );
      const result = await completedScan(
        settings.outputDir!,
        "complete",
        checkout,
      );
      const manifestPath = join(settings.outputDir!, "scan-manifest.json");
      result.manifest.scan.scope.includePaths = ["src"];
      await writeFile(manifestPath, JSON.stringify(result.manifest));
      const coveragePath = join(settings.outputDir!, "coverage.json");
      const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
      coverage.mode = "scoped_path";
      coverage.includePaths = ["src"];
      coverage.inventoryStrategy = "scoped_path";
      await writeFile(coveragePath, JSON.stringify(coverage));
      await reseal(settings.outputDir!);
      return result;
    },
  );
  const campaign = options(paths, client(runs), {
    scanOptionsByMode: { standard: { target: [requested] } },
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(runs).toHaveBeenCalledTimes(1);
});

test("qualified campaign recovers its report from an unrelated Python invocation directory", async () => {
  if (
    await runTestInSubprocess(
      fileURLToPath(import.meta.url),
      "qualified campaign recovers its report from an unrelated Python invocation directory",
    )
  )
    return;
  const paths = await fixture();
  const source = await repository(paths.root, "python-invocation-source");
  await writeFile(
    paths.input,
    `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs), {
    config: { pythonPath: PYTHON },
  });
  const initial = await runMultiscan(campaign);
  const ledger = await readFile(initial.resultsPath, "utf8");
  const originalDirectory = process.cwd();
  try {
    process.chdir(dirname(await realpath(PYTHON)));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
  } finally {
    process.chdir(originalDirectory);
  }
  expect(await readFile(initial.resultsPath, "utf8")).toBe(ledger);
  expect(runs).toHaveBeenCalledTimes(1);
});

for (const spelling of ["absolute", "home", "parent alias"] as const) {
  testPosix(
    `resume compatibility retains configured scope with ${spelling} spelling`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "scope-spelling-source");
      await writeFile(
        paths.input,
        `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
      );
      const original = join(paths.output, "checkouts", "repo", "src");
      let requested = original;
      if (spelling === "home")
        requested = `~/${relative(homedir(), original).split(sep).join("/")}`;
      if (spelling === "parent alias") {
        const alias = join(paths.root, "campaign-alias");
        await symlink(paths.output, alias, "dir");
        requested = join(alias, "checkouts", "repo", "src");
      }
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => {
          const target = await normalizeTarget(checkout, settings.target!);
          expect(target.paths).toEqual(["src"]);
          const result = await completedScan(
            settings.outputDir!,
            "complete",
            checkout,
          );
          result.manifest.scan.scope.includePaths = [...target.paths];
          await writeFile(
            join(settings.outputDir!, "scan-manifest.json"),
            JSON.stringify(result.manifest),
          );
          const coveragePath = join(settings.outputDir!, "coverage.json");
          const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
          Object.assign(coverage, {
            mode: "scoped_path",
            includePaths: target.paths,
            inventoryStrategy: "scoped_path",
          });
          await writeFile(coveragePath, JSON.stringify(coverage));
          await reseal(settings.outputDir!);
          return result;
        },
      );
      const campaign = options(paths, client(runs), {
        scanOptionsByMode: { standard: { target: [requested] } },
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

testPosix(
  "resume compatibility retains a tracked scope alias anchored to its checkout basename",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "scope-layout-source");
    await symlink("../repo/src", join(source.path, "alias"), "dir");
    git(source.path, "add", "alias");
    git(
      source.path,
      "-c",
      "user.name=Multiscan Test",
      "-c",
      "user.email=multiscan@example.test",
      "commit",
      "-qm",
      "add checkout-relative scope alias",
    );
    const revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${revision},alias\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

testPosix(
  "resume compatibility preserves a recovery checkout reached through a directory link",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "linked-recovery-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const taskRoot = join(paths.output, "recovery-checkouts", "repo");
    // Recreate the owned checkout retained by interruption after receipt publication.
    git(
      paths.root,
      "clone",
      "--quiet",
      source.path,
      join(taskRoot, "attempt-2"),
    );
    const retained = join(paths.root, "retained-recovery");
    await rename(taskRoot, retained);
    await symlink(retained, taskRoot, "dir");
    const marker = join(retained, "attempt-2", "retained.txt");
    await writeFile(marker, "retained recovery checkout\n");
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readFile(marker, "utf8")).toBe("retained recovery checkout\n");
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("resume compatibility recovers a failed completed bundle without fetching its unavailable source", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "failed-completed-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  await runMultiscan(
    options(
      paths,
      client(async (checkout, settings = {}) => {
        await completedScan(settings.outputDir!, "complete", checkout);
        throw new Error("Synthetic failure after saved completion");
      }),
      { maxAttempts: 1 },
    ),
  );
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  const runs = mock(completeRun);
  const recoverScan = mock(async (dir: string) => {
    const saved = await loadContract(dir, { pluginRoot: PLUGIN_ROOT });
    return {
      ...saved,
      coverage: { completeness: saved.coverage.completeness },
    } as ScanResult;
  });
  expect(
    await runMultiscan(options(paths, client(runs), { recoverScan })),
  ).toMatchObject({ completed: 1, failed: 0 });
  expect(recoverScan).toHaveBeenCalledTimes(1);
  expect(runs).toHaveBeenCalledTimes(0);
});

for (const section of ["rootCause", "validation", "attackPath"] as const) {
  test(`resume compatibility reuses sealed legacy ${section} references`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "legacy-reference-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(completeRun);
    const campaign = options(paths, client(runs));
    const first = await runMultiscan(campaign);
    const dir = (await results(first.resultsPath))[0]!["outputDir"] as string;
    const path = join(dir, "findings.json");
    const saved = JSON.parse(
      await readFile(path, "utf8"),
    ) as ScanResult["findings"];
    const finding = saved.findings[0]!;
    finding.code_evidence = [{ id: "saved-evidence", code: "extract()" }];
    finding[section] = {
      summary: "Existing saved source evidence",
      evidenceRefs: ["saved-evidence", "obsolete-evidence"],
    };
    await writeFile(path, JSON.stringify(saved));
    await reseal(dir);
    expect(
      (await loadContract(dir, { pluginRoot: PLUGIN_ROOT })).findings
        .findings[0]![section],
    ).toEqual(finding[section]);
    const bytes = await readFile(path);
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
    expect(await readFile(path)).toEqual(bytes);
  });
}

for (const spelling of [
  "plain",
  "ancestor relative",
  "absolute link",
] as const) {
  testPosix(
    `original coordinates preserve tracked scope with ${spelling} spelling`,
    async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "coordinate-source");
      const destination =
        spelling === "absolute link"
          ? join(paths.output, "checkouts", "repo", "src")
          : spelling === "ancestor relative"
            ? "../../checkouts/repo/src"
            : "src";
      await symlink(destination, join(source.path, "alias"), "dir");
      git(source.path, "add", "alias");
      git(
        source.path,
        "-c",
        "user.name=Multiscan Test",
        "-c",
        "user.email=multiscan@example.test",
        "commit",
        "-qm",
        "add supported scope link",
      );
      const revision = git(source.path, "rev-parse", "HEAD");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${revision},alias\n`,
      );
      const runs = mock(completeRun);
      const campaign = options(paths, client(runs));
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
    },
  );
}

testPosix(
  "original coordinates retain ancestor-relative configured scope",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "configured-coordinate-source");
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const target = await normalizeTarget(checkout, settings.target!);
        expect(target.paths).toEqual(["src"]);
        const result = await completedScan(
          settings.outputDir!,
          "complete",
          checkout,
        );
        result.manifest.scan.scope.includePaths = [...target.paths];
        await writeFile(
          join(settings.outputDir!, "scan-manifest.json"),
          JSON.stringify(result.manifest),
        );
        const coveragePath = join(settings.outputDir!, "coverage.json");
        const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
        Object.assign(coverage, {
          mode: "scoped_path",
          includePaths: target.paths,
          inventoryStrategy: "scoped_path",
        });
        await writeFile(coveragePath, JSON.stringify(coverage));
        await reseal(settings.outputDir!);
        return result;
      },
    );
    const campaign = options(paths, client(runs), {
      scanOptionsByMode: { standard: { target: ["../../checkouts/repo/src"] } },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

test("original coordinates reuse an existing pinned scope checkout without refetching", async () => {
  const paths = await fixture();
  const source = await repository(paths.root, "retained-coordinate-source");
  await writeFile(
    paths.input,
    `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
  );
  const runs = mock(completeRun);
  const campaign = options(paths, client(runs));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 0,
  });
  const checkout = join(paths.output, "checkouts", "repo");
  git(paths.root, "clone", "--quiet", source.path, checkout);
  await rename(source.path, join(paths.root, "temporarily-unavailable-source"));
  expect(await runMultiscan(campaign)).toMatchObject({
    completed: 1,
    skipped: 1,
  });
  expect(runs).toHaveBeenCalledTimes(1);
});

(process.platform === "win32" ? test : test.skip)(
  "original coordinates retain canonical Windows checkout parent spelling",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "windows-coordinate-source");
    await mkdir(join(paths.output, "CHECKOUTS"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

(process.platform === "win32" ? test : test.skip)(
  "original coordinates retain canonical Windows recovery parent spelling",
  async () => {
    const paths = await fixture();
    const source = await repository(
      paths.root,
      "windows-recovery-coordinate-source",
    );
    await mkdir(join(paths.output, "RECOVERY-CHECKOUTS"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const recovery of [false, true]) {
  for (const partial of ["empty", "missing subtree"] as const) {
    test(`retained preparation completes ${recovery ? "recovery" : "normal"} checkout with ${partial}`, async () => {
      const paths = await fixture();
      const source = await repository(paths.root, "partial-checkout-source");
      await writeFile(
        paths.input,
        `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
      );
      if (recovery)
        await runMultiscan(
          options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
        );
      const runs = mock(
        async (
          checkout: string,
          settings: Parameters<SecurityClient["run"]>[1] = {},
        ) => completedScan(settings.outputDir!, "complete", checkout),
      );
      const campaign = options(
        paths,
        client(runs),
        recovery ? { recoverScan: async () => undefined } : {},
      );
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 0,
      });
      const checkout = recovery
        ? join(paths.output, "recovery-checkouts", "repo", "attempt-2")
        : join(paths.output, "checkouts", "repo");
      if (partial === "empty")
        await mkdir(checkout, { recursive: true, mode: 0o700 });
      else {
        git(paths.root, "clone", "--quiet", source.path, checkout);
        await rm(join(checkout, "src"), { recursive: true });
      }
      const retained = join(checkout, "retained.txt");
      await writeFile(retained, "Preserved interrupted checkout data.\n");
      expect(await runMultiscan(campaign)).toMatchObject({
        completed: 1,
        skipped: 1,
      });
      expect(runs).toHaveBeenCalledTimes(1);
      if (recovery)
        expect(await readFile(retained, "utf8")).toBe(
          "Preserved interrupted checkout data.\n",
        );
    });
  }
}

testPosix(
  "retained preparation preserves a configured source-local Python interpreter",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "source-local-python");
    const interpreter = join(source.path, ".venv", "bin", "python");
    await mkdir(dirname(interpreter), { recursive: true });
    await writeFile(
      interpreter,
      `#!/usr/bin/env node\nconst {spawnSync} = require("node:child_process");\nconst result = spawnSync(${JSON.stringify(PYTHON)}, process.argv.slice(2), {stdio: "inherit"});\nif (result.error) throw result.error;\nprocess.exit(result.status ?? 1);\n`,
      { mode: 0o700 },
    );
    expect((await lstat(interpreter)).isFile()).toBe(true);
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const selected = await runtime.resolvePluginPythonCommand({
          configuredPath: interpreter,
          protectedRoot: checkout,
          environment: runtime.pluginHelperEnvironment(process.env),
        });
        expect(selected.executable).toBe(interpreter);
        return completedScan(settings.outputDir!, "complete", checkout);
      },
    );
    const campaign = options(paths, client(runs), {
      config: { pythonPath: interpreter },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const binding of ["gitfile", "worktree", "common", "objects"] as const) {
  test(`retained Git bindings keep ${binding} writes inside the campaign checkout`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "retained-binding-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const outside = await repository(paths.root, "other-owned-repository");
    await writeFile(
      join(outside.path, "retained-marker.txt"),
      "Preserve the other repository.\n",
    );
    git(outside.path, "add", ".");
    git(outside.path, "commit", "--quiet", "-m", "Other repository state");
    const originalHead = git(outside.path, "rev-parse", "HEAD");
    const originalFiles = await readFile(
      join(outside.path, "retained-marker.txt"),
      "utf8",
    );
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    if (binding === "gitfile") {
      await rm(join(checkout, ".git"), { recursive: true, force: true });
      await writeFile(
        join(checkout, ".git"),
        `gitdir: ${join(outside.path, ".git")}\n`,
      );
    } else if (binding === "worktree") {
      git(checkout, "config", "core.worktree", outside.path);
    } else if (binding === "common") {
      await writeFile(
        join(checkout, ".git", "commondir"),
        `${join(outside.path, ".git")}\n`,
      );
    } else {
      await rm(join(checkout, ".git", "objects"), {
        recursive: true,
        force: true,
      });
      await symlink(
        join(outside.path, ".git", "objects"),
        join(checkout, ".git", "objects"),
        "junction",
      );
    }
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(git(outside.path, "rev-parse", "HEAD")).toBe(originalHead);
    expect(
      await readFile(join(outside.path, "retained-marker.txt"), "utf8"),
    ).toBe(originalFiles);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

(process.platform === "win32" ? test : test.skip)(
  "retained Git bindings reject a Windows recovery parent junction before checkout writes",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "junction-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const externalParent = join(paths.root, "other-recovery-parent");
    await mkdir(externalParent);
    const externalCheckout = join(externalParent, "attempt-2");
    git(paths.root, "clone", "--quiet", source.path, externalCheckout);
    const runs = mock(
      async (
        _checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", externalCheckout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    await rename(externalCheckout, join(externalParent, "retained-attempt"));
    const lexicalParent = join(paths.output, "recovery-checkouts", "repo");
    await rm(lexicalParent, { recursive: true, force: true });
    await symlink(externalParent, lexicalParent, "junction");
    await expect(runMultiscan(campaign)).rejects.toThrow();
    expect(
      await lstat(externalCheckout).then(
        () => true,
        () => false,
      ),
    ).toBe(false);
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const entry of ["config", "FETCH_HEAD"] as const) {
  test(`metadata recovery refuses external ${entry} write destinations`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "metadata-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const outside = await repository(paths.root, "other-metadata-repository");
    git(outside.path, "config", "core.filemode", "false");
    const destination = join(outside.path, ".git", entry);
    if (entry === "FETCH_HEAD")
      await writeFile(destination, "Preserve this other owned metadata.\n");
    const bytes = await readFile(destination);
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    await rm(join(checkout, ".git", entry), { force: true });
    await symlink(destination, join(checkout, ".git", entry));
    let failed = false;
    try {
      await runMultiscan(campaign);
    } catch {
      failed = true;
    }
    expect(await readFile(destination)).toEqual(bytes);
    expect(failed).toBe(true);
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

for (const partial of [false, true]) {
  test(`metadata recovery restores an interrupted repository with absent HEAD=${partial}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "partial-metadata-source");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs));
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const checkout = join(paths.output, "checkouts", "repo");
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    if (partial) await rm(join(checkout, ".git", "HEAD"));
    await writeFile(
      join(checkout, "retained.txt"),
      "Preserve interrupted data.\n",
    );
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  });
}

testPosix(
  "metadata recovery preserves explicitly configured campaign-local Python",
  async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "campaign-local-python-source");
    const interpreter = join(paths.output, "tools", "bin", "python");
    await mkdir(dirname(interpreter), { recursive: true });
    await writeFile(
      interpreter,
      `#!/usr/bin/env node\nconst {spawnSync} = require("node:child_process");\nconst result = spawnSync(${JSON.stringify(PYTHON)}, process.argv.slice(2), {stdio: "inherit"});\nif (result.error) throw result.error;\nprocess.exit(result.status ?? 1);\n`,
      { mode: 0o700 },
    );
    await writeFile(
      paths.input,
      `id,repository,revision\nrepo,${source.path},${source.revision}\n`,
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => {
        const selected = await runtime.resolvePluginPythonCommand({
          configuredPath: interpreter,
          protectedRoot: checkout,
          environment: runtime.pluginHelperEnvironment(process.env),
        });
        expect(selected.executable).toBe(interpreter);
        return completedScan(settings.outputDir!, "complete", checkout);
      },
    );
    const campaign = options(paths, client(runs), {
      config: { pythonPath: interpreter },
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(runs).toHaveBeenCalledTimes(1);
  },
);

for (const modified of [false, true]) {
  test(`preserved recovery data retains unrelated tracked modifications=${modified}`, async () => {
    const paths = await fixture();
    const source = await repository(paths.root, "preserved-tracked-source");
    await writeFile(
      join(source.path, "README.md"),
      "Original tracked notes.\n",
    );
    git(source.path, "add", ".");
    git(
      source.path,
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Tracked notes",
    );
    source.revision = git(source.path, "rev-parse", "HEAD");
    await writeFile(
      paths.input,
      `id,repository,revision,scope\nrepo,${source.path},${source.revision},src\n`,
    );
    await runMultiscan(
      options(paths, client(rejecting("Interrupted")), { maxAttempts: 1 }),
    );
    const runs = mock(
      async (
        checkout: string,
        settings: Parameters<SecurityClient["run"]>[1] = {},
      ) => completedScan(settings.outputDir!, "complete", checkout),
    );
    const campaign = options(paths, client(runs), {
      recoverScan: async () => undefined,
    });
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 0,
    });
    const checkout = join(
      paths.output,
      "recovery-checkouts",
      "repo",
      "attempt-2",
    );
    git(paths.root, "clone", "--quiet", source.path, checkout);
    await rm(join(checkout, "src"), { recursive: true });
    const notes = modified
      ? "Preserve interrupted tracked notes.\n"
      : "Original tracked notes.\n";
    if (modified) await writeFile(join(checkout, "README.md"), notes);
    await writeFile(
      join(checkout, "retained.txt"),
      "Preserve untracked recovery data.\n",
    );
    expect(await runMultiscan(campaign)).toMatchObject({
      completed: 1,
      skipped: 1,
    });
    expect(await readFile(join(checkout, "README.md"), "utf8")).toBe(notes);
    expect(await readFile(join(checkout, "retained.txt"), "utf8")).toBe(
      "Preserve untracked recovery data.\n",
    );
    expect(await readFile(join(checkout, "src", "app.ts"), "utf8")).toBe(
      await readFile(join(source.path, "src", "app.ts"), "utf8"),
    );
    expect(runs).toHaveBeenCalledTimes(1);
  });
}
