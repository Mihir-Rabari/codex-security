import { execFileSync } from "node:child_process";
import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";
import { chmod, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { delimiter, dirname, join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { deduplicateScanInternal } from "../src/deduplication/scan.js";
import { savedScanWorkbench } from "../src/saved-scan-bootstrap.js";
import { resolveCompletedScan } from "../src/saved-scan.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import type { FindingEmbeddingBinding } from "../src/deduplication/local.js";
import type { Finding } from "../src/models.js";
import { screeningPairSlot } from "../src/deduplication/deduplication-reviewer.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { rejecting } from "./support/errors.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "saved-scan-bootstrap-",
);
afterEach(cleanup);

async function fixture(git = false) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(join(repository, "src"), { recursive: true });
  await writeFile(
    join(repository, "src", "extract.py"),
    "# Synthetic fixture\n",
  );
  if (git) {
    execFileSync("git", ["init", "-q", repository]);
    execFileSync("git", ["-C", repository, "add", "."]);
    execFileSync("git", [
      "-C",
      repository,
      "-c",
      "user.name=Synthetic Fixture",
      "-c",
      "user.email=fixture@example.test",
      "commit",
      "-qm",
      "Synthetic fixture",
    ]);
  }
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    CODEX_HOME: join(root, "codex"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const python = await resolvePluginPython({ environment });
  const options = { environment, python, pluginRoot: PLUGIN_ROOT };
  async function scan(name: string) {
    const scanDir = join(root, name);
    await mkdir(scanDir, { mode: 0o700 });
    const registered = await runWorkbench(options, [
      "register-cli-scan",
      "--repository",
      repository,
      "--scan-dir",
      scanDir,
      "--recipe-json",
      JSON.stringify({
        config: {},
        mode: "standard",
        repository,
        target: { kind: "repository", paths: [] },
      }),
    ]);
    const scanId = registered["scanId"] as string;
    await copyCompletedScanFixture(scanDir);
    const manifest = JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    );
    manifest.scan.id = scanId;
    manifest.scan.target.kind = git ? "git_revision" : "directory_snapshot";
    if (git)
      manifest.scan.target.revision = execFileSync(
        "git",
        ["-C", repository, "rev-parse", "HEAD"],
        { encoding: "utf8" },
      ).trim();
    delete manifest.scan.sealedAt;
    delete manifest.scan.artifacts;
    await writeFile(
      join(scanDir, "scan-manifest.json"),
      JSON.stringify(manifest),
    );
    const document = JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    );
    document.scanId = scanId;
    const finding = document.findings[0];
    finding.identity = { anchor: `synthetic-${name}` };
    finding.locations = [
      {
        path: "src/extract.py",
        startLine: 1,
        endLine: 1,
        role: "root_control",
      },
    ];
    finding.codeEvidence = [
      {
        id: "synthetic",
        label: "Synthetic evidence",
        path: "src/extract.py",
        startLine: 1,
        code: "# Synthetic fixture",
        explanation: "Fixture evidence only.",
      },
    ];
    await writeFile(join(scanDir, "findings.json"), JSON.stringify(document));
    const coverage = JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    );
    coverage.scanId = scanId;
    await writeFile(join(scanDir, "coverage.json"), JSON.stringify(coverage));
    await runWorkbench(options, ["complete-scan", "--scan-id", scanId]);
    return { scanId, scanDir };
  }
  const first = await scan("first");
  const second = await scan("second");
  const embed = mock(async (findings: readonly Finding[]) =>
    findings.map(() => ({ model: "synthetic", vector: [1, 0, 0] })),
  );
  const embedding: FindingEmbeddingBinding = {
    embedder: { embed },
    model: "synthetic",
    dimensions: 3,
    cacheNamespace: "bootstrap-test-v1",
  };
  const reviewer = {
    screen: mock(async (findings: readonly Finding[]) => ({
      decisions: Object.fromEntries(
        findings
          .slice(1)
          .map((_, i) => [
            screeningPairSlot(i),
            { decision: "SAME" as const, rationale: "Same control" },
          ]),
      ),
    })),
    reviewPair: mock(async (findings: readonly Finding[]) => ({
      decision: "SAME" as const,
      rationale: "Same control",
      canonicalFindingId: findings[0]!.findingId,
      mergedFinding: findings[0]!,
    })),
  };
  return {
    root,
    repository,
    environment,
    python,
    first,
    second,
    embedding,
    embed,
    reviewer,
  };
}

for (const source of ["PYTHON", "PATH", "linked PYTHON"] as const) {
  for (const resumed of [false, true]) {
    test.skipIf(process.platform === "win32")(
      `saved-scan dedupe never probes repository ${source} (${resumed ? "resumed" : "fresh"})`,
      async () => {
        const f = await fixture();
        const options = {
          embedding: f.embedding,
          workflowId: "bootstrap-workflow",
        };
        const dependencies = {
          environment: f.environment,
          reviewer: f.reviewer,
          fetch: rejecting("Unexpected HTTP request"),
        };
        if (resumed)
          await deduplicateScanInternal(f.first.scanId, options, dependencies);
        const executable = join(f.repository, "python3");
        const marker = join(f.root, "probed");
        await writeFile(
          executable,
          '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
        );
        await chmod(executable, 0o700);
        const linked = join(f.root, "linked-python");
        if (source === "linked PYTHON") await symlink(executable, linked);
        const environment = {
          ...f.environment,
          TEST_PYTHON_PROBE: marker,
          ...(source === "PATH"
            ? {
                PATH: [
                  f.repository,
                  dirname(f.python),
                  f.environment.PATH,
                ].join(delimiter),
              }
            : { PYTHON: source === "PYTHON" ? executable : linked }),
        };
        // The production bootstrap must run: do not inject runWorkbench here.
        const result = deduplicateScanInternal(f.first.scanId, options, {
          ...dependencies,
          environment,
        });
        if (source === "PATH")
          expect((await result).deduplicationStatus).toBe("completed");
        else {
          const error = await result.catch((error: unknown) => error);
          expect(existsSync(marker)).toBe(false);
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toContain(
            "PYTHON interpreter is unavailable or unusable",
          );
        }
        expect(existsSync(marker)).toBe(false);
      },
    );
  }
}

test("saved-scan bootstrap supports IDs, prefixes and latest and persists one duplicate group on resume", async () => {
  const f = await fixture();
  const dependencies = {
    environment: { ...f.environment, PYTHON: f.python },
    reviewer: f.reviewer,
    fetch: rejecting("Unexpected HTTP request"),
  };
  const first = await deduplicateScanInternal(
    f.first.scanId,
    { embedding: f.embedding, workflowId: "saved-scan" },
    dependencies,
  );
  expect(first.duplicateGroups).toHaveLength(1);
  expect(f.embed).toHaveBeenCalledTimes(1);
  expect(f.reviewer.reviewPair).toHaveBeenCalledTimes(1);
  const again = await deduplicateScanInternal(
    f.first.scanId.slice(0, 8).toUpperCase(),
    { embedding: f.embedding, workflowId: "saved-scan" },
    dependencies,
  );
  expect(again.duplicateGroups).toEqual(first.duplicateGroups);
  expect(f.embed).toHaveBeenCalledTimes(1);
  expect(f.reviewer.reviewPair).toHaveBeenCalledTimes(1);
  const store = new SqliteFindingsStore(dependencies.environment);
  expect(
    await store.listDedupeGroups(first.duplicateGroups[0]![0]!),
  ).toHaveLength(1);
  for (const requestedId of [
    f.first.scanId.replaceAll("-", ""),
    `{${f.first.scanId.toUpperCase()}}`,
    `urn:uuid:${f.first.scanId}`,
    "latest",
  ]) {
    const workbench = await savedScanWorkbench(requestedId, {
      ...dependencies,
      pluginRoot: PLUGIN_ROOT,
      currentDirectory: f.repository,
    });
    const scan = await resolveCompletedScan(requestedId, {
      currentDirectory: () => f.repository,
      runWorkbench: workbench,
    });
    expect(scan.scanId).toBe(
      requestedId === "latest" ? f.second.scanId : f.first.scanId,
    );
  }
});

test("bootstrap fails before Python for ambiguous, absent, malformed and changed targets and never creates a database", async () => {
  const f = await fixture();
  const options = {
    environment: {
      ...f.environment,
      PYTHON: join(f.repository, "must-not-run"),
    },
    pluginRoot: PLUGIN_ROOT,
    currentDirectory: f.root,
  };
  await expect(savedScanWorkbench("short", options)).rejects.toThrow(
    "at least eight",
  );
  await expect(savedScanWorkbench("ffffffff", options)).rejects.toThrow(
    "not found",
  );
  const missing = join(f.root, "missing-state");
  await expect(
    savedScanWorkbench(f.first.scanId, {
      ...options,
      environment: {
        ...options.environment,
        CODEX_SECURITY_STATE_DIR: missing,
      },
    }),
  ).rejects.toThrow("before Python discovery");
  expect(existsSync(missing)).toBe(false);
  const pinned = await savedScanWorkbench(f.first.scanId, {
    ...options,
    environment: { ...f.environment, PYTHON: f.python },
  });
  const db = new Database(
    join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
  );
  try {
    db.query("UPDATE scans SET id = ? WHERE id = ?").run(
      `${f.first.scanId.slice(0, 8)}-1111-4111-8111-111111111111`,
      f.second.scanId,
    );
    await expect(
      savedScanWorkbench(f.first.scanId.slice(0, 8), options),
    ).rejects.toThrow("multiple scans");
    db.query("UPDATE scans SET target_path = ? WHERE id = ?").run(
      f.root,
      f.first.scanId,
    );
    await expect(
      pinned(["get-scan", "--scan-id", f.first.scanId]),
    ).rejects.toThrow("history changed");
    db.query("UPDATE scans SET target_path = 'relative' WHERE id = ?").run(
      f.first.scanId,
    );
    await expect(savedScanWorkbench(f.first.scanId, options)).rejects.toThrow(
      "absolute repository",
    );
  } finally {
    db.close();
  }
});

test.skipIf(process.platform === "win32")(
  "latest preserves worktree matching while protecting the saved checkout before Python discovery",
  async () => {
    const f = await fixture(true);
    const worktree = join(f.root, "other-worktree");
    execFileSync(
      "git",
      ["-C", f.repository, "worktree", "add", "--detach", worktree],
      { stdio: "pipe" },
    );
    const executable = join(f.repository, "python3");
    const marker = join(f.root, "probed");
    await writeFile(
      executable,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
    );
    await chmod(executable, 0o700);
    const options = {
      environment: {
        ...f.environment,
        PYTHON: executable,
        TEST_PYTHON_PROBE: marker,
      },
      currentDirectory: worktree,
      pluginRoot: PLUGIN_ROOT,
    };
    const unsafe = await savedScanWorkbench("latest", options);
    await expect(
      resolveCompletedScan("latest", {
        currentDirectory: () => worktree,
        runWorkbench: unsafe,
      }),
    ).rejects.toThrow("PYTHON interpreter is unavailable or unusable");
    expect(existsSync(marker)).toBe(false);
    const safe = await savedScanWorkbench("latest", {
      ...options,
      environment: { ...options.environment, PYTHON: f.python },
    });
    expect(
      (
        await resolveCompletedScan("latest", {
          currentDirectory: () => worktree,
          runWorkbench: safe,
        })
      ).scanId,
    ).toBe(f.second.scanId);
  },
);

test.skipIf(process.platform === "win32")(
  "Python rediscovery keeps protecting the caller checkout when a saved target is supplied",
  async () => {
    const f = await fixture();
    const caller = join(f.root, "caller-checkout");
    await mkdir(caller);
    const python = join(caller, "python3");
    const marker = join(f.root, "caller-probed");
    await writeFile(
      python,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
    );
    await chmod(python, 0o700);
    const source = new URL("../src/runtime.ts", import.meta.url).href;
    const script = `
    const { resolvePluginPython } = await import(${JSON.stringify(source)});
    try {
      await resolvePluginPython({ environment: process.env, protectedRoot: ${JSON.stringify(f.repository)} });
      process.exitCode = 1;
    } catch (error) {
      if (!String(error).includes("PYTHON interpreter is unavailable or unusable")) throw error;
    }
  `;
    execFileSync(process.execPath, ["-e", script], {
      cwd: caller,
      env: { ...f.environment, PYTHON: python, TEST_PYTHON_PROBE: marker },
      stdio: "pipe",
    });
    expect(existsSync(marker)).toBe(false);
  },
);
