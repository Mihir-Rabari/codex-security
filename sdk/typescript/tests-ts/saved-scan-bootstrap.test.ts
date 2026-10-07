import { execFileSync, spawn, spawnSync } from "node:child_process";
import { Database } from "bun:sqlite";
import { once } from "node:events";
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
    `{{${f.first.scanId}}}`,
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
  await expect(
    savedScanWorkbench(f.first.scanId + "}".repeat(100_000) + "x", options),
  ).rejects.toThrow("not found");
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
    await mkdir(join(caller, ".git"));
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

test.skipIf(process.platform === "win32")(
  "default CLI protects saved targets before Python lookup",
  async () => {
    const f = await fixture();
    await deduplicateScanInternal(
      f.first.scanId,
      { workflowId: "synthetic-workflow", embedding: f.embedding },
      { environment: f.environment, reviewer: f.reviewer },
    );
    const python = join(f.repository, "python3");
    const marker = join(f.root, "cli-probed");
    await writeFile(
      python,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
    );
    await chmod(python, 0o700);
    const source = new URL("../src/cli.ts", import.meta.url).href;
    for (const args of [
      ["dedupe", "--scan", f.first.scanId],
      ["dedupe", "--scan", f.first.scanId.slice(0, 8)],
      ["dedupe", "--workflow-id", "synthetic-workflow"],
    ]) {
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          `const {main} = await import(${JSON.stringify(source)}); process.exitCode = await main(${JSON.stringify(args)});`,
        ],
        {
          cwd: f.root,
          env: { ...f.environment, PYTHON: python, TEST_PYTHON_PROBE: marker },
          encoding: "utf8",
        },
      );
      expect(result.status).toBe(2);
      expect(result.stderr).toContain(
        "PYTHON interpreter is unavailable or unusable",
      );
      expect(existsSync(marker)).toBe(false);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "an unrelated working directory does not exclude trusted Python",
  async () => {
    const f = await fixture();
    const source = new URL("../src/runtime.ts", import.meta.url).href;
    for (const cwd of ["/", f.root]) {
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          `const {resolvePluginPython} = await import(${JSON.stringify(source)}); await resolvePluginPython({environment: process.env, protectedRoot: ${JSON.stringify(f.repository)}});`,
        ],
        {
          cwd,
          env: { ...f.environment, PYTHON: f.python },
          encoding: "utf8",
        },
      );
      expect(result.status).toBe(0);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "Python discovery protects the enclosing checkout of a nested target",
  async () => {
    const f = await fixture();
    const target = join(f.repository, "component");
    await mkdir(target);
    await mkdir(join(f.repository, ".git"));
    const python = join(f.repository, "python3");
    const marker = join(f.root, "enclosing-checkout-probed");
    await writeFile(
      python,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
    );
    await chmod(python, 0o700);
    await expect(
      resolvePluginPython({
        environment: {
          ...f.environment,
          PYTHON: python,
          TEST_PYTHON_PROBE: marker,
        },
        protectedRoot: target,
      }),
    ).rejects.toThrow("PYTHON interpreter is unavailable or unusable");
    expect(existsSync(marker)).toBe(false);
  },
);

for (const selector of ["latest", "workflow"] as const) {
  test(`bootstrap ${selector} ignores unrelated history enclosing trusted Python`, async () => {
    const f = await fixture(true);
    const workflowId = "scoped-bootstrap";
    await deduplicateScanInternal(
      f.first.scanId,
      { workflowId, embedding: f.embedding },
      { environment: f.environment, reviewer: f.reviewer },
    );
    const db = new Database(
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    );
    try {
      db.query("INSERT INTO security_targets VALUES (?, ?, ?, ?, ?)").run(
        "unrelated-target",
        dirname(f.python),
        "Unrelated synthetic target",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
      );
      db.query(
        "UPDATE scans SET target_path = ?, target_id = ? WHERE id = ?",
      ).run(dirname(f.python), "unrelated-target", f.second.scanId);
    } finally {
      db.close();
    }
    const workbench = await savedScanWorkbench(
      selector === "latest" ? "latest" : { workflowId },
      {
        environment: { ...f.environment, PYTHON: f.python },
        pluginRoot: PLUGIN_ROOT,
        currentDirectory: f.repository,
      },
    );
    if (selector === "latest") {
      expect(
        (
          await resolveCompletedScan("latest", {
            currentDirectory: () => f.repository,
            runWorkbench: workbench,
          })
        ).scanId,
      ).toBe(f.first.scanId);
    } else {
      const result = await workbench(
        ["finding-workflow"],
        JSON.stringify({ id: workflowId, action: "get" }),
      );
      expect((result["workflow"] as { scanId: string }).scanId).toBe(
        f.first.scanId,
      );
    }
  });
}

test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "workflow bootstrap ignores inaccessible unrelated history",
  async () => {
    const f = await fixture();
    const workflowId = "scoped-bootstrap";
    await deduplicateScanInternal(
      f.first.scanId,
      { workflowId, embedding: f.embedding },
      { environment: f.environment, reviewer: f.reviewer },
    );
    const inaccessible = join(f.root, "inaccessible-history");
    await mkdir(inaccessible);
    const db = new Database(
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    );
    try {
      db.query(
        "UPDATE scans SET status = 'failed', target_path = ?, target_id = NULL WHERE id = ?",
      ).run(join(inaccessible, "checkout"), f.second.scanId);
    } finally {
      db.close();
    }
    await chmod(inaccessible, 0);
    try {
      const workbench = await savedScanWorkbench(
        { workflowId },
        {
          environment: { ...f.environment, PYTHON: f.python },
          pluginRoot: PLUGIN_ROOT,
          currentDirectory: f.repository,
        },
      );
      const result = await workbench(
        ["finding-workflow"],
        JSON.stringify({ id: workflowId, action: "get" }),
      );
      expect((result["workflow"] as { scanId: string }).scanId).toBe(
        f.first.scanId,
      );
    } finally {
      await chmod(inaccessible, 0o700);
    }
  },
);

test.skipIf(process.platform === "win32")(
  "latest preserves origin matching without executing another checkout's Git",
  async () => {
    const f = await fixture(true);
    const clone = join(f.root, "other-clone");
    execFileSync("git", ["clone", "--quiet", f.repository, clone]);
    execFileSync("git", [
      "-C",
      f.repository,
      "remote",
      "add",
      "origin",
      "https://example.test/team/synthetic.git",
    ]);
    execFileSync("git", [
      "-C",
      clone,
      "remote",
      "set-url",
      "origin",
      "git@example.test:team/synthetic.git",
    ]);
    const executable = join(f.repository, "git");
    const marker = join(f.root, "git-probed");
    await writeFile(
      executable,
      '#!/bin/sh\nprintf probed > "$TEST_GIT_PROBE"\nprintf "not-git\\n"\n',
    );
    await chmod(executable, 0o700);
    const bootstrap = new URL("../src/saved-scan-bootstrap.ts", import.meta.url)
      .href;
    const saved = new URL("../src/saved-scan.ts", import.meta.url).href;
    const script = `const { savedScanWorkbench } = await import(${JSON.stringify(bootstrap)});
    const { resolveCompletedScan } = await import(${JSON.stringify(saved)});
    const workbench = await savedScanWorkbench("latest", { environment: process.env, pluginRoot: ${JSON.stringify(PLUGIN_ROOT)}, currentDirectory: process.cwd() });
    const scan = await resolveCompletedScan("latest", { currentDirectory: () => process.cwd(), runWorkbench: workbench });
    console.log(scan.scanId);`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: clone,
      env: {
        ...f.environment,
        PATH: f.repository + delimiter + f.environment.PATH,
        PYTHON: f.python,
        TEST_GIT_PROBE: marker,
      },
      encoding: "utf8",
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(f.second.scanId);
    expect(existsSync(marker)).toBe(false);
  },
);

test.skipIf(process.platform === "win32")(
  "legacy workflow state resolves its bound target before Python discovery",
  async () => {
    const f = await fixture();
    const state = join(f.root, "legacy-state");
    await mkdir(state);
    const db = new Database(join(state, "workbench.sqlite3"));
    try {
      db.exec(
        "CREATE TABLE scans (id TEXT PRIMARY KEY, target_path TEXT NOT NULL); CREATE TABLE finding_workflows (id TEXT PRIMARY KEY, state_json TEXT NOT NULL)",
      );
      db.query("INSERT INTO scans VALUES (?, ?)").run(
        f.first.scanId,
        f.repository,
      );
      db.query("INSERT INTO finding_workflows VALUES (?, ?)").run(
        "legacy-workflow",
        JSON.stringify({ scanId: f.first.scanId }),
      );
    } finally {
      db.close();
    }
    const executable = join(f.repository, "python3");
    const marker = join(f.root, "legacy-probed");
    await writeFile(
      executable,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
    );
    await chmod(executable, 0o700);
    const workbench = await savedScanWorkbench(
      { workflowId: "legacy-workflow" },
      {
        environment: {
          ...f.environment,
          CODEX_SECURITY_STATE_DIR: state,
          PYTHON: executable,
          TEST_PYTHON_PROBE: marker,
        },
        pluginRoot: PLUGIN_ROOT,
        currentDirectory: f.root,
      },
    );
    await expect(
      workbench(
        ["finding-workflow"],
        JSON.stringify({ id: "legacy-workflow", action: "get" }),
      ),
    ).rejects.toThrow("PYTHON interpreter is unavailable or unusable");
    expect(existsSync(marker)).toBe(false);
  },
);

for (const version of [1, 15]) {
  test(`latest upgrades schema ${version} after selecting a trusted target`, async () => {
    const f = await fixture();
    const state = join(f.root, `legacy-${version}`);
    await mkdir(state);
    const database = join(state, "workbench.sqlite3");
    const script = `
import sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_schema import MIGRATIONS
connection = sqlite3.connect(sys.argv[2])
connection.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)")
for version, name, sql in MIGRATIONS:
    if version > int(sys.argv[4]): break
    connection.executescript(sql)
    connection.execute("INSERT INTO schema_migrations VALUES (?, ?, ?)", (version, name, "2026-01-01T00:00:00Z"))
connection.execute("ATTACH DATABASE ? AS source", (sys.argv[3],))
for table in ["workspaces", "scans", "scan_progress"]:
    columns = ",".join(row[1] for row in connection.execute(f"PRAGMA main.table_info({table})"))
    connection.execute(f"INSERT INTO main.{table} ({columns}) SELECT {columns} FROM source.{table}")
connection.commit()
connection.close()
`;
    execFileSync(f.python, [
      "-I",
      "-B",
      "-c",
      script,
      join(PLUGIN_ROOT, "scripts"),
      database,
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      String(version),
    ]);
    const workbench = await savedScanWorkbench("latest", {
      environment: {
        ...f.environment,
        CODEX_SECURITY_STATE_DIR: state,
        PYTHON: f.python,
      },
      pluginRoot: PLUGIN_ROOT,
      currentDirectory: f.repository,
    });
    expect(
      (
        await resolveCompletedScan("latest", {
          currentDirectory: () => f.repository,
          runWorkbench: workbench,
        })
      ).scanId,
    ).toBe(f.second.scanId);
    const db = new Database(database, { readwrite: true, create: false });
    try {
      expect(
        (
          db
            .prepare("SELECT MAX(version) AS version FROM schema_migrations")
            .get() as { version: number }
        ).version,
      ).toBeGreaterThan(version);
      expect(db.query("SELECT id FROM security_targets").all()).toHaveLength(1);
    } finally {
      db.close();
    }
  });
}

test("latest follows progress timestamps and excludes canceled scans", async () => {
  const f = await fixture();
  const db = new Database(
    join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
  );
  try {
    db.query(
      "UPDATE scan_progress SET updated_at = '2099-01-01T00:00:00Z' WHERE scan_id = ?",
    ).run(f.first.scanId);
    async function latest() {
      const workbench = await savedScanWorkbench("latest", {
        environment: { ...f.environment, PYTHON: f.python },
        pluginRoot: PLUGIN_ROOT,
        currentDirectory: f.repository,
      });
      return (
        await resolveCompletedScan("latest", {
          currentDirectory: () => f.repository,
          runWorkbench: workbench,
        })
      ).scanId;
    }
    expect(await latest()).toBe(f.first.scanId);
    db.query(
      "UPDATE scans SET canceled_at = '2099-01-02T00:00:00Z' WHERE id = ?",
    ).run(f.first.scanId);
    expect(await latest()).toBe(f.second.scanId);
  } finally {
    db.close();
  }
});

test.skipIf(process.platform === "win32")(
  "latest never executes Git from a saved non-Git target",
  async () => {
    const f = await fixture(true);
    const other = join(f.root, "non-git-target");
    await mkdir(other);
    const marker = join(f.root, "non-git-probed");
    await writeFile(
      join(other, "git"),
      '#!/bin/sh\nprintf probed > "$TEST_GIT_PROBE"\nprintf "not-git\\n"\n',
      { mode: 0o700 },
    );
    const db = new Database(
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    );
    try {
      db.query("INSERT INTO security_targets VALUES (?, ?, ?, ?, ?)").run(
        "non-git-target",
        other,
        "Synthetic non-Git target",
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
      );
      db.query(
        "UPDATE scans SET target_path = ?, target_id = ? WHERE id = ?",
      ).run(other, "non-git-target", f.second.scanId);
    } finally {
      db.close();
    }
    const workbench = await savedScanWorkbench("latest", {
      environment: {
        ...f.environment,
        PYTHON: f.python,
        PATH: other + delimiter + f.environment.PATH,
        TEST_GIT_PROBE: marker,
      },
      pluginRoot: PLUGIN_ROOT,
      currentDirectory: f.repository,
    });
    expect(
      (
        await resolveCompletedScan("latest", {
          currentDirectory: () => f.repository,
          runWorkbench: workbench,
        })
      ).scanId,
    ).toBe(f.first.scanId);
    expect(existsSync(marker)).toBe(false);
  },
);

test.skipIf(process.platform === "win32")(
  "bootstrap protects a target committed only to the live WAL",
  async () => {
    const f = await fixture();
    const target = join(f.root, "wal-target");
    await mkdir(target);
    const executable = join(target, "python3");
    const marker = join(f.root, "wal-target-probed");
    await writeFile(
      executable,
      '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
      { mode: 0o700 },
    );
    const db = new Database(
      join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    );
    try {
      db.exec("PRAGMA wal_autocheckpoint = 0");
      db.query("UPDATE scans SET target_path = ? WHERE id = ?").run(
        target,
        f.first.scanId,
      );
      const workbench = await savedScanWorkbench(f.first.scanId, {
        environment: {
          ...f.environment,
          PYTHON: executable,
          TEST_PYTHON_PROBE: marker,
        },
        pluginRoot: PLUGIN_ROOT,
        currentDirectory: f.root,
      });
      await expect(
        workbench(["get-scan", "--scan-id", f.first.scanId]),
      ).rejects.toThrow("PYTHON interpreter is unavailable or unusable");
      expect(existsSync(marker)).toBe(false);
    } finally {
      db.close();
    }
  },
);

test("saved-scan bootstrap waits for a concurrent database writer", async () => {
  const f = await fixture();
  const writer = spawn(
    process.execPath,
    [
      "-e",
      `
    const { Database } = require("bun:sqlite");
    const database = new Database(${JSON.stringify(join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"))});
    database.exec("PRAGMA journal_mode = DELETE; BEGIN EXCLUSIVE");
    process.stdout.write("locked");
    setTimeout(() => {
      database.exec("COMMIT");
      database.close();
    }, 1000);
  `,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const closed = once(writer, "close");
  try {
    await Promise.race([
      once(writer.stdout!, "data"),
      closed.then(() => {
        throw new Error("Writer exited before acquiring its lock");
      }),
    ]);
    const workbench = await savedScanWorkbench(f.first.scanId, {
      environment: f.environment,
      currentDirectory: f.repository,
      pluginRoot: PLUGIN_ROOT,
    });
    const result = await workbench(["get-scan", "--scan-id", f.first.scanId]);
    expect((result["scan"] as { scanId: string }).scanId).toBe(f.first.scanId);
    expect((await closed)[0]).toBe(0);
  } finally {
    writer.kill();
    await closed;
  }
});

for (const source of ["PYTHON", "PATH"] as const) {
  test.skipIf(process.platform === "win32")(
    `saved missing targets still protect their enclosing checkout from ${source}`,
    async () => {
      const f = await fixture(true);
      const target = join(f.repository, "deleted-component", "nested");
      const python = join(f.repository, "python3");
      const marker = join(f.root, "missing-target-probed");
      await writeFile(
        python,
        '#!/bin/sh\nprintf probed > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
        { mode: 0o700 },
      );
      const db = new Database(
        join(f.environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      );
      try {
        db.query("UPDATE scans SET target_path = ? WHERE id = ?").run(
          target,
          f.first.scanId,
        );
      } finally {
        db.close();
      }
      const workbench = await savedScanWorkbench(f.first.scanId, {
        environment: {
          ...f.environment,
          TEST_PYTHON_PROBE: marker,
          ...(source === "PYTHON"
            ? { PYTHON: python }
            : { PATH: f.repository + delimiter + f.environment.PATH }),
        },
        pluginRoot: PLUGIN_ROOT,
        currentDirectory: f.root,
      });
      const result = workbench(["get-scan", "--scan-id", f.first.scanId]);
      if (source === "PYTHON")
        await expect(result).rejects.toThrow(
          "PYTHON interpreter is unavailable or unusable",
        );
      else {
        expect((await result)["scan"]).toMatchObject({
          scanId: f.first.scanId,
        });
        expect(workbench.environment["PYTHON"]).not.toBe(python);
      }
      expect(existsSync(marker)).toBe(false);
    },
  );
}
