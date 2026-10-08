import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile, unlink } from "node:fs/promises";
import { join, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { loadContract } from "../src/contract.js";
import { ScanResult } from "../src/result.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures();
afterEach(cleanup);
const sourcePlugin = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
type Row = Record<string, any>;

async function fixture(diff = false) {
  const directory = await temporaryDirectory("worker-candidate-lifecycle-");
  const modules = join(directory, "modules");
  await build({
    bundle: true,
    entryPoints: Object.fromEntries(
      Object.entries({
        context: "artifact-context",
        draft: "artifact-scan-draft",
        reducer: "artifact-deep-reducer",
        validation: "deep-scan/artifact-validation",
        artifacts: "deep-scan/artifacts",
        discovery: "artifact-discovery",
        validate: "artifact-validation-phase",
      }).map(([name, file]) => [
        name,
        join(sourcePlugin, "mcp-app/src", `${file}.ts`),
      ]),
    ),
    outdir: modules,
    outExtension: { ".js": ".mjs" },
    format: "esm",
    platform: "node",
    banner: {
      js: 'import { createRequire } from "node:module";const require = createRequire(import.meta.url);',
    },
  });
  const load = (name: string) =>
    import(pathToFileURL(join(modules, `${name}.mjs`)).href);
  const api = {
    context: await load("context"),
    draft: await load("draft"),
    reducer: await load("reducer"),
    validation: await load("validation"),
    artifacts: await load("artifacts"),
    discovery: await load("discovery"),
    validate: await load("validate"),
  };
  const repoRoot = join(directory, "repository"),
    home = join(directory, "home");
  await mkdir(repoRoot);
  await mkdir(home, { mode: 0o700 });
  await writeFile(join(repoRoot, "app.py"), "value = 1\n");
  const git = (...args: string[]) =>
    execFileSync(
      "git",
      [
        "-C",
        repoRoot,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        ...args,
      ],
      { encoding: "utf8" },
    ).trim();
  if (diff) {
    git("init", "-q");
    git("add", "app.py");
    git("commit", "-qm", "Synthetic fixture");
  }
  const workbench = async (args: string[]) =>
    JSON.parse(
      execFileSync(
        process.env["PYTHON"]?.trim() || "python3",
        [join(PLUGIN_ROOT, "scripts/workbench_db.py"), ...args],
        {
          encoding: "utf8",
          env: {
            ...process.env,
            CODEX_HOME: home,
            CODEX_SECURITY_STATE_DIR: join(directory, "state"),
          },
        },
      ),
    );
  const { scan } = await workbench([
    diff ? "start-prompt-only-scan" : "start-headless-standard-scan",
    "--thread-id",
    "synthetic-worker-lifecycle",
    "--target-path",
    repoRoot,
    "--scope",
    ".",
    "--scan-root",
    join(directory, "scans"),
    ...(diff
      ? [
          "--mode",
          "diff",
          "--diff-target-kind",
          "commit",
          "--diff-head-revision",
          git("rev-parse", "HEAD"),
        ]
      : []),
  ]);
  const parent = await api.context.createScanArtifactContext(
    scan.scanId,
    workbench,
    { requireRunning: true, pluginRoot: PLUGIN_ROOT },
  );
  const draft = (
    coverage: Row = {},
    findings: Row[] = [],
    complete = true,
  ) => ({
    scanId: scan.scanId,
    complete,
    findings,
    coverage: {
      completeness: "partial",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
      ...coverage,
    },
  });
  const checkpointBytes = new Map<string, Buffer>();
  const remember = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const file = join(directory, entry.name);
      if (entry.isDirectory()) await remember(file);
      else if (
        file.split(sep).includes("checkpoints") ||
        entry.name === "result.json"
      )
        checkpointBytes.set(file, await readFile(file));
    }
  };
  const unchanged = async () => {
    for (const [file, bytes] of checkpointBytes)
      expect((await readFile(file)).equals(bytes)).toBe(true);
  };
  const json = async (file: string) => JSON.parse(await readFile(file, "utf8"));
  const publish = (input: Row) =>
    api.draft.recordCodexSecurityScanDraftViaWorkbench(
      parent,
      { ...input, handoffClaimToken: parent.handoffClaimToken },
      workbench,
    );
  const complete = async () => {
    await workbench([
      "complete-scan",
      "--scan-id",
      scan.scanId,
      ...(parent.handoffClaimToken
        ? ["--claim-token", parent.handoffClaimToken]
        : []),
    ]);
    const contract = await loadContract(parent.root, {
      pluginRoot: PLUGIN_ROOT,
      expectedScanId: scan.scanId,
    });
    return new ScanResult({
      ...contract,
      scanDir: parent.root,
      threadId: "synthetic-worker-lifecycle",
      turnResult: {},
    });
  };
  return {
    api,
    directory,
    repoRoot,
    scanId: scan.scanId,
    parent,
    draft,
    workbench,
    remember,
    unchanged,
    json,
    publish,
    complete,
  };
}

const finding = () => ({
  ruleId: "synthetic-review",
  title: "Synthetic finding",
  summary: "Original synthetic evidence",
  taxonomy: { category: "synthetic", cwe: [] },
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic evidence" },
  locations: [{ path: "app.py", startLine: 1 }],
  remediation: "Apply synthetic fix",
  provenance: { source: "local_plugin", candidateId: "candidate-one" },
});

for (const scenario of [
  "confirmation-inherited",
  "confirmation-fresh",
  "confirmation-pending",
  "archive-missing",
  "archive-valid",
  "archive-missing-no-finding",
  "archive-confirmed",
]) {
  test(`public worker state reaches reducer and SDK: ${scenario}`, async () => {
    const f = await fixture();
    const workerRoot = join(
      f.parent.root,
      "artifacts/deep_discovery/workers/worker-one/output",
    );
    await mkdir(workerRoot, { recursive: true });
    const context = {
      root: workerRoot,
      repoRoot: f.repoRoot,
      scanId: f.scanId,
      layout: "worker",
      scope: ".",
    };
    const write = (input: Row) =>
      f.api.draft.recordCodexSecurityWorkerScanDraft(context, input);
    if (scenario.startsWith("confirmation")) {
      await write(f.draft({ completeness: "complete" }, [finding()]));
      const pending = {
        id: "reopened-gap",
        candidateId: "candidate-one",
        reason: "Additional validation required.",
      };
      await write(f.draft({ deferred: [pending] }));
      const saved = (await f.json(join(workerRoot, "result.json"))).findings[0];
      expect(saved.provenance.candidateReopened).toBe(true);
      if (scenario === "confirmation-fresh")
        delete saved.provenance.candidateReopened;
      saved.summary = "Confirmed with additional synthetic evidence.";
      await write(
        f.draft(
          {
            completeness:
              scenario === "confirmation-pending" ? "partial" : "complete",
            deferred: scenario === "confirmation-pending" ? [pending] : [],
          },
          [saved],
        ),
      );
    } else {
      if (scenario !== "archive-missing-no-finding")
        await write(f.draft({}, [finding()], false));
      await mkdir(join(workerRoot, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(workerRoot, "artifacts/proof/decision.txt"),
        "Synthetic decision evidence.\n",
      );
      await write(
        f.draft(
          {
            surfaces: [
              {
                id: "decision",
                candidateId: "candidate-one",
                label: "Reviewed candidate",
                disposition: "rejected",
                receiptRefs: ["artifacts/proof/decision.txt"],
              },
            ],
          },
          [],
          false,
        ),
      );
      const archive = join(workerRoot, "../attempts/attempt-01");
      await f.api.artifacts.archiveDirectory(workerRoot, archive);
      if (scenario !== "archive-valid")
        await unlink(join(archive, "artifacts/proof/decision.txt"));
      await f.remember(archive);
      await write(
        f.draft(
          { completeness: "complete" },
          scenario === "archive-confirmed"
            ? [
                {
                  ...finding(),
                  summary: "Newly confirmed after resumed review.",
                },
              ]
            : [],
        ),
      );
    }
    await f.remember(workerRoot);
    const validated = await f.api.validation.validateDiscoveryArtifacts(
      { workersRoot: workerRoot },
      join(workerRoot, "result.json"),
      f.scanId,
    );
    expect(validated).toBeDefined();
    const reducerRoot = join(
      f.parent.root,
      "artifacts/deep_discovery/dedup/reducer/output",
    );
    await mkdir(reducerRoot, { recursive: true });
    const contextReducer = {
      root: reducerRoot,
      repoRoot: f.repoRoot,
      scanId: f.scanId,
      layout: "reducer",
      deepReducer: {
        scanRoot: f.parent.root,
        claimedWorkers: [
          { id: "worker-one", resultPath: join(workerRoot, "result.json") },
        ],
      },
    };
    const input =
      await f.api.reducer.getCodexSecurityDeepReducerInputs(contextReducer);
    const expectedPending =
      scenario === "confirmation-pending" ||
      scenario === "archive-missing" ||
      scenario === "archive-missing-no-finding";
    const expectedFindings =
      scenario.startsWith("confirmation") || scenario === "archive-confirmed"
        ? 1
        : 0;
    for (let attempt = 0; attempt < 2; attempt++) {
      await f.api.reducer.recordCodexSecurityDeepReduction(contextReducer, {
        scanId: f.scanId,
        findings: input.discoveries[0].result.findings,
      });
      const result = await f.json(join(reducerRoot, "result.json"));
      expect(result.findings.length).toBe(expectedFindings);
      expect((result.unresolvedCandidates ?? []).length).toBe(
        Number(expectedPending),
      );
    }
    const result = await f.json(join(reducerRoot, "result.json"));
    await f.publish(f.api.validation.deepReductionScanDraft(result));
    await f.workbench([
      "prepare-scan-completion",
      "--scan-id",
      f.scanId,
      "--claim-token",
      f.parent.handoffClaimToken,
    ]);
    const sdk = await f.complete();
    expect(sdk.findings.findings.length).toBe(expectedFindings);
    expect(sdk.unresolvedCandidates.length).toBe(Number(expectedPending));
    if (scenario === "archive-missing")
      expect(JSON.stringify(sdk.unresolvedCandidates)).toContain(
        "Original synthetic evidence",
      );
    if (scenario === "confirmation-inherited")
      expect(
        sdk.findings.findings[0]!.provenance["candidateReopened"],
      ).not.toBe(true);
    await f.unchanged();
  });
}

for (const decision of ["pending", "suppressed", "not_applicable"]) {
  for (const resolution of ["none", "receipt", "validation"]) {
    const replacement = resolution === "receipt";
    test(`public draft after prepared receipt recovery retains current decision: ${decision}, resolution=${resolution}`, async () => {
      const f = await fixture(true);
      const discovery = join(f.parent.root, "artifacts/02_discovery");
      await mkdir(discovery, { recursive: true });
      await writeFile(join(discovery, "in_scope_files.txt"), "app.py\n");
      await f.api.discovery.recordCodexSecurityDiscoveryCandidates(
        {
          candidates: [
            {
              cwe_ids: [],
              locations: [
                {
                  path: "app.py",
                  start_line: 1,
                  end_line: 1,
                  role: "evidence",
                },
              ],
              summary: "Synthetic review candidate",
              evidence: "Synthetic evidence",
            },
          ],
        },
        f.parent,
      );
      const candidateId = (
        await f.api.discovery.listCodexSecurityCandidates({}, f.parent)
      ).rows[0].candidate_id;
      await f.publish(
        f.draft(
          {
            deferred: [
              {
                id: "authored-gap",
                candidateId,
                reason: "Original authored proof gap.",
              },
            ],
          },
          [],
          false,
        ),
      );
      if (decision !== "pending")
        await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
          validations: [
            {
              candidateId,
              validation: {
                disposition: decision,
                method: "Static inspection",
                confidence: "high",
                confidence_rationale: "Synthetic evidence",
                rubric: "Synthetic criterion",
                evidence: "Candidate dismissed.",
                counterevidence_or_proof_gap:
                  "Independent terminal validation.",
                remaining_uncertainty: "",
              },
            },
          ],
        });
      const ref = "artifacts/proof/decision.txt";
      await mkdir(join(f.parent.root, "artifacts/proof"), { recursive: true });
      await writeFile(
        join(f.parent.root, ref),
        "Synthetic decision evidence.\n",
      );
      const surface = {
        id: "authored-decision",
        candidateId,
        label: "Authored candidate review",
        disposition: "rejected",
        notes: "Authored decision with receipt.",
        receiptRefs: [ref],
      };
      await f.publish(
        f.draft({ completeness: "complete", surfaces: [surface] }),
      );
      await unlink(join(f.parent.root, ref));
      await f.remember(join(f.parent.root, "checkpoints"));
      await f.workbench(["prepare-scan-completion", "--scan-id", f.scanId]);
      expect(
        (await f.json(join(f.parent.root, "coverage.json"))).deferred.length,
      ).toBeGreaterThan(0);
      if (resolution === "validation")
        await f.api.validate.recordCodexSecurityCandidateValidations(f.parent, {
          validations: [
            {
              candidateId,
              validation: {
                disposition: decision === "pending" ? "suppressed" : decision,
                method: "Static inspection",
                confidence: "high",
                confidence_rationale: "New synthetic evidence",
                rubric: "Synthetic criterion",
                evidence: "New independent validation dismissed the candidate.",
                counterevidence_or_proof_gap: "Newly verified proof.",
                remaining_uncertainty: "",
              },
            },
          ],
        });
      const replaced = "artifacts/proof/replacement.txt";
      if (replacement)
        await writeFile(
          join(f.parent.root, replaced),
          "New validation evidence.\n",
        );
      await f.publish(
        f.draft({
          completeness: "complete",
          surfaces: replacement
            ? [{ ...surface, receiptRefs: [replaced] }]
            : [],
        }),
      );
      const sdk = await f.complete();
      expect(sdk.unresolvedCandidates.length).toBe(
        Number(resolution === "none"),
      );
      expect(
        sdk.coverage.surfaces.some(
          (row) => row.disposition === "needs_follow_up",
        ),
      ).toBe(resolution === "none");
      await f.unchanged();
    });
  }
}
