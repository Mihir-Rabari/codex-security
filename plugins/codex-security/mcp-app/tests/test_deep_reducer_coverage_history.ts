import assert from "node:assert/strict";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";
import { workerDraft, scanId } from "./scan-draft-fixture.ts";

const source = fileURLToPath(new URL("../src", import.meta.url));
const { recordCodexSecurityWorkerScanDraft, parsePersistedScanDraft } =
  await importSource(path.join(source, "artifact-scan-draft.ts"));
const { readDeepReductionSources, recordCodexSecurityDeepReduction } =
  await importSource(path.join(source, "artifact-deep-reducer.ts"));
const { validateDiscoveryArtifacts } = await importSource(
  path.join(source, "deep-scan/artifact-validation.ts"),
);
const { archiveDirectory } = await importSource(
  path.join(source, "deep-scan/artifacts.ts"),
);

async function fixture() {
  const root = await temporaryDirectory("deep-reducer-coverage-history-", true);
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/workers/discovery-0001",
  );
  const output = path.join(workerRoot, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  const reducerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/dedup/dedup-0001/output",
  );
  await mkdir(reducerRoot, { recursive: true });
  const workerContext = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "worker",
  };
  const context = {
    root: reducerRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      persistSourceCoverage: true,
      claimedWorkers: [{ id: "synthetic-worker", attempt: 2, resultPath }],
    },
  };
  return {
    root,
    scanRoot,
    workerRoot,
    output,
    resultPath,
    reducerRoot,
    workerContext,
    context,
  };
}

for (const close of [false, true]) {
  test(`accepted worker ${close ? "closure" : "pending control"} survives actual reducer publication`, async () => {
    const f = await fixture();
    try {
      const pending = {
        id: "review",
        reason: "Synthetic review still needs evidence.",
      };
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [pending],
          },
        }),
      );
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: close ? "complete" : "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: close ? [] : [pending],
            ...(close
              ? {
                  resolvedDeferred: [
                    { id: "review", reason: "Synthetic review completed." },
                  ],
                }
              : {}),
          },
        }),
      );
      const original = await readFile(f.resultPath);
      const accepted = parsePersistedScanDraft(JSON.parse(original.toString()));
      if (close) assert.equal(accepted.coverage.resolvedDeferred.length, 1);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      await recordCodexSecurityDeepReduction(f.context, {
        scanId,
        complete: true,
        findings: [],
      });
      const persisted = JSON.parse(
        await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
      );
      parsePersistedScanDraft({
        scanId,
        complete: true,
        findings: [],
        coverage: persisted.sourceCoverage,
      });
      if (close) {
        assert.equal(persisted.sourceCoverage.resolvedDeferred?.length, 1);
        assert.equal(
          persisted.sourceCoverage.resolvedDeferred[0].reason,
          "Synthetic review completed.",
        );
        assert.equal(persisted.sourceCoverage.deferred.length, 0);
      } else {
        assert.equal(persisted.sourceCoverage.deferred.length, 1);
        assert.equal(persisted.sourceCoverage.resolvedDeferred?.length ?? 0, 0);
      }
      assert.deepEqual(await readFile(f.resultPath), original);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const direct of [false, true]) {
  test(`${direct ? "accepted direct-file" : "worker recording control"} retry retains archived-only observations`, async () => {
    const f = await fixture();
    try {
      await recordCodexSecurityWorkerScanDraft(
        f.workerContext,
        workerDraft([], {
          complete: false,
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                id: "saved-surface",
                label: "Synthetic archived-only surface",
                disposition: "needs_follow_up",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [
              {
                pattern: "synthetic-excluded/**",
                reason: "Synthetic archived exclusion.",
              },
            ],
            deferred: [
              {
                id: "saved-task",
                reason: "Synthetic archived proof remains.",
                surfaceIds: ["saved-surface"],
              },
            ],
          },
        }),
      );
      const archive = path.join(f.workerRoot, "attempts/attempt-01");
      await archiveDirectory(f.output, archive);
      const historical = await readFile(path.join(archive, "result.json"));
      await mkdir(f.output, { recursive: true });
      const completed = workerDraft([], { complete: true });
      if (direct) await writeFile(f.resultPath, JSON.stringify(completed));
      else await recordCodexSecurityWorkerScanDraft(f.workerContext, completed);
      const current = await readFile(f.resultPath);
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const inputs = await readDeepReductionSources(f.context);
      const coverage = inputs.discoveries[0].coverage;
      assert.equal(coverage.surfaces.length, 1);
      assert.equal(coverage.explicitExclusions.length, 1);
      assert.equal(coverage.deferred.length, 1);
      for (const field of ["surfaces", "explicitExclusions", "deferred"])
        assert.equal(coverage[field][0].provenance.attempt, 1);
      assert.deepEqual(
        new Set(coverage.deferred[0].surfaceIds),
        new Set(coverage.surfaces.map((row: { id: string }) => row.id)),
      );
      assert.deepEqual(await readFile(f.resultPath), current);
      assert.deepEqual(
        await readFile(path.join(archive, "result.json")),
        historical,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("one worker closure retains another worker's same-named pending review", async () => {
  const f = await fixture();
  try {
    const pending = {
      id: "shared-review",
      reason: "Synthetic independent review remains.",
    };
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      }),
    );
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: true,
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
          resolvedDeferred: [
            {
              id: pending.id,
              reason: "Synthetic first worker review completed.",
            },
          ],
        },
      }),
    );
    const secondOutput = path.join(
      f.scanRoot,
      "artifacts/deep_discovery/workers/discovery-0002/output",
    );
    await mkdir(secondOutput, { recursive: true });
    const secondResult = path.join(secondOutput, "result.json");
    await recordCodexSecurityWorkerScanDraft(
      { ...f.workerContext, root: secondOutput },
      workerDraft([], {
        complete: true,
        coverage: {
          completeness: "partial",
          surfaces: [],
          explicitExclusions: [],
          deferred: [pending],
        },
      }),
    );
    f.context.deepReducer.claimedWorkers.push({
      id: "independent-worker",
      attempt: 1,
      resultPath: secondResult,
    });
    const originals = await Promise.all([
      readFile(f.resultPath),
      readFile(secondResult),
    ]);
    for (const result of [f.resultPath, secondResult])
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        result,
        scanId,
      );
    await recordCodexSecurityDeepReduction(f.context, {
      scanId,
      complete: true,
      findings: [],
    });
    const persisted = JSON.parse(
      await readFile(path.join(f.reducerRoot, "result.json"), "utf8"),
    );
    parsePersistedScanDraft({
      scanId,
      complete: true,
      findings: [],
      coverage: persisted.sourceCoverage,
    });
    assert.equal(persisted.sourceCoverage.resolvedDeferred?.length, 1);
    assert.equal(persisted.sourceCoverage.deferred.length, 1);
    assert.equal(
      persisted.sourceCoverage.deferred[0].provenance.workerId,
      "independent-worker",
    );
    assert.notEqual(
      persisted.sourceCoverage.resolvedDeferred[0].id,
      persisted.sourceCoverage.deferred[0].id,
    );
    assert.deepEqual(
      await Promise.all([readFile(f.resultPath), readFile(secondResult)]),
      originals,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test("accepted direct-file terminal outcome retains generic archive evidence without reopening the candidate", async () => {
  const f = await fixture();
  try {
    const candidateId = "candidate-1";
    await recordCodexSecurityWorkerScanDraft(
      f.workerContext,
      workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "candidate-surface",
              label: "Synthetic candidate proof",
              candidateId,
              disposition: "needs_follow_up",
              receiptRefs: [],
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              id: "candidate-task",
              candidateId,
              reason: "Synthetic candidate proof remains.",
              surfaceIds: ["candidate-surface"],
            },
            {
              id: "generic-task",
              reason: "Synthetic independent generic review remains.",
            },
          ],
        },
      }),
    );
    const archive = path.join(f.workerRoot, "attempts/attempt-01");
    await archiveDirectory(f.output, archive);
    const historical = await readFile(path.join(archive, "result.json"));
    await mkdir(f.output, { recursive: true });
    await writeFile(
      f.resultPath,
      JSON.stringify(
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                id: "candidate-terminal",
                label: "Synthetic candidate rejected",
                candidateId,
                disposition: "rejected",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      ),
    );
    const current = await readFile(f.resultPath);
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
    const inputs = await readDeepReductionSources(f.context);
    const coverage = inputs.discoveries[0].coverage;
    assert.equal(coverage.deferred.length, 1);
    assert.equal(
      coverage.deferred[0].reason,
      "Synthetic independent generic review remains.",
    );
    assert.equal(
      coverage.deferred.some(
        (row: { candidateId?: string }) => row.candidateId === candidateId,
      ),
      false,
    );
    assert.equal(
      coverage.surfaces.some(
        (row: { candidateId?: string; disposition: string }) =>
          row.candidateId === candidateId && row.disposition === "rejected",
      ),
      true,
    );
    assert.equal(
      coverage.surfaces.some(
        (row: { candidateId?: string; disposition: string }) =>
          row.candidateId === candidateId &&
          row.disposition === "needs_follow_up",
      ),
      false,
    );
    assert.deepEqual(await readFile(f.resultPath), current);
    assert.deepEqual(
      await readFile(path.join(archive, "result.json")),
      historical,
    );
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});
