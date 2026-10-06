import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { publishCoverageFixture } from "./deep_scan_coverage_fixture.mjs";

for (const resume of [false, true]) {
  for (const stopAfterDraft of [false, true]) {
    test(`archived receipt survives ${resume ? "reconstruction" : "live retry"} and ${stopAfterDraft ? "recovery" : "completion"}`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "retry-coverage-"));
      try {
        await publishCoverageFixture(root, "complete", {
          receiptRetry: true,
          stopAfterDraft,
          resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

const { readDeepReductionSources } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const { recordCodexSecurityWorkerScanDraft } = await (
  await import("./import-module.ts")
).importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { workerDraft, scanId } = await import("./scan-draft-fixture.ts");

for (const history of ["valid", "unreadable", "mixed"]) {
  const malformedHistory = history !== "valid";
  const readableHistory = history !== "unreadable";
  test(`accepted retry coverage preserves available history (${history})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-origin-"));
    try {
      const workerRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
      );
      const output = path.join(workerRoot, "output");
      const resultPath = path.join(output, "result.json");
      const archivePrefix =
        "artifacts/deep_discovery/workers/discovery-0001/attempts/attempt-01/";
      const descriptions = {
        workerId: "unrelated",
        attempt: 99,
        description: "Original review.",
      };
      const retained = {
        completeness: "partial",
        surfaces: [
          {
            id: "prior",
            label: "Prior review",
            disposition: "needs_follow_up",
            receiptRefs: ["artifacts/prior.txt"],
            provenance: descriptions,
          },
        ],
        explicitExclusions: [
          {
            pattern: "vendor/",
            reason: "External sources.",
            provenance: descriptions,
          },
        ],
        deferred: [
          {
            id: "pending",
            reason: "Review remains.",
            surfaceIds: ["prior"],
            provenance: descriptions,
          },
        ],
        openQuestions: ["Retained question."],
      };
      const carried = structuredClone(retained);
      carried.surfaces[0].receiptRefs = [archivePrefix + "artifacts/prior.txt"];
      const current = structuredClone(carried);
      current.surfaces.push({
        id: "same-id",
        label: "Current review",
        disposition: "no_issue_found",
        receiptRefs: [],
      });
      const files = new Map();
      const save = async (file, value) => {
        await mkdir(path.dirname(file), { recursive: true });
        const bytes = JSON.stringify(value);
        await writeFile(file, bytes);
        files.set(file, bytes);
      };
      await save(
        resultPath,
        workerDraft([], { complete: true, coverage: current }),
      );
      if (malformedHistory) {
        const broken = path.join(
          workerRoot,
          "attempts",
          "attempt-02",
          "checkpoints",
          "broken.json",
        );
        await mkdir(path.dirname(broken), { recursive: true });
        await writeFile(broken, "{");
        files.set(broken, "{");
      }
      if (readableHistory) {
        const old = structuredClone(retained);
        old.surfaces.push({
          id: "same-id",
          label: "Previous review",
          disposition: "no_issue_found",
          receiptRefs: [],
        });
        await save(
          path.join(workerRoot, "attempts", "attempt-01", "result.json"),
          workerDraft([], { complete: false, coverage: old }),
        );
        await save(
          path.join(workerRoot, "attempts", "attempt-02", "result.json"),
          workerDraft([], { complete: false, coverage: carried }),
        );
      }
      const sources = await readDeepReductionSources({
        root: path.join(
          root,
          "artifacts",
          "deep_discovery",
          "dedup",
          "dedup-0001",
          "output",
        ),
        repoRoot: root,
        scanId,
        layout: "reducer",
        deepReducer: {
          scanRoot: root,
          claimedWorkers: [{ id: "worker", attempt: 3, resultPath }],
        },
      });
      const coverage = sources.discoveries[0].coverage;
      if (readableHistory) {
        assert.deepEqual(
          coverage.reviews.map((review) => review.attempt).sort(),
          [1, 3],
        );
        for (const field of [
          "surfaces",
          "explicitExclusions",
          "deferred",
          "openQuestions",
        ])
          assert.equal(coverage[field][0].provenance.attempt, 1, field);
        assert.equal(coverage.surfaces[1].provenance.attempt, 3);
        assert.deepEqual(coverage.deferred[0].surfaceIds, [
          coverage.surfaces[0].id,
        ]);
        assert.equal(coverage.surfaces[0].provenance.workerId, "worker");
      }
      assert.equal(coverage.surfaces.length, 2);
      if (malformedHistory)
        await assert.rejects(
          recordCodexSecurityWorkerScanDraft(
            { root: output, repoRoot: root, scanId, layout: "worker" },
            workerDraft([], { complete: true, coverage: current }),
          ),
          /archived scan checkpoint: stored JSON is malformed/,
        );
      for (const [file, bytes] of files)
        assert.equal(await readFile(file, "utf8"), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
