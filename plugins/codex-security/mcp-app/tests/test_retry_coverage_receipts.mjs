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

for (const history of [
  "valid",
  "unreadable",
  "mixed",
  "malformed-head",
  "missing-selected",
  "malformed-selected",
  "invalid-head",
  "invalid-selected",
  "wrong-scan-selected",
  "wrong-scan-result",
]) {
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
        const attempt = path.join(workerRoot, "attempts", "attempt-02");
        const checkpoint = "a".repeat(64) + ".json";
        if (history === "malformed-head") {
          await mkdir(attempt, { recursive: true });
          const headPath = path.join(attempt, "checkpoint-head.json");
          await writeFile(headPath, "{");
          files.set(headPath, "{");
        } else if (history === "invalid-head") {
          await save(path.join(attempt, "checkpoint-head.json"), {
            checkpoint: "../unrelated.json",
          });
        } else if (history.endsWith("selected")) {
          await save(path.join(attempt, "checkpoint-head.json"), {
            checkpoint,
          });
          if (history === "malformed-selected") {
            const selected = path.join(attempt, "checkpoints", checkpoint);
            await mkdir(path.dirname(selected), { recursive: true });
            await writeFile(selected, "{");
            files.set(selected, "{");
          } else if (
            history === "invalid-selected" ||
            history === "wrong-scan-selected"
          ) {
            await save(
              path.join(attempt, "checkpoints", checkpoint),
              history === "invalid-selected"
                ? { scanId }
                : {
                    ...workerDraft([], { complete: false, coverage: retained }),
                    scanId: "22222222-2222-4222-8222-222222222222",
                  },
            );
          }
        } else if (history !== "wrong-scan-result") {
          const broken = path.join(attempt, "checkpoints", "broken.json");
          await mkdir(path.dirname(broken), { recursive: true });
          await writeFile(broken, "{");
          files.set(broken, "{");
        }
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
      if (history === "wrong-scan-result") {
        await save(
          path.join(workerRoot, "attempts", "attempt-02", "result.json"),
          {
            ...workerDraft([], { complete: false, coverage: carried }),
            scanId: "22222222-2222-4222-8222-222222222222",
          },
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
          history === "invalid-head"
            ? /archived checkpoint head is invalid/
            : history === "wrong-scan-selected" ||
                history === "wrong-scan-result"
              ? /scanId does not match the authoritative workbench scan/
              : history === "invalid-selected"
                ? /Invalid input: expected array, received undefined/
                : /archived scan checkpoint.*(?:stored JSON is malformed|requested artifact is unavailable)/,
        );
      for (const [file, bytes] of files)
        assert.equal(await readFile(file, "utf8"), bytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

for (const workflowVersion of ["deep-scan-mcp/v1", "deep-security-scan/v2"]) {
  for (const resume of [false, true]) {
    test(`workbench version reaches reducer persistence (${workflowVersion}, resume: ${resume})`, async () => {
      const root = await mkdtemp(path.join(tmpdir(), "coverage-version-"));
      try {
        await publishCoverageFixture(root, "partial", {
          workflowVersion,
          resume,
          continueAfterResume: resume,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    });
  }
}

for (const omitted of ["none", "receipts", "ids-and-receipts"]) {
  test(`direct-file retry attribution follows persisted normalization (${omitted})`, async () => {
    const root = await mkdtemp(path.join(tmpdir(), "retry-normalization-"));
    try {
      const workerRoot = path.join(
        root,
        "artifacts",
        "deep_discovery",
        "workers",
        "discovery-0001",
      );
      const output = path.join(workerRoot, "output");
      const archive = path.join(
        workerRoot,
        "attempts",
        "attempt-01",
        "result.json",
      );
      await mkdir(path.dirname(archive), { recursive: true });
      await mkdir(output);
      const missingIds = omitted === "ids-and-receipts";
      const prior = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              ...(missingIds ? {} : { id: "prior" }),
              label: "Prior review",
              disposition: "needs_follow_up",
              ...(omitted === "none" ? { receiptRefs: [] } : {}),
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              ...(missingIds ? {} : { id: "pending", surfaceIds: ["prior"] }),
              reason: "Prior review remains.",
            },
          ],
        },
      });
      const archivedBytes = JSON.stringify(prior);
      await writeFile(archive, archivedBytes);
      await recordCodexSecurityWorkerScanDraft(
        { root: output, repoRoot: root, scanId, layout: "worker" },
        workerDraft([], {
          complete: true,
          coverage: {
            completeness: "complete",
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition: "no_issue_found",
                receiptRefs: [],
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      const resultPath = path.join(output, "result.json");
      const acceptedBytes = await readFile(resultPath, "utf8");
      const accepted = JSON.parse(acceptedBytes);
      assert.equal(accepted.coverage.surfaces.length, 2);
      assert.equal(typeof accepted.coverage.surfaces[1].id, "string");
      assert.deepEqual(accepted.coverage.surfaces[1].receiptRefs, []);
      assert.equal(typeof accepted.coverage.deferred[0].id, "string");
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
          claimedWorkers: [{ id: "discovery-0001", attempt: 2, resultPath }],
        },
      });
      const coverage = sources.discoveries[0].coverage;
      assert.deepEqual(
        coverage.surfaces.map((row) => row.provenance.attempt),
        [2, 1],
      );
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.deepEqual(
        coverage.reviews.map((row) => row.attempt).sort(),
        [1, 2],
      );
      if (!missingIds)
        assert.deepEqual(coverage.deferred[0].surfaceIds, [
          coverage.surfaces[1].id,
        ]);
      assert.equal(await readFile(archive, "utf8"), archivedBytes);
      assert.equal(await readFile(resultPath, "utf8"), acceptedBytes);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}
