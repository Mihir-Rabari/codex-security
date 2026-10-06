import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { fixture } from "./scan-draft-recovery-fixture.ts";
import { finding, workerDraft } from "./scan-draft-fixture.ts";

for (const mode of ["standard", "diff"] as const) {
  for (const outcome of ["reported", "rejected"] as const) {
    for (const sameOwner of [false, true]) {
      for (const payload of ["candidate", "finding"] as const) {
        test(`legacy candidate coverage reconciles ${mode}/${outcome}/${payload}/${sameOwner ? "same" : "other"} owner`, async (t) => {
          const f = await fixture(t, mode);
          const candidateId = "legacy-candidate";
          const previous = {
            id: candidateId,
            sourceWorkerId: "worker-before",
            reason: "Saved candidate evidence remains available.",
            [payload]: {
              ...finding("legacy", "src/legacy.ts"),
              summary: "Saved older review evidence.",
            },
          };
          const generic = {
            id: "generic-review",
            reason: "Independent unfinished work.",
          };
          await f.write(f.draft({ deferred: [previous, generic] }));
          const current = finding("legacy", "src/legacy.ts");
          const resolved = {
            ...current,
            provenance: {
              ...current.provenance,
              candidateId,
              sourceWorkerId: sameOwner ? "worker-before" : "worker-after",
            },
          };
          await f.write({
            ...f.draft(),
            findings: outcome === "reported" ? [resolved] : [],
            coverage: {
              ...f.draft().coverage,
              surfaces:
                outcome === "rejected"
                  ? [
                      {
                        id: "current-decision",
                        candidateId,
                        sourceWorkerId: resolved.provenance.sourceWorkerId,
                        label: "Current candidate review",
                        disposition: "rejected",
                        notes: "Current validation resolved this candidate.",
                      },
                    ]
                  : [],
            },
          });
          const coverage = await f.read();
          assert.equal(
            coverage.deferred.some(
              (row: { id: string }) => row.id === candidateId,
            ),
            !sameOwner,
          );
          assert.ok(
            coverage.deferred.some(
              (row: { id: string }) => row.id === generic.id,
            ),
          );
          if (sameOwner && outcome === "reported") {
            const saved = JSON.parse(
              await readFile(path.join(f.root, "findings.json"), "utf8"),
            );
            assert.ok(
              JSON.stringify(saved.findings[0].provenance).includes(
                "Saved older review evidence.",
              ),
            );
          }
        });
      }
    }
  }
}

const {
  recordCodexSecurityScanDraft,
  recordCodexSecurityScanDraftViaWorkbench,
} = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);
const {
  deepReductionScanDraft,
  discoveryReductionInput,
  reconcileDeepReduction,
} = await importSource(
  new URL("../src/deep-scan/artifact-validation.ts", import.meta.url).pathname,
);

test("publishes colliding worker-local deferred IDs without changing their evidence", async (t) => {
  const { context } = await fixture(t, "deep");
  const candidate = {
    id: "candidate-review",
    candidateId: "candidate-review",
    reason: "Synthetic validation remains pending.",
    candidate: { evidence: "Retain the saved review evidence." },
  };
  const discoveries = ["worker-one", "worker-two", "worker-three"].map(
    (workerId, index) => ({
      workerId,
      result: discoveryReductionInput(
        workerDraft([], {
          scanId: context.scanId,
          coverage: {
            completeness: "partial",
            surfaces: [],
            explicitExclusions: [],
            deferred: [
              {
                ...candidate,
                ...(index === 2
                  ? { id: "candidate-review-2", candidateId: "reserved-review" }
                  : {}),
              },
            ],
          },
        }),
        workerId,
      ),
    }),
  );
  const aggregate = reconcileDeepReduction(
    { scanId: context.scanId, findings: [] },
    discoveries,
    null,
  );
  const original = structuredClone(aggregate);
  const projected = deepReductionScanDraft(aggregate);
  let published = false;
  await recordCodexSecurityScanDraftViaWorkbench(
    context,
    { ...projected, handoffClaimToken: context.handoffClaimToken },
    async (args: string[]) => {
      const draft = JSON.parse(
        await readFile(args[args.indexOf("--draft-path") + 1]!, "utf8"),
      );
      const rows = draft.coverage.deferred;
      assert.equal(new Set(rows.map((row: { id: string }) => row.id)).size, 3);
      assert.equal(rows[2].id, "candidate-review-2");
      for (let index = 0; index < rows.length; index++) {
        const { id: _id, ...actual } = rows[index];
        const { id: _localId, ...expected } =
          original.unresolvedCandidates[index];
        assert.deepEqual(actual, expected);
      }
      published = true;
    },
  );
  assert.equal(published, true);
  assert.deepEqual(aggregate, original);
  assert.deepEqual(deepReductionScanDraft(aggregate), projected);
});

for (const mode of ["standard", "diff"] as const) {
  test(`keeps a same-identity ${mode} reassessment when its attribution changes`, async (t) => {
    const { context, draft } = await fixture(t, mode);
    const earlier = {
      ...finding("shared", "src/handler.ts"),
      identity: { anchor: "shared-review" },
      severity: { level: "high" },
      provenance: { source: "local_plugin", sourceWorkerId: "earlier-worker" },
    };
    const current = {
      ...earlier,
      summary: "Current evidence lowers the severity.",
      severity: { level: "low" },
      provenance: { source: "local_plugin", sourceWorkerId: "current-worker" },
    };
    await recordCodexSecurityScanDraft(context, {
      ...draft({}, true),
      findings: [earlier],
    });
    await recordCodexSecurityScanDraft(context, {
      ...draft({}, true),
      findings: [current],
    });
    const saved = JSON.parse(
      await readFile(path.join(context.root, "findings.json"), "utf8"),
    );
    assert.equal(saved.findings.length, 1);
    assert.equal(saved.findings[0].severity.level, "low");
    assert.equal(saved.findings[0].summary, current.summary);
    assert.deepEqual(saved.findings[0].provenance.previousFindings, [earlier]);

    const independentRoot = path.join(context.root, "independent");
    await mkdir(independentRoot);
    const independentContext = { ...context, root: independentRoot };
    await recordCodexSecurityScanDraft(independentContext, {
      ...draft({}, true),
      findings: [
        earlier,
        {
          ...current,
          identity: { anchor: "shared-review", instance: "independent" },
        },
      ],
    });
    const independent = JSON.parse(
      await readFile(path.join(independentRoot, "findings.json"), "utf8"),
    );
    assert.equal(independent.findings.length, 2);
  });
}
