import assert from "node:assert/strict";
import { cp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { scanId, workerDraft } from "./scan-draft-fixture.ts";
import { draftFixture } from "./scan-draft-recovery-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  fileURLToPath(new URL("../src/artifact-deep-reducer.ts", import.meta.url)),
);
const {
  recordCodexSecurityWorkerScanDraft,
  recordCodexSecurityScanDraft,
  parsePersistedScanDraft,
  readArchivedWorkerCheckpoints,
} = await importSource(
  fileURLToPath(new URL("../src/artifact-scan-draft.ts", import.meta.url)),
);
const { validateDiscoveryArtifacts } = await importSource(
  fileURLToPath(
    new URL("../src/deep-scan/artifact-validation.ts", import.meta.url),
  ),
);
const { archiveDirectory } = await importSource(
  fileURLToPath(new URL("../src/deep-scan/artifacts.ts", import.meta.url)),
);

async function fixture() {
  const root = await temporaryDirectory("retry-coverage-origin-", true);
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts",
    "deep_discovery",
    "workers",
    "discovery-0001",
  );
  const output = path.join(workerRoot, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  const context = {
    root: path.join(
      scanRoot,
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
      scanRoot,
      claimedWorkers: [{ id: "synthetic-worker", attempt: 3, resultPath }],
    },
  };
  return { root, workerRoot, output, resultPath, context };
}

for (const malformed of [
  "none",
  "json",
  "schema",
  "head-json",
  "head-checkpoint",
  "head-missing",
]) {
  test(`accepted current coverage survives archived ${malformed}`, async () => {
    const f = await fixture();
    try {
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await mkdir(path.join(archive, "checkpoints"), { recursive: true });
      const name = "a".repeat(64) + ".json";
      const contents =
        malformed === "json"
          ? "{"
          : JSON.stringify(
              malformed === "schema" || malformed === "head-checkpoint"
                ? {}
                : workerDraft([]),
            );
      if (malformed !== "head-missing")
        await writeFile(path.join(archive, "checkpoints", name), contents);
      if (
        malformed === "head-json" ||
        malformed === "head-checkpoint" ||
        malformed === "head-missing"
      )
        await writeFile(
          path.join(archive, "checkpoint-head.json"),
          malformed === "head-json"
            ? "{"
            : JSON.stringify({ checkpoint: name }),
        );
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const before = await readFile(f.resultPath);
      const sources = await readDeepReductionSources(f.context);
      assert.equal(sources.discoveries.length, 1);
      assert.deepEqual(await readFile(f.resultPath), before);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const unsafe of ["wrong-scan", "linked-checkpoints"]) {
  test(`archived ${unsafe} retains its existing rejection`, async () => {
    const f = await fixture();
    try {
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await mkdir(archive, { recursive: true });
      if (unsafe === "wrong-scan") {
        await mkdir(path.join(archive, "checkpoints"));
        await writeFile(
          path.join(archive, "checkpoints", "a.json"),
          JSON.stringify(
            workerDraft([], { scanId: "12c17317-9594-49e0-b06a-d72fd7e14bba" }),
          ),
        );
      } else {
        const outside = path.join(f.root, "outside");
        await mkdir(outside);
        await symlink(
          outside,
          path.join(archive, "checkpoints"),
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true })),
      );
      await assert.rejects(
        readArchivedWorkerCheckpoints({
          root: f.output,
          repoRoot: f.root,
          scanId,
          layout: "worker",
        }),
        unsafe === "wrong-scan"
          ? /scanId does not match|different scan/
          : /safe directory/,
      );
      const accepted = await readDeepReductionSources(f.context);
      assert.equal(accepted.discoveries.length, 1);
      assert.deepEqual(accepted.discoveries[0].result.findings, []);
      assert.deepEqual(
        JSON.parse(await readFile(f.resultPath, "utf8")),
        workerDraft([], { complete: true }),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const duplicate of [false, true]) {
  test(`raw saved surface references retain every matching target=${duplicate}`, async () => {
    const f = await fixture();
    try {
      const coverage = {
        completeness: "partial",
        surfaces: [
          {
            id: "shared",
            label: "First surface",
            disposition: "needs_follow_up",
          },
          {
            id: duplicate ? "shared" : "second",
            label: "Second surface",
            disposition: "needs_follow_up",
          },
        ],
        explicitExclusions: [],
        deferred: [
          {
            id: "task",
            reason: "Follow up first surface.",
            surfaceIds: ["shared"],
          },
        ],
      };
      await writeFile(
        f.resultPath,
        JSON.stringify(workerDraft([], { complete: true, coverage })),
      );
      const source = (await readDeepReductionSources(f.context)).discoveries[0]
        .coverage;
      assert.deepEqual(
        source.deferred[0].surfaceIds,
        source.surfaces
          .slice(0, duplicate ? 2 : 1)
          .map((surface: { id: string }) => surface.id),
      );
      assert.notEqual(source.surfaces[0].id, source.surfaces[1].id);
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("three actual cumulative worker attempts retain original coverage ownership", async () => {
  const f = await fixture();
  try {
    const worker = {
      root: f.output,
      repoRoot: f.root,
      scanId,
      layout: "worker",
    };
    for (const attempt of [1, 2, 3]) {
      await mkdir(f.output, { recursive: true });
      await recordCodexSecurityWorkerScanDraft(
        worker,
        workerDraft([], {
          complete: attempt === 3,
          coverage: {
            completeness: attempt === 3 ? "complete" : "partial",
            surfaces: [
              {
                id: `surface-${attempt}`,
                label: `Review ${attempt}`,
                disposition: "no_issue_found",
              },
            ],
            explicitExclusions: [],
            deferred: [],
          },
        }),
      );
      if (attempt < 3)
        await archiveDirectory(
          f.output,
          path.join(f.workerRoot, "attempts", `attempt-0${attempt}`),
        );
    }
    const source = (await readDeepReductionSources(f.context)).discoveries[0]
      .coverage;
    for (const attempt of [1, 2, 3]) {
      assert.equal(
        source.surfaces.find(
          (row: { label: string }) => row.label === `Review ${attempt}`,
        ).provenance.attempt,
        attempt,
      );
      assert.ok(
        source.reviews.some(
          (review: { attempt: number }) => review.attempt === attempt,
        ),
      );
    }
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const withReceipts of [false, true]) {
  for (const directFile of [false, true]) {
    for (const optionalIds of [false, true]) {
      test(`retry writer retains raw archived coverage ownership, optional IDs=${optionalIds}, receipts=${withReceipts}, direct file=${directFile}`, async () => {
        const f = await fixture();
        try {
          f.context.deepReducer.claimedWorkers[0].attempt = 2;
          const inherited = workerDraft([], {
            complete: false,
            coverage: {
              completeness: "partial",
              surfaces: [
                {
                  ...(optionalIds
                    ? { id: "first-surface", receiptRefs: [] }
                    : {}),
                  receiptRefs: withReceipts ? ["artifacts/review.txt"] : [],
                  label: "First attempt review",
                  disposition: "needs_follow_up",
                },
              ],
              explicitExclusions: [],
              deferred: [
                {
                  ...(optionalIds ? { id: "first-task" } : {}),
                  reason: "First attempt still needs validation.",
                },
              ],
            },
          });
          // A worker can finish with an incomplete result; its retry uses the normal
          // recording API to retain those saved observations.
          if (withReceipts) {
            await mkdir(path.join(f.output, "artifacts"), { recursive: true });
            await writeFile(
              path.join(f.output, "artifacts/review.txt"),
              "Original synthetic review.\n",
            );
          }
          await writeFile(f.resultPath, JSON.stringify(inherited));
          const archive = path.join(f.workerRoot, "attempts", "attempt-01");
          await archiveDirectory(f.output, archive);
          const archiveResult = path.join(archive, "result.json");
          const before = await readFile(archiveResult);
          await mkdir(f.output, { recursive: true });
          if (directFile) {
            if (withReceipts) {
              await mkdir(path.join(f.output, "artifacts"), {
                recursive: true,
              });
              await writeFile(
                path.join(f.output, "artifacts/review.txt"),
                "Original synthetic review.\n",
              );
            }
            await writeFile(
              f.resultPath,
              JSON.stringify({ ...inherited, complete: true }),
            );
            await validateDiscoveryArtifacts(
              { workersRoot: path.dirname(f.workerRoot) },
              f.resultPath,
              scanId,
            );
          } else
            await recordCodexSecurityWorkerScanDraft(
              {
                root: f.output,
                repoRoot: f.root,
                scanId,
                layout: "worker",
              },
              workerDraft([], { complete: true }),
            );
          const source = (await readDeepReductionSources(f.context))
            .discoveries[0].coverage;
          for (const field of ["surfaces", "deferred"])
            assert.equal(source[field][0].provenance.attempt, 1);
          assert.ok(
            source.reviews.some(
              (review: { attempt: number }) => review.attempt === 1,
            ),
          );
          assert.deepEqual(await readFile(archiveResult), before);
        } finally {
          await rm(f.root, { recursive: true, force: true });
        }
      });
    }
  }
}

test("persisted optional coverage IDs retain their original host-projection shape", async () => {
  const f = await fixture();
  try {
    const source = workerDraft([], {
      complete: true,
      coverage: {
        completeness: "partial",
        surfaces: [
          {
            label: "Synthetic pending surface",
            disposition: "needs_follow_up",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [],
        deferred: [{ reason: "Review the synthetic pending task." }],
      },
    });
    await writeFile(f.resultPath, JSON.stringify(source));
    const original = await readFile(f.resultPath);
    const sources = await readDeepReductionSources(f.context);
    const discovery = sources.discoveries[0];
    const parsed = parsePersistedScanDraft(JSON.parse(original.toString()));
    assert.equal(parsed.coverage.surfaces[0].id, undefined);
    assert.equal(parsed.coverage.deferred[0].id, undefined);
    assert.equal(discovery.coverage.surfaces[0].provenance.sourceId, undefined);
    assert.equal(discovery.coverage.deferred[0].provenance.sourceId, undefined);
    assert.equal(
      discovery.coverage.surfaces[0].id,
      "synthetic-worker-attempt-3-surface-1",
    );
    assert.equal(
      discovery.coverage.deferred[0].id,
      "synthetic-worker-attempt-3-deferred-1",
    );
    assert.deepEqual(await readFile(f.resultPath), original);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

test("generic Deep progress preserves parent review and provenance extensions", async () => {
  const root = await temporaryDirectory("parent-review-extensions-", true);
  try {
    const { context, draft } = draftFixture(root, "deep");
    const reviews = [
      { workerId: "synthetic-child", attempt: 1, completeness: "complete" },
    ];
    const provenance = {
      workerId: "synthetic-child",
      attempt: 1,
      candidateId: "candidate-1",
    };
    const surfaces = [
      {
        id: "parent-surface",
        candidateId: "candidate-1",
        label: "Parent review",
        disposition: "rejected",
        receiptRefs: [],
        provenance,
      },
    ];
    await recordCodexSecurityScanDraft(
      context,
      draft({ reviews, surfaces }, false),
    );
    const coverage = JSON.parse(
      await readFile(path.join(root, "coverage.json"), "utf8"),
    );
    assert.deepEqual(coverage.reviews, reviews);
    assert.deepEqual(coverage.surfaces, surfaces);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const nestedKeyOrder of [false, true]) {
  test(`copied incomplete retries retain their first receipt and raw deferred origin, nested order=${nestedKeyOrder}`, async () => {
    const f = await fixture();
    try {
      const input = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "original-review",
              label: "Original review",
              disposition: "needs_follow_up",
              receiptRefs: ["artifacts/review.txt"],
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              reason: "Original pending proof.",
              provenance: { details: { a: 1, b: 2 } },
            },
          ],
        },
      });
      await mkdir(path.join(f.output, "artifacts"));
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        "Synthetic original review.\n",
      );
      await writeFile(f.resultPath, JSON.stringify(input));
      const first = path.join(f.workerRoot, "attempts", "attempt-01");
      await cp(f.output, first, { recursive: true, preserveTimestamps: true });
      const second = path.join(f.workerRoot, "attempts", "attempt-02");
      await archiveDirectory(f.output, second);
      await mkdir(f.output, { recursive: true });
      if (nestedKeyOrder) {
        const final = {
          ...structuredClone(input),
          complete: true,
          coverage: {
            ...input.coverage,
            deferred: [
              {
                reason: "Original pending proof.",
                provenance: { details: { b: 2, a: 1 } },
              },
            ],
          },
        };
        await mkdir(path.join(f.output, "artifacts"));
        await writeFile(
          path.join(f.output, "artifacts/review.txt"),
          "Synthetic original review.\n",
        );
        await writeFile(f.resultPath, JSON.stringify(final));
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
      } else {
        await recordCodexSecurityWorkerScanDraft(
          { root: f.output, repoRoot: f.root, scanId, layout: "worker" },
          workerDraft([], { complete: true }),
        );
      }
      const source = (await readDeepReductionSources(f.context)).discoveries[0]
        .coverage;
      for (const field of ["surfaces", "deferred"])
        assert.equal(source[field][0].provenance.attempt, 1);
      assert.ok(
        source.reviews.some((row: { attempt: number }) => row.attempt === 1),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

test("a failed nonregular attempt preserves readable retry origin history", async () => {
  const f = await fixture();
  try {
    const original = workerDraft([], {
      complete: false,
      coverage: {
        completeness: "partial",
        surfaces: [
          {
            id: "original",
            label: "Retained review",
            disposition: "needs_follow_up",
            receiptRefs: [],
          },
        ],
        explicitExclusions: [],
        deferred: [
          {
            id: "original-gap",
            reason: "The first review still needs validation.",
          },
        ],
      },
    });
    await writeFile(f.resultPath, JSON.stringify(original));
    const first = path.join(f.workerRoot, "attempts", "attempt-01");
    await archiveDirectory(f.output, first);
    await mkdir(path.join(f.output, "result.json"), { recursive: true });
    await archiveDirectory(
      f.output,
      path.join(f.workerRoot, "attempts", "attempt-02"),
    );
    await mkdir(f.output, { recursive: true });
    await writeFile(
      f.resultPath,
      JSON.stringify({ ...original, complete: true }),
    );
    await validateDiscoveryArtifacts(
      { workersRoot: path.dirname(f.workerRoot) },
      f.resultPath,
      scanId,
    );
    const bytes = await readFile(path.join(first, "result.json"));
    await assert.rejects(
      readArchivedWorkerCheckpoints({
        root: f.output,
        repoRoot: f.root,
        scanId,
        layout: "worker",
      }),
      /archived result is not a safe file/,
    );
    const coverage = (await readDeepReductionSources(f.context)).discoveries[0]
      .coverage;
    assert.equal(coverage.surfaces[0].provenance.attempt, 1);
    assert.equal(coverage.deferred[0].provenance.attempt, 1);
    assert.ok(
      coverage.reviews.some(
        (review: { attempt: number }) => review.attempt === 1,
      ),
    );
    assert.deepEqual(await readFile(path.join(first, "result.json")), bytes);
  } finally {
    await rm(f.root, { recursive: true, force: true });
  }
});

for (const checkpointCollection of ["file", "linked", "readable"]) {
  test(`an unusable checkpoint collection preserves independent retry history: ${checkpointCollection}`, async () => {
    const f = await fixture();
    try {
      const original = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "review",
              label: "First accepted review",
              disposition: "needs_follow_up",
              receiptRefs: [],
            },
          ],
          explicitExclusions: [],
          deferred: [
            { id: "gap", reason: "The first review still needs proof." },
          ],
        },
      });
      await writeFile(f.resultPath, JSON.stringify(original));
      const first = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, first);
      const second = path.join(f.workerRoot, "attempts", "attempt-02");
      await mkdir(second, { recursive: true });
      await writeFile(
        path.join(second, "result.json"),
        JSON.stringify(workerDraft([], { complete: false })),
      );
      if (checkpointCollection === "file") {
        await writeFile(
          path.join(second, "checkpoints"),
          "Unusable failed checkpoint collection.\n",
        );
      } else if (checkpointCollection === "linked") {
        const outside = path.join(f.root, "unrelated-checkpoints");
        await mkdir(outside);
        await writeFile(
          path.join(outside, "unrelated.json"),
          "{unrelated bytes}",
        );
        await symlink(
          outside,
          path.join(second, "checkpoints"),
          process.platform === "win32" ? "junction" : "dir",
        );
      } else {
        await mkdir(path.join(second, "checkpoints"));
      }
      await mkdir(f.output, { recursive: true });
      await writeFile(
        f.resultPath,
        JSON.stringify({ ...original, complete: true }),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const oldBytes = await readFile(path.join(first, "result.json"));
      if (checkpointCollection !== "readable") {
        await assert.rejects(
          readArchivedWorkerCheckpoints({
            root: f.output,
            repoRoot: f.root,
            scanId,
            layout: "worker",
          }),
          /safe directory/,
        );
      }
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.equal(coverage.surfaces[0].provenance.attempt, 1);
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.ok(
        coverage.reviews.some(
          (review: { attempt: number }) => review.attempt === 1,
        ),
      );
      assert.deepEqual(
        await readFile(path.join(first, "result.json")),
        oldBytes,
      );
      if (checkpointCollection === "linked") {
        assert.equal(
          await readFile(
            path.join(f.root, "unrelated-checkpoints", "unrelated.json"),
            "utf8",
          ),
          "{unrelated bytes}",
        );
      }
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const changedReceipt of [false, true]) {
  test(`actual receipt bytes determine a retried surface origin: changed=${changedReceipt}`, async () => {
    const f = await fixture();
    try {
      const original = workerDraft([], {
        complete: false,
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "surface",
              label: "Same review metadata",
              disposition: "needs_follow_up",
              receiptRefs: ["artifacts/review.txt"],
            },
          ],
          explicitExclusions: [],
          deferred: [
            { id: "gap", reason: "The same review still needs proof." },
          ],
        },
      });
      await mkdir(path.join(f.output, "artifacts"));
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        "Original synthetic review.\n",
      );
      await writeFile(f.resultPath, JSON.stringify(original));
      const archive = path.join(f.workerRoot, "attempts", "attempt-01");
      await archiveDirectory(f.output, archive);
      await mkdir(path.join(f.output, "artifacts"));
      const currentBytes = changedReceipt
        ? "Changed synthetic review.\n"
        : "Original synthetic review.\n";
      await writeFile(
        path.join(f.output, "artifacts/review.txt"),
        currentBytes,
      );
      await writeFile(
        f.resultPath,
        JSON.stringify({ ...original, complete: true }),
      );
      await validateDiscoveryArtifacts(
        { workersRoot: path.dirname(f.workerRoot) },
        f.resultPath,
        scanId,
      );
      const coverage = (await readDeepReductionSources(f.context))
        .discoveries[0].coverage;
      assert.equal(
        coverage.surfaces[0].provenance.attempt,
        changedReceipt ? 3 : 1,
      );
      assert.equal(coverage.deferred[0].provenance.attempt, 1);
      assert.equal(
        await readFile(path.join(f.output, "artifacts/review.txt"), "utf8"),
        currentBytes,
      );
      assert.equal(
        await readFile(path.join(archive, "artifacts/review.txt"), "utf8"),
        "Original synthetic review.\n",
      );
      assert.ok(
        coverage.reviews.some(
          (review: { attempt: number }) => review.attempt === 1,
        ),
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const mode of ["idless", "explicit", "mixed"]) {
  for (const attempts of [2, 3]) {
    test(`legacy equal coverage rows keep occurrence origins, mode=${mode}, attempts=${attempts}`, async () => {
      const f = await fixture();
      try {
        f.context.deepReducer.claimedWorkers[0].attempt = attempts;
        const archivedBytes: { path: string; bytes: Buffer }[] = [];
        for (let attempt = 1; attempt <= attempts; attempt++) {
          await mkdir(f.output, { recursive: true });
          const surface = {
            label: "Synthetic repeated legacy observation",
            disposition: "needs_follow_up",
            receiptRefs: [],
          };
          const surfaces = Array.from({ length: attempt }, (_, index) => ({
            ...surface,
            ...(mode === "explicit" || (mode === "mixed" && index > 0)
              ? { id: `legacy-${index + 1}` }
              : {}),
          }));
          // Persisted older worker outputs retain optional IDs and row order.
          await writeFile(
            f.resultPath,
            JSON.stringify(
              workerDraft([], {
                complete: true,
                coverage: {
                  completeness: "partial",
                  surfaces,
                  explicitExclusions: [],
                  deferred: [],
                },
              }),
            ),
          );
          if (attempt < attempts) {
            const bytes = await readFile(f.resultPath);
            const archive = path.join(
              f.workerRoot,
              "attempts",
              `attempt-0${attempt}`,
            );
            await archiveDirectory(f.output, archive);
            archivedBytes.push({
              path: path.join(archive, "result.json"),
              bytes,
            });
          }
        }
        const original = await readFile(f.resultPath);
        await validateDiscoveryArtifacts(
          { workersRoot: path.dirname(f.workerRoot) },
          f.resultPath,
          scanId,
        );
        const coverage = (await readDeepReductionSources(f.context))
          .discoveries[0].coverage;
        assert.deepEqual(
          coverage.surfaces.map(
            (row: { provenance: { attempt: number } }) =>
              row.provenance.attempt,
          ),
          Array.from({ length: attempts }, (_, index) => index + 1),
        );
        assert.equal(
          new Set(coverage.surfaces.map((row: { id: string }) => row.id)).size,
          attempts,
        );
        assert.deepEqual(await readFile(f.resultPath), original);
        for (const archived of archivedBytes)
          assert.deepEqual(await readFile(archived.path), archived.bytes);
      } finally {
        await rm(f.root, { recursive: true, force: true });
      }
    });
  }
}
