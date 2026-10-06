import assert from "node:assert/strict";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { test } from "node:test";
import { importSource } from "./import-module.ts";
import { scanId, workerDraft } from "./scan-draft-fixture.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const { readDeepReductionSources } = await importSource(
  new URL("../src/artifact-deep-reducer.ts", import.meta.url).pathname,
);
const { recordCodexSecurityWorkerScanDraft } = await importSource(
  new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
);
const { archiveDirectory } = await importSource(
  new URL("../src/deep-scan/artifacts.ts", import.meta.url).pathname,
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
      await writeFile(path.join(archive, "checkpoints", name), contents);
      if (malformed === "head-json" || malformed === "head-checkpoint")
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
        readDeepReductionSources(f.context),
        unsafe === "wrong-scan"
          ? /scanId does not match|different scan/
          : /safe directory/,
      );
    } finally {
      await rm(f.root, { recursive: true, force: true });
    }
  });
}

for (const duplicate of [false, true]) {
  test(`raw saved duplicate surface references retain first target=${duplicate}`, async () => {
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
      assert.equal(source.deferred[0].surfaceIds[0], source.surfaces[0].id);
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
