import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { build } from "esbuild";

const bundle = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/artifact-diff-candidates.ts", import.meta.url).pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { preserveUnconfirmedDiffCandidates } = await import(
  `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].contents).toString("base64")}`
);

function candidate(candidateId, validation, attackPath) {
  return {
    candidate_id: candidateId,
    cwe_ids: [],
    locations: [
      { path: "src/handler.ts", start_line: 1, end_line: 2, role: "evidence" },
    ],
    summary: "A synthetic candidate needs review.",
    evidence: "Synthetic candidate evidence.",
    ...(validation ? { validation: { disposition: validation } } : {}),
    ...(attackPath ? { attack_path: { decision: attackPath } } : {}),
  };
}

function draft(deferred = []) {
  return {
    scanId: "11111111-1111-4111-8111-111111111111",
    findings: [],
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred,
    },
  };
}

async function fixture(t, candidates) {
  const root = await mkdtemp(path.join(tmpdir(), "diff-candidates-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  if (candidates !== undefined) {
    const discovery = path.join(root, "artifacts", "02_discovery");
    await mkdir(discovery, { recursive: true });
    await writeFile(
      path.join(discovery, "candidate_ledger.jsonl"),
      candidates.map((row) => JSON.stringify(row)).join("\n"),
    );
  }
  return { root, repoRoot: root, layout: "scan", mode: "diff" };
}

test("diff outcomes retain unresolved candidates and exclude terminal decisions", async (t) => {
  const outcomes = [
    [undefined, undefined, true],
    ["reportable", undefined, true],
    ["deferred", undefined, true],
    ["reportable", "deferred", true],
    ["deferred", "reportable", true],
    ["deferred", "ignore", true],
    ["suppressed", "deferred", true],
    ["not_applicable", "deferred", true],
    ["reportable", "reportable", false],
    ["reportable", "ignore", false],
    ["suppressed", undefined, false],
    ["not_applicable", undefined, false],
  ];
  const candidates = outcomes.map(([validation, attackPath], index) =>
    candidate(`candidate-${index}`, validation, attackPath),
  );
  const input = draft();
  const context = await fixture(t, candidates);
  const result = await preserveUnconfirmedDiffCandidates(context, input);
  const expected = candidates.filter((_, index) => outcomes[index][2]);
  assert.deepEqual(
    result.coverage.deferred.map((item) => item.candidateId),
    expected.map((item) => item.candidate_id),
  );
  assert.deepEqual(
    result.coverage.deferred.map((item) => item.candidate),
    expected,
  );
  assert.equal(result.coverage.completeness, "partial");
  assert.deepEqual(input, draft());
  assert.deepEqual(
    await preserveUnconfirmedDiffCandidates(context, result),
    result,
    "Repeated checkpoints must not append the same pending candidates again.",
  );
});

test("diff reconciliation enriches pending records and retains general coverage work", async (t) => {
  const pending = candidate("pending", "deferred", "deferred");
  pending.attack_path.proof_gap =
    "A synthetic runtime check remains unfinished.";
  const context = await fixture(t, [
    pending,
    candidate("rejected", "suppressed"),
    candidate("undefined", "reportable", "reportable"),
  ]);
  const general = { reason: "A source directory still needs review." };
  const result = await preserveUnconfirmedDiffCandidates(
    context,
    draft([
      { id: "pending", reason: "Keep the original follow-up question." },
      { candidateId: "rejected", reason: "An earlier incomplete checkpoint." },
      general,
    ]),
  );
  assert.deepEqual(result.coverage.deferred, [
    {
      id: "pending",
      candidateId: "pending",
      candidate: pending,
      reason: "Keep the original follow-up question.",
    },
    general,
  ]);
  const added = await preserveUnconfirmedDiffCandidates(context, draft());
  assert.equal(
    added.coverage.deferred[0].reason,
    pending.attack_path.proof_gap,
  );
});

test("final findings and explicit candidate resolutions are not reopened", async (t) => {
  const context = await fixture(t, [
    candidate("confirmed"),
    candidate("rejected"),
    candidate("not-applicable"),
  ]);
  const input = draft();
  input.findings = [{ extensions: { candidateId: "confirmed" } }];
  input.coverage.surfaces = [
    { candidateId: "rejected", disposition: "rejected" },
    { candidateId: "not-applicable", disposition: "not_applicable" },
  ];
  assert.deepEqual(
    await preserveUnconfirmedDiffCandidates(context, input),
    input,
  );
});

test("legacy diff drafts without a ledger and other modes retain their behavior", async (t) => {
  const context = await fixture(t);
  const input = draft();
  assert.equal(await preserveUnconfirmedDiffCandidates(context, input), input);
  assert.equal(
    await preserveUnconfirmedDiffCandidates(
      { ...context, mode: "standard" },
      input,
    ),
    input,
  );
});
