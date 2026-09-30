import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
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
const draftBundle = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/artifact-scan-draft.ts", import.meta.url).pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { recordCodexSecurityScanDraft } = await import(
  `data:text/javascript;base64,${Buffer.from(draftBundle.outputFiles[0].contents).toString("base64")}`
);

const validationBundle = await build({
  bundle: true,
  entryPoints: [
    new URL("../src/artifact-validation-phase.ts", import.meta.url).pathname,
  ],
  format: "esm",
  platform: "node",
  write: false,
});
const { recordCodexSecurityCandidateValidations } = await import(
  `data:text/javascript;base64,${Buffer.from(validationBundle.outputFiles[0].contents).toString("base64")}`
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
  return {
    root,
    repoRoot: root,
    layout: "scan",
    mode: "diff",
    scanId: draft().scanId,
    status: "running",
    scope: ".",
    targetContract: {
      target: {
        allowedKinds: ["git_diff"],
        targetId: "target_diff",
        displayName: "synthetic-repository",
      },
      scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
      diffTarget: {
        kind: "range",
        baseRevision: "base123",
        headRevision: "head456",
      },
    },
  };
}

test("diff outcomes retain unresolved candidates and exclude terminal dismissals", async (t) => {
  const outcomes = [
    [undefined, undefined, true],
    ["reportable", undefined, true],
    ["deferred", undefined, true],
    ["reportable", "deferred", true],
    ["deferred", "reportable", true],
    ["deferred", "ignore", true],
    ["suppressed", "deferred", true],
    ["not_applicable", "deferred", true],
    ["reportable", "reportable", true],
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
  assert.deepEqual(
    result.coverage.surfaces,
    expected.map((item) => ({
      candidateId: item.candidate_id,
      label: item.summary,
      disposition: "needs_follow_up",
      notes: result.coverage.deferred.find(
        (pending) => pending.candidateId === item.candidate_id,
      ).reason,
    })),
  );
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
    candidate("ignored", "reportable", "ignore"),
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

test("pending diff candidates retain their authored follow-up surfaces", async (t) => {
  const pending = candidate("pending-review", "deferred");
  const context = await fixture(t, [pending]);
  const input = draft();
  input.coverage.surfaces = [
    {
      candidateId: pending.candidate_id,
      label: "Authored review boundary",
      disposition: "needs_follow_up",
      notes: "Keep the analyst's coverage evidence.",
    },
  ];
  const result = await preserveUnconfirmedDiffCandidates(context, input);
  assert.deepEqual(result.coverage.surfaces, input.coverage.surfaces);
  assert.equal(result.coverage.deferred.length, 1);
});

for (const mapping of ["candidateId", "surfaceIds"]) {
  test(`pending diff candidates preserve a shared reported surface linked by ${mapping}`, async (t) => {
    const pending = candidate("pending-review", "deferred");
    const context = await fixture(t, [pending]);
    const input = draft([
      {
        candidateId: pending.candidate_id,
        reason: "The second candidate still needs validation.",
        ...(mapping === "surfaceIds" ? { surfaceIds: ["shared-surface"] } : {}),
      },
    ]);
    input.findings = [{ provenance: { candidateId: "confirmed-review" } }];
    input.coverage.surfaces = [
      {
        id: "shared-surface",
        ...(mapping === "candidateId"
          ? { candidateId: pending.candidate_id }
          : {}),
        label: "Shared review boundary",
        disposition: "reported",
        notes: "The shared surface contains a retained finding.",
      },
    ];
    const result = await preserveUnconfirmedDiffCandidates(context, input);
    assert.deepEqual(result.coverage.surfaces, input.coverage.surfaces);
    assert.equal(result.coverage.deferred.length, 1);
    assert.equal(result.coverage.completeness, "partial");
  });
}

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

for (const remaining of ["none", "deferred", "surface", "explicit partial"]) {
  test(`terminal diff decisions close a saved checkpoint with ${remaining} remaining`, async (t) => {
    const pending = candidate("pending-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    if (remaining === "deferred") {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.deferred.push({
        reason: "An unrelated source review remains unfinished.",
      });
    }
    if (remaining === "surface") {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.surfaces.push({
        label: "Unrelated source review",
        disposition: "needs_follow_up",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const savedCheckpoint = JSON.parse(
      await readFile(path.join(context.root, "coverage.json"), "utf8"),
    );
    assert.equal(savedCheckpoint.completeness, "partial");
    assert.ok(
      savedCheckpoint.deferred.some(
        (item) => item.candidateId === pending.candidate_id,
      ),
    );
    assert.ok(
      savedCheckpoint.surfaces.some(
        (item) =>
          item.candidateId === pending.candidate_id &&
          item.disposition === "needs_follow_up",
      ),
    );

    await writeFile(
      path.join(
        context.root,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      ),
      JSON.stringify({ ...pending, validation: { disposition: "suppressed" } }),
    );
    const finalDraft = { ...draft(), complete: true };
    if (remaining === "explicit partial")
      finalDraft.coverage.completeness = "partial";
    await recordCodexSecurityScanDraft(context, finalDraft);
    const saved = JSON.parse(
      await readFile(path.join(context.root, "coverage.json"), "utf8"),
    );
    assert.equal(
      saved.completeness,
      remaining === "none" ? "complete" : "partial",
    );
    assert.equal(
      saved.deferred.some((item) => item.candidateId === pending.candidate_id),
      false,
    );
    assert.equal(
      saved.surfaces.some((item) => item.candidateId === pending.candidate_id),
      false,
    );
    if (remaining === "deferred") assert.equal(saved.deferred.length, 1);
    if (remaining === "surface") assert.equal(saved.surfaces.length, 1);
  });
}

for (const remaining of [
  "none",
  "shared checkpoint",
  "shared current",
  "shared direct candidate",
  "generic gap",
  "current follow-up",
]) {
  test(`ledger resolution clears linked historical follow-ups with ${remaining} remaining`, async (t) => {
    const pending = candidate("linked-review");
    const other = candidate("other-review");
    const context = await fixture(t, [
      pending,
      ...(remaining === "shared direct candidate" ? [other] : []),
    ]);
    const linkedSurface = {
      id: "shared-boundary",
      ...(remaining === "shared direct candidate"
        ? { candidateId: other.candidate_id }
        : {}),
      label: "Synthetic review boundary",
      disposition: "needs_follow_up",
      notes: "The linked candidate needs validation.",
    };
    const checkpoint = {
      ...draft([
        {
          candidateId: pending.candidate_id,
          reason: "Validate the linked candidate.",
          surfaceIds: [linkedSurface.id],
        },
      ]),
      complete: false,
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push(linkedSurface);
    if (remaining === "shared direct candidate") {
      checkpoint.coverage.deferred.push({
        candidateId: other.candidate_id,
        reason: "The directly linked candidate still needs validation.",
      });
    }
    if (remaining === "generic gap") {
      checkpoint.coverage.deferred.push({
        reason: "An unrelated source review remains unfinished.",
        surfaceIds: ["generic-boundary"],
      });
      checkpoint.coverage.surfaces.push({
        id: "generic-boundary",
        label: "Unrelated source review",
        disposition: "needs_follow_up",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const ledger = path.join(
      context.root,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    );
    const otherDeferred = {
      candidateId: other.candidate_id,
      reason: "A second candidate still needs validation.",
      surfaceIds: [linkedSurface.id],
    };
    if (remaining === "shared checkpoint") {
      await writeFile(
        ledger,
        [pending, other].map((row) => JSON.stringify(row)).join("\n"),
      );
      const sharedCheckpoint = { ...draft([otherDeferred]), complete: false };
      sharedCheckpoint.coverage.completeness = "partial";
      await recordCodexSecurityScanDraft(context, sharedCheckpoint);
    }
    const shared = remaining.startsWith("shared");
    await writeFile(
      ledger,
      [
        { ...pending, validation: { disposition: "suppressed" } },
        ...(shared ? [other] : []),
      ]
        .map((row) => JSON.stringify(row))
        .join("\n"),
    );
    const finalDraft = {
      ...draft(remaining === "shared current" ? [otherDeferred] : []),
      complete: true,
    };
    if (remaining === "shared current" || remaining === "current follow-up")
      finalDraft.coverage.completeness = "partial";
    if (remaining === "current follow-up") {
      finalDraft.coverage.surfaces.push({
        ...linkedSurface,
        notes: "The current draft explicitly retains additional review work.",
      });
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, finalDraft);
      const saved = JSON.parse(
        await readFile(path.join(context.root, "coverage.json"), "utf8"),
      );
      assert.equal(
        saved.completeness,
        remaining === "none" ? "complete" : "partial",
      );
      assert.equal(
        saved.deferred.some(
          (item) => item.candidateId === pending.candidate_id,
        ),
        false,
      );
      assert.deepEqual(
        saved.surfaces.map((surface) => surface.id),
        remaining === "generic gap"
          ? ["generic-boundary"]
          : shared || remaining === "current follow-up"
            ? [linkedSurface.id]
            : [],
      );
      if (shared) {
        assert.deepEqual(
          saved.deferred.map((item) => item.candidateId),
          [other.candidate_id],
        );
      }
      if (remaining === "generic gap") assert.equal(saved.deferred.length, 1);
      if (remaining === "current follow-up") {
        assert.equal(
          saved.surfaces[0].notes,
          finalDraft.coverage.surfaces[0].notes,
        );
      }
    }
  });
}

for (const resolution of ["finding", "exclusion"]) {
  test(`mixed ledger and current ${resolution} resolutions clear linked follow-ups`, async (t) => {
    const automatic = candidate("automatic-review");
    const linked = candidate("linked-review");
    const context = await fixture(t, [automatic, linked]);
    const checkpoint = {
      ...draft([
        {
          candidateId: linked.candidate_id,
          reason: "Validate the linked candidate.",
          surfaceIds: ["linked-boundary"],
        },
      ]),
      complete: false,
    };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push({
      id: "linked-boundary",
      label: "Synthetic review boundary",
      disposition: "needs_follow_up",
    });
    await recordCodexSecurityScanDraft(context, checkpoint);

    const resolved = { ...draft(), complete: false };
    if (resolution === "finding") {
      resolved.findings.push({
        ruleId: "synthetic-review",
        title: "Synthetic reviewed finding",
        summary: "The synthetic review has reached a final finding.",
        severity: { level: "low" },
        confidence: { level: "high", rationale: "Synthetic review evidence." },
        taxonomy: { category: "synthetic", cwe: [] },
        locations: [{ path: "src/handler.ts", startLine: 1 }],
        remediation: "Apply the synthetic remediation.",
        provenance: {
          source: "local_plugin",
          candidateId: linked.candidate_id,
        },
      });
    } else {
      resolved.coverage.explicitExclusions.push({
        candidateId: linked.candidate_id,
        disposition: "rejected",
        pattern: "src/handler.ts",
        reason: "Synthetic review resolved this candidate.",
      });
    }
    await recordCodexSecurityScanDraft(context, resolved);
    await writeFile(
      path.join(
        context.root,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      ),
      [{ ...automatic, validation: { disposition: "suppressed" } }, linked]
        .map((row) => JSON.stringify(row))
        .join("\n"),
    );
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, {
        ...resolved,
        complete: true,
      });
      const saved = JSON.parse(
        await readFile(path.join(context.root, "coverage.json"), "utf8"),
      );
      assert.equal(saved.completeness, "complete");
      assert.deepEqual(saved.deferred, []);
      assert.deepEqual(saved.surfaces, []);
      if (resolution === "exclusion") {
        assert.equal(
          saved.explicitExclusions[0].candidateId,
          linked.candidate_id,
        );
      } else {
        const findings = JSON.parse(
          await readFile(path.join(context.root, "findings.json"), "utf8"),
        );
        assert.equal(
          findings.findings[0].provenance.candidateId,
          linked.candidate_id,
        );
      }
    }
  });
}

for (const disposition of ["rejected", "not_applicable"]) {
  test(`explicit ${disposition} exclusions resolve diff candidates through later drafts`, async (t) => {
    const pending = candidate("excluded-review");
    const context = await fixture(t, [pending]);
    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    const finalDraft = { ...draft(), complete: true };
    finalDraft.coverage.explicitExclusions.push({
      candidateId: pending.candidate_id,
      disposition,
      pattern: "src/handler.ts",
      reason: "The synthetic candidate was resolved during source review.",
    });
    await recordCodexSecurityScanDraft(context, finalDraft);
    const coveragePath = path.join(context.root, "coverage.json");
    const resolved = JSON.parse(await readFile(coveragePath, "utf8"));
    assert.equal(resolved.completeness, "complete");
    assert.deepEqual(resolved.deferred, []);
    assert.deepEqual(resolved.explicitExclusions[0].candidate, pending);
    assert.equal(resolved.explicitExclusions[0].disposition, disposition);

    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const retained = JSON.parse(await readFile(coveragePath, "utf8"));
    assert.equal(retained.completeness, "complete");
    assert.deepEqual(retained.deferred, []);
    assert.deepEqual(retained.explicitExclusions, resolved.explicitExclusions);
  });

  test(`new deferred review supersedes an older ${disposition} exclusion`, async (t) => {
    const pending = candidate("reopened-review");
    const context = await fixture(t, [pending]);
    const earlierExclusion = {
      candidateId: pending.candidate_id,
      disposition,
      pattern: "src/handler.ts",
      reason: "An earlier synthetic review dismissed the candidate.",
    };
    const unrelatedExclusion = {
      pattern: "vendor/**",
      reason: "The independent vendor scope remains excluded.",
    };
    const earlier = { ...draft(), complete: false };
    earlier.coverage.explicitExclusions.push(
      earlierExclusion,
      unrelatedExclusion,
    );
    await recordCodexSecurityScanDraft(context, earlier);
    const checkpoints = path.join(context.root, "checkpoints");
    const history = await Promise.all(
      (await readdir(checkpoints)).map(async (name) => [
        name,
        await readFile(path.join(checkpoints, name), "utf8"),
      ]),
    );
    assert.ok(
      history.some(([, content]) =>
        JSON.parse(content).coverage.explicitExclusions.some(
          (item) => item.reason === earlierExclusion.reason,
        ),
      ),
    );
    const currentExclusion = {
      candidateId: "another-candidate",
      disposition: "not_applicable",
      pattern: "src/other.ts",
      reason: "This current exclusion remains authoritative.",
    };
    const followup = {
      ...draft([
        {
          candidateId: pending.candidate_id,
          reason: "Later evidence requires another review.",
        },
      ]),
      complete: false,
    };
    followup.coverage.completeness = "partial";
    followup.coverage.explicitExclusions.push(currentExclusion);
    for (let attempt = 0; attempt < 2; attempt++) {
      await recordCodexSecurityScanDraft(context, followup);
      const saved = JSON.parse(
        await readFile(path.join(context.root, "coverage.json"), "utf8"),
      );
      assert.deepEqual(
        saved.deferred.map((item) => item.candidateId),
        [pending.candidate_id],
      );
      assert.equal(
        saved.deferred[0].reason,
        followup.coverage.deferred[0].reason,
      );
      assert.equal(saved.completeness, "partial");
      assert.deepEqual(saved.explicitExclusions, [
        currentExclusion,
        unrelatedExclusion,
      ]);
    }
    for (const [name, content] of history) {
      assert.equal(
        await readFile(path.join(checkpoints, name), "utf8"),
        content,
      );
    }
  });

  test(`terminal diff ledger resolution retains saved ${disposition} surface rationale`, async (t) => {
    const pending = candidate("resolved-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    checkpoint.coverage.completeness = "partial";
    checkpoint.coverage.surfaces.push({
      candidateId: pending.candidate_id,
      label: "Synthetic candidate review",
      disposition: "needs_follow_up",
    });
    await recordCodexSecurityScanDraft(context, checkpoint);
    await writeFile(
      path.join(
        context.root,
        "artifacts",
        "02_discovery",
        "candidate_ledger.jsonl",
      ),
      JSON.stringify({ ...pending, validation: { disposition: "suppressed" } }),
    );
    const finalDraft = { ...draft(), complete: true };
    finalDraft.coverage.surfaces.push({
      candidateId: pending.candidate_id,
      label: "Synthetic candidate review",
      disposition,
      notes: "Source review established the candidate's terminal disposition.",
    });
    await recordCodexSecurityScanDraft(context, finalDraft);
    const coveragePath = path.join(context.root, "coverage.json");
    const resolved = JSON.parse(await readFile(coveragePath, "utf8"));
    assert.equal(resolved.completeness, "complete");
    assert.deepEqual(resolved.deferred, []);
    assert.equal(resolved.surfaces.length, 1);
    assert.equal(resolved.surfaces[0].disposition, disposition);
    assert.deepEqual(resolved.surfaces[0].candidate, pending);

    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
    const retained = JSON.parse(await readFile(coveragePath, "utf8"));
    assert.equal(retained.completeness, "complete");
    assert.deepEqual(retained.deferred, []);
    assert.deepEqual(retained.surfaces, resolved.surfaces);
  });
}

test("reportable diff ledger rows remain pending until a finding is saved", async (t) => {
  const pending = candidate("reportable-review");
  const context = await fixture(t, [pending]);
  await recordCodexSecurityScanDraft(context, { ...draft(), complete: false });
  const ledgerPath = path.join(
    context.root,
    "artifacts",
    "02_discovery",
    "candidate_ledger.jsonl",
  );
  const reportable = candidate(
    pending.candidate_id,
    "reportable",
    "reportable",
  );
  await writeFile(ledgerPath, JSON.stringify(reportable));
  await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
  const coveragePath = path.join(context.root, "coverage.json");
  const missingFinding = JSON.parse(await readFile(coveragePath, "utf8"));
  assert.equal(missingFinding.completeness, "partial");
  assert.equal(missingFinding.deferred.length, 1);
  assert.equal(missingFinding.deferred[0].candidateId, pending.candidate_id);
  assert.deepEqual(missingFinding.deferred[0].candidate, reportable);
  assert.match(missingFinding.deferred[0].reason, /no saved finding/u);

  const finalDraft = { ...draft(), complete: true };
  finalDraft.findings.push({
    ruleId: "synthetic-review",
    title: "Synthetic reviewed finding",
    summary: "The synthetic review has reached a final finding.",
    severity: { level: "low" },
    confidence: { level: "high", rationale: "Synthetic review evidence." },
    taxonomy: { category: "synthetic", cwe: [] },
    locations: [{ path: "src/handler.ts", startLine: 1 }],
    remediation: "Apply the synthetic remediation.",
    provenance: { source: "local_plugin", candidateId: pending.candidate_id },
  });
  await recordCodexSecurityScanDraft(context, finalDraft);
  const saved = JSON.parse(await readFile(coveragePath, "utf8"));
  assert.equal(saved.completeness, "complete");
  assert.deepEqual(saved.deferred, []);
  await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });
  const retained = JSON.parse(await readFile(coveragePath, "utf8"));
  assert.equal(retained.completeness, "complete");
  assert.deepEqual(retained.deferred, []);
  const findings = JSON.parse(
    await readFile(path.join(context.root, "findings.json"), "utf8"),
  );
  assert.equal(findings.findings.length, 1);
  assert.equal(
    findings.findings[0].provenance.candidateId,
    pending.candidate_id,
  );
});

for (const authored of [false, true]) {
  test(`diff checkpoints refresh ledger evidence and ${authored ? "retain authored" : "update generated"} reasons`, async (t) => {
    const pending = candidate("updated-review");
    const context = await fixture(t, [pending]);
    const checkpoint = { ...draft(), complete: false };
    const authoredReason = "Retain the analyst's specific follow-up request.";
    const authoredNote = "Keep the analyst's candidate annotation.";
    if (authored) {
      checkpoint.coverage.completeness = "partial";
      checkpoint.coverage.deferred.push({
        candidateId: pending.candidate_id,
        reason: authoredReason,
        candidate: { ...pending, analystNote: authoredNote },
        notes: "A coverage annotation must also survive.",
      });
    }
    await recordCodexSecurityScanDraft(context, checkpoint);
    const ledgerPath = path.join(
      context.root,
      "artifacts",
      "02_discovery",
      "candidate_ledger.jsonl",
    );
    const coveragePath = path.join(context.root, "coverage.json");
    const validation = {
      ...pending,
      evidence: "Updated source evidence after validation.",
      validation: {
        disposition: "deferred",
        counterevidence_or_proof_gap:
          "A synthetic validation input is missing.",
      },
    };
    const attackPath = {
      ...validation,
      evidence: "Updated source evidence after attack-path review.",
      attack_path: {
        decision: "deferred",
        proof_gap: "A synthetic deployment adapter is missing.",
      },
    };
    for (const reviewed of [validation, attackPath]) {
      await writeFile(ledgerPath, JSON.stringify(reviewed));
      await recordCodexSecurityScanDraft(context, {
        ...draft(),
        complete: true,
      });
      const saved = JSON.parse(await readFile(coveragePath, "utf8"));
      assert.equal(saved.completeness, "partial");
      assert.equal(saved.deferred.length, 1);
      const item = saved.deferred[0];
      assert.deepEqual(
        item.candidate,
        authored ? { ...reviewed, analystNote: authoredNote } : reviewed,
      );
      assert.equal(
        item.reason,
        authored
          ? authoredReason
          : (reviewed.attack_path?.proof_gap ??
              reviewed.validation.counterevidence_or_proof_gap),
      );
      if (authored)
        assert.equal(item.notes, checkpoint.coverage.deferred[0].notes);
    }
  });
}

for (const uncertainty of ["  A runtime check is still required.\n", " \t "]) {
  test(`blank phase reasons preserve readable diff checkpoints: ${uncertainty.trim() ? "recorded uncertainty" : "fallback"}`, async (t) => {
    const pending = candidate("blank-reason");
    const context = await fixture(t, [pending]);
    const validation = {
      disposition: "deferred",
      method: "source review",
      confidence: "low",
      confidence_rationale: "The runtime behavior remains unverified.",
      rubric: "Source review",
      evidence: "Synthetic source evidence.",
      counterevidence_or_proof_gap: " \t\n ",
      remaining_uncertainty: uncertainty,
    };
    const accepted = await recordCodexSecurityCandidateValidations(context, {
      validations: [{ candidateId: pending.candidate_id, validation }],
    });
    assert.equal(accepted.rowsWritten, 1);

    await recordCodexSecurityScanDraft(context, {
      ...draft(),
      complete: false,
    });
    await recordCodexSecurityScanDraft(context, { ...draft(), complete: true });

    const saved = JSON.parse(
      await readFile(path.join(context.root, "coverage.json"), "utf8"),
    );
    const expectedReason = uncertainty.trim()
      ? uncertainty
      : `Candidate review is incomplete: ${pending.summary}`;
    assert.equal(saved.completeness, "partial");
    assert.equal(saved.deferred[0].reason, expectedReason);
    assert.equal(saved.surfaces[0].notes, expectedReason);
    assert.deepEqual(saved.deferred[0].candidate.validation, validation);
  });
}
