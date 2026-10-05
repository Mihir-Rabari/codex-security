import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  draftApi,
  draftFixture,
  fixture,
  interruptDraftWrite,
} from "./scan-draft-recovery-fixture.mjs";

const execFileAsync = promisify(execFile);
const finding = (title, metadata = {}) => ({
  ruleId: "fixture.review",
  title,
  summary: "Synthetic saved evidence must retain its identity.",
  severity: { level: "low" },
  confidence: { level: "high", rationale: "Synthetic persistence fixture." },
  taxonomy: { category: "other", cwe: [] },
  locations: [{ path: "src/example.py", startLine: 1 }],
  remediation: "Complete the review.",
  provenance: { source: "local_plugin" },
  ...metadata,
});
const variants = {
  provenance: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    }),
  ],
  extension: [
    finding("Synthetic review", { extensions: { candidateId: "candidate-1" } }),
  ],
  unicode: [
    finding("Café review", {
      provenance: { source: "local_plugin", candidateId: "Évidence /réview._" },
    }),
  ],
  title: [finding("Café /réview._")],
  siblings: ["First review", "Second review"].map((title) =>
    finding(title, {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    }),
  ),
  report: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { reportId: "Synthetic Report" },
    }),
  ],
  ledger: [
    finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { ledgerRowId: "Synthetic Ledger" },
    }),
  ],
  "no candidate siblings": [finding("First review"), finding("Second review")],
  "shared ledger": ["First review", "Second review"].map((title) =>
    finding(title, { extensions: { ledgerRowId: "shared-ledger" } }),
  ),
};

for (const layout of ["standard", "diff", "deep"]) {
  for (const [variant, findings] of Object.entries(variants)) {
    test(`${layout}: first checkpoint publication preserves ${variant} identities`, async (t) => {
      const normal = await fixture(t, layout);
      const recovered = await fixture(t, layout);
      await normal.write({ ...normal.draft(), findings });
      await draftApi.saveScanDraftCheckpoint(
        recovered.context,
        { ...recovered.draft(), findings },
        false,
      );
      const result = await recoverAndFinalize(normal, recovered);
      assert.equal(result.normal.length, findings.length);
      assert.equal(result.recovered.length, findings.length);
      assert.deepEqual(result.warnings, []);
      assert.deepEqual(result.recovered, result.normal);
    });
  }
}

for (const layout of ["standard", "diff", "worker"]) {
  test(`${layout}: adding candidate metadata preserves a report-backed finding`, async (t) => {
    const f = await fixture(t, layout);
    const initial = finding("Synthetic report", {
      extensions: { reportId: "report-1" },
    });
    await f.write({ ...f.draft(), findings: [initial] });
    await f.write({
      ...f.draft(),
      findings: [
        {
          ...initial,
          provenance: { source: "local_plugin", candidateId: "candidate-1" },
        },
      ],
    });
    const saved = JSON.parse(
      await readFile(
        path.join(
          f.root,
          layout === "worker" ? "result.json" : "findings.json",
        ),
        "utf8",
      ),
    );
    assert.equal(saved.findings.length, 1);
    assert.equal(saved.findings[0].provenance.candidateId, "candidate-1");
  });
}

async function recoverAndFinalize(normal, recovered, workers = []) {
  const { stdout } = await execFileAsync(
    process.env.PYTHON?.trim() || "python3",
    [
      "-c",
      `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from workbench_saved_results import merge_saved_results
from finalize_scan_contract import _prepare_scan_finalization
normal,recovered=map(Path,sys.argv[2:4])
scan_id=sys.argv[4]
manifest=json.loads((normal/'scan-manifest.json').read_text())
coverage=json.loads((normal/'coverage.json').read_text())
binding={'status':'failed','allowedTargetKinds':[manifest['scan']['target']['kind']],'target':manifest['scan']['target'],'scope':manifest['scan']['scope'],'coverageMode':coverage['mode']}
warnings=[]
recovery=merge_saved_results(recovered,scan_id,binding,json.loads(sys.argv[5]),warnings,stopped=True,reason='Synthetic interruption')
ordinary=(manifest,json.loads((normal/'findings.json').read_text()),coverage)
results=[]
for root,documents in [(normal,ordinary),(recovered,recovery)]:
 documents[0]['scan'].update(id=scan_id,producer={'name':'codex-security-plugin','version':'0.1.0'},status='failed',startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
 for document in documents[1:]: document['scanId']=scan_id
 prepared=_prepare_scan_finalization(root,completion_warnings=warnings,draft_documents=documents)
 results.append([{'title':row['title'],'identity':row['identity'],'fingerprints':row['fingerprints'],'findingId':row['findingId'],'workerMetadata':row.get('provenance',{}).get('workerId')} for row in prepared[3]['findings']])
print(json.dumps({'normal':results[0],'recovered':results[1],'warnings':warnings}))`,
      fileURLToPath(new URL("../../scripts", import.meta.url)),
      normal.root,
      recovered.root,
      normal.context.scanId,
      JSON.stringify(workers),
    ],
  );
  return JSON.parse(stdout);
}

for (const layout of ["standard", "diff", "deep"]) {
  test(`${layout}: canonical rows without identities use their sibling context`, async (t) => {
    const normal = await fixture(t, layout);
    const recovered = await fixture(t, layout);
    for (const f of [normal, recovered])
      await f.write({ ...f.draft(), findings: variants.siblings });
    const destination = path.join(recovered.root, "findings.json");
    const document = JSON.parse(await readFile(destination, "utf8"));
    for (const row of document.findings) delete row.identity;
    await writeFile(destination, JSON.stringify(document));
    const result = await recoverAndFinalize(normal, recovered);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const layout of ["standard", "diff"]) {
  test(`${layout}: a new sibling survives a published singleton`, async (t) => {
    const normal = await fixture(t, layout);
    const recovered = await fixture(t, layout);
    for (const f of [normal, recovered])
      await f.write({ ...f.draft(), findings: variants.siblings.slice(0, 1) });
    await normal.write({ ...normal.draft(), findings: variants.siblings });
    await interruptDraftWrite(path.join(recovered.root, "findings.json"), () =>
      recovered.write({ ...recovered.draft(), findings: variants.siblings }),
    );
    const result = await recoverAndFinalize(normal, recovered);
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
  for (const metadata of ["provenance", "extensions"]) {
    for (const reported of [false, true]) {
      for (const cut of ["raw", "reconciled"]) {
        test(`${layout}: ${metadata} enrichment (report=${reported}) retains identities after two ${cut} interruptions`, async (t) => {
          const normal = await fixture(t, layout);
          const recovered = await fixture(t, layout);
          const first = finding(
            "Synthetic report",
            reported
              ? {
                  extensions: { reportId: "report-1" },
                }
              : {},
          );
          const second = {
            ...first,
            [metadata]: { ...first[metadata], candidateId: "candidate-1" },
          };
          for (const value of [first, second]) {
            await normal.write({ ...normal.draft(), findings: [value] });
            const input = { ...recovered.draft(), findings: [value] };
            if (cut === "raw")
              await draftApi.saveScanDraftCheckpoint(
                recovered.context,
                input,
                false,
              );
            else
              await interruptDraftWrite(
                path.join(recovered.root, "findings.json"),
                () => recovered.write(input),
              );
          }
          const result = await recoverAndFinalize(normal, recovered);
          assert.equal(result.normal.length, 1);
          assert.deepEqual(result.recovered, result.normal);
          assert.deepEqual(result.warnings, []);
        });
      }
    }
  }
}

for (const variant of [
  "different titles",
  "same title",
  "normalized aliases",
  "authored anchor",
  "rejected sibling",
]) {
  test(`deep: worker-local candidates match combined publication (${variant})`, async (t) => {
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
    const workers = [];
    const findings = [];
    for (const [index, id] of ["reviewer-a", "reviewer-b"].entries()) {
      const root = path.join(recovered.root, id);
      await mkdir(root);
      const worker = draftFixture(root, "worker");
      const value = finding(
        variant === "same title" || index === 0
          ? "First review"
          : "Second review",
        {
          provenance: {
            source: "local_plugin",
            candidateId:
              variant === "normalized aliases"
                ? index === 0
                  ? "Case"
                  : "Caſe"
                : "candidate-1",
          },
        },
      );
      if (variant === "authored anchor" && index === 0)
        value.identity = { anchor: "established-review" };
      await worker.write({ ...worker.draft(), findings: [value] });
      const result = JSON.parse(
        await readFile(path.join(root, "result.json"), "utf8"),
      );
      if (variant === "rejected sibling" && index === 1) {
        await worker.write(
          worker.draft(
            {
              surfaces: [
                {
                  id: "review-completed",
                  label: "Review completed",
                  candidateId: "candidate-1",
                  disposition: "rejected",
                },
              ],
            },
            true,
          ),
        );
      } else {
        findings.push(
          ...result.findings.map((row) => ({
            ...row,
            provenance: { ...row.provenance, workerId: id },
          })),
        );
      }
      workers.push({
        id,
        kind: "discovery",
        artifact_dir: root,
        result_manifest_path: null,
        attempt: 1,
      });
    }
    await normal.write({ ...normal.draft(), findings });
    const result = await recoverAndFinalize(normal, recovered, workers);
    assert.equal(result.normal.length, variant === "rejected sibling" ? 1 : 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

for (const [kind, metadata, identifier] of [
  ["candidate aliases", "provenance"],
  ["report enrichment", "extensions", "reportId"],
  ["report enrichment", "extensions", "ledgerRowId"],
  ...[undefined, "reportId", "ledgerRowId"].flatMap((identifier) =>
    ["provenance", "extensions"].map((metadata) => [
      "candidate enrichment",
      metadata,
      identifier,
    ]),
  ),
]) {
  test(`deep: ${kind} via ${metadata}/${identifier ?? "plain"} matches published worker identities`, async (t) => {
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
    const normalRoot = path.join(normal.root, "reviewer");
    const recoveryRoot = path.join(recovered.root, "reviewer");
    await mkdir(normalRoot);
    await mkdir(recoveryRoot);
    const publishedWorker = draftFixture(normalRoot, "worker");
    const interruptedWorker = draftFixture(recoveryRoot, "worker");
    const first = finding("First review", {
      ...(kind === "candidate enrichment"
        ? {}
        : {
            provenance: {
              source: "local_plugin",
              candidateId:
                kind === "candidate aliases" ? "CASE" : "candidate-1",
            },
          }),
      ...(kind === "candidate enrichment" && identifier
        ? { extensions: { [identifier]: "report-1" } }
        : {}),
    });
    const second = structuredClone(first);
    if (kind === "candidate aliases") {
      second.title = "Second review";
      second.provenance.candidateId = "case";
    } else if (kind === "report enrichment") {
      second.extensions = { [identifier]: "report-1" };
    } else {
      second[metadata] = { ...second[metadata], candidateId: "candidate-1" };
    }
    for (const worker of [publishedWorker, interruptedWorker])
      await worker.write({ ...worker.draft(), findings: [first] });
    await publishedWorker.write({
      ...publishedWorker.draft(),
      findings: [second],
    });
    await draftApi.saveScanDraftCheckpoint(
      interruptedWorker.context,
      { ...interruptedWorker.draft(), findings: [second] },
      false,
    );
    const result = JSON.parse(
      await readFile(path.join(normalRoot, "result.json"), "utf8"),
    );
    await normal.write({
      ...normal.draft(),
      findings: result.findings.map((row) => ({
        ...row,
        provenance: { ...row.provenance, workerId: "reviewer" },
      })),
    });
    const comparison = await recoverAndFinalize(normal, recovered, [
      {
        id: "reviewer",
        kind: "discovery",
        artifact_dir: recoveryRoot,
        result_manifest_path: null,
        attempt: 1,
      },
    ]);
    assert.equal(
      comparison.normal.length,
      kind === "candidate aliases" ? 2 : 1,
    );
    const byTitle = (left, right) => left.title.localeCompare(right.title);
    assert.deepEqual(
      comparison.recovered.sort(byTitle),
      comparison.normal.sort(byTitle),
    );
    assert.deepEqual(comparison.warnings, []);
  });
}

for (const layout of ["standard", "diff"]) {
  test(`${layout}: growing raw cross-location siblings retain published identities`, async (t) => {
    const normal = await fixture(t, layout);
    const recovered = await fixture(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "shared-candidate" },
    });
    const second = {
      ...first,
      title: "Second review",
      locations: [{ path: "src/example.py", startLine: 2 }],
    };
    for (const findings of [[first], [first, second]]) {
      await normal.write({ ...normal.draft(), findings });
      await draftApi.saveScanDraftCheckpoint(
        recovered.context,
        { ...recovered.draft(), findings },
        false,
      );
    }
    const result = await recoverAndFinalize(normal, recovered);
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

test("deep: explicit worker identity survives candidate enrichment", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  const nwroot = path.join(normal.root, "reviewer"),
    rwroot = path.join(recovered.root, "reviewer");
  await mkdir(nwroot);
  await mkdir(rwroot);
  const nw = draftFixture(nwroot, "worker"),
    rw = draftFixture(rwroot, "worker");
  const first = finding("First review", {
    identity: { anchor: "authored-review" },
  });
  const second = {
    ...first,
    provenance: { ...first.provenance, candidateId: "candidate-1" },
  };
  await nw.write({ ...nw.draft(), findings: [first] });
  await rw.write({ ...rw.draft(), findings: [first] });
  await nw.write({ ...nw.draft(), findings: [second] });
  await draftApi.saveScanDraftCheckpoint(
    rw.context,
    { ...rw.draft(), findings: [second] },
    false,
  );
  const result = JSON.parse(
    await readFile(path.join(nwroot, "result.json"), "utf8"),
  );
  await normal.write({
    ...normal.draft(),
    findings: result.findings.map((row) => ({
      ...row,
      provenance: { ...row.provenance, workerId: "reviewer" },
    })),
  });
  const comparison = await recoverAndFinalize(normal, recovered, [
    {
      id: "reviewer",
      kind: "discovery",
      artifact_dir: rwroot,
      result_manifest_path: null,
      attempt: 1,
    },
  ]);
  assert.equal(comparison.normal.length, 1);
  assert.deepEqual(comparison.recovered, comparison.normal);
  assert.deepEqual(comparison.warnings, []);
});

for (const layout of ["standard", "diff", "worker"]) {
  for (const variant of [
    "reportId",
    "ledgerRowId",
    "metadata enrichment",
    "authored identity",
    "retained sibling",
  ]) {
    test(`${layout}: checkpoint reconciliation preserves ${variant}`, async (t) => {
      const normal = await fixture(t, layout === "worker" ? "deep" : layout);
      const recovered = await fixture(t, layout === "worker" ? "deep" : layout);
      let normalSource = normal,
        recoveredSource = recovered;
      const workers = [];
      if (layout === "worker") {
        for (const f of [normal, recovered])
          await mkdir(path.join(f.root, "reviewer"));
        normalSource = draftFixture(
          path.join(normal.root, "reviewer"),
          "worker",
        );
        recoveredSource = draftFixture(
          path.join(recovered.root, "reviewer"),
          "worker",
        );
        workers.push({
          id: "reviewer",
          kind: "discovery",
          artifact_dir: recoveredSource.root,
          result_manifest_path: null,
          attempt: 1,
        });
      }
      const first = finding("First review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
      });
      let second = structuredClone(first);
      if (["reportId", "ledgerRowId", "authored identity"].includes(variant)) {
        const field = variant === "authored identity" ? "reportId" : variant;
        first.extensions = { [field]: "report-1" };
        second.extensions = { [field]: "report-2" };
      }
      if (variant === "metadata enrichment")
        second.extensions = { reportId: "report-1" };
      if (variant === "authored identity") {
        first.identity = { anchor: "authored-review" };
        second.identity = { anchor: "authored-review" };
      }
      if (variant === "retained sibling") second.title = "Second review";
      const initial =
        variant === "retained sibling" ? [first, second] : [first];
      for (const f of [normalSource, recoveredSource])
        await f.write({ ...f.draft(), findings: initial });
      await normalSource.write({
        ...normalSource.draft({}, true),
        findings: [second],
      });
      await draftApi.saveScanDraftCheckpoint(
        recoveredSource.context,
        { ...recoveredSource.draft({}, true), findings: [second] },
        false,
      );
      if (layout === "worker") {
        const saved = JSON.parse(
          await readFile(path.join(normalSource.root, "result.json"), "utf8"),
        );
        await normal.write({
          ...normal.draft(),
          findings: saved.findings.map((row) => ({
            ...row,
            provenance: { ...row.provenance, workerId: "reviewer" },
          })),
        });
      }
      const result = await recoverAndFinalize(normal, recovered, workers);
      const count = ["metadata enrichment", "authored identity"].includes(
        variant,
      )
        ? 1
        : 2;
      assert.equal(result.normal.length, count);
      assert.equal(result.recovered.length, count);
      if (variant === "retained sibling")
        assert.deepEqual(result.normal.map((row) => row.title).sort(), [
          "First review",
          "Second review",
        ]);
      const ordered = (rows) =>
        rows.sort((left, right) =>
          left.findingId.localeCompare(right.findingId),
        );
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"])
  for (const metadata of ["provenance", "extensions"]) {
    test(`${layout}: candidate-backed canonical duplicate without identity (${metadata})`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const input = finding("Synthetic review", {
        [metadata]: {
          ...(metadata === "provenance" ? { source: "local_plugin" } : {}),
          candidateId: "candidate-1",
        },
      });
      for (const f of [normal, recovered])
        await f.write({ ...f.draft(), findings: [input] });
      const dest = path.join(recovered.root, "findings.json");
      const doc = JSON.parse(await readFile(dest, "utf8"));
      const duplicate = structuredClone(doc.findings[0]);
      delete duplicate.identity;
      doc.findings.push(duplicate);
      await writeFile(dest, JSON.stringify(doc));
      const result = await recoverAndFinalize(normal, recovered);
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
    });
  }

for (const layout of ["standard", "diff", "deep"])
  for (const metadata of ["provenance", "extensions"]) {
    test(`${layout}: raw candidate identity remains distinct when content matches (${metadata})`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const one = finding("Synthetic review", {
        [metadata]: {
          ...(metadata === "provenance" ? { source: "local_plugin" } : {}),
          candidateId: "candidate-1",
        },
      });
      const two = {
        ...one,
        [metadata]: { ...one[metadata], candidateId: "candidate-2" },
      };
      await normal.write({ ...normal.draft(), findings: [one, two] });
      await recovered.write({ ...recovered.draft(), findings: [one] });
      const dest = path.join(recovered.root, "findings.json");
      const doc = JSON.parse(await readFile(dest, "utf8"));
      const second = structuredClone(doc.findings[0]);
      delete second.identity;
      second[metadata].candidateId = "candidate-2";
      doc.findings.push(second);
      await writeFile(dest, JSON.stringify(doc));
      const result = await recoverAndFinalize(normal, recovered);
      assert.equal(result.normal.length, 2);
      assert.deepEqual(result.recovered, result.normal);
    });
  }

for (const layout of ["standard", "diff", "deep"]) {
  test(`${layout}: cumulative distinct owners retain publication identity`, async (t) => {
    const normal = await fixture(t, layout);
    const recovered = await fixture(t, layout);
    const first = finding("Synthetic ownership review", {
      provenance: {
        source: "local_plugin",
        candidateId: "candidate-1",
        workerId: "worker-a",
      },
    });
    const second = {
      ...structuredClone(first),
      identity: { anchor: "authored-worker-b" },
      provenance: { ...first.provenance, workerId: "worker-b" },
    };
    for (const findings of [[first], [first, second]]) {
      await normal.write({ ...normal.draft(), findings });
      await draftApi.saveScanDraftCheckpoint(
        recovered.context,
        { ...recovered.draft(), findings },
        false,
      );
    }
    const result = await recoverAndFinalize(normal, recovered);
    assert.equal(result.normal.length, 2);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
  for (const [field, blank] of [
    ["reportId", " "],
    ["ledgerRowId", "\t"],
  ]) {
    test(`${layout}: blank ${field} enrichment retains publication identity`, async (t) => {
      const normal = await fixture(t, layout);
      const recovered = await fixture(t, layout);
      const first = finding("Synthetic metadata review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        extensions: { [field]: blank },
      });
      const second = { ...first, extensions: { [field]: "report-1" } };
      for (const value of [first, second]) {
        await normal.write({ ...normal.draft(), findings: [value] });
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          { ...recovered.draft(), findings: [value] },
          false,
        );
      }
      const result = await recoverAndFinalize(normal, recovered);
      assert.equal(result.normal.length, 1);
      assert.equal(result.recovered.length, 1);
      assert.deepEqual(result.warnings, []);
      assert.deepEqual(result.recovered, result.normal);
    });
  }
}
for (const field of ["reportId", "ledgerRowId"]) {
  test(`deep: worker blank ${field} enrichment retains publication identity`, async (t) => {
    const normal = await fixture(t, "deep");
    const recovered = await fixture(t, "deep");
    const normalRoot = path.join(normal.root, "reviewer");
    const recoveredRoot = path.join(recovered.root, "reviewer");
    await mkdir(normalRoot);
    await mkdir(recoveredRoot);
    const normalWorker = draftFixture(normalRoot, "worker");
    const recoveredWorker = draftFixture(recoveredRoot, "worker");
    const first = finding("Synthetic worker review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { [field]: " \t " },
    });
    const second = { ...first, extensions: { [field]: "report-1" } };
    for (const value of [first, second]) {
      await normalWorker.write({ ...normalWorker.draft(), findings: [value] });
      await draftApi.saveScanDraftCheckpoint(
        recoveredWorker.context,
        { ...recoveredWorker.draft(), findings: [value] },
        false,
      );
    }
    const saved = JSON.parse(
      await readFile(path.join(normalRoot, "result.json"), "utf8"),
    );
    await normal.write({
      ...normal.draft(),
      findings: saved.findings.map((row) => ({
        ...row,
        provenance: { ...row.provenance, workerId: "reviewer" },
      })),
    });
    const result = await recoverAndFinalize(normal, recovered, [
      {
        id: "reviewer",
        kind: "discovery",
        artifact_dir: recoveredRoot,
        result_manifest_path: null,
        attempt: 1,
      },
    ]);
    assert.equal(result.normal.length, 1);
    assert.equal(result.recovered.length, 1);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
}

for (const layout of ["standard", "diff", "deep"]) {
  test(`${layout}: later authored identity survives raw checkpoint recovery`, async (t) => {
    const normal = await fixture(t, layout),
      recovered = await fixture(t, layout);
    const first = finding("Synthetic review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const second = { ...first, identity: { anchor: "authored-review" } };
    for (const value of [first, second]) {
      await normal.write({ ...normal.draft(), findings: [value] });
      await draftApi.saveScanDraftCheckpoint(
        recovered.context,
        { ...recovered.draft(), findings: [value] },
        false,
      );
    }
    const result = await recoverAndFinalize(normal, recovered);
    assert.equal(result.normal.length, 2);
    assert.deepEqual(
      [...result.recovered].sort((a, b) =>
        a.identity.anchor.localeCompare(b.identity.anchor),
      ),
      [...result.normal].sort((a, b) =>
        a.identity.anchor.localeCompare(b.identity.anchor),
      ),
    );
  });
  for (const metadata of [{ id: "synthetic-worker" }, ["synthetic-worker"]]) {
    test(`${layout}: arbitrary worker provenance survives recovery (${Array.isArray(metadata) ? "array" : "object"})`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const value = finding("Synthetic review", {
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: metadata,
        },
      });
      for (const f of [normal, recovered])
        await f.write({ ...f.draft(), findings: [value] });
      const result = await recoverAndFinalize(normal, recovered);
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.recovered[0].workerMetadata, metadata);
    });
  }
}
