import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { readFile, writeFile, mkdir, utimes, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  draftApi,
  draftFixture,
  fixture,
  interruptDraftWrite,
} from "./scan-draft-recovery-fixture.ts";

const execFileAsync = promisify(execFile);
type FixtureFinding = Record<string, unknown> & {
  title: string;
  summary: string;
  severity: { level: string };
  locations: Array<{ path: string; startLine: number }>;
  provenance: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  identity?: { anchor?: string; instance?: string; [key: string]: unknown };
};
type RecoveredFinding = FixtureFinding & {
  identity: { anchor: string; instance?: string; [key: string]: unknown };
  findingId: string;
};
type DraftFixture = ReturnType<typeof draftFixture>;
const finding = (
  title: string,
  metadata: Record<string, unknown> = {},
): FixtureFinding => ({
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

for (const layout of ["standard", "diff", "deep"] as const) {
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

for (const layout of ["standard", "diff", "worker"] as const) {
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

async function recoverAndFinalize(
  normal: DraftFixture,
  recovered: DraftFixture,
  workers: Record<string, unknown>[] = [],
  details = false,
  replay = false,
): Promise<{
  normal: RecoveredFinding[];
  recovered: RecoveredFinding[];
  warnings: unknown[];
  historySummaries: string[];
}> {
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
if json.loads(sys.argv[7]):
 replayed=merge_saved_results(recovered,scan_id,binding,json.loads(sys.argv[5]),[],stopped=True,reason='Synthetic interruption',frozen_source_digests=recovery[0]['scan']['preservedSources'])
 assert replayed == recovery, 'Frozen recovery changed the retained documents'
ordinary=(manifest,json.loads((normal/'findings.json').read_text()),coverage)
results=[]
for root,documents in [(normal,ordinary),(recovered,recovery)]:
 documents[0]['scan'].update(id=scan_id,producer={'name':'codex-security-plugin','version':'0.1.0'},status='failed',startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
 for document in documents[1:]: document['scanId']=scan_id
 prepared=_prepare_scan_finalization(root,completion_warnings=warnings,draft_documents=documents)
 results.append([{'title':row['title'],'identity':row['identity'],'fingerprints':row['fingerprints'],'findingId':row['findingId'],'occurrenceId':row['occurrenceId'],'workerMetadata':row.get('provenance',{}).get('workerId'),**({'summary':row['summary'],'locations':row['locations'],'severity':row['severity'],'candidateMetadata':{'provenance':row.get('provenance',{}).get('candidateId'),'extensions':row.get('extensions')}} if json.loads(sys.argv[6]) else {})} for row in prepared[3]['findings']])
print(json.dumps({'normal':results[0],'recovered':results[1],'warnings':warnings,'historySummaries':[previous.get('summary') for row in recovery[1]['findings'] for previous in row.get('provenance',{}).get('previousFindings',[]) if isinstance(previous,dict)]}))`,
      fileURLToPath(new URL("../../scripts", import.meta.url)),
      normal.root,
      recovered.root,
      normal.context.scanId!,
      JSON.stringify(workers),
      JSON.stringify(details),
      JSON.stringify(replay),
    ],
  );
  return JSON.parse(stdout);
}

for (const layout of ["standard", "diff", "deep"] as const) {
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
for (const layout of ["standard", "diff"] as const) {
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
  for (const metadata of ["provenance", "extensions"] as const) {
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
          const result = await recoverAndFinalize(normal, recovered, [], true);
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
          ...result.findings.map((row: FixtureFinding) => ({
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
        ? { extensions: { [identifier!]: "report-1" } }
        : {}),
    });
    const second = structuredClone(first);
    if (kind === "candidate aliases") {
      second.title = "Second review";
      second.provenance.candidateId = "case";
    } else if (kind === "report enrichment") {
      second.extensions = { [identifier!]: "report-1" };
    } else {
      second[metadata!] = {
        ...(second[metadata!] as Record<string, unknown>),
        candidateId: "candidate-1",
      };
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
      findings: result.findings.map((row: FixtureFinding) => ({
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
    const byTitle = (left: FixtureFinding, right: FixtureFinding) =>
      left.title.localeCompare(right.title);
    assert.deepEqual(
      comparison.recovered.sort(byTitle),
      comparison.normal.sort(byTitle),
    );
    assert.deepEqual(comparison.warnings, []);
  });
}

for (const layout of ["standard", "diff"] as const) {
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
    findings: result.findings.map((row: FixtureFinding) => ({
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

for (const layout of ["standard", "diff", "worker"] as const) {
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
          findings: saved.findings.map((row: FixtureFinding) => ({
            ...row,
            provenance: { ...row.provenance, workerId: "reviewer" },
          })),
        });
      }
      const result = await recoverAndFinalize(
        normal,
        recovered,
        workers,
        variant === "metadata enrichment",
      );
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
      const ordered = (rows: RecoveredFinding[]) =>
        rows.sort((left, right) =>
          left.findingId.localeCompare(right.findingId),
        );
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const)
  for (const metadata of ["provenance", "extensions"] as const) {
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

for (const layout of ["standard", "diff", "deep"] as const)
  for (const metadata of ["provenance", "extensions"] as const) {
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

for (const layout of ["standard", "diff", "deep"] as const) {
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
      findings: saved.findings.map((row: FixtureFinding) => ({
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

for (const layout of ["standard", "diff", "deep"] as const) {
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
  for (const metadata of [
    { id: "synthetic-worker" },
    ["synthetic-worker"],
  ] as const) {
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
for (const layout of ["standard", "diff", "deep"] as const) {
  for (const shape of ["summary revision", "shared ledger"]) {
    test(`${layout}: report reconciliation ${shape}`, async (t) => {
      const normal = await fixture(t, layout);
      const recovered = await fixture(t, layout);
      const first = finding("First review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(shape === "shared ledger"
          ? { extensions: { ledgerRowId: "ledger-1" } }
          : {}),
      });
      const second = { ...structuredClone(first), title: "Second review" };
      const snapshots =
        shape === "summary revision"
          ? [
              [first, second],
              [{ ...first, summary: "Revised evidence." }, second],
            ]
          : [[first, second]];
      for (const findings of snapshots) {
        await normal.write({ ...normal.draft(), findings });
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          { ...recovered.draft(), findings },
          false,
        );
      }
      const result = await recoverAndFinalize(normal, recovered, [], true);

      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, result.normal.length);
      assert.deepEqual(result.warnings, []);
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
    });
  }
}

test("deep: refined candidate retains independent cross-location report", async (t) => {
  const normal = await fixture(t, "deep");
  const recovered = await fixture(t, "deep");
  const normalRoot = path.join(normal.root, "reviewer");
  const recoveredRoot = path.join(recovered.root, "reviewer");
  await mkdir(normalRoot);
  await mkdir(recoveredRoot);
  const normalWorker = draftFixture(normalRoot, "worker");
  const recoveredWorker = draftFixture(recoveredRoot, "worker");
  const first = finding("First review", {
    severity: { level: "high" },
    provenance: { source: "local_plugin", candidateId: "candidate-1" },
  });
  const refined = {
    ...first,
    locations: [{ path: "src/example.py", startLine: 2 }],
  };
  const second = {
    ...structuredClone(first),
    title: "Second review",
    summary: "Independent evidence.",
    severity: { level: "low" },
  };
  for (const findings of [[first], [refined, second]]) {
    await normalWorker.write({ ...normalWorker.draft(), findings });
    await draftApi.saveScanDraftCheckpoint(
      recoveredWorker.context,
      { ...recoveredWorker.draft(), findings },
      false,
    );
  }
  const saved = JSON.parse(
    await readFile(path.join(normalRoot, "result.json"), "utf8"),
  );
  await normal.write({
    ...normal.draft(),
    findings: saved.findings.map((row: FixtureFinding) => ({
      ...row,
      provenance: { ...row.provenance, workerId: "reviewer" },
    })),
  });
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [
      {
        id: "reviewer",
        kind: "discovery",
        artifact_dir: recoveredRoot,
        result_manifest_path: null,
        attempt: 1,
      },
    ],
    true,
  );

  assert.ok(result.recovered.some((row) => row.title === "Second review"));
  assert.equal(result.normal.length, 3);
  assert.equal(result.recovered.length, 3);
  assert.deepEqual(result.warnings, []);
  const ordered = (rows: RecoveredFinding[]) =>
    [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
  assert.deepEqual(ordered(result.recovered), ordered(result.normal));
});
for (const layout of ["standard", "diff"] as const) {
  test(`${layout}: revised sibling publication completes with unique identities`, async (t) => {
    const f = await fixture(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const second = { ...structuredClone(first), title: "Second review" };
    await f.write({ ...f.draft(), findings: [first, second] });
    await f.write({
      ...f.draft({}, true),
      findings: [{ ...first, summary: "Revised evidence." }, second],
    });
    const { stdout } = await execFileAsync(
      process.env.PYTHON?.trim() || "python3",
      [
        "-c",
        `import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from finalize_scan_contract import _prepare_scan_finalization
root=Path(sys.argv[2])
documents=tuple(json.loads((root/name).read_text()) for name in ('scan-manifest.json','findings.json','coverage.json'))
documents[0]['scan'].update(id=sys.argv[3],status='completed',producer={'name':'test','version':'1'},startedAt='2026-05-31T18:00:00Z',completedAt='2026-05-31T18:09:00Z')
for document in documents[1:]: document['scanId']=sys.argv[3]
prepared=_prepare_scan_finalization(root,draft_documents=documents)
print(len(prepared[3]['findings']))`,
        fileURLToPath(new URL("../../scripts", import.meta.url)),
        f.root,
        f.context.scanId!,
      ],
    );
    assert.equal(stdout.trim(), "2");
  });
}
for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: repeated shared-ledger publication preserves allocated identities`, async (t) => {
    const normal = await fixture(t, layout);
    const recovered = await fixture(t, layout);
    const first = finding("First review", {
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
      extensions: { ledgerRowId: "ledger-1" },
    });
    const second = { ...structuredClone(first), title: "Second review" };
    for (let index = 0; index < 2; index++) {
      for (const f of [normal, recovered])
        await f.write({ ...f.draft(), findings: [first, second] });
    }
    const result = await recoverAndFinalize(normal, recovered, [], true);
    assert.equal(result.normal.length, 2);
    assert.equal(result.recovered.length, 2);
    assert.deepEqual(result.warnings, []);
    assert.deepEqual(result.recovered, result.normal);
  });
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const cut of ["canonical", "raw"]) {
    test(`${layout}: ownership enrichment preserves publication identity (${cut})`, async (t) => {
      const normal = await fixture(t, layout);
      const recovered = await fixture(t, layout);
      const first = finding("Synthetic ownership review", {
        identity: { anchor: "authored-review" },
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
      });
      const second = {
        ...first,
        provenance: { ...first.provenance, workerId: "worker-a" },
      };
      for (const row of [first, second]) {
        await normal.write({ ...normal.draft(), findings: [row] });
        if (cut === "canonical")
          await recovered.write({ ...recovered.draft(), findings: [row] });
        else
          await draftApi.saveScanDraftCheckpoint(
            recovered.context,
            { ...recovered.draft(), findings: [row] },
            false,
          );
      }
      const result = await recoverAndFinalize(normal, recovered);

      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  test(`${layout}: ownership enrichment keeps a newly known independent owner`, async (t) => {
    const normal = await fixture(t, layout),
      recovered = await fixture(t, layout);
    const first = finding("Synthetic ownership review", {
      identity: { anchor: "authored-first" },
      provenance: { source: "local_plugin", candidateId: "candidate-1" },
    });
    const owned = {
      ...first,
      provenance: { ...first.provenance, workerId: "worker-a" },
    };
    const independent = {
      ...first,
      identity: { anchor: "authored-second" },
      provenance: { ...first.provenance, workerId: "worker-b" },
    };
    for (const findings of [[first], [owned, independent]]) {
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
  });
}
for (const authored of [false, true]) {
  test(`deep: ownership enrichment cannot bridge bound workers authored=${authored}`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const workers = [],
      findings = [];
    for (const id of ["worker-a", "worker-b"]) {
      const workerRoot = path.join(recovered.root, id);
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const value = finding("Synthetic bound owner review", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      for (const row of [
        value,
        { ...value, provenance: { ...value.provenance, workerId: id } },
      ]) {
        await draftApi.saveScanDraftCheckpoint(
          worker.context,
          { ...worker.draft(), findings: [row] },
          false,
        );
      }
      findings.push({
        ...value,
        provenance: { ...value.provenance, workerId: id },
      });
      workers.push({
        id,
        kind: "discovery",
        artifact_dir: workerRoot,
        result_manifest_path: null,
        attempt: 1,
      });
    }
    await normal.write({ ...normal.draft(), findings });
    const result = await recoverAndFinalize(normal, recovered, workers);

    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
  });
}

const checkpointName = (input: unknown) =>
  createHash("sha256").update(JSON.stringify(input)).digest("hex") + ".json";
for (const order of ["earlier-first", "later-first"]) {
  for (const metadata of ["extensions", "provenance"] as const) {
    for (const initialLevel of ["low", "high"]) {
      test(`worker revised raw checkpoint retains ${metadata} enrichment (${order}, ${initialLevel} to low)`, async (t) => {
        const normal = await fixture(t, "deep"),
          recovered = await fixture(t, "deep");
        const normalRoot = path.join(normal.root, "reviewer"),
          recoveredRoot = path.join(recovered.root, "reviewer");
        for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
        const worker = draftFixture(normalRoot, "worker"),
          recoveryWorker = draftFixture(recoveredRoot, "worker");
        const initial = {
          ...finding("Synthetic review"),
          summary: "Initial assessment.",
          severity: { level: initialLevel },
        };
        const revised = {
          ...initial,
          summary: "Corrected assessment.",
          severity: { level: "low" },
          [metadata]: { ...initial[metadata], candidateId: "candidate-1" },
        };
        const oldDraft = { ...worker.draft(), findings: [initial] };
        let newDraft,
          suffix = 0;
        do {
          newDraft = {
            ...worker.draft(),
            findings: [revised],
            threatModel: { summary: `Synthetic checkpoint ${suffix++}.` },
          };
        } while (
          checkpointName(oldDraft) < checkpointName(newDraft) !==
          (order === "earlier-first")
        );
        for (const [index, draft] of [oldDraft, newDraft].entries()) {
          await worker.write(draft);
          await draftApi.saveScanDraftCheckpoint(
            recoveryWorker.context,
            draft,
            false,
          );
          await utimes(
            path.join(recoveredRoot, "checkpoints", checkpointName(draft)),
            100 + index * 100,
            100 + index * 100,
          );
        }
        const saved = JSON.parse(
          await readFile(path.join(normalRoot, "result.json"), "utf8"),
        );
        assert.equal(saved.findings.length, 1);
        assert.equal(saved.findings[0].summary, revised.summary);
        assert.equal(saved.findings[0].severity.level, "low");
        assert.equal(saved.findings[0][metadata].candidateId, "candidate-1");
        await normal.write({
          ...normal.draft(),
          findings: saved.findings.map((row: FixtureFinding) => ({
            ...row,
            provenance: { ...row.provenance, workerId: "reviewer" },
          })),
        });
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [
            {
              id: "reviewer",
              kind: "discovery",
              artifact_dir: recoveredRoot,
              result_manifest_path: null,
              attempt: 1,
            },
          ],
          true,
        );
        assert.deepEqual(result.warnings, []);
        assert.equal(result.recovered.length, 1);
        assert.deepEqual(result.recovered, result.normal);
      });
    }
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const [field, value] of Object.entries({
    description: "Synthetic annotation",
    source: "authored",
    version: 1,
  })) {
    for (const authoredFirst of [true, false]) {
      test(`${layout}: semantic identity reserves ${field} metadata (authored first=${authoredFirst})`, async (t) => {
        const normal = await fixture(t, layout),
          recovered = await fixture(t, layout);
        const authored = finding("First review", {
          identity: {
            anchor: "candidate-1",
            instance: "second-review",
            [field]: value,
          },
          extensions: { candidateId: "candidate-1" },
        });
        const generated = finding("Second review", {
          locations: [{ path: "src/example.py", startLine: 2 }],
          extensions: { candidateId: "candidate-1" },
        });
        const reserved = finding("Reserved review", {
          identity: {
            anchor: "candidate-1",
            instance: "second-review-2",
            [field]: value,
          },
          locations: [{ path: "src/example.py", startLine: 3 }],
          extensions: { candidateId: "candidate-1" },
        });
        const findings = authoredFirst
          ? [authored, generated, reserved]
          : [generated, reserved, authored];
        await normal.write({ ...normal.draft(), findings });
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          { ...recovered.draft(), findings },
          false,
        );
        const result = await recoverAndFinalize(normal, recovered, [], true);
        assert.equal(result.normal.length, 3);
        assert.equal(result.recovered.length, 3);
        assert.deepEqual(result.warnings, []);
        assert.deepEqual(result.recovered, result.normal);
        assert.deepEqual(
          result.recovered.find((row) => row.title === "First review")!
            .identity,
          authored.identity,
        );
        assert.equal(
          result.recovered.find((row) => row.title === "Second review")!
            .identity.instance,
          "second-review-3",
        );
      });
    }
  }
}

for (const sameTitle of [false, true]) {
  test(`bound owner overrides shared metadata sameTitle=${sameTitle}`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const workers = [],
      findings = [];
    for (const [index, id] of ["worker-a", "worker-b"].entries()) {
      const workerRoot = path.join(recovered.root, id);
      await mkdir(workerRoot);
      const worker = draftFixture(workerRoot, "worker");
      const value = finding(
        sameTitle
          ? "Synthetic shared review"
          : `${index === 0 ? "First" : "Second"} review`,
        {
          provenance: {
            source: "local_plugin",
            candidateId: "candidate-1",
            workerId: "discovery",
          },
        },
      );
      await worker.write({ ...worker.draft(), findings: [value] });
      const saved = JSON.parse(
        await readFile(path.join(workerRoot, "result.json"), "utf8"),
      );
      findings.push(...saved.findings);
      workers.push({
        id,
        kind: "discovery",
        artifact_dir: workerRoot,
        result_manifest_path: null,
        attempt: 1,
      });
    }
    await normal.write({ ...normal.draft(), findings });
    const result = await recoverAndFinalize(normal, recovered, workers);
    assert.equal(result.normal.length, 2);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const authored of [false, true]) {
  test(`bound owner keeps same worker metadata revision authored=${authored}`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const workerRoot = path.join(recovered.root, "worker-a"),
      normalWorkerRoot = path.join(normal.root, "worker-a");
    await mkdir(workerRoot);
    await mkdir(normalWorkerRoot);
    const worker = draftFixture(workerRoot, "worker"),
      normalWorker = draftFixture(normalWorkerRoot, "worker");
    for (const alias of ["discovery", "refined"]) {
      const value = finding("Synthetic shared review", {
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: alias,
        },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      await normalWorker.write({ ...normalWorker.draft(), findings: [value] });
      await draftApi.saveScanDraftCheckpoint(
        worker.context,
        { ...worker.draft(), findings: [value] },
        false,
      );
    }
    const saved = JSON.parse(
      await readFile(path.join(normalWorkerRoot, "result.json"), "utf8"),
    );
    await normal.write({ ...normal.draft(), findings: saved.findings });
    const result = await recoverAndFinalize(normal, recovered, [
      {
        id: "worker-a",
        kind: "discovery",
        artifact_dir: workerRoot,
        result_manifest_path: null,
        attempt: 1,
      },
    ]);
    assert.equal(result.normal.length, 1);
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

const savedWorker = (root: string) => ({
  id: "reviewer",
  kind: "discovery",
  artifact_dir: root,
  result_manifest_path: null,
  attempt: 1,
});
async function dateDraftFiles(root: string, time: number): Promise<void> {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const target = path.join(root, entry.name);
    if (entry.isDirectory()) await dateDraftFiles(target, time);
    else await utimes(target, time, time);
  }
}

for (const metadata of ["provenance", "extensions"] as const) {
  for (const shape of ["shared siblings", "reportId", "ledgerRowId"]) {
    test(`raw group authority preserves ${shape} with ${metadata} candidates`, async (t) => {
      const normal = await fixture(t, "deep"),
        recovered = await fixture(t, "deep");
      const normalRoot = path.join(normal.root, "reviewer"),
        recoveredRoot = path.join(recovered.root, "reviewer");
      for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
      const writer = draftFixture(normalRoot, "worker"),
        interrupted = draftFixture(recoveredRoot, "worker");
      const first = finding("First review");
      first[metadata] = { ...first[metadata], candidateId: "candidate-1" };
      if (shape === "shared siblings")
        first.extensions = { ...first.extensions, ledgerRowId: "ledger-1" };
      const second = { ...structuredClone(first), title: "Second review" };
      const initial = shape === "shared siblings" ? [first, second] : [first];
      const revised = {
        ...(shape === "shared siblings" ? second : first),
        summary: "Revised evidence.",
        severity: { level: "high" },
        ...(shape === "shared siblings"
          ? {}
          : {
              locations: [{ path: "src/example.py", startLine: 1, endLine: 2 }],
              extensions: { ...first.extensions, [shape]: "report-1" },
            }),
      };
      for (const worker of [writer, interrupted])
        await worker.write({ ...worker.draft(), findings: initial });
      await dateDraftFiles(recoveredRoot, 100);
      const update = { ...writer.draft(), findings: [revised] };
      await writer.write(update);
      await draftApi.saveScanDraftCheckpoint(
        interrupted.context,
        update,
        false,
      );
      await utimes(
        path.join(recoveredRoot, "checkpoints", checkpointName(update)),
        200,
        200,
      );
      const saved = JSON.parse(
        await readFile(path.join(normalRoot, "result.json"), "utf8"),
      );
      assert.equal(saved.findings.length, initial.length);
      await normal.write({
        ...normal.draft(),
        findings: saved.findings.map((row: FixtureFinding) => ({
          ...row,
          provenance: { ...row.provenance, workerId: "reviewer" },
        })),
      });
      const result = await recoverAndFinalize(
        normal,
        recovered,
        [savedWorker(recoveredRoot)],
        true,
        true,
      );
      const ordered = (rows: RecoveredFinding[]) =>
        [...rows].sort((a, b) => a.findingId.localeCompare(b.findingId));
      assert.equal(result.normal.length, initial.length);
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const authored of [false, true]) {
    test(`${layout}: canonical group retains ownership enrichment (authored=${authored})`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const initial = finding("Synthetic ownership", {
        provenance: { source: "local_plugin", candidateId: "candidate-1" },
        ...(authored ? { identity: { anchor: "authored-review" } } : {}),
      });
      for (const writer of [normal, recovered])
        await writer.write({ ...writer.draft(), findings: [initial] });
      await dateDraftFiles(recovered.root, 100);
      const revised = {
        ...initial,
        provenance: { ...initial.provenance, workerId: "reviewer" },
      };
      const update = { ...normal.draft(), findings: [revised] };
      await normal.write(update);
      await draftApi.saveScanDraftCheckpoint(recovered.context, update, false);
      const { handoffClaimToken: _claim, ...checkpoint } = update;
      await utimes(
        path.join(recovered.root, "checkpoints", checkpointName(checkpoint)),
        200,
        200,
      );
      const result = await recoverAndFinalize(
        normal,
        recovered,
        [],
        true,
        true,
      );
      assert.equal(result.normal.length, 1);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}

for (const layout of ["standard", "diff"] as const) {
  for (const metadata of ["provenance", "extensions"] as const) {
    test(`${layout}: reciprocal containment preserves ${metadata} sibling identities`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const first = finding("Synthetic review");
      first[metadata] = { ...first[metadata], candidateId: "candidate-1" };
      const second = {
        ...structuredClone(first),
        extensions: { ...first.extensions, reportId: "report-1" },
      };
      for (const writer of [normal, recovered])
        await writer.write({ ...writer.draft(), findings: [first, second] });
      const before = JSON.parse(
        await readFile(path.join(normal.root, "findings.json"), "utf8"),
      );
      await dateDraftFiles(recovered.root, 100);
      const update = {
        ...normal.draft(),
        findings: [{ ...first, summary: "Revised evidence." }, second],
      };
      await normal.write(update);
      const saved = JSON.parse(
        await readFile(path.join(normal.root, "findings.json"), "utf8"),
      );
      assert.equal(saved.findings.length, 2);
      assert.deepEqual(
        saved.findings.map((row: FixtureFinding) => row.identity),
        before.findings.map((row: FixtureFinding) => row.identity),
      );
      await draftApi.saveScanDraftCheckpoint(recovered.context, update, false);
      const { handoffClaimToken: _claim, ...checkpoint } = update;
      await utimes(
        path.join(recovered.root, "checkpoints", checkpointName(checkpoint)),
        200,
        200,
      );
      const result = await recoverAndFinalize(
        normal,
        recovered,
        [],
        true,
        true,
      );
      assert.equal(result.normal.length, 2);
      assert.deepEqual(result.recovered, result.normal);
      assert.deepEqual(result.warnings, []);
    });
  }
}
const revisionFinding = (level: string, summary: string) =>
  finding("Synthetic review", {
    identity: { anchor: "candidate-1" },
    severity: { level },
    summary,
    provenance: {
      source: "local_plugin",
      candidateId: "candidate-1",
      workerId: "reviewer",
    },
  });
for (const source of ["selected checkpoint", "published result"]) {
  test(`finding precedence retains ${source} at tied timestamps`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const output = path.join(recovered.root, "reviewer");
    await mkdir(output);
    const worker = draftFixture(output, "worker");
    const initial = {
      ...worker.draft({}, true),
      findings: [revisionFinding("low", "Initial evidence.")],
    };
    const latest = {
      ...worker.draft({}, true),
      findings: [revisionFinding("high", "Completed evidence.")],
    };
    await worker.write(initial);
    await worker.write(latest);
    const saved = JSON.parse(
      await readFile(path.join(output, "result.json"), "utf8"),
    );
    await normal.write({ ...normal.draft({}, true), findings: saved.findings });
    // Valid JSON whitespace controls filename order without changing the evidence.
    const names = await readdir(path.join(output, "checkpoints"));
    let contents = JSON.stringify(initial),
      name = "";
    do {
      contents += "\n";
      name = createHash("sha256").update(contents).digest("hex") + ".json";
    } while (names.some((existing) => existing > name));
    await writeFile(path.join(output, "checkpoints", name), contents);
    if (source === "published result") {
      const { rm } = await import("node:fs/promises");
      await rm(path.join(output, "checkpoint-head.json"));
    }
    await dateDraftFiles(output, 100);
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [savedWorker(output)],
      true,
      true,
    );
    assert.equal(result.normal[0].severity.level, "high");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}
for (const layout of ["standard", "diff", "worker"] as const) {
  test(`${layout}: finding precedence retains terminal evidence over later progress`, async (t) => {
    const parentLayout = layout === "worker" ? "deep" : layout;
    const normal = await fixture(t, parentLayout),
      recovered = await fixture(t, parentLayout);
    const normalRoot =
      layout === "worker" ? path.join(normal.root, "reviewer") : normal.root;
    const recoveredRoot =
      layout === "worker"
        ? path.join(recovered.root, "reviewer")
        : recovered.root;
    if (layout === "worker")
      for (const root of [normalRoot, recoveredRoot]) await mkdir(root);
    const writer =
      layout === "worker" ? draftFixture(normalRoot, "worker") : normal;
    const interrupted =
      layout === "worker" ? draftFixture(recoveredRoot, "worker") : recovered;
    const terminal = {
      ...writer.draft({}, true),
      findings: [revisionFinding("high", "Completed evidence.")],
    };
    const progress = {
      ...writer.draft(),
      findings: [revisionFinding("low", "Incomplete progress.")],
    };
    for (const f of [writer, interrupted]) await f.write(terminal);
    await dateDraftFiles(recoveredRoot, 100);
    await writer.write(progress);
    await draftApi.saveScanDraftCheckpoint(
      interrupted.context,
      progress,
      false,
    );
    const { handoffClaimToken: _claim, ...rawProgress } = progress;
    await utimes(
      path.join(recoveredRoot, "checkpoints", checkpointName(rawProgress)),
      200,
      200,
    );
    if (layout === "worker") {
      const saved = JSON.parse(
        await readFile(path.join(normalRoot, "result.json"), "utf8"),
      );
      assert.equal(saved.findings[0].severity.level, "high");
      await normal.write({
        ...normal.draft({}, true),
        findings: saved.findings,
      });
    }
    const result = await recoverAndFinalize(
      normal,
      recovered,
      layout === "worker" ? [savedWorker(recoveredRoot)] : [],
      true,
      true,
    );
    assert.equal(result.normal[0].severity.level, "high");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
    assert.ok(result.historySummaries.includes("Incomplete progress."));
  });
}
test("finding precedence compares parent and worker observation times", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  const workerRoot = path.join(recovered.root, "reviewer");
  await mkdir(workerRoot);
  const worker = draftFixture(workerRoot, "worker");
  await worker.write({
    ...worker.draft({}, true),
    findings: [revisionFinding("low", "Earlier worker evidence.")],
  });
  const latest = {
    ...normal.draft({}, true),
    findings: [revisionFinding("high", "Newer parent evidence.")],
  };
  for (const f of [normal, recovered]) await f.write(latest);
  await dateDraftFiles(recovered.root, 200);
  await dateDraftFiles(workerRoot, 100);
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [savedWorker(workerRoot)],
    true,
    true,
  );
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});
for (const revised of [false, true]) {
  test(`finding revision retains the published collision identity (revised=${revised})`, async (t) => {
    const normal = await fixture(t, "deep"),
      recovered = await fixture(t, "deep");
    const findings = [1, 2].map((line) =>
      finding(`Synthetic report ${line}`, {
        identity: { anchor: "shared" },
        locations: [{ path: "src/example.py", startLine: line }],
        provenance: {
          source: "local_plugin",
          candidateId: "candidate-1",
          workerId: "reviewer",
        },
      }),
    );
    const workerRoot = path.join(recovered.root, "reviewer");
    await mkdir(workerRoot);
    const worker = draftFixture(workerRoot, "worker");
    await worker.write({ ...worker.draft({}, true), findings });
    for (const f of [normal, recovered])
      await f.write({ ...f.draft({}, true), findings });
    await dateDraftFiles(recovered.root, 100);
    const latest = findings.map((row) => ({
      ...row,
      summary: revised ? "Updated evidence." : row.summary,
    }));
    await worker.write({
      ...worker.draft({}, true),
      findings: latest,
      threatModel: { summary: "New context." },
    });
    if (revised)
      await normal.write({ ...normal.draft({}, true), findings: latest });
    const result = await recoverAndFinalize(
      normal,
      recovered,
      [savedWorker(workerRoot)],
      true,
      true,
    );
    assert.equal(result.normal[1].identity.instance, "saved-2");
    assert.deepEqual(result.recovered, result.normal);
    assert.deepEqual(result.warnings, []);
  });
}

test("finding precedence keeps a resumed worker revision despite newer archive timestamps", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  const output = path.join(recovered.root, "reviewer"),
    archive = path.join(output, "attempts", "attempt-1");
  await mkdir(archive, { recursive: true });
  const oldWorker = draftFixture(archive, "worker"),
    currentWorker = draftFixture(output, "worker");
  await oldWorker.write({
    ...oldWorker.draft({}, true),
    findings: [revisionFinding("high", "Archived assessment.")],
  });
  const latest = {
    ...currentWorker.draft({}, true),
    findings: [revisionFinding("low", "Corrected resumed assessment.")],
  };
  await currentWorker.write(latest);
  await normal.write({ ...normal.draft({}, true), findings: latest.findings });
  await dateDraftFiles(output, 100);
  await dateDraftFiles(archive, 200);
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [{ ...savedWorker(output), attempt: 2 }],
    true,
    true,
  );
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});

test("finding precedence excludes archived attempts before comparing a parent revision", async (t) => {
  const normal = await fixture(t, "deep"),
    recovered = await fixture(t, "deep");
  const output = path.join(recovered.root, "reviewer"),
    archive = path.join(output, "attempts", "attempt-1");
  await mkdir(archive, { recursive: true });
  const oldWorker = draftFixture(archive, "worker"),
    currentWorker = draftFixture(output, "worker");
  await oldWorker.write({
    ...oldWorker.draft({}, true),
    findings: [revisionFinding("low", "Archived assessment.")],
  });
  await currentWorker.write({
    ...currentWorker.draft({}, true),
    findings: [revisionFinding("low", "Current worker assessment.")],
  });
  const latest = {
    ...normal.draft({}, true),
    findings: [revisionFinding("high", "Newer parent assessment.")],
  };
  for (const f of [normal, recovered]) await f.write(latest);
  await dateDraftFiles(recovered.root, 150);
  await dateDraftFiles(output, 100);
  await dateDraftFiles(archive, 200);
  const result = await recoverAndFinalize(
    normal,
    recovered,
    [{ ...savedWorker(output), attempt: 2 }],
    true,
    true,
  );
  assert.deepEqual(result.recovered, result.normal);
  assert.deepEqual(result.warnings, []);
});

for (const layout of ["standard", "diff", "deep"] as const) {
  for (const reverse of [false, true]) {
    for (const published of [false, true]) {
      test(`one-to-one ${layout} unreported revision (published=${published}, reverse=${reverse})`, async (t) => {
        const normal = await fixture(t, layout),
          recovered = await fixture(t, layout);
        const first = finding("First review");
        const revised = {
          ...first,
          summary: "Revised synthetic evidence.",
          severity: { level: "high" },
        };
        const second = finding("Independent review", {
          extensions: { reportId: "report-2" },
        });
        const initial = { ...normal.draft(), findings: [first] };
        await normal.write(initial);
        if (published)
          await recovered.write({ ...recovered.draft(), findings: [first] });
        else
          await draftApi.saveScanDraftCheckpoint(
            recovered.context,
            { ...recovered.draft(), findings: [first] },
            false,
          );
        await dateDraftFiles(recovered.root, 100);
        const rows = reverse ? [second, revised] : [revised, second];
        await normal.write({ ...normal.draft(), findings: rows });
        const update = { ...recovered.draft(), findings: rows };
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          update,
          false,
        );
        const { handoffClaimToken: _claim, ...checkpoint } = update;
        await utimes(
          path.join(recovered.root, "checkpoints", checkpointName(checkpoint)),
          200,
          200,
        );
        const result = await recoverAndFinalize(
          normal,
          recovered,
          [],
          true,
          true,
        );
        assert.equal(result.normal.length, 2);
        assert.equal(result.recovered.length, 2);
        const ordered = (values: RecoveredFinding[]) =>
          [...values].sort((a, b) => a.title.localeCompare(b.title));
        assert.deepEqual(ordered(result.recovered), ordered(result.normal));
        assert.deepEqual(result.warnings, []);
      });
    }
    test(`one-to-one ${layout} historical siblings (reverse=${reverse})`, async (t) => {
      const normal = await fixture(t, layout),
        recovered = await fixture(t, layout);
      const first = finding("Synthetic review", {
        extensions: { candidateId: "candidate-1" },
      });
      const second = {
        ...structuredClone(first),
        locations: [{ path: "src/example.py", startLine: 2 }],
      };
      const finalRows = reverse ? [second, first] : [first, second];
      for (const [index, rows] of [[first], [second], finalRows].entries()) {
        await normal.write({ ...normal.draft(), findings: rows });
        const update = { ...recovered.draft(), findings: rows };
        await draftApi.saveScanDraftCheckpoint(
          recovered.context,
          update,
          false,
        );
        const { handoffClaimToken: _claim, ...checkpoint } = update;
        await utimes(
          path.join(recovered.root, "checkpoints", checkpointName(checkpoint)),
          (index + 1) * 100,
          (index + 1) * 100,
        );
      }
      const result = await recoverAndFinalize(
        normal,
        recovered,
        [],
        true,
        true,
      );
      assert.equal(result.normal.length, 2);
      assert.equal(result.recovered.length, 2);
      const ordered = (values: RecoveredFinding[]) =>
        [...values].sort(
          (a, b) => a.locations[0]!.startLine - b.locations[0]!.startLine,
        );
      assert.deepEqual(ordered(result.recovered), ordered(result.normal));
      assert.deepEqual(result.warnings, []);
    });
  }
}
