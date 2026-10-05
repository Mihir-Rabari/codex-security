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
 results.append([{'title':row['title'],'identity':row['identity'],'fingerprints':row['fingerprints'],'findingId':row['findingId']} for row in prepared[3]['findings']])
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
    for (const cut of ["raw", "reconciled"]) {
      test(`${layout}: ${metadata} enrichment retains identities after two ${cut} interruptions`, async (t) => {
        const normal = await fixture(t, layout);
        const recovered = await fixture(t, layout);
        const first = finding("Synthetic report", {
          extensions: { reportId: "report-1" },
        });
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
