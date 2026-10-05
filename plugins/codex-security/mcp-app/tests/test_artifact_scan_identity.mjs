import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { draftApi, fixture } from "./scan-draft-recovery-fixture.mjs";

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
recovery=merge_saved_results(recovered,scan_id,binding,[],warnings,stopped=True,reason='Synthetic interruption')
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
        ],
      );
      const result = JSON.parse(stdout);
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
