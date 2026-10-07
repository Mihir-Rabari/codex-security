import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { importSource } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFileAsync = promisify(execFile);
const { createScanArtifactContext } = await importSource(
  "../src/artifact-context.ts",
  { absWorkingDir: import.meta.dirname },
);
const { recordCodexSecurityScanDraftViaWorkbench: record } = await importSource(
  "../src/artifact-scan-draft.ts",
  { absWorkingDir: import.meta.dirname },
);

for (const collision of [false, true]) {
  for (const missingReceipt of [false, true]) {
    for (const disposition of ["rejected", "not_applicable"] as const) {
      test(`candidate receipt recovery retains a general closure (collision=${collision}, missing=${missingReceipt}, disposition=${disposition})`, async (t) => {
        const directory = await temporaryDirectory(
          "candidate-work-identity-",
          true,
        );
        t.after(() => rm(directory, { recursive: true, force: true }));
        const target = path.join(directory, "target");
        const home = path.join(directory, "home");
        await mkdir(target);
        await mkdir(home, { mode: 0o700 });
        await writeFile(path.join(target, "app.py"), "synthetic source\n");
        const workbench = async (args: string[]) => {
          const { stdout } = await execFileAsync(
            process.env.PYTHON?.trim() || "python3",
            [
              path.join(import.meta.dirname, "../../scripts/workbench_db.py"),
              ...args,
            ],
            {
              env: {
                ...process.env,
                CODEX_HOME: home,
                CODEX_SECURITY_STATE_DIR: path.join(directory, "state"),
              },
            },
          );
          return JSON.parse(stdout);
        };
        const { scan } = await workbench([
          "start-headless-standard-scan",
          "--thread-id",
          "synthetic-general-review",
          "--target-path",
          target,
          "--scope",
          ".",
          "--scan-root",
          path.join(directory, "scans"),
        ]);
        const context = await createScanArtifactContext(
          scan.scanId,
          workbench,
          {
            requireRunning: true,
          },
        );
        const first = await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: false,
            findings: [],
            coverage: {
              completeness: "partial",
              surfaces: [],
              explicitExclusions: [],
              deferred: [
                { id: "general-review", reason: "Independent general review." },
              ],
            },
          },
          workbench,
        );
        const generalId = first.coverage.deferred[0]!.id;
        const closure = {
          id: generalId,
          reason: "Independent general review completed.",
        };
        const receipt = path.join(context.root, "artifacts/receipt.txt");
        await mkdir(path.dirname(receipt), { recursive: true });
        await writeFile(receipt, "Synthetic candidate review evidence.\n");
        await record(
          context,
          {
            scanId: scan.scanId,
            handoffClaimToken: context.handoffClaimToken,
            complete: true,
            findings: [],
            coverage: {
              completeness: "complete",
              surfaces: [
                {
                  id: "candidate-decision",
                  label: "Candidate review",
                  candidateId: collision ? generalId : "candidate-review",
                  disposition,
                  notes: "Candidate review completed separately.",
                  receiptRefs: ["artifacts/receipt.txt"],
                },
              ],
              explicitExclusions: [],
              deferred: [],
              resolvedDeferred: [closure],
            },
          },
          workbench,
        );
        if (missingReceipt) await unlink(receipt);
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        const coveragePath = path.join(context.root, "coverage.json");
        const saved = await readFile(coveragePath);
        const coverage = JSON.parse(saved.toString());
        assert.deepEqual(coverage.resolvedDeferred, [closure]);
        assert.equal(
          coverage.surfaces[0].disposition,
          missingReceipt ? "needs_follow_up" : disposition,
        );
        await workbench([
          "prepare-scan-completion",
          "--scan-id",
          scan.scanId,
          "--claim-token",
          context.handoffClaimToken!,
        ]);
        assert.deepEqual(await readFile(coveragePath), saved);
      });
    }
  }
}
