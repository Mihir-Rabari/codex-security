import { expect, test } from "bun:test";
import { writeSemanticScanDraft } from "../src/scan-draft-publication.js";

test.each([false, true])(
  "staging cleanup preserves publication outcome (failure: %p)",
  async (fail) => {
    const failure = new Error("publication failed");
    const removed: string[] = [];
    const staged = new Map<string, unknown>();
    let invocation: readonly string[] = [];
    const publication = writeSemanticScanDraft(
      {
        scanDir: "/synthetic/scan",
        contract: {
          mode: "standard",
          targetContract: {
            target: {
              allowedKinds: ["git_worktree"],
              targetId: "synthetic",
              displayName: "fixture",
            },
            scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
          },
        },
        expectedDigest: "accepted-draft-digest",
        reconciledCheckpointIds: ["pending.json"],
        claimToken: "synthetic-claim",
        writer: {
          async restore(path, contents) {
            staged.set(path, JSON.parse(Buffer.from(contents).toString()));
          },
          async remove(path) {
            removed.push(path);
            throw new Error("cleanup unavailable");
          },
        },
        async workbench(args) {
          invocation = args;
          if (fail) throw failure;
        },
        onCleanupError() {
          throw new Error("optional diagnostic failed");
        },
      },
      {
        scanId: "synthetic-scan",
        handoffClaimToken: "synthetic-claim",
        findings: [],
        coverage: {
          completeness: "complete",
          surfaces: [],
          explicitExclusions: [],
          deferred: [],
        },
      },
    );
    if (fail) await expect(publication).rejects.toBe(failure);
    else await publication;
    expect(removed).toEqual([...staged.keys()]);
    expect(invocation.slice(-4)).toEqual([
      "--expected-draft-digest",
      "accepted-draft-digest",
      "--claim-token",
      "synthetic-claim",
    ]);
    const checkpoint = [...staged].find(([name]) =>
      name.endsWith(".checkpoint.json"),
    )![1];
    expect(checkpoint).not.toHaveProperty("handoffClaimToken");
  },
);
