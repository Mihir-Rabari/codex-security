import { join, dirname } from "node:path";
import { mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "bun:test";
import { build } from "esbuild";
import {
  combineScanCoverage,
  createScanMergeValidator,
  deterministicScanMerge,
  materializeScanAggregate,
  hydrateScanAggregate,
  serializeScanAggregate,
  scanAggregateRevisionArtifacts,
  scanMergePrompt,
  scanMergeModelInputs,
  type ScanMergeInput,
  type ScanMergeDecision,
} from "../src/scan-merge.js";
import {
  prepareSemanticScanDraft,
  scanFindingIdentity,
  type JsonObject,
  type SemanticCoverage,
  type SemanticFinding,
} from "../src/scan-semantics.js";
import { semanticFinding, semanticCoverage } from "./helpers/semantic-scan.js";

const parent = "7fc17317-9594-49e0-b06a-d72fd7e14bba";
const root = fileURLToPath(
  new URL("./fixtures/merge-parent/", import.meta.url),
);
const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
let merge: Awaited<ReturnType<typeof createScanMergeValidator>>;
beforeAll(async () => {
  merge = await createScanMergeValidator(pluginRoot);
});
function finding(anchor = "shared", extra: Partial<SemanticFinding> = {}) {
  return semanticFinding({ identity: { anchor }, ...extra });
}
function child(
  scanId: string,
  findings: SemanticFinding[] = [finding()],
  coverage: JsonObject = {},
): ScanMergeInput {
  return {
    scanId,
    scanDir: join(root, "artifacts", "scans", scanId),
    sourceFindings: structuredClone(findings),
    draft: {
      scanId: parent,
      findings: findings.map((value, index) => ({
        ...structuredClone(value),
        provenance: {
          ...value.provenance,
          sourceFindingIds: [`${scanId}:${index}`],
        },
      })),
      coverage: semanticCoverage(coverage),
    },
  };
}
function decision(...refs: string[][]): ScanMergeDecision {
  return {
    scanId: parent,
    groups: refs.map((sourceFindingIds) => ({
      sourceFindingIds,
      representativeId: sourceFindingIds[0]!,
    })),
  };
}

describe("local scan merging", () => {
  test("keeps immutable originals once and materializes only public exports", () => {
    const input = child("a", [
      finding("shared", { extensions: { detail: "exact" } }),
    ]);
    const result = merge(decision(["a:0"]), [input], null);
    expect(result.aggregate.sourceFindings).toEqual({
      "a:0": input.sourceFindings[0]!,
    });
    expect(
      result.aggregate.findings[0]!.provenance.sourceFindings,
    ).toBeUndefined();
    const exported = materializeScanAggregate(result.aggregate);
    expect(exported).not.toHaveProperty("sourceFindings");
    expect(exported.findings[0]!.provenance.sourceFindings).toEqual([
      { id: "a:0", finding: input.sourceFindings[0]! },
    ]);
    exported.findings[0]!.title = "changed export";
    result.aggregate.sourceFindings["a:0"]!["title"] = "changed internal copy";
    expect(input.sourceFindings[0]!["title"]).toBe("Unsafe output");
    expect(result.aggregate.findings[0]!.title).toBe("Unsafe output");
  });

  test.each([
    [decision(["unknown:0"]), "unknown source"],
    [decision(["a:0"], ["a:0"]), "more than once"],
    [decision(), "unaccounted"],
    [
      {
        scanId: parent,
        groups: [{ sourceFindingIds: ["a:0"], representativeId: "elsewhere" }],
      },
      "representative",
    ],
    [
      { scanId: parent, groups: [{ representativeId: "a:0" }] },
      "Invalid scan merge",
    ],
    [{ scanId: parent, findings: [] }, "Invalid scan merge"],
  ])("rejects incomplete or invalid source partitions %#", (raw, message) => {
    expect(() => merge(raw, [child("a")], null)).toThrow(String(message));
  });

  test("rejects unfinished inputs and a different parent", () => {
    const input = child("a");
    input.draft.complete = false;
    expect(() => merge(decision(["a:0"]), [input], null)).toThrow(
      "completed inputs",
    );
    delete input.draft.complete;
    input.draft.scanId = "different";
    expect(() => merge(decision(["a:0"]), [input], null)).toThrow(
      "different parent",
    );
  });

  test("retains accepted identities, prevents splits, and attributes novel groups once", () => {
    const a = child("a"),
      b = child("b");
    const first = merge(decision(["a:0", "b:0"]), [a, b], null);
    expect(first.newFindingScanIds).toEqual(["a"]);
    expect(() =>
      merge(decision(["a:0"], ["b:0"]), [], first.aggregate),
    ).toThrow("split");
    const later = merge(
      decision(["c:0"], ["d:0", "b:0", "a:0"]),
      [child("c"), child("d")],
      first.aggregate,
    );
    expect(later.newFindingScanIds).toEqual(["c"]);
    expect(scanFindingIdentity(later.aggregate.findings[1]!)).toBe(
      scanFindingIdentity(first.aggregate.findings[0]!),
    );
    expect(
      new Set(later.aggregate.findings.map(scanFindingIdentity)).size,
    ).toBe(2);
    expect(
      later.aggregate.findings.every(
        (f) => f.provenance["previousFindings"] === undefined,
      ),
    ).toBe(true);
  });

  test("combines repairs and locations and retains the highest observed severity", () => {
    const a = child("a", [
      finding("a", {
        remediation: "Repair first",
        severity: { level: "low" },
        remediationTests: ["test first"],
      }),
    ]);
    const b = child("b", [
      finding("b", {
        remediation: "Repair second",
        locations: [{ path: "src/second.ts", startLine: 2 }],
        preventiveControls: ["control second"],
      }),
    ]);
    const result = merge(decision(["a:0", "b:0"]), [a, b], null).aggregate
      .findings[0]!;
    expect(result.remediation).toBe("Repair first\n\nRepair second");
    expect(result.locations).toHaveLength(2);
    expect(result.remediationTests).toEqual(["test first"]);
    expect(result.preventiveControls).toEqual(["control second"]);
    expect(result.severity.level).toBe("high");
  });

  test("merges accepted aliases while preserving every original identity in exports", () => {
    const inputs = [
      child("a", [finding("alias-a")]),
      child("b", [finding("alias-b")]),
    ];
    const previous = merge(decision(["a:0"], ["b:0"]), inputs, null).aggregate;
    const result = merge(decision(["b:0", "a:0"]), [], previous);
    expect(result.newFindingScanIds).toEqual([]);
    expect(result.aggregate.findings[0]!.identity).toEqual(
      previous.findings[0]!.identity,
    );
    expect(
      materializeScanAggregate(result.aggregate).findings[0]!.provenance
        .sourceFindings,
    ).toHaveLength(2);
  });

  test("does not repeat accepted summary and repair paragraphs in later observations", () => {
    const a = child("a", [
      finding("a", { summary: "First detail", remediation: "First repair" }),
    ]);
    const b = child("b", [
      finding("b", {
        summary: "Second detail\n\nShared detail",
        remediation: "Second repair\n\nShared repair",
      }),
    ]);
    const first = merge(decision(["a:0", "b:0"]), [a, b], null).aggregate;
    first.findings[0]!.summary += "\n\nAccepted context";
    const before = structuredClone(first);
    const repeated = merge(
      decision(["a:0", "b:0", "c:0"]),
      [child("c", [b.draft.findings[0]!])],
      first,
    ).aggregate;
    expect(repeated.findings[0]!.summary).toBe(
      "First detail\n\nSecond detail\n\nShared detail\n\nAccepted context",
    );
    expect(repeated.findings[0]!.remediation).toBe(
      "First repair\n\nSecond repair\n\nShared repair",
    );
    expect(first).toEqual(before);
    expect(
      materializeScanAggregate(repeated).findings[0]!.provenance.sourceFindings,
    ).toHaveLength(3);
  });

  test("stores accepted revisions once without recursive histories", () => {
    const first = merge(decision(["a:0"]), [child("a")], null).aggregate;
    const second = merge(
      decision(["a:0", "b:0"]),
      [child("b")],
      first,
    ).aggregate;
    expect(Object.values(second.revisions!)).toEqual(first.findings);
    expect(
      materializeScanAggregate(second).findings[0]!.provenance[
        "previousFindings"
      ],
    ).toEqual(first.findings);
    const repeated = merge(decision(["a:0", "b:0"]), [], second).aggregate;
    expect(repeated.revisions).toEqual(second.revisions);
    expect(repeated.findings[0]!.provenance["revisionIds"]).toEqual(
      second.findings[0]!.provenance["revisionIds"],
    );
  });

  test("round-trips aggregate references without copying original payloads into checkpoints", async () => {
    const directory = await mkdtemp(join(tmpdir(), "merge-references-"));
    try {
      const a = child("a"),
        b = child("b");
      const first = merge(decision(["a:0"]), [a], null).aggregate;
      const aggregate = {
        ...merge(decision(["a:0", "b:0"]), [b], first).aggregate,
        coverage: semanticCoverage(),
      };
      const artifacts = [
        ...scanMergeModelInputs([a, b], null).artifacts,
        ...scanAggregateRevisionArtifacts(aggregate, new Set()),
      ];
      for (const artifact of artifacts) {
        await mkdir(dirname(join(directory, artifact.path)), {
          recursive: true,
          mode: 0o700,
        });
        await writeFile(join(directory, artifact.path), artifact.contents, {
          mode: 0o600,
        });
      }
      const stored = serializeScanAggregate(aggregate);
      expect(stored).not.toHaveProperty("sourceFindings");
      expect(stored).not.toHaveProperty("revisions");
      expect(stored.sourceFindingIds).toEqual(["a:0", "b:0"]);
      expect(await hydrateScanAggregate(directory, stored)).toEqual(aggregate);
      expect(
        scanAggregateRevisionArtifacts(aggregate, new Set(stored.revisionIds)),
      ).toEqual([]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("reconciles differing contexts even when reports are empty", () => {
    const a = child("a", []),
      b = child("b", []);
    a.draft.threatModel = { summary: "First context" };
    b.draft.threatModel = { summary: "Second context" };
    expect(() => merge(decision(), [a, b], null)).toThrow(
      "ambiguous threatModel",
    );
    expect(
      merge(
        { ...decision(), threatModel: { summary: "Combined" } },
        [a, b],
        null,
      ).aggregate.threatModel,
    ).toEqual({ summary: "Combined" });
    expect(deterministicScanMerge([a, b], null)).toBeNull();
  });

  test("avoids model decisions only for a first single report or compatible empty batches", () => {
    const a = child("a");
    const first = deterministicScanMerge([a], null)!;
    const previous = merge(first, [a], null).aggregate;
    expect(first).toEqual(decision(["a:0"]));
    expect(
      deterministicScanMerge([child("a", []), child("b", [])], null),
    ).toEqual(decision());
    expect(deterministicScanMerge([a, child("b", [])], null)).toBeNull();
    expect(deterministicScanMerge([child("b")], previous)).toBeNull();
    expect(deterministicScanMerge([child("b", [])], previous)).toEqual(first);
    const empty = child("b", []);
    empty.draft.scope = { summary: "different" };
    previous.scope = { summary: "previous" };
    expect(deterministicScanMerge([empty], previous)).toBeNull();
  });

  test("unions already projected coverage without mutating inputs or namespacing twice", () => {
    const first = child("first", [], {
      completeness: "partial",
      surfaces: [
        {
          id: "first/api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/first/artifacts/review.json"],
        },
      ],
      deferred: [
        {
          candidateId: "first-candidate",
          reason: "Check ownership.",
          surfaceIds: ["first/api"],
        },
      ],
      openQuestions: ["Can an untrusted caller reach the route?"],
    });
    const second = child("second", [], {
      surfaces: [
        {
          id: "second/api",
          label: "API",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/second/artifacts/review.json"],
        },
      ],
      deferred: [
        {
          candidateId: "second-candidate",
          reason: "Check ownership.",
          surfaceIds: ["second/api"],
        },
      ],
      openQuestions: first.draft.coverage.openQuestions,
    });
    const before = structuredClone([first, second]);
    const combined = combineScanCoverage(
      [first.draft.coverage, second.draft.coverage],
      ["One interrupted scan retains unfinished work."],
    );
    expect(combined.completeness).toBe("partial");
    expect(combined.surfaces).toEqual([
      ...first.draft.coverage.surfaces,
      ...second.draft.coverage.surfaces,
    ]);
    expect(combined.deferred).toEqual([
      ...first.draft.coverage.deferred,
      ...second.draft.coverage.deferred,
      { reason: "One interrupted scan retains unfinished work." },
    ]);
    expect(combined.openQuestions).toHaveLength(1);
    combined.surfaces[0]!.id = "changed";
    expect([first, second]).toEqual(before);
    expect(
      combineScanCoverage([
        child("unknown", [], { completeness: "unknown" }).draft.coverage,
      ]).completeness,
    ).toBe("unknown");
    expect(
      combineScanCoverage([child("empty", []).draft.coverage]).completeness,
    ).toBe("complete");
    expect(combineScanCoverage([], ["No scan completed."]).completeness).toBe(
      "partial",
    );
  });

  test("combines large coverage and unresolved lists on Node without argument limits", async () => {
    // Bun accepts more function arguments than supported Node runtimes do.
    const bundled = await build({
      stdin: {
        resolveDir: fileURLToPath(new URL("../src/", import.meta.url)),
        contents: `
import assert from "node:assert/strict";
import { combineScanCoverage } from "./scan-merge.ts";
const count = 150_000;
const coverage = {
  completeness: "complete",
  surfaces: Array.from({ length: count }, (_, index) => ({
    id: "child/surface-" + index, label: "Surface " + index, disposition: "no_issue_found",
  })),
  explicitExclusions: [],
  deferred: Array.from({ length: count }, (_, index) => ({ reason: "Deferred " + index })),
};
const unresolved = Array.from({ length: count }, (_, index) => "Unresolved " + index);
const combined = combineScanCoverage([coverage], unresolved);
assert.equal(combined.completeness, "partial");
assert.deepEqual(combined.surfaces, coverage.surfaces);
assert.deepEqual(combined.deferred.slice(0, count), coverage.deferred);
assert.deepEqual(combined.deferred.slice(count), unresolved.map(reason => ({ reason })));
combined.surfaces[0].label = "Changed";
assert.equal(coverage.surfaces[0].label, "Surface 0");
`,
      },
      bundle: true,
      platform: "node",
      format: "cjs",
      write: false,
    });
    execFileSync("node", ["--input-type=commonjs"], {
      input: bundled.outputFiles[0]!.text,
      encoding: "utf8",
    });
  });

  test("retains saved parent coverage without rebasing its identities or receipts", () => {
    const prior: SemanticCoverage = {
      completeness: "partial",
      surfaces: [
        {
          id: "prior/surface",
          label: "Saved surface",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/deep-scan/prior/review.json"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Generated dependencies." },
      ],
      deferred: [
        {
          candidateId: "prior:candidate",
          reason: "Saved incomplete validation.",
          surfaceIds: ["prior/surface"],
          receiptRefs: ["artifacts/deep-scan/prior/candidate.json"],
        },
      ],
      openQuestions: ["Can a caller reach the saved candidate?"],
    };
    const original = structuredClone(prior);
    const fresh = child("fresh", [], {
      completeness: "complete",
      surfaces: [
        {
          id: "fresh/new-surface",
          label: "Fresh surface",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/scans/fresh/artifacts/fresh.json"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/**", reason: "Generated dependencies." },
      ],
    });
    const coverage = combineScanCoverage([fresh.draft.coverage], [], prior);
    expect(coverage["completeness"]).toBe("partial");
    expect(coverage["surfaces"]).toEqual([
      prior.surfaces[0]!,
      {
        id: "fresh/new-surface",
        label: "Fresh surface",
        disposition: "no_issue_found",
        receiptRefs: ["artifacts/scans/fresh/artifacts/fresh.json"],
      },
    ]);
    expect(coverage["deferred"]).toEqual(prior.deferred);
    expect(coverage["explicitExclusions"]).toEqual(prior.explicitExclusions);
    expect(coverage["openQuestions"]).toEqual(prior.openQuestions);
    (coverage["surfaces"] as JsonObject[])[0]!["id"] = "changed";
    expect(prior).toEqual(original);
    expect(
      combineScanCoverage([], [], {
        completeness: "complete",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      })["completeness"],
    ).toBe("complete");
    expect(
      combineScanCoverage([fresh.draft.coverage], [], {
        completeness: "unknown",
        surfaces: [],
        explicitExclusions: [],
        deferred: [],
      })["completeness"],
    ).toBe("unknown");
  });

  test("uses ordinary target and coverage publication at the export boundary", () => {
    const input = child("first");
    const { aggregate } = merge(decision(["first:0"]), [input], null);
    const prepared = prepareSemanticScanDraft(
      {
        mode: "deep",
        targetRevision: "pinned-revision",
        targetContract: {
          target: {
            allowedKinds: ["repository"],
            targetId: "fixture",
            displayName: "Fixture",
          },
          scope: {
            requiredIncludePaths: ["src"],
            requiredExcludePaths: ["vendor"],
          },
        },
      },
      {
        ...materializeScanAggregate(aggregate),
        coverage: combineScanCoverage([input.draft.coverage]),
      },
    );
    expect(prepared.manifest).toHaveProperty(
      "scan.target.revision",
      "pinned-revision",
    );
    expect(prepared.coverage).toHaveProperty("mode", "scoped_path");
    expect(prepared.findings).toHaveProperty(
      "findings.0.provenance.sourceFindings",
      [{ id: "first:0", finding: input.sourceFindings[0]! }],
    );
  });

  test("publishes only new immutable originals and keeps complete oversized evidence", async () => {
    const a = child("a", [
      finding("a", { summary: "Unicode π. ".repeat(50_000) + "tail evidence" }),
    ]);
    const previous = merge(decision(["a:0"]), [a], null).aggregate;
    const initial = scanMergeModelInputs([a], null);
    expect(JSON.parse(initial.artifacts[0]!.contents.toString())).toEqual(
      a.sourceFindings[0],
    );
    const b = child("b");
    const later = scanMergeModelInputs([b], previous);
    expect(later.artifacts).toHaveLength(1);
    expect(later.artifacts[0]!.path).not.toBe(initial.artifacts[0]!.path);
    expect(JSON.parse(later.index.toString()).sources).toHaveLength(2);
    expect(JSON.parse(later.index.toString()).previous).not.toHaveProperty(
      "sourceFindings",
    );
    let calls = 0;
    const prompt = await scanMergePrompt(parent, [b], previous, root, {
      async restore() {
        throw new Error("Batch required");
      },
      async restoreMany(artifacts) {
        calls++;
        expect(artifacts).toHaveLength(2);
      },
    });
    expect(calls).toBe(1);
    expect(prompt).toContain("representativeId");
    expect(prompt).toContain(
      JSON.stringify(join(root, "artifacts/deep-scan/merge-inputs.json")),
    );
  });
});
