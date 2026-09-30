import type { SemanticFinding } from "../src/semantic-models.js";
import { tmpdir } from "node:os";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { createScanMergeValidator } from "../src/scan-merge.js";
import {
  containsSavedFinding,
  preserveFindingDetails,
  type JsonObject,
} from "../src/scan-semantics.js";

const pluginRoot = fileURLToPath(
  new URL("../../../plugins/codex-security/", import.meta.url),
);
const scratch = tmpdir();
const parent = "11111111-2222-4333-8444-555555555555";
const alternate = "11111111-2222-4333-8444-666666666666";
const commonPath = "schemas/definitions/artifact-common.schema.json";
const draftPath = "schemas/tools/scan-draft.schema.json";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function schemaRoot() {
  await mkdir(scratch, { recursive: true });
  const root = await mkdtemp(join(scratch, "reconciliation-"));
  directories.push(root);
  await mkdir(join(root, "schemas/definitions"), { recursive: true });
  await mkdir(join(root, "schemas/tools"), { recursive: true });
  const [common, draft] = await Promise.all(
    [commonPath, draftPath].map(async (path) => {
      const text = await readFile(join(pluginRoot, path), "utf8");
      await writeFile(join(root, path), text);
      return JSON.parse(text);
    }),
  );
  return { root, common, draft };
}

test("schema reuse observes both files changing without changing existing validators", async () => {
  const { root, common, draft } = await schemaRoot();
  const first = await createScanMergeValidator(root);
  const repeated = await createScanMergeValidator(root);
  const empty = { scanId: parent, groups: [] };
  const expected = {
    scanId: parent,
    findings: [],
    sourceFindings: {},
    revisions: {},
  };
  expect(first(empty, [], null).aggregate).toEqual(expected);
  expect(repeated(empty, [], null).aggregate).toEqual(expected);

  const originalScanId = draft.$defs.scanDraftInput.properties.scanId;
  draft.$defs.scanDraftInput.properties.scanId = { const: alternate };
  await writeFile(join(root, draftPath), JSON.stringify(draft));
  const changedDraft = await createScanMergeValidator(root);
  expect(() => changedDraft(empty, [], null)).toThrow("Invalid scan merge");
  expect(first(empty, [], null).aggregate).toEqual(expected);

  draft.$defs.scanDraftInput.properties.scanId = originalScanId;
  common.$defs.scanId.const = alternate;
  await writeFile(join(root, draftPath), JSON.stringify(draft));
  await writeFile(join(root, commonPath), JSON.stringify(common));
  const changedCommon = await createScanMergeValidator(root);
  expect(() => changedCommon(empty, [], null)).toThrow("Invalid scan merge");
  expect(
    changedCommon({ ...empty, scanId: alternate }, [], null).aggregate.scanId,
  ).toBe(alternate);
  expect(repeated(empty, [], null).aggregate).toEqual(expected);

  await rm(join(root, commonPath));
  await expect(createScanMergeValidator(root)).rejects.toThrow("ENOENT");
  await writeFile(join(root, commonPath), "{");
  await expect(createScanMergeValidator(root)).rejects.toThrow(SyntaxError);
});

test("concurrent schema roots retain independent validation and errors", async () => {
  const [one, two] = await Promise.all([schemaRoot(), schemaRoot()]);
  two.common.$defs.scanId.const = alternate;
  await writeFile(join(two.root, commonPath), JSON.stringify(two.common));
  const validators = await Promise.all(
    [one.root, two.root, one.root, two.root].map(createScanMergeValidator),
  );
  for (const [index, validate] of validators.entries()) {
    const scanId = index % 2 === 0 ? parent : alternate;
    const empty = { scanId, groups: [] };
    const expected = {
      scanId,
      findings: [],
      sourceFindings: {},
      revisions: {},
    };
    expect(validate(empty, [], null).aggregate).toEqual(expected);
    expect(() => validate({ ...empty, groups: [{}] }, [], null)).toThrow(
      "Invalid scan merge",
    );
    expect(validate(empty, [], null).aggregate).toEqual(expected);
  }
});

function finding(anchor = "record"): SemanticFinding {
  return {
    ruleId: "security-misconfiguration.synthetic-record",
    identity: { anchor },
    title: "Synthetic configuration record",
    summary: "Original synthetic evidence.",
    severity: { level: "medium" },
    confidence: { level: "high", rationale: "Fixed offline fixture." },
    taxonomy: { category: "security-misconfiguration", cwe: ["CWE-16"] },
    locations: [{ path: "src/record.ts", startLine: 1, endLine: 2 }],
    remediation: "Correct the synthetic configuration.",
    provenance: { source: "local_plugin" },
    extensions: {
      opaque: { evidence: ["exact\u0000bytes", "x".repeat(16384)] },
    },
  };
}

function provenance(entry: JsonObject): JsonObject {
  return entry["provenance"] as JsonObject;
}

test("comparison projections do not mutate prior evidence and saved synthesis stays detached", () => {
  const previous = finding();
  provenance(previous)["previousFindings"] = [{ summary: "older" }];
  const before = structuredClone(previous);
  const current = finding();
  delete current["identity"];
  expect(containsSavedFinding(current, previous)).toBe(true);
  current["summary"] = "Changed synthesis.";
  expect(containsSavedFinding(current, previous)).toBe(false);
  preserveFindingDetails(current, previous);
  const history = provenance(current)["previousFindings"] as JsonObject[];
  expect(history[1]!["summary"]).toBe(previous["summary"]);
  (history[1]!["extensions"] as JsonObject)["opaque"] = { evidence: [] };
  expect(previous).toEqual(before);
});
