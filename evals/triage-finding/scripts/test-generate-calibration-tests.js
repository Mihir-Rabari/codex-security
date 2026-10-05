#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const evalDir = path.resolve(__dirname, "..");
const generator = path.join(evalDir, "scripts", "generate-calibration-tests.js");
const dataset = path.join(evalDir, "datasets", "triage-calibration-seed.json");
const { selectedVariants, variantCaseId, inputId, targetRepoPath } = require("./generate-calibration-tests");
const { plannedJobs } = require("./hydrate-calibration-repos");
const trackedTests = path.join(evalDir, "tests", "calibration-oss.yaml");

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "triage-calibration-tests-"));
process.on("exit", () => fs.rmSync(tmpDir, { recursive: true, force: true }));
const generated = path.join(tmpDir, "calibration-oss.yaml");
const generatedSmoke = path.join(tmpDir, "calibration-smoke.yaml");

execFileSync(process.execPath, [generator, "--dataset", dataset, "--output", generated], {
  cwd: evalDir,
  stdio: "pipe",
});

const generatedYaml = fs.readFileSync(generated, "utf8");
const trackedYaml = fs.readFileSync(trackedTests, "utf8");

assert.equal(generatedYaml, trackedYaml, "tracked calibration tests are stale; run calibration:generate");
const variants = selectedVariants(JSON.parse(fs.readFileSync(dataset, "utf8")), {});
const ids = variants.map(({ testCase, variant }) => variantCaseId(testCase, variant));
assert.equal(new Set(ids).size, variants.length);
for (const { testCase, variant } of variants) {
  const id = variantCaseId(testCase, variant);
  assert.match(id, /^case-[a-f0-9]{16}$/);
  assert.equal(inputId(testCase, variant), id);
  assert.equal(path.basename(targetRepoPath("/repos", testCase, variant)), id);
  assert.ok(generatedYaml.includes(`case_id: ${id}`));
}
for (const job of plannedJobs(JSON.parse(fs.readFileSync(dataset, "utf8")), { repoRoot: "/repos" })) {
  assert.ok(ids.includes(path.basename(job.targetDir)));
}
assert.doesNotMatch(generatedYaml, /(?:case_id:|input_id:|target_repo:)[^\n]*(?:-vulnerable|-fixed|\/vulnerable|\/fixed)/);
assert.match(generatedYaml, /expected_verdicts: confirmed/);
assert.match(generatedYaml, /expected_verdicts: not_actionable/);
assert.doesNotMatch(
  generatedYaml,
  /expected_evidence_terms:\n\s+- /,
  "Promptfoo expands array-valued vars into extra test cases; evidence terms must be a scalar",
);

execFileSync(
  process.execPath,
  [
    generator,
    "--dataset",
    dataset,
    "--output",
    generatedSmoke,
    "--case",
    "oss-dompurify-ghsa-v8jm-5vwx-cfxm",
    "--variant",
    "vulnerable",
  ],
  {
    cwd: evalDir,
    stdio: "pipe",
  },
);

const smokeYaml = fs.readFileSync(generatedSmoke, "utf8");
assert.equal((smokeYaml.match(/^- description:/gm) || []).length, 1);
assert.match(smokeYaml, /calibration_variant: vulnerable/);
assert.doesNotMatch(smokeYaml, /calibration_variant: fixed/);
const selected = variants.find(({ testCase, variant }) => testCase.case_id === "oss-dompurify-ghsa-v8jm-5vwx-cfxm" && variant.variant_id === "vulnerable");
assert.ok(smokeYaml.includes(`case_id: ${variantCaseId(selected.testCase, selected.variant)}`));

console.log("calibration test generation matches tracked YAML and supports filtered smoke output");
