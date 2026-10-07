#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";

const evalDir = path.resolve(import.meta.dirname, "..");
const generator = path.join(
  evalDir,
  "scripts",
  "generate-calibration-tests.mts",
);
const dataset = path.join(evalDir, "datasets", "triage-calibration-seed.json");
const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve("promptfoo"))("yaml");
const trackedTests = path.join(evalDir, "tests", "calibration-oss.yaml");

const tmpDir = fs.mkdtempSync(
  path.join(os.tmpdir(), "triage-calibration-tests-"),
);
process.on("exit", () => fs.rmSync(tmpDir, { recursive: true, force: true }));
const generated = path.join(tmpDir, "calibration-oss.yaml");
const generatedSmoke = path.join(tmpDir, "calibration-smoke.yaml");

execFileSync(
  process.execPath,
  [
    "--experimental-strip-types",
    generator,
    "--dataset",
    dataset,
    "--output",
    generated,
  ],
  {
    cwd: evalDir,
    stdio: "pipe",
  },
);

const generatedYaml = fs.readFileSync(generated, "utf8");
const trackedYaml = fs.readFileSync(trackedTests, "utf8");

assert.equal(
  generatedYaml,
  trackedYaml,
  "tracked calibration tests are stale; run calibration:generate",
);
const tests: {
  metadata: Record<string, string>;
  vars: Record<string, string>;
}[] = parse(generatedYaml);
const ids = tests.map((test) => test.vars.case_id);
assert.equal(ids.length, 16);
assert.equal(new Set(ids).size, ids.length);
for (const test of tests) {
  const id = test.vars.case_id;
  assert.match(id, /^case-[a-f0-9]{16}$/);
  assert.equal(test.metadata.case_id, id);
  assert.equal(test.vars.expected_ids, id);
  assert.equal(path.basename(test.vars.target_repo), id);
  assert.ok(test.vars.finding_input.includes(`input_id: ${id}`));
}
assert.doesNotMatch(
  generatedYaml,
  /(?:case_id:|input_id:|target_repo:)[^\n]*(?:-vulnerable|-fixed|\/vulnerable|\/fixed)/,
);
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
    "--experimental-strip-types",
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
const smoke = parse(smokeYaml)[0];
assert.equal(
  smoke.vars.case_id,
  tests.find(
    (test) =>
      test.metadata.calibration_case_id ===
        "oss-dompurify-ghsa-v8jm-5vwx-cfxm" &&
      test.metadata.calibration_variant === "vulnerable",
  )!.vars.case_id,
);

console.log(
  "calibration test generation matches tracked YAML and supports filtered smoke output",
);

const relativeOutput = path.join(tmpDir, "relative.yaml");
execFileSync(
  process.execPath,
  [
    "--experimental-strip-types",
    generator,
    "--output",
    relativeOutput,
    "--repo-root",
    "./scratch-repos",
  ],
  { cwd: tmpDir },
);
const explicitRoot = path.join(tmpDir, "scratch-repos");
const relativeYaml = fs.readFileSync(relativeOutput, "utf8");
assert.ok(
  relativeYaml.includes(`target_repo_root: ${JSON.stringify(explicitRoot)}`),
);
const hydration = execFileSync(
  process.execPath,
  [
    "--experimental-strip-types",
    path.join(evalDir, "scripts", "hydrate-calibration-repos.mts"),
    "--repo-root",
    explicitRoot,
    "--dry-run",
  ],
  { encoding: "utf8" },
);
const plannedPaths = hydration
  .split("\n")
  .filter((line) => line.startsWith("  "));
assert.deepEqual(
  (parse(relativeYaml) as typeof tests).map((test) => test.vars.target_repo),
  plannedPaths.map((line) => line.slice(2)),
);
