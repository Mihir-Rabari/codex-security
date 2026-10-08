#!/usr/bin/env node

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import runtimeVars from "./runtime-vars.mts";

const evalRoot = path.resolve(import.meta.dirname, "..");

// Fixture paths remain relative to the provider's freshly staged working root.
for (const target of [
  "evals/triage-finding/fixtures/repo",
  "evals/triage-finding/fixtures/policy-repo",
  path.join(evalRoot, "artifacts", "sastbench-targets", "opaque-target"),
  "https://github.com/example/repository",
  "No explicit repository supplied by the user.",
]) {
  assert.equal(runtimeVars({ target_repo: target }).target_repo, target);
}

const calibrationRepo = "calibration-0123456789abcdef";
for (const customRoot of ["", path.join(evalRoot, "custom targets # space")]) {
  const replayed = runtimeVars({
    calibration_repo: calibrationRepo,
    calibration_repo_root: customRoot,
    target_repo: "old checkout",
  });
  assert.equal(
    replayed.target_repo,
    path.join(
      customRoot || path.join(evalRoot, "artifacts", "calibration-repos"),
      calibrationRepo,
    ),
  );
}

for (const name of [
  "promptfooconfig.yaml",
  "promptfooconfig.calibration.yaml",
  "sastbench/promptfooconfig.sastbench.yaml",
]) {
  const config = fs.readFileSync(path.join(evalRoot, name), "utf8");
  assert.match(config, /":minimal": read\n\s+":workspace_roots": read/);
  assert.match(config, /plugins: false/);
  assert.match(config, /memories: false/);
  assert.doesNotMatch(config, /working_dir:|CODEX_MCP_NODE_PATH:/);
  if (name === "promptfooconfig.calibration.yaml") {
    assert.ok(config.includes("{{calibration_repo}}"));
    assert.match(config, /transformVars:/);
  }
}
assert.match(
  fs.readFileSync(
    path.join(evalRoot, "promptfooconfig.calibration-smoke.yaml"),
    "utf8",
  ),
  /\$ref: \.\/promptfooconfig\.calibration\.yaml/,
);
assert.ok(
  fs
    .readFileSync(path.join(evalRoot, "prompts/triage-request.txt"), "utf8")
    .startsWith(
      "Read and follow plugins/codex-security/skills/triage-finding/SKILL.md",
    ),
);
console.log("triage Promptfoo target path tests passed");
