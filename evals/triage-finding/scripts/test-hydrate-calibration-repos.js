#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const childProcess = require("node:child_process");
const path = require("node:path");

const evalDir = path.join(__dirname, "..");
const scriptPath = path.join(evalDir, "scripts", "hydrate-calibration-repos.js");

function runHydrator(args) {
  return childProcess.execFileSync(process.execPath, [scriptPath, ...args], {
    cwd: evalDir,
    encoding: "utf8",
  });
}

const allOutput = runHydrator(["--dry-run"]);
assert.match(allOutput, /would hydrate 16 calibration variants/);
assert.match(allOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);
assert.match(allOutput, /https:\/\/github\.com\/mantisbt\/mantisbt/);
assert.match(allOutput, /80990f43153167c73f11eb4b2bc7108d0c3d6b46/);

const filteredOutput = runHydrator(["--dry-run", "--case", "oss-mantisbt-ghsa-73vx-49mv-v8w5", "--variant", "fixed"]);
assert.match(filteredOutput, /would hydrate 1 calibration variant/);
assert.match(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/fixed/);
assert.doesNotMatch(filteredOutput, /oss-mantisbt-ghsa-73vx-49mv-v8w5\/vulnerable/);

console.log("calibration hydration dry-run tests passed");

const fs = require("node:fs");
const os = require("node:os");
const { plannedJobs } = require("./hydrate-calibration-repos");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "calibration-hydrate-"));
try {
  const git = (...args) => childProcess.execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "--quiet");
  git("-c", "user.name=Synthetic Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-m", "fixture");
  git("remote", "add", "origin", "https://original.example.test/repo");
  const head = git("rev-parse", "HEAD");
  const data = { cases: [{ case_id: "example", repo: { url: root }, variants: [{ variant_id: "fixed", checkout_ref: head }] }] };
  const repoRoot = path.join(root, "targets");
  const [job] = plannedJobs(data, { repoRoot });
  fs.mkdirSync(path.join(job.targetDir, ".git"), { recursive: true });
  const dataset = path.join(root, "dataset.json");
  fs.writeFileSync(dataset, JSON.stringify(data));
  const args = [scriptPath, "--dataset", dataset, "--repo-root", repoRoot];
  const failed = childProcess.spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.notEqual(failed.status, 0);
  assert.equal(git("remote", "get-url", "origin"), "https://original.example.test/repo");
  assert.equal(git("rev-parse", "HEAD"), head);
  fs.rmSync(job.targetDir, { recursive: true });
  childProcess.execFileSync(process.execPath, args, { stdio: "pipe" });
  assert.equal(childProcess.execFileSync("git", ["rev-parse", "HEAD"], { cwd: job.targetDir, encoding: "utf8" }).trim(), head);
  assert.equal(git("remote", "get-url", "origin"), "https://original.example.test/repo");
} finally {
  fs.rmSync(root, { recursive: true, force: true });
}
