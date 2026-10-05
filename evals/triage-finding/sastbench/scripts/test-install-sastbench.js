#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");

const { verifyInstallation } = require("./install-sastbench");
const {
  EXPECTED_CASE_COUNT,
  EXPECTED_LABEL_COUNTS,
  SASTBENCH_COMMIT,
  SASTBENCH_DATASET_SHA256,
  SASTBENCH_REPOSITORY_URL,
} = require("./sastbench-lib");

function validInspection(overrides = {}) {
  return {
    origin: SASTBENCH_REPOSITORY_URL,
    head: SASTBENCH_COMMIT,
    clean: true,
    datasetSha256: SASTBENCH_DATASET_SHA256,
    caseCount: EXPECTED_CASE_COUNT,
    labelCounts: { ...EXPECTED_LABEL_COUNTS },
    ...overrides,
  };
}

assert.deepEqual(verifyInstallation(validInspection()), validInspection());
assert.throws(
  () => verifyInstallation(validInspection({ origin: "https://example.test/wrong.git" })),
  /origin mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ head: "0".repeat(40) })),
  /commit mismatch/,
);
assert.throws(() => verifyInstallation(validInspection({ clean: false })), /local changes/);
assert.throws(
  () => verifyInstallation(validInspection({ datasetSha256: "0".repeat(64) })),
  /dataset SHA-256 mismatch/,
);
assert.throws(
  () => verifyInstallation(validInspection({ caseCount: EXPECTED_CASE_COUNT - 1 })),
  /case count mismatch/,
);
assert.throws(
  () =>
    verifyInstallation(
      validInspection({
        labelCounts: { true_positive: 300, false_positive: 2437 },
      }),
    ),
  /true_positive count mismatch/,
);

console.log("sastbench installer verification tests passed");

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const childProcess = require("node:child_process");
const { installSastBench } = require("./install-sastbench");
const root = fs.mkdtempSync(path.join(os.tmpdir(), "sastbench-install-"));
const target = path.join(root, "checkout");
const originalExec = childProcess.execFileSync;
let fetches = 0;
try {
  childProcess.execFileSync = (_command, args, options) => {
    if (args[0] === "init") fs.mkdirSync(path.join(options.cwd, ".git"));
    if (args[0] === "fetch") { fetches++; throw new Error("synthetic fetch failed"); }
    return "";
  };
  for (let attempt = 0; attempt < 2; attempt++) {
    assert.throws(() => installSastBench(target), /synthetic fetch failed/);
    assert.equal(fs.existsSync(target), false);
  }
  assert.equal(fetches, 2, "a retry must fetch again instead of inspecting an incomplete checkout");
  fs.mkdirSync(target);
  fs.writeFileSync(path.join(target, "keep.txt"), "existing work");
  assert.throws(() => installSastBench(target), /not a Git checkout/);
  assert.equal(fs.readFileSync(path.join(target, "keep.txt"), "utf8"), "existing work");
} finally {
  childProcess.execFileSync = originalExec;
  fs.rmSync(root, { recursive: true, force: true });
}
