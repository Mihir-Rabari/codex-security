#!/usr/bin/env node
"use strict";

const path = require("node:path");
const { runPromptfoo, stageSkillRuntime } = require("../../scripts/run-promptfoo");
const artifacts = path.resolve(__dirname, "..", "..", "artifacts");

if (require.main === module) {
  runPromptfoo(process.argv.slice(2), {
    SASTBENCH_TARGET_ROOT: path.join(artifacts, "sastbench-targets"),
    SASTBENCH_GIT_CACHE_ROOT: path.join(artifacts, "sastbench-git-cache"),
  }).then((code) => { process.exitCode = code; }).catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { runPromptfoo, stageSkillRuntime };
