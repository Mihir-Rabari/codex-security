#!/usr/bin/env node
import path from "node:path";
import { realpathSync } from "node:fs";
import {
  runPromptfoo,
  stageSkillRuntime,
} from "../../scripts/run-promptfoo.mts";
const artifacts = path.resolve(import.meta.dirname, "..", "..", "artifacts");

function invokedAsMain() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === import.meta.filename;
  } catch {
    // A virtual entry point imports this module without invoking the runner.
    return false;
  }
}

if (invokedAsMain()) {
  runPromptfoo(process.argv.slice(2), {
    SASTBENCH_TARGET_ROOT: path.join(artifacts, "sastbench-targets"),
    SASTBENCH_GIT_CACHE_ROOT: path.join(artifacts, "sastbench-git-cache"),
  })
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}

export { runPromptfoo, stageSkillRuntime };
