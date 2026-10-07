#!/usr/bin/env node
import path from "node:path";
import { runMain } from "../../scripts/run-promptfoo.mts";
const artifacts = path.resolve(import.meta.dirname, "..", "..", "artifacts");

runMain(import.meta.filename, {
  SASTBENCH_TARGET_ROOT: path.join(artifacts, "sastbench-targets"),
  SASTBENCH_GIT_CACHE_ROOT: path.join(artifacts, "sastbench-git-cache"),
});
