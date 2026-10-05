#!/usr/bin/env node
import path from "node:path";
import fs from "node:fs";
import { createRequire } from "node:module";
const { runPromptfoo, stageSkillRuntime } = createRequire(import.meta.url)(
  "../../scripts/run-promptfoo.js",
);
const artifacts = path.resolve(import.meta.dirname, "..", "..", "artifacts");
if (
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  import.meta.filename === fs.realpathSync(process.argv[1])
) {
  runPromptfoo(process.argv.slice(2), {
    SASTBENCH_TARGET_ROOT: path.join(artifacts, "sastbench-targets"),
    SASTBENCH_GIT_CACHE_ROOT: path.join(artifacts, "sastbench-git-cache"),
  })
    .then((code: number) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(error);
      process.exitCode = 1;
    });
}
export { runPromptfoo, stageSkillRuntime };
