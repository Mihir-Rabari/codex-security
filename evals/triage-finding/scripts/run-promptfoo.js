#!/usr/bin/env node
"use strict";

const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const EVAL_ROOT = path.resolve(__dirname, "..");
const PLUGIN_ROOT = path.resolve(
  EVAL_ROOT,
  "..",
  "..",
  "plugins",
  "codex-security",
);
const TRIAGE_SKILL_ROOT = path.join(PLUGIN_ROOT, "skills", "triage-finding");
const PROMPTFOO_BIN = path.join(EVAL_ROOT, "node_modules", ".bin", "promptfoo");

function copyDirectory(sourceRoot, targetRoot, excludedNames = new Set()) {
  fs.mkdirSync(targetRoot, { recursive: true });
  for (const entry of fs.readdirSync(sourceRoot, { withFileTypes: true })) {
    if (excludedNames.has(entry.name)) {
      continue;
    }
    const sourcePath = path.join(sourceRoot, entry.name);
    const targetPath = path.join(targetRoot, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(sourcePath, targetPath, excludedNames);
      continue;
    }
    if (!entry.isFile()) {
      throw new Error(
        "Refusing to stage non-file runtime entry: " + sourcePath,
      );
    }
    fs.copyFileSync(sourcePath, targetPath);
  }
}

/**
 * Give Codex a throwaway working directory that contains only the skill files
 * it needs. The label-bearing dataset and Promptfoo harness stay in EVAL_ROOT.
 */
function stageSkillRuntime() {
  const runtimeRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "codex-security-triage-finding-"),
  );
  const stagedPluginRoot = path.join(runtimeRoot, "plugins", "codex-security");
  copyDirectory(
    TRIAGE_SKILL_ROOT,
    path.join(stagedPluginRoot, "skills", "triage-finding"),
    new Set(["evals"]),
  );
  for (const sharedDirectory of ["references", "schemas"]) {
    const sourcePath = path.join(PLUGIN_ROOT, sharedDirectory);
    if (fs.existsSync(sourcePath)) {
      copyDirectory(sourcePath, path.join(stagedPluginRoot, sharedDirectory));
    }
  }
  copyDirectory(
    path.join(EVAL_ROOT, "fixtures"),
    path.join(runtimeRoot, "evals", "triage-finding", "fixtures"),
  );
  return fs.realpathSync(runtimeRoot);
}

async function runPromptfoo(promptfooArgs, environment = {}) {
  const runtimeRoot = stageSkillRuntime();
  const env = {
    ...process.env,
    ...environment,
    TRIAGE_RUNTIME_ROOT: runtimeRoot,
    SASTBENCH_RUNTIME_ROOT: runtimeRoot,
    TRIAGE_CALIBRATION_ROOT: path.join(
      EVAL_ROOT,
      "artifacts",
      "calibration-repos",
    ),
  };
  let child;
  let interrupted;
  const handlers = ["SIGINT", "SIGTERM"].map((signal) => {
    const handler = () => {
      interrupted = signal;
      child?.kill(signal);
    };
    process.on(signal, handler);
    return [signal, handler];
  });
  try {
    return await new Promise((resolve, reject) => {
      child = childProcess.spawn(PROMPTFOO_BIN, promptfooArgs, {
        cwd: EVAL_ROOT,
        env,
        stdio: "inherit",
      });
      child.once("error", reject);
      child.once("close", (code, signal) => {
        const stoppedBy = interrupted || signal;
        resolve(
          stoppedBy === "SIGINT"
            ? 130
            : stoppedBy === "SIGTERM"
              ? 143
              : (code ?? 1),
        );
      });
    });
  } finally {
    for (const [signal, handler] of handlers) process.off(signal, handler);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  runPromptfoo(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });
}

module.exports = { runPromptfoo, stageSkillRuntime };
