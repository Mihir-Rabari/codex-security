#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { createRequire } = require("node:module");
const childProcess = require("node:child_process");
const {
  stageSkillRuntime,
} = require("../../sastbench/scripts/run-sastbench-promptfoo.js");
const { CORPUS, FIXTURE_ROOT } = require("./sca-result.js");

const EVAL_ROOT = path.resolve(__dirname, "../..");

function codexPackageRequire() {
  const sdkRequire = createRequire(
    fs.realpathSync(
      path.join(EVAL_ROOT, "node_modules/@openai/codex-sdk/package.json"),
    ),
  );
  return createRequire(sdkRequire.resolve("@openai/codex/package.json"));
}

function nativeCodexRuntimeRoot() {
  const codexRequire = codexPackageRequire();
  return path.dirname(
    codexRequire.resolve(
      `@openai/codex-${process.platform}-${process.arch}/package.json`,
    ),
  );
}

function stageProviderConfig(
  runtime,
  codexHome,
  codexScript = path.join(
    path.dirname(codexPackageRequire().resolve("@openai/codex/package.json")),
    "bin/codex.js",
  ),
) {
  // Match the SDK's read-only helpers: an empty table does not remove inherited servers.
  const inherited = JSON.parse(
    childProcess.execFileSync(
      process.execPath,
      [
        codexScript,
        "-C",
        runtime,
        "-c",
        "features.plugins=false",
        "-c",
        "features.apps=false",
        "mcp",
        "list",
        "--json",
      ],
      { env: { ...process.env, CODEX_HOME: codexHome }, encoding: "utf8" },
    ),
  );
  const provider = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../provider.json"), "utf8"),
  );
  provider.config.cli_config.mcp_servers = Object.fromEntries(
    inherited.map(({ name }) => [name, { enabled: false }]),
  );
  const output = path.join(runtime, "provider.json");
  fs.writeFileSync(output, JSON.stringify(provider));
  return output;
}

function stageRuntime() {
  const runtime = stageSkillRuntime();
  try {
    for (const testCase of CORPUS.cases) {
      fs.cpSync(
        path.join(FIXTURE_ROOT, testCase.case_id),
        path.join(runtime, "cases", testCase.case_id),
        { recursive: true },
      );
    }
    return runtime;
  } catch (error) {
    fs.rmSync(runtime, { recursive: true, force: true });
    throw error;
  }
}

function main(args = process.argv.slice(2)) {
  if (args.length === 0)
    throw new Error("Expected Promptfoo arguments (validate config or eval)");
  const runtime = stageRuntime();
  fs.mkdirSync(path.join(EVAL_ROOT, "artifacts"), { recursive: true });
  try {
    const codexHome =
      process.env.CODEX_HOME || path.join(os.homedir(), ".codex");
    const providerConfig = stageProviderConfig(runtime, codexHome);
    childProcess.execFileSync(
      path.join(EVAL_ROOT, "node_modules/.bin/promptfoo"),
      args,
      {
        cwd: EVAL_ROOT,
        env: {
          ...process.env,
          SCA_EVAL_RUNTIME_ROOT: runtime,
          SCA_EVAL_CODEX_RUNTIME_ROOT: nativeCodexRuntimeRoot(),
          SCA_EVAL_CODEX_HOME: codexHome,
          SCA_EVAL_PROVIDER_CONFIG: providerConfig,
          PROMPTFOO_CONFIG_DIR: ".promptfoo",
          PROMPTFOO_DISABLE_WAL_MODE: "true",
        },
        stdio: "inherit",
      },
    );
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
}

if (require.main === module) main();
module.exports = {
  stageRuntime,
  stageProviderConfig,
  nativeCodexRuntimeRoot,
  main,
};
