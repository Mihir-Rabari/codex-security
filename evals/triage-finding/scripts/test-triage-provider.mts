import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
const require = createRequire(import.meta.url);
const { parse } = createRequire(require.resolve("promptfoo"))("yaml");

const evalRoot = path.resolve(import.meta.dirname, "..");
const runner = path.join(import.meta.dirname, "run-promptfoo.mts");
interface Capture {
  cwd: string;
  policy: string;
  proxies: Record<string, string>;
  nodePath: string;
  directories: string[];
  overrides: string[];
}

const proxies = {
  HTTP_PROXY: "http://http.example.test:8080",
  HTTPS_PROXY: "http://https.example.test:8080",
  ALL_PROXY: "http://all.example.test:8080",
  NO_PROXY: "localhost,.example.test",
};

function invoke(args: string[], environment: NodeJS.ProcessEnv) {
  return new Promise<{ code: number | null; output: string }>(
    (resolve, reject) => {
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", runner, ...args],
        {
          cwd: evalRoot,
          env: { ...process.env, ...environment, NODE_USE_ENV_PROXY: "" },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let output = "";
      child.stdout.on("data", (chunk) => {
        output += chunk;
      });
      child.stderr.on("data", (chunk) => {
        output += chunk;
      });
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, output }));
    },
  );
}

// Exercise the pinned provider and Codex SDK subprocess without a model request.
// The normal setup command supplies the host helper build used by the runner.
test(
  "provider preserves proxies and rebinds saved evaluations to fresh runtimes",
  { skip: process.platform === "win32", timeout: 120000 },
  async (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "triage-provider-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const capture = path.join(root, "captures.jsonl");
    const fakeCodex = path.join(root, "codex");
    const fail = path.join(root, "fail");
    fs.writeFileSync(
      fakeCodex,
      `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const cwd = process.argv[process.argv.indexOf('--cd') + 1];
const launcher = path.join(cwd, 'plugins/codex-security/scripts/launch_codex_security_mcp');
const fixture = path.join(cwd, 'evals/triage-finding/fixtures/repo');
fs.writeFileSync(path.join(fixture, 'SECURITY.md'), '# Synthetic policy\\n');
const policy = cp.execFileSync(launcher, ['--helper', 'resolve-security-md', '--repo', fixture, '--scope', 'src/server.js', '--out', '-'], {encoding:'utf8'});
const directories = process.argv.flatMap((arg, index) => arg === '--add-dir' ? [process.argv[index + 1]] : []);
const overrides = process.argv.flatMap((arg, index) => arg === '--config' ? [process.argv[index + 1]] : []);
fs.appendFileSync(${JSON.stringify(capture)}, JSON.stringify({cwd,policy,directories,overrides,nodePath:process.env.CODEX_MCP_NODE_PATH, proxies: Object.fromEntries(${JSON.stringify(Object.keys(proxies))}.map(key => [key,process.env[key]]))}) + '\\n');
console.log(JSON.stringify({type:'thread.started', thread_id:'synthetic-thread'}));
if (fs.existsSync(${JSON.stringify(fail)})) {
 console.log(JSON.stringify({type:'turn.failed',error:{message:'synthetic retryable failure'}}));
} else {
 console.log(JSON.stringify({type:'item.completed', item:{id:'message',type:'agent_message',text:'ok'}}));
 console.log(JSON.stringify({type:'turn.completed',usage:{input_tokens:1,cached_input_tokens:0,output_tokens:1}}));
}
`,
      { mode: 0o755 },
    );
    const ambientNode = path.join(root, "ambient-node", "bin", "node");
    fs.mkdirSync(path.dirname(ambientNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      ambientNode,
      fs.constants.COPYFILE_FICLONE,
    );
    const environment = {
      ...proxies,
      CODEX_MCP_NODE_PATH: ambientNode,
      OPENAI_API_KEY: "synthetic-test-key",
      PROMPTFOO_CONFIG_DIR: path.join(root, "state"),
      PROMPTFOO_DISABLE_WAL_MODE: "true",
      PROMPTFOO_DISABLE_TELEMETRY: "1",
      PROMPTFOO_DISABLE_UPDATE: "1",
    };
    const configPath = path.join(root, "config.json");
    const provider = parse(
      fs.readFileSync(path.join(evalRoot, "promptfooconfig.yaml"), "utf8"),
    ).providers[0];
    provider.id = `file://${path.join(import.meta.dirname, "triage-provider.mts")}`;
    provider.config.codex_path_override = fakeCodex;
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        providers: [provider],
        prompts: ["hello"],
        tests: [{ assert: [{ type: "equals", value: "ok" }] }],
      }),
    );
    fs.writeFileSync(fail, "");
    const initial = await invoke(
      [
        "eval",
        "-c",
        configPath,
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      environment,
    );
    assert.notEqual(initial.code, 0, initial.output);
    assert.match(initial.output, /synthetic retryable failure/);
    let rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture);
    assert.equal(rows.length, 1);
    assert.deepEqual(rows[0].proxies, proxies);
    assert.match(rows[0].policy, /Synthetic policy/);
    assert.equal(fs.existsSync(rows[0].cwd), false);
    fs.rmSync(fail);
    const retry = await invoke(
      [
        "eval",
        "--retry-errors",
        "--no-cache",
        "--no-share",
        "--no-progress-bar",
      ],
      environment,
    );
    assert.equal(retry.code, 0, retry.output);
    rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture);
    assert.equal(rows.length, 2);
    assert.notEqual(rows[0].cwd, rows[1].cwd);
    assert.equal(fs.existsSync(rows[1].cwd), false);

    // Delete the stored result to make a completed evaluation resumable, retaining
    // the original persisted provider configuration and prompt.
    const Database = createRequire(require.resolve("promptfoo"))(
      "better-sqlite3",
    );
    const database = new Database(
      path.join(environment.PROMPTFOO_CONFIG_DIR, "promptfoo.db"),
    );
    database.prepare("DELETE FROM eval_results").run();
    database.close();
    const resumed = await invoke(
      ["eval", "--resume", "--no-cache", "--no-share", "--no-progress-bar"],
      environment,
    );
    assert.equal(resumed.code, 0, resumed.output);
    rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture);
    assert.equal(rows.length, 3);
    assert.equal(new Set(rows.map((row) => row.cwd)).size, 3);
    for (const row of rows) {
      assert.deepEqual(row.proxies, proxies);
      assert.equal(fs.existsSync(row.cwd), false);
      assert.equal(row.nodePath, ambientNode);
      assert.deepEqual(row.directories, [path.dirname(row.nodePath)]);
    }

    const calibration = parse(
      fs.readFileSync(
        path.join(evalRoot, "promptfooconfig.calibration.yaml"),
        "utf8",
      ),
    ).providers[0];
    calibration.id = provider.id;
    calibration.config.codex_path_override = fakeCodex;
    const customNode = path.join(root, "custom-node", "bin", "node");
    fs.mkdirSync(path.dirname(customNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      customNode,
      fs.constants.COPYFILE_FICLONE,
    );
    calibration.config.cli_env.CODEX_MCP_NODE_PATH = customNode;
    const selectedNode = path.join(
      root,
      "selected-node",
      "bin",
      "synthetic-node",
    );
    fs.mkdirSync(path.dirname(selectedNode), { recursive: true });
    fs.copyFileSync(
      process.execPath,
      selectedNode,
      fs.constants.COPYFILE_FICLONE,
    );
    const nodeAlias = path.join(root, "node-alias");
    fs.symlinkSync(customNode, nodeAlias);
    const nodeChoices = [
      customNode,
      path.relative(path.join(os.tmpdir(), "runtime-placeholder"), customNode),
      "node",
      nodeAlias,
      path.join(root, "missing-node"),
      "synthetic-node",
    ];
    const calibrationConfig = path.join(root, "calibration.json");
    fs.mkdirSync(path.join(root, "case"));
    fs.writeFileSync(
      calibrationConfig,
      JSON.stringify({
        providers: nodeChoices.map((nodePath, index) => ({
          ...calibration,
          label: `custom-runtime-${index}`,
          config: {
            ...calibration.config,
            cli_env: {
              ...calibration.config.cli_env,
              CODEX_MCP_NODE_PATH: nodePath,
              PATH: `${path.dirname(selectedNode)}${path.delimiter}${path.dirname(customNode)}${path.delimiter}${process.env.PATH}`,
            },
          },
        })),
        prompts: ["hello"],
        tests: [
          {
            vars: { target_repo_root: root, case_id: "case" },
            assert: [{ type: "equals", value: "ok" }],
          },
        ],
      }),
    );
    const simultaneous = await Promise.all(
      [configPath, calibrationConfig].map((config, index) =>
        invoke(
          [
            "eval",
            "-c",
            config,
            "--no-cache",
            "--no-share",
            "--no-progress-bar",
          ],
          {
            ...environment,
            CODEX_MCP_NODE_PATH: index === 0 ? undefined : ambientNode,
            PROMPTFOO_CONFIG_DIR: path.join(root, `concurrent-${index}`),
          },
        ),
      ),
    );
    for (const result of simultaneous)
      assert.equal(result.code, 0, result.output);
    rows = fs
      .readFileSync(capture, "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Capture);
    assert.equal(rows.length, 10);
    assert.equal(new Set(rows.map((row) => row.cwd)).size, 5);
    for (const row of rows) {
      assert.deepEqual(row.proxies, proxies);
      assert.match(row.policy, /Synthetic policy/);
      assert.equal(fs.existsSync(row.cwd), false);
      assert.match(
        row.overrides.join("\n"),
        /permissions\.triage_runtime_only\.filesystem\.:workspace_roots="read"/,
      );
      assert.deepEqual(
        row.directories,
        row.nodePath === customNode || row.nodePath === selectedNode
          ? [path.join(root, "case"), path.dirname(row.nodePath)]
          : [path.dirname(row.nodePath)],
      );
    }
    assert.equal(rows.filter((row) => row.nodePath === customNode).length, 5);
    assert.equal(rows.filter((row) => row.nodePath === selectedNode).length, 1);
    assert.equal(rows.filter((row) => row.nodePath === ambientNode).length, 3);
    assert.equal(
      rows.filter((row) => row.nodePath === fs.realpathSync(process.execPath))
        .length,
      1,
    );
  },
);
