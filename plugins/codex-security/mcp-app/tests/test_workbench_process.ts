import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import type { ExecFileOptionsWithStringEncoding } from "node:child_process";
import { promisify } from "node:util";

type WorkbenchProcessFixture = (
  python: string,
  args: string[],
  options: ExecFileOptionsWithStringEncoding,
) => Promise<{ stdout: string; stderr: string }>;

declare global {
  var workbenchProcessFixture: WorkbenchProcessFixture | undefined;
}

interface WorkbenchModule {
  executeWorkbench(
    python: string,
    args: string[],
    stateDir?: string,
    input?: string | Buffer,
  ): Promise<Record<string, unknown>>;
}
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
const invocations: {
  args: string[];
  options: ExecFileOptionsWithStringEncoding;
}[] = [];
let failure: Error | undefined;
globalThis.workbenchProcessFixture = (_python, args, options) => {
  invocations.push({ args, options });
  return failure
    ? Promise.reject(failure)
    : Promise.resolve({ stdout: "{}", stderr: "" });
};
try {
  const { executeWorkbench } = (await importModule({
    stdin: {
      contents:
        source.replace(
          "const execFileAsync = promisify(execFile);",
          "const execFileAsync = globalThis.workbenchProcessFixture;",
        ) + "\nexport { executeWorkbench };",
      loader: "ts",
      resolveDir: applicationRoot,
    },
    define: {
      __dirname: JSON.stringify(applicationRoot),
      "import.meta.url": JSON.stringify(
        new URL("../server.ts", import.meta.url).href,
      ),
    },
    loader: { ".md": "text" },
  })) as WorkbenchModule;
  for (const command of [
    "cancel-scan",
    "fail-scan",
    "preserve-scan-results",
    "complete-scan",
    "start-prompt-only-scan",
  ]) {
    await executeWorkbench("fixture-python", [command, "--scan-id", "fixture"]);
    assert.equal(
      invocations.at(-1)!.options.timeout,
      300_000,
      `${command} must allow its saved-result publication to finish`,
    );
  }
  await executeWorkbench("fixture-python", [
    "inspect-target",
    "--target-path",
    "/fixture",
  ]);
  assert.equal(invocations.at(-1)!.options.timeout, 30_000);
  failure = Object.assign(
    new Error("Command failed: fixture-python\nfixture diagnostic"),
    {
      killed: true,
      signal: "SIGTERM",
      stderr: "fixture diagnostic",
      stdout: "",
    },
  );
  await assert.rejects(
    executeWorkbench("fixture-python", ["cancel-scan"]),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /cancel-scan.*timed out.*300/);
      assert.match(error.message, /fixture diagnostic/);
      assert.equal(error.cause, failure);
      return true;
    },
  );
  await assert.rejects(
    promisify(execFile)(
      process.execPath,
      ["-e", 'process.stdout.write("x".repeat(65536))'],
      { maxBuffer: 1024 },
    ),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.ok("code" in error);
      assert.equal(error.code, "ERR_CHILD_PROCESS_STDIO_MAXBUFFER");
      failure = error;
      return true;
    },
  );
  await assert.rejects(
    executeWorkbench("fixture-python", ["cancel-scan"]),
    (error) => error === failure,
  );
} finally {
  delete globalThis.workbenchProcessFixture;
}

const { executeWorkbench } = (await importModule({
  stdin: {
    contents: source + "\nexport { executeWorkbench };",
    loader: "ts",
    resolveDir: applicationRoot,
  },
  define: {
    __dirname: JSON.stringify(applicationRoot),
    "import.meta.url": JSON.stringify(
      new URL("../server.ts", import.meta.url).href,
    ),
  },
  loader: { ".md": "text" },
})) as WorkbenchModule;
const root = await temporaryDirectory("workbench-large-context-");
try {
  const target = join(root, "target");
  await mkdir(target);
  await writeFile(join(target, "example.py"), "value = 1\n");
  const state = join(root, "state");
  const python = process.env.PYTHON || "python3";
  const userContext = "x".repeat(1_500_000);
  const begun = (await executeWorkbench(
    python,
    [
      "begin-deep-scan",
      "--target-path",
      target,
      "--scope",
      ".",
      "--thread-id",
      "synthetic-owner",
      "--scan-root",
      join(root, "scans"),
      "--user-context-stdin",
    ],
    state,
    userContext,
  )) as { deepScan: { scanId: string } };
  const scanId = begun.deepScan.scanId;
  const readScan = async () =>
    (await executeWorkbench(
      python,
      ["get-scan", "--scan-id", scanId],
      state,
    )) as {
      workspace: {
        results: { userContext: string; progress: { status: string } };
      };
    };
  const current = await readScan();
  assert.equal(current.workspace.results.userContext, userContext);
  assert.equal(current.workspace.results.progress.status, "running");
  await executeWorkbench(python, ["cancel-scan", "--scan-id", scanId], state);
  assert.equal(
    (await readScan()).workspace.results.progress.status,
    "canceled",
  );
  await assert.rejects(
    executeWorkbench(
      python,
      ["cancel-scan", "--scan-id", "00000000-0000-4000-8000-000000000000"],
      state,
    ),
    (error: unknown) => {
      assert.ok(error instanceof Error && "stderr" in error);
      assert.match(String(error.stderr), /Codex Security scan not found/);
      return true;
    },
  );
} finally {
  await rm(root, { recursive: true, force: true });
}
