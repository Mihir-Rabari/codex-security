import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { importModule } from "./import-module.ts";

const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
function declaration(name: string, next: string) {
  const start = source.indexOf(`${name}(`);
  const end = source.indexOf(`\n${next}`, start);
  assert.ok(start >= 0 && end > start);
  return source.slice(start, end);
}
const {
  invoke,
  calls,
  rejectNext,
}: {
  invoke: (args: string[]) => Promise<unknown>;
  calls: { args: string[]; timeout: number }[];
  rejectNext: (error: Error) => void;
} = await importModule({
  stdin: {
    loader: "ts",
    contents: `
      const calls = [];
      let failure;
      const execFileAsync = (_command, args, options) => {
        calls.push({ args, timeout: options.timeout });
        if (failure) { const error = failure; failure = undefined; return Promise.reject(error); }
        return Promise.resolve({ stdout: '{}' });
      };
      const PLUGIN_ROOT = '/synthetic/plugin';
      const workbenchScriptPath = () => '/synthetic/plugin/scripts/workbench_db.py';
      const resolvePythonCommand = async () => 'synthetic-python';
      const missingPythonHelperMessage = () => undefined;
      const executeWorkbenchWithStateSelection = (python, args, input) => executeWorkbench(python, args, undefined, input);
      const isJsonObject = (value) => value && typeof value === 'object';
      ${declaration("async function runWorkbench", "async function executeWorkbenchWithStateSelection")}
      ${declaration("async function executeWorkbench", "async function pinFallbackWorkbenchStateDir")}
      ${declaration("function isExecError", "function failureDiagnostic")}
      ${declaration("function failureDiagnostic", "function completionFailureMessage")}
      export { runWorkbench as invoke, calls };
      export const rejectNext = (error) => { failure = error; };
    `,
  },
});
for (const command of [
  "cancel-scan",
  "fail-scan",
  "preserve-scan-results",
  "list-scans",
])
  await invoke([command]);
assert.deepEqual(
  calls.map(({ timeout }) => timeout),
  [300_000, 300_000, 300_000, 30_000],
);
const timeout = Object.assign(
  new Error("Command failed: synthetic-python\nsynthetic stderr"),
  {
    killed: true,
    signal: "SIGTERM",
    code: null,
    stderr: "synthetic stderr",
  },
);
rejectNext(timeout);
await assert.rejects(invoke(["cancel-scan"]), (error: Error) => {
  assert.match(error.message, /timed out/);
  assert.match(error.message, /synthetic stderr/);
  assert.equal(error.cause, timeout);
  return true;
});
const bufferFailure = Object.assign(
  new Error("stdout maxBuffer length exceeded"),
  {
    killed: true,
    signal: "SIGTERM",
    code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER",
    stderr: "",
  },
);
rejectNext(bufferFailure);
await assert.rejects(
  invoke(["cancel-scan"]),
  (error) => error === bufferFailure,
);
