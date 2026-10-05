import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { importModule } from "./import-module.mjs";

const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");
const calls = [];
let workspace;
let joining = false;
let persisted;
let release;
globalThis.cancelResponseFixture = {
  registry: {
    async cancelAndWait(_scanId, _reason, persist) {
      if (!joining) {
        joining = true;
        await persist();
        persisted.resolve();
      }
      await release.promise;
      return true;
    },
    shutdown() {},
  },
  async workbench(args) {
    calls.push(args);
    return args[0] === "get-scan"
      ? { workspace, scan: workspace.scan }
      : workspace;
  },
};
try {
  const { createCodexSecurityServer } = await importModule({
    stdin: {
      contents: source
        .replace(
          "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
          "const deepScanCoordinators = globalThis.cancelResponseFixture.registry;",
        )
        .replace(
          "async function runWorkbench(",
          "const runWorkbench = (...args) => globalThis.cancelResponseFixture.workbench(...args);\nasync function unusedRunWorkbench(",
        ),
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
  });
  const server = createCodexSecurityServer();
  const cancel =
    server._registeredTools.cancel_codex_security_scan_from_app.handler;
  workspace = {
    setup: { submitted: true },
    scan: { progress: { status: "canceled" } },
  };
  persisted = Promise.withResolvers();
  release = Promise.withResolvers();
  const first = cancel({ scanId: "fixture-scan" });
  await persisted.promise;
  const second = cancel({ scanId: "fixture-scan" });
  release.resolve();
  for (const result of await Promise.all([first, second])) {
    assert.deepEqual(result.structuredContent.workspace, workspace);
  }
  assert.deepEqual(
    calls.map(([command]) => command),
    ["cancel-scan", "get-scan"],
  );
  workspace = {
    setup: { submitted: true },
    scan: { progress: { status: "failed" } },
  };
  assert.deepEqual(
    (await cancel({ scanId: "fixture-scan" })).structuredContent.workspace,
    workspace,
  );
  assert.equal(
    calls.at(-1)[0],
    "get-scan",
    "late cancellation must not overwrite a saved failure",
  );
  await server.close();
} finally {
  delete globalThis.cancelResponseFixture;
}
