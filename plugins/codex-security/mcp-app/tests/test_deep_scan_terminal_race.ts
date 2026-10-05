import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { ScanDraftInput } from "../src/artifact-scan-draft.js";
import type { DeepScanRunState } from "../src/deep-scan/types.js";
import { importModule } from "./import-module.ts";
import { temporaryDirectory } from "./support/temporary-directories.ts";

const execFileAsync = promisify(execFile);
const applicationRoot = fileURLToPath(new URL("../", import.meta.url));
const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const {
  WorkbenchDeepScanStore,
  DeepScanCoordinatorRegistry,
  createScanArtifactContext,
  recordCodexSecurityScanDraftViaWorkbench,
} = await importModule({
  stdin: {
    contents: `export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";
export { DeepScanCoordinatorRegistry } from "./src/deep-scan/registry.ts";
export { createScanArtifactContext } from "./src/artifact-context.ts";
export { recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";`,
    resolveDir: applicationRoot,
  },
  loader: { ".md": "text" },
});
const source = await readFile(new URL("../server.ts", import.meta.url), "utf8");

for (const ordering of [
  "failure response first",
  "failure response last",
  "lost cancellation response",
]) {
  await test(ordering, { timeout: 30_000 }, async () => {
    const root = await temporaryDirectory("deep-scan-terminal-race-");
    const registry = new DeepScanCoordinatorRegistry();
    const cleanupEntered = Promise.withResolvers<void>();
    const cleanupRelease = Promise.withResolvers<void>();
    const cancelEntered = Promise.withResolvers<void>();
    const cancelRelease = Promise.withResolvers<void>();
    const failureCommitted = Promise.withResolvers<void>();
    const failureResponse = Promise.withResolvers<void>();
    let server:
      | ReturnType<(typeof import("../server.ts"))["createCodexSecurityServer"]>
      | undefined;
    let terminal: Promise<DeepScanRunState> | undefined;
    let cancellation: Promise<unknown> | undefined;
    let failure: Promise<unknown> | undefined;
    try {
      const target = join(root, "target");
      const environment = {
        ...process.env,
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
        CODEX_HOME: join(root, "home"),
      };
      await mkdir(target);
      await writeFile(join(target, "fixture.py"), "value = 1\n");
      await mkdir(join(environment.CODEX_HOME, "codex-security"), {
        recursive: true,
      });
      await writeFile(
        join(environment.CODEX_HOME, "codex-security", "config.toml"),
        "[deep_scan]\nworkers = 1\nmax_discovery_runs = 1\nmax_time_hours = 1e-12\n",
        { mode: 0o600 },
      );
      const runWorkbench = async (args: string[]) => {
        const { stdout } = await execFileAsync(
          process.env.PYTHON || "python3",
          [join(pluginRoot, "scripts", "workbench_db.py"), ...args],
          { cwd: pluginRoot, env: environment },
        );
        return JSON.parse(stdout);
      };
      Object.assign(globalThis, {
        terminalRaceFixture: {
          registry,
          async workbench(args: string[]) {
            if (args[0] === "cancel-scan") {
              cancelEntered.resolve();
              await cancelRelease.promise;
            }
            const result = await runWorkbench(args);
            if (args[0] === "fail-scan") {
              failureCommitted.resolve();
              await failureResponse.promise;
            }
            if (
              args[0] === "cancel-scan" &&
              ordering === "lost cancellation response"
            )
              throw new Error("synthetic committed cancellation response lost");
            return result;
          },
        },
      });
      const { createCodexSecurityServer } = await importModule({
        stdin: {
          contents: source
            .replace(
              "const deepScanCoordinators = new DeepScanCoordinatorRegistry();",
              "const deepScanCoordinators = globalThis.terminalRaceFixture.registry;",
            )
            .replace(
              "async function runWorkbench(",
              "const runWorkbench = (...args) => globalThis.terminalRaceFixture.workbench(...args);\nasync function unusedRunWorkbench(",
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
      const application = createCodexSecurityServer();
      server = application;
      const cancel =
        application._registeredTools.cancel_codex_security_scan_from_app
          .handler;
      const fail =
        application._registeredTools.fail_codex_security_scan.handler;
      const store = new WorkbenchDeepScanStore(runWorkbench);
      const run = await store.begin({
        targetPath: target,
        scope: ".",
        threadId: "fixture-owner",
        scanRoot: join(root, "scans"),
      });
      const claim = await store.claimCoordinator({
        scanId: run.scanId,
        threadId: "fixture-owner",
      });
      const get = store.get.bind(store);
      let held = false;
      store.get = async (...args: [string, string]) => {
        const result = await get(...args);
        if (!held && result.status === "succeeded") {
          held = true;
          cleanupEntered.resolve();
          await cleanupRelease.promise;
        }
        return result;
      };
      const coordinator = registry.start({
        run: claim.run,
        store,
        executor: {
          async run() {
            throw new Error("expired deadline must not launch a worker");
          },
        },
        pluginRoot,
        threadId: "fixture-owner",
        heartbeatIntervalMs: 60_000,
        onComplete: async (draft: ScanDraftInput) => {
          const context = await createScanArtifactContext(
            run.scanId,
            runWorkbench,
            { requireRunning: true },
          );
          await recordCodexSecurityScanDraftViaWorkbench(
            context,
            draft,
            runWorkbench,
          );
        },
        onStopped: async (stopped: DeepScanRunState) => {
          await runWorkbench([
            "preserve-scan-results",
            "--scan-id",
            stopped.scanId,
            "--thread-id",
            "fixture-owner",
            "--coordinator-generation",
            String(stopped.coordinatorGeneration),
          ]);
        },
      });
      terminal = coordinator.settled();
      void terminal!.catch(() => {});
      await cleanupEntered.promise;
      cancellation = cancel({ scanId: run.scanId });
      void cancellation!.catch(() => {});
      await cancelEntered.promise;
      if (ordering !== "lost cancellation response") {
        failure = fail(
          { scanId: run.scanId, message: "synthetic committed parent failure" },
          {},
        );
        void failure!.catch(() => {});
        await failureCommitted.promise;
        assert.equal(
          (
            await runWorkbench([
              "get-deep-scan",
              "--scan-id",
              run.scanId,
              "--thread-id",
              "fixture-owner",
            ])
          ).deepScan.status,
          "succeeded",
        );
        assert.equal(
          (await runWorkbench(["get-scan", "--scan-id", run.scanId])).workspace
            .results.progress.status,
          "failed",
        );
        if (ordering === "failure response first") {
          failureResponse.resolve();
          await failure;
        }
      }
      cancelRelease.resolve();
      cleanupRelease.resolve();
      if (ordering === "lost cancellation response") {
        await assert.rejects(
          cancellation!,
          /synthetic committed cancellation response lost/,
        );
        await assert.rejects(
          terminal!,
          /synthetic committed cancellation response lost/,
        );
        assert.equal(
          (await runWorkbench(["get-scan", "--scan-id", run.scanId])).workspace
            .results.progress.status,
          "canceled",
        );
      } else {
        await assert.rejects(
          cancellation!,
          /Only a running scan can be canceled/,
        );
        const stopped = await terminal!;
        assert.equal(
          stopped.status,
          ordering === "failure response first" ? "failed" : "succeeded",
        );
        if (ordering === "failure response first")
          assert.match(stopped.error!, /synthetic committed parent failure/);
        failureResponse.resolve();
        await failure;
      }
    } finally {
      cleanupRelease.resolve();
      cancelRelease.resolve();
      failureResponse.resolve();
      registry.shutdown("fixture cleanup");
      await Promise.allSettled([terminal, cancellation, failure]);
      await server?.close();
      Reflect.deleteProperty(globalThis, "terminalRaceFixture");
      await rm(root, { recursive: true, force: true });
    }
  });
}
