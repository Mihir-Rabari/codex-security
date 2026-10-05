import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

export async function testDeepScanLifecycle({
  fixtureRun,
  FakeStore,
  FakeExecutor,
  createCoordinator,
  DeepScanCoordinatorRegistry,
  immediateClock,
  eventually,
}) {
  const fixture = () =>
    fixtureRun({
      workers: 1,
      subagents: 0,
      stopAfterNoNew: 3,
      maxDiscoveryRuns: 1,
    });

  for (const stage of [
    "final read",
    "final read success",
    "onComplete",
    "onStopped",
  ]) {
    const f = await fixture();
    const store = new FakeStore(f.run);
    const executor = new FakeExecutor({
      blockDiscovery: stage === "onStopped",
      dedupNewFindings: [0],
    });
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    const persisting = Promise.withResolvers();
    const persist = Promise.withResolvers();
    let publications = 0;
    if (stage.startsWith("final read")) {
      const get = store.get.bind(store);
      store.get = async () => {
        const snapshot = await get();
        if (snapshot.status === "succeeded") {
          entered.resolve();
          await release.promise;
        }
        return snapshot;
      };
    }
    const coordinator = createCoordinator(f, store, executor, {
      threadId: "synthetic-owner",
      heartbeatIntervalMs: 60_000,
      onComplete: async () => {
        if (stage === "onComplete") {
          entered.resolve();
          await release.promise;
        }
      },
      onStopped: async () => {
        publications++;
        if (stage === "onStopped") {
          entered.resolve();
          await release.promise;
        }
      },
    });
    coordinator.start();
    const terminal = coordinator.settled();
    void terminal.catch(() => {});
    if (stage === "onStopped") {
      await executor.discoveryStarted.promise;
      store.run.status = "canceled";
      coordinator.cancel("synthetic stop");
    }
    await entered.promise;
    const cancellation = coordinator.cancelAfterPersistence(
      "late cancellation",
      async () => {
        persisting.resolve();
        await persist.promise;
        if (stage !== "final read success")
          throw new Error("late persistence failed");
        store.run.status = "canceled";
      },
    );
    void cancellation.catch(() => {});
    release.resolve();
    await persisting.promise;
    assert.equal(await coordinator.wait(undefined, 25), undefined, stage);
    persist.resolve();
    if (stage === "final read success") {
      assert.equal((await cancellation).status, "canceled");
      assert.equal((await terminal).status, "canceled");
      assert.equal(store.run.status, "canceled");
    } else {
      await assert.rejects(cancellation, /late persistence failed/);
      await assert.rejects(terminal, /late persistence failed/);
    }
    assert.equal(
      publications,
      ["onStopped", "final read success"].includes(stage) ? 1 : 0,
    );
  }

  for (const late of [false, true]) {
    const f = await fixture();
    const store = new FakeStore(f.run);
    const executor = new FakeExecutor({ blockDiscovery: true });
    const preserving = Promise.withResolvers();
    const release = Promise.withResolvers();
    let calls = 0;
    const coordinator = createCoordinator(f, store, executor, {
      threadId: "synthetic-owner",
      onStopped: async () => {
        calls++;
        preserving.resolve();
        await release.promise;
      },
    });
    coordinator.start();
    await executor.discoveryStarted.promise;
    const terminal = coordinator.settled();
    void terminal.catch(() => {});
    if (late) {
      store.run.status = "failed";
      store.run.error = "original synthetic failure";
      coordinator.failExternallyPersisted(store.run.error);
      await preserving.promise;
    }
    await assert.rejects(
      coordinator.cancelAfterPersistence("synthetic cancellation", async () => {
        store.run.status = "failed";
        store.run.error = "original synthetic failure";
        throw new Error("synthetic cancellation persistence failure");
      }),
      /synthetic cancellation persistence failure/,
    );
    await preserving.promise;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(calls, 1);
    release.resolve();
    if (late) {
      const stopped = await terminal;
      assert.equal(stopped.status, "failed");
      assert.equal(stopped.error, "original synthetic failure");
    } else {
      await assert.rejects(
        terminal,
        /synthetic cancellation persistence failure/,
      );
    }
  }

  for (const action of ["replacement", "cancellation"]) {
    const f = await fixture();
    f.run.coordinatorGeneration = 1;
    const store = new FakeStore(f.run);
    const executor = new FakeExecutor({ blockDiscovery: true });
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    const coordinator = createCoordinator(f, store, executor, {
      threadId: "synthetic-owner",
      heartbeatIntervalMs: 60_000,
      onStopped: async () => {
        entered.resolve();
        await release.promise;
      },
      observeReplacement: async () => {
        entered.resolve();
        return await release.promise;
      },
    });
    coordinator.start();
    await executor.discoveryStarted.promise;
    let heartbeat;
    if (action === "replacement") {
      store.run.coordinatorGeneration = 2;
      heartbeat = coordinator.renewHeartbeat();
      await entered.promise;
    } else {
      store.run.status = "canceled";
      coordinator.cancel("persisted cancellation");
      await entered.promise;
      await coordinator.renewHeartbeat();
    }
    assert.equal(await coordinator.wait(undefined, 25), undefined);
    release.resolve({
      ...store.run,
      status: "succeeded",
      terminalReason: "capped",
    });
    await heartbeat;
    const terminal = await coordinator.settled();
    assert.equal(
      terminal.status,
      action === "replacement" ? "succeeded" : "canceled",
    );
    if (action === "replacement")
      assert.equal(terminal.coordinatorGeneration, 2);
  }

  for (const beforeObservation of [false, true]) {
    const f = await fixture();
    f.run.coordinatorGeneration = 1;
    const store = new FakeStore(f.run);
    const executor = new FakeExecutor({ blockDiscovery: true });
    const registry = new DeepScanCoordinatorRegistry();
    const coordinator = registry.start({
      run: f.run,
      store,
      executor,
      pluginRoot: f.pluginRoot,
      clock: immediateClock,
      threadId: "synthetic-owner",
      heartbeatIntervalMs: 60_000,
    });
    await executor.discoveryStarted.promise;
    store.run.coordinatorGeneration = 2;
    const ownershipRead = Promise.withResolvers();
    const releaseRead = Promise.withResolvers();
    if (beforeObservation) {
      const get = store.get.bind(store);
      store.get = async () => {
        ownershipRead.resolve();
        await releaseRead.promise;
        return await get();
      };
    }
    const heartbeat = coordinator.renewHeartbeat();
    if (beforeObservation) await ownershipRead.promise;
    else await eventually(() => registry.get(f.run.scanId) === undefined);
    registry.shutdown("synthetic shutdown");
    releaseRead.resolve();
    const completed = await Promise.race([
      heartbeat.then(() => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 100)),
    ]);
    if (!completed) {
      store.run.status = "canceled";
      await heartbeat;
    }
    assert.equal(
      completed,
      true,
      "shutdown must settle replacement observation",
    );
    assert.equal(
      (await coordinator.settled()).status,
      beforeObservation ? "canceled" : "failed",
    );
  }

  {
    const f = await fixture();
    f.run.coordinatorGeneration = 1;
    const store = new FakeStore(f.run);
    const committed = Promise.withResolvers();
    const release = Promise.withResolvers();
    const commitDedup = store.commitDedup.bind(store);
    store.commitDedup = async (input) => {
      const snapshot = await commitDedup(input);
      committed.resolve();
      await release.promise;
      return snapshot;
    };
    let heartbeats = 0;
    const heartbeatCoordinator = store.heartbeatCoordinator.bind(store);
    store.heartbeatCoordinator = async (input) => {
      heartbeats++;
      return await heartbeatCoordinator(input);
    };
    const coordinator = createCoordinator(
      f,
      store,
      new FakeExecutor({ dedupNewFindings: [0] }),
      {
        threadId: "synthetic-owner",
        heartbeatIntervalMs: 60_000,
        observeReplacement: async (run) => ({
          ...run,
          status: "succeeded",
          terminalReason: "capped",
        }),
      },
    );
    coordinator.start();
    await committed.promise;
    store.run.coordinatorGeneration = 2;
    await coordinator.renewHeartbeat();
    await coordinator.renewHeartbeat();
    release.resolve();
    const terminal = await coordinator.settled();
    assert.equal(
      heartbeats,
      1,
      "ownership loss stops heartbeats before cleanup settles",
    );
    assert.equal(terminal.status, "succeeded");
    assert.equal(terminal.coordinatorGeneration, 2);
  }

  for (const kind of ["discovery", "dedup"]) {
    for (const persisted of [false, true]) {
      const f = await fixture();
      if (persisted) {
        f.run.scanDir = path.join(
          path.dirname(f.run.scanDir),
          `service-${kind}-2`,
          "scan",
        );
        await mkdir(f.run.scanDir, { recursive: true });
      }
      const label = `${kind}-${persisted ? "0003" : "0001"}`;
      const workerRoot = path.join(
        f.run.scanDir,
        "artifacts",
        "deep_discovery",
        kind === "discovery" ? "workers" : "dedup",
        label,
      );
      await mkdir(workerRoot, { recursive: true });
      const promptPath = path.join(workerRoot, "prompt.md");
      await writeFile(promptPath, "retained synthetic prompt");
      if (persisted)
        f.run.persistedWorkers = [
          {
            id: "interrupted-worker",
            kind,
            status: "canceled",
            promptPath,
            artifactDir: path.join(workerRoot, "output"),
            attempt: 0,
            mergeState: "none",
          },
        ];
      const coordinator = createCoordinator(
        f,
        new FakeStore(f.run),
        new FakeExecutor({ dedupNewFindings: [0] }),
      );
      coordinator.start();
      const terminal = await coordinator.wait(undefined, 5_000);
      assert.equal(terminal?.status, "succeeded", terminal?.error);
      assert.equal(
        await readFile(promptPath, "utf8"),
        "retained synthetic prompt",
      );
    }
  }
}
