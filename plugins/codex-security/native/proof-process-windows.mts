import assert from "node:assert/strict";
import { once } from "node:events";
import { join } from "node:path";
import { binaryPath } from "./binding.mjs";
import { loadWindowsBinding } from "./windows-binding.mjs";
import { widePath, windowsFileSystem } from "./windows-files.mjs";
import { spawnWindowsProcess } from "./windows-process.mjs";

export async function processProof(
  root: string,
): Promise<Record<string, boolean>> {
  const native = loadWindowsBinding(),
    files = windowsFileSystem(native);
  const cwd = join(root, "process-\ud800");
  files.mkdir(widePath(cwd));
  try {
    const arguments_ = [
      "high-\ud800",
      "low-\udfff",
      "replacement-�",
      'quote"and\\',
      "",
      "東京 😀",
    ];
    const script = `const fs=require('node:fs'), native=require(${JSON.stringify(binaryPath)}); const args=native.windowsArguments().slice(3).map(value=>value.toString('utf16le')); const cwd=native.windowsAbsolutePath(Buffer.from('.', 'utf16le')).value.toString('utf16le'); process.stderr.write(JSON.stringify({args,cwd,setting:process.env.INVENTORY_PROCESS_FIXTURE,rawSetting:native.windowsEnvironment(Buffer.from("INVENTORY_PROCESS_RAW", "utf16le")).toString("utf16le")})); process.stdout.write(fs.readFileSync(0)); process.exitCode=23;`;
    const child = spawnWindowsProcess(
      binaryPath,
      process.execPath,
      ["-e", script, ...arguments_],
      {
        cwd,
        env: { ...process.env, INVENTORY_PROCESS_FIXTURE: "inherited" },
        stdio: ["pipe", "pipe", "pipe"],
      },
      { INVENTORY_PROCESS_RAW: "raw-\udfff" },
    );
    const stdout: Buffer[] = [],
      stderr: Buffer[] = [];
    child.stdout!.on("data", (data: Buffer) => stdout.push(data));
    child.stderr!.on("data", (data: Buffer) => stderr.push(data));
    const done = once(child, "close");
    const bytes = Buffer.concat([
      Buffer.from([0, 255, 128]),
      Buffer.alloc(256 * 1024, 17),
    ]);
    child.stdin!.end(bytes);
    assert.deepEqual(await done, [23, null]);
    assert.deepEqual(Buffer.concat(stdout), bytes);
    const result = JSON.parse(Buffer.concat(stderr).toString("utf8"));
    assert.deepEqual(result.args, arguments_);
    assert.equal(result.cwd.toLowerCase(), cwd.toLowerCase());
    assert.equal(result.setting, "inherited");
    assert.equal(result.rawSetting, "raw-\udfff");

    const moduleOptions = "--input-type=module";
    const moduleChild = spawnWindowsProcess(
      binaryPath,
      process.execPath,
      [
        "-e",
        "import process from 'node:process'; process.stdout.write(process.env.NODE_OPTIONS);",
      ],
      {
        cwd,
        env: { ...process.env, NODE_OPTIONS: moduleOptions },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const moduleOutput: Buffer[] = [];
    moduleChild.stdout!.on("data", (data: Buffer) => moduleOutput.push(data));
    moduleChild.stderr!.resume();
    assert.deepEqual(await once(moduleChild, "close"), [0, null]);
    assert.equal(Buffer.concat(moduleOutput).toString("utf8"), moduleOptions);

    files.writeFile(
      widePath(join(root, "hook.cjs")),
      Buffer.from("process.env.INVENTORY_PRELOAD = 'cjs';"),
    );
    files.writeFile(
      widePath(join(root, "preload.mjs")),
      Buffer.from("process.env.INVENTORY_PRELOAD = 'esm';"),
    );
    for (const [key, nodeOptions, expected, override] of [
      ["NODE_OPTIONS", "--require ./hook.cjs", "cjs", undefined],
      ["Node_Options", "--import=./preload.mjs", "esm", undefined],
      ["NODE_OPTIONS", "--require ./absent.cjs", "cjs", "--require ./hook.cjs"],
    ] as const) {
      const env = Object.fromEntries(
        Object.entries(process.env).filter(
          ([name]) => name.toUpperCase() !== "NODE_OPTIONS",
        ),
      );
      if (key === "NODE_OPTIONS" && override === undefined)
        env["node_options"] = "--require ./absent.cjs";
      env[key] = nodeOptions;
      const snapshot = { ...env };
      const preloaded = spawnWindowsProcess(
        binaryPath,
        process.execPath,
        [
          "-e",
          "process.stdout.write(JSON.stringify({options:process.env.NODE_OPTIONS,preloaded:process.env.INVENTORY_PRELOAD}));",
        ],
        { cwd: root, env, stdio: ["ignore", "pipe", "pipe"] },
        override === undefined ? {} : { Node_Options: override },
      );
      const output: Buffer[] = [],
        errors: Buffer[] = [];
      preloaded.stdout!.on("data", (data: Buffer) => output.push(data));
      preloaded.stderr!.on("data", (data: Buffer) => errors.push(data));
      assert.deepEqual(
        await once(preloaded, "close"),
        [0, null],
        Buffer.concat(errors).toString(),
      );
      assert.deepEqual(JSON.parse(Buffer.concat(output).toString()), {
        options: override ?? nodeOptions,
        preloaded: expected,
      });
      assert.deepEqual(env, snapshot);
    }

    for (let attempt = 0; attempt < 3; attempt++) {
      const quick = spawnWindowsProcess(
        binaryPath,
        process.execPath,
        ["-e", "process.exit(19)"],
        { stdio: ["ignore", "pipe", "pipe"] },
      );
      assert.deepEqual(await once(quick, "close"), [19, null]);
    }
    for (const malformed of [Buffer.from([1]), widePath("bad\0value")])
      assert.throws(() =>
        native.runWindowsProcess(widePath(process.execPath), [malformed]),
      );
    const missing = spawnWindowsProcess(
      binaryPath,
      join(cwd, "absent-\udfff.exe"),
      [],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const errors: Error[] = [];
    missing.on("error", (error) => errors.push(error));
    await new Promise<void>((resolve) =>
      missing.once("close", () => resolve()),
    );
    assert.equal(errors.length, 1);
    assert(errors[0]!.message.length > 0);

    const originalExecutable = process.execPath;
    let missingShim: ReturnType<typeof spawnWindowsProcess>;
    try {
      process.execPath = join(root, "absent-node.exe");
      missingShim = spawnWindowsProcess(binaryPath, originalExecutable, [], {
        stdio: ["ignore", "pipe", "pipe"],
      });
    } finally {
      process.execPath = originalExecutable;
    }
    const shimErrors: NodeJS.ErrnoException[] = [];
    missingShim.on("error", (error) => shimErrors.push(error));
    await new Promise<void>((resolve) =>
      missingShim.once("close", () => resolve()),
    );
    assert.deepEqual(
      shimErrors.map((error) => error.code),
      ["ENOENT"],
    );

    for (const mode of ["abort", "kill"] as const) {
      const controller = new AbortController();
      const cancelled = spawnWindowsProcess(binaryPath, process.execPath, [], {
        stdio: ["ignore", "pipe", "pipe"],
        ...(mode === "abort" ? { signal: controller.signal } : {}),
      });
      const errors: NodeJS.ErrnoException[] = [];
      cancelled.on("error", (error) => errors.push(error));
      const closed = new Promise<void>((resolve) =>
        cancelled.once("close", () => resolve()),
      );
      if (mode === "abort") controller.abort();
      else assert.equal(cancelled.kill(), true);
      await closed;
      assert.deepEqual(
        errors.map((error) => error.code),
        mode === "abort" ? ["ABORT_ERR"] : [],
      );
    }

    // Readiness proves the real child is running; closing the shim must close inherited pipes.
    const hanging = spawnWindowsProcess(
      binaryPath,
      process.execPath,
      [
        "-e",
        "process.stdout.write('ready'); setInterval(()=>{},1000)",
        "raw-\ud800",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    const closed = once(hanging, "close", {
      signal: AbortSignal.timeout(10_000),
    });
    await once(hanging.stdout!, "data", {
      signal: AbortSignal.timeout(10_000),
    });
    assert.equal(hanging.kill(), true);
    await closed;
    assert(hanging.stdout!.readableEnded);
    assert(hanging.stderr!.readableEnded);
    return {
      wideArgumentsAndCwd: true,
      inheritedSettingsAndBinaryStreams: true,
      inheritedModuleModeForTarget: true,
      targetPreloadsAndOverrides: true,
      exitAndSpawnErrors: true,
      failedShimReportsOnce: true,
      earlyCancellationReportsOnce: true,
      killingShimClosesChildStreams: true,
    };
  } finally {
    files.unlink(widePath(cwd));
  }
}
