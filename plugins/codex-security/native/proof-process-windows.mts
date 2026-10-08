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
  const arguments_ = [
    "high-\ud800",
    "low-\udfff",
    "replacement-�",
    'quote"and\\',
    "",
    "東京 😀",
  ];
  const script = `const fs=require('node:fs'), native=require(${JSON.stringify(binaryPath)}); const args=native.windowsArguments().slice(3).map(value=>value.toString('utf16le')); const cwd=native.windowsAbsolutePath(Buffer.from('.', 'utf16le')).value.toString('utf16le'); process.stderr.write(JSON.stringify({args,cwd,setting:process.env.INVENTORY_PROCESS_FIXTURE})); process.stdout.write(fs.readFileSync(0)); process.exitCode=23;`;
  const child = spawnWindowsProcess(
    binaryPath,
    process.execPath,
    ["-e", script, ...arguments_],
    {
      cwd,
      env: { ...process.env, INVENTORY_PROCESS_FIXTURE: "inherited" },
      stdio: ["pipe", "pipe", "pipe"],
    },
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
  await new Promise<void>((resolve) => missing.once("close", () => resolve()));
  assert.equal(errors.length, 1);
  assert(errors[0]!.message.length > 0);

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
  await once(hanging.stdout!, "data", { signal: AbortSignal.timeout(10_000) });
  assert.equal(hanging.kill(), true);
  await closed;
  assert(hanging.stdout!.readableEnded);
  assert(hanging.stderr!.readableEnded);
  return {
    wideArgumentsAndCwd: true,
    inheritedSettingsAndBinaryStreams: true,
    exitAndSpawnErrors: true,
    killingShimClosesChildStreams: true,
  };
}
