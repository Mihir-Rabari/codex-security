import { spawn, type SpawnOptions } from "node:child_process";

// The wrapper is private: target values travel as UTF-16 bytes, never as script text.
const shim = `
process.once('message', ({ binary, executable, args, cwd, environment }) => {
const wide = value => Buffer.from(value, 'base64');
const disconnect = () => { if (process.connected) process.disconnect(); };
try {
  const result = require(binary).runWindowsProcess(wide(executable), args.map(wide), cwd === undefined ? undefined : wide(cwd), environment.map(({name,value}) => ({name:wide(name),value:wide(value)})));
  process.exitCode = result.status;
  if (result.error) process.send({ spawnError: { errno: result.error, message: result.message } }, disconnect);
  else disconnect();
} catch (error) {
  process.exitCode = 1;
  process.send({ spawnError: { message: error.message } }, disconnect);
}
});
`;

/** Keep Node's asynchronous byte streams while Windows receives exact UTF-16 argv/cwd. */
export function spawnWindowsProcess(
  binary: string,
  executable: string,
  args: string[],
  options: SpawnOptions & {
    cwd?: string;
    stdio: ["ignore" | "pipe", "pipe", "pipe"];
  },
  environment: Record<string, string> = {},
) {
  const wide = (value: string) =>
    Buffer.from(value, "utf16le").toString("base64");
  const payload = {
    binary,
    executable: wide(executable),
    args: args.map(wide),
    environment: Object.entries(environment).map(([name, value]) => ({
      name: wide(name),
      value: wide(value),
    })),
    ...(typeof options.cwd === "string" ? { cwd: wide(options.cwd) } : {}),
  };
  const child = spawn(process.execPath, ["--input-type=commonjs", "-e", shim], {
    ...options,
    cwd: undefined,
    stdio: [...options.stdio, "ipc"],
  });
  child.once("spawn", () => {
    child.send(payload, (error) => {
      if (error) child.emit("error", error);
    });
  });
  child.on("message", (message: unknown) => {
    const report = message as {
      spawnError?: { errno?: number; message?: string };
    };
    if (report.spawnError)
      child.emit(
        "error",
        Object.assign(new Error(report.spawnError.message), {
          code: "WINDOWS_PROCESS_ERROR",
          errno: report.spawnError.errno,
        }),
      );
  });
  return child;
}
