import {
  environmentValue,
  resolvedPathText as canonical,
} from "./helper-files";
import {
  spawn,
  type SpawnOptions,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import {
  basename,
  dirname,
  delimiter,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { createRequire } from "node:module";
import { spawnWindowsProcess } from "../../../native/windows-process.mjs";
import { nativeTarget } from "../../../native/platform.mjs";
import { decodePosixBytes, encodePosixPath } from "./posix-path";
import {
  ancestors,
  append,
  directory,
  executable,
  exists,
  inside,
  linkedParent,
  lstat,
  regular,
  sameFile,
  walk,
  windows,
} from "./inventory-paths";
import { isBinarySample, PREVIEW_READ_BYTES } from "./source-preview";

const repositoryEnvironment = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_CEILING_DIRECTORIES",
  "GIT_COMMON_DIR",
  "GIT_DIR",
  "GIT_DISCOVERY_ACROSS_FILESYSTEM",
  "GIT_INDEX_FILE",
  "GIT_NAMESPACE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_WORK_TREE",
];

function trustedGit(target: string): string | undefined {
  let protectedRoot = canonical(target);
  for (const ancestor of ancestors(protectedRoot))
    if (exists(append(ancestor, ".git"))) protectedRoot = ancestor;
  const configured = environmentValue("CODEX_SECURITY_GIT");
  if (configured === "") return undefined;
  if (configured !== undefined && !isAbsolute(configured))
    throw new Error(
      "CODEX_SECURITY_GIT must name an absolute trusted executable.",
    );
  const candidates =
    configured !== undefined
      ? [configured]
      : (environmentValue("PATH") ?? "")
          .split(delimiter)
          .flatMap((entry) =>
            (windows ? ["git.exe", "git.com"] : ["git"]).map((name) =>
              append(windows ? entry.replace(/^"|"$/gu, "") : entry, name),
            ),
          );
  for (const candidate of candidates) {
    let invocation: string, resolved: string;
    try {
      invocation = append(canonical(dirname(candidate)), basename(candidate));
      resolved = canonical(candidate);
    } catch {
      continue;
    }
    if (
      !executable(resolved) ||
      (windows &&
        (!/\.(exe|com)$/iu.test(candidate) || /\.(bat|cmd)$/iu.test(resolved)))
    )
      continue;
    const inRepository = [resolve(candidate), invocation, resolved].some(
      (path) => {
        try {
          inside(protectedRoot, path);
          return true;
        } catch {
          return false;
        }
      },
    );
    if (inRepository) {
      if (configured !== undefined)
        throw new Error(
          "CODEX_SECURITY_GIT must stay outside the protected repository.",
        );
      continue;
    }
    return invocation;
  }
  return undefined;
}

function spawnTool(
  command: string,
  args: string[],
  options: SpawnOptions & {
    cwd?: string;
    stdio: ["ignore" | "pipe", "pipe", "pipe"];
  },
  inheritedEnvironment: Record<string, string>,
) {
  const raw = (value: string) =>
    (windows ? /[\ud800-\udfff]/u : /[\udc80-\udcff]/u).test(value);
  const environment = Object.fromEntries(
    Object.entries(inheritedEnvironment).filter(([, value]) => raw(value)),
  );
  const values = [
    command,
    ...args,
    ...(typeof options.cwd === "string" ? [options.cwd] : []),
    ...Object.values(environment),
  ];
  if (windows) {
    if (!values.some((value) => /[\ud800-\udfff]/u.test(value)))
      return spawn(command, args, options);
    const binary = createRequire(import.meta.url).resolve(
      `./native/${nativeTarget}/windows.node`,
    );
    return spawnWindowsProcess(binary, command, args, options, environment);
  }
  if (!values.some((value) => /[\udc80-\udcff]/u.test(value)))
    return spawn(command, args, options);
  // Node encodes argv/cwd as UTF-8. POSIX sh can reconstruct raw filename bytes
  // with its builtin printf; a sentinel preserves trailing newlines in each value.
  const assign = (value: string) => {
    if (value.includes("\0"))
      throw new TypeError("Process arguments must not contain NUL bytes");
    const octal = [...encodePosixPath(value)]
      .map((byte) => `\\0${byte.toString(8).padStart(3, "0")}`)
      .join("");
    return `value=$(printf '%b.' '${octal}'); value=\${value%.}`;
  };
  const script = [
    "set --",
    ...Object.entries(environment).flatMap(([name, value]) => [
      assign(value),
      `${name}="$value"; export ${name}`,
    ]),
    ...[command, ...args].flatMap((value) => [
      assign(value),
      'set -- "$@" "$value"',
    ]),
    ...(typeof options.cwd === "string"
      ? [assign(options.cwd), 'cd -P -- "$value" || exit']
      : []),
    'exec "$@"',
  ].join("\n");
  return spawn("/bin/sh", ["-c", script], { ...options, cwd: undefined });
}

// Both callers inherit these paths; Git's separate repository-variable overrides stay intact.
function inheritedToolPaths(): Record<string, string> {
  return Object.fromEntries(
    ["HOME", "PATH"].flatMap((name) => {
      const value = environmentValue(name);
      return value === undefined ? [] : [[name, value]];
    }),
  );
}

function gitProcess(repo: string, args: string[]) {
  const command = trustedGit(repo);
  if (!command) return undefined;
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(env)) {
    const key = windows ? name.toUpperCase() : name;
    if (repositoryEnvironment.includes(key) || key === "GIT_LITERAL_PATHSPECS")
      delete env[name];
  }
  env.GIT_LITERAL_PATHSPECS = "1";
  return spawnTool(
    command,
    [
      "-c",
      "core.fsmonitor=false",
      "-c",
      "i18n.logOutputEncoding=UTF-8",
      "-C",
      repo,
      ...args,
    ],
    { env, stdio: ["pipe", "pipe", "pipe"] },
    inheritedToolPaths(),
  ) as ChildProcessWithoutNullStreams;
}

export async function runTool(
  command: string,
  args: string[],
  cwd: string,
): Promise<{ status: number; stdout: Buffer; stderr: string }> {
  const child = spawnTool(
    command,
    args,
    {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    },
    inheritedToolPaths(),
  );
  return collect(child);
}

async function collect(
  child: ReturnType<typeof spawn>,
): Promise<{ status: number; stdout: Buffer; stderr: string }> {
  const stdout: Buffer[] = [],
    stderr: Buffer[] = [];
  child.stdout!.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr!.on("data", (chunk: Buffer) => stderr.push(chunk));
  const status = await new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
  return {
    status,
    stdout: Buffer.concat(stdout),
    stderr: Buffer.concat(stderr).toString("utf8"),
  };
}

export async function git(repo: string, args: string[]) {
  const child = gitProcess(repo, args);
  if (!child) return { status: 127, stdout: Buffer.alloc(0), stderr: "" };
  child.stdin.end();
  return collect(child);
}

function gitLine(data: Buffer): string {
  return decodePosixBytes(data).replace(windows ? /\r?\n$/u : /\n$/u, "");
}

function paths(data: Buffer): string[] {
  return decodePosixBytes(data).split("\0").filter(Boolean);
}
function requireSuccess(result: {
  status: number;
  stdout: Buffer;
  stderr: string;
}): Buffer {
  if (result.status)
    throw new Error(
      result.stderr.trim() || `Git exited with status ${result.status}`,
    );
  return result.stdout;
}

export async function directoryPaths(
  target: string,
): Promise<string[] | undefined> {
  const root = await git(target, ["rev-parse", "--show-toplevel"]);
  if (root.status || !root.stdout.length) return undefined;
  const repository = canonical(gitLine(root.stdout));
  const prefix = decodePosixBytes(
    requireSuccess(await git(target, ["rev-parse", "--show-prefix"])),
  )
    .replace(/\n$/u, "")
    .replace(/\/$/u, "");
  const scope = prefix ? append(repository, prefix) : repository;
  inside(repository, canonical(scope));
  if (!sameFile(scope, target))
    throw new Error("Scan target must stay inside its Git working tree.");
  const depth = prefix ? prefix.split("/").length : 0;
  // Git's ASCII case folding does not cover Unicode directory aliases.
  const unicodeCase = [...prefix].some(
    (character) =>
      character.charCodeAt(0) > 127 &&
      character.toLowerCase() !== character.toUpperCase(),
  );
  const listing = paths(
    requireSuccess(
      await git(repository, [
        ...(depth && !unicodeCase ? ["--no-literal-pathspecs"] : []),
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "-z",
        "--",
        depth && !unicodeCase ? `:(icase,literal)${prefix}` : ".",
      ]),
    ),
  );
  const found = new Set<string>(),
    matching = new Map<string, boolean>();
  for (const name of listing) {
    const parts = name.split("/");
    if (parts.length <= depth) continue;
    if (depth) {
      const indexedPrefix = append(repository, parts.slice(0, depth).join(sep));
      if (!matching.has(indexedPrefix))
        matching.set(indexedPrefix, sameFile(indexedPrefix, scope));
      if (!matching.get(indexedPrefix)) continue;
    }
    const path = append(target, parts.slice(depth).join(sep));
    try {
      if (linkedParent(target, path)) continue;
      lstat(path);
    } catch {
      continue;
    }
    found.add(path);
    if (directory(path) && !lstat(path).isSymbolicLink()) {
      const nestedRoot = await git(path, ["rev-parse", "--show-toplevel"]);
      const nested =
        nestedRoot.status === 0 && sameFile(gitLine(nestedRoot.stdout), path)
          ? await directoryPaths(path)
          : undefined;
      for (const child of nested ?? walk(path))
        if (!relative(path, child).split(sep).includes(".git"))
          found.add(child);
    }
  }
  return [...found];
}

export interface Change {
  path: string;
  status: string;
}
async function changed(repo: string, args: string[]): Promise<Change[]> {
  const fields = paths(
    requireSuccess(
      await git(repo, [
        "diff",
        "--ignore-submodules=all",
        "--raw",
        "-z",
        "--diff-filter=ACMRDT",
        ...args,
      ]),
    ),
  );
  const changes: Change[] = [];
  for (let index = 0; index < fields.length;) {
    const metadata = fields[index++]!.split(" "),
      status = metadata.at(-1)![0]!;
    if (status === "C" || status === "R") index++;
    const path = fields[index++]!;
    if (
      (status === "D" ? metadata[0]!.slice(1) : metadata[1]!).startsWith("100")
    )
      changes.push({ path, status });
  }
  return changes;
}
export async function changedPaths(
  repo: string,
  base: string,
  head: string,
  mode: string,
): Promise<Change[]> {
  if (mode === "revisions") return changed(repo, [`${base}..${head}`]);
  const unstaged = await changed(repo, [base]),
    staged = await changed(repo, ["--cached", base]);
  const result = new Map(staged.map((change) => [change.path, change]));
  for (const change of unstaged) result.set(change.path, change);
  for (const path of paths(
    requireSuccess(
      await git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]),
    ),
  ))
    if (!path.endsWith("/")) result.set(path, { path, status: "A" });
  return [...result.values()].filter(
    ({ path, status }) => status === "D" || regular(append(repo, path)),
  );
}

/** Consume each complete blob while retaining at most the preview prefix. */
export async function blobSamples(
  repo: string,
  names: string[],
): Promise<([Buffer, boolean] | undefined)[]> {
  if (!names.length) return [];
  const child = gitProcess(repo, ["cat-file", "--batch", "-Z"]);
  if (!child) return names.map(() => undefined);
  const completion = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code ?? 1));
  });
  child.stderr.resume();
  child.stdin.on("error", () => {});
  child.stdin.end(encodePosixPath(names.join("\0") + "\0"));
  const result: ([Buffer, boolean] | undefined)[] = [];
  let pending = Buffer.alloc(0),
    remaining: number | undefined,
    sample = Buffer.alloc(0),
    binary = false,
    bom = Buffer.alloc(0),
    unitTail = Buffer.alloc(0);
  try {
    for await (const chunk of child.stdout) {
      pending = Buffer.concat([pending, chunk as Buffer]);
      while (pending.length) {
        if (remaining === undefined) {
          const end = pending.indexOf(0);
          if (end < 0) break;
          const header = pending.subarray(0, end).toString("utf8").split(" ");
          pending = pending.subarray(end + 1);
          if (header.at(-2) !== "blob") {
            result.push(undefined);
            continue;
          }
          remaining = Number(header.at(-1));
          sample = Buffer.alloc(0);
          binary = false;
          bom = Buffer.alloc(0);
          unitTail = Buffer.alloc(0);
        }
        if (remaining > 0) {
          const length = Math.min(remaining, pending.length),
            data = pending.subarray(0, length);
          if (sample.length < PREVIEW_READ_BYTES)
            sample = Buffer.concat([
              sample,
              data.subarray(0, PREVIEW_READ_BYTES - sample.length),
            ]);
          const classified = Buffer.concat([unitTail, data]);
          if (
            !bom.length &&
            sample.length >= 2 &&
            ((sample[0] === 0xff && sample[1] === 0xfe) ||
              (sample[0] === 0xfe && sample[1] === 0xff))
          )
            bom = sample.subarray(0, 2);
          // Hold one byte until encoding can be identified, and preserve UTF-16 unit alignment.
          const classifyLength =
            classified.length -
            (bom.length || sample.length < 2 ? classified.length % 2 : 0);
          if (classifyLength)
            binary ||= isBinarySample(
              bom.length
                ? Buffer.concat([bom, classified.subarray(0, classifyLength)])
                : classified.subarray(0, classifyLength),
            );
          unitTail = classified.subarray(classifyLength);
          remaining -= length;
          pending = pending.subarray(length);
          if (remaining) break;
        }
        if (!pending.length) break;
        if (pending[0] !== 0) throw new Error("Invalid Git blob framing");
        pending = pending.subarray(1);
        if (!bom.length && unitTail.length) binary ||= unitTail.includes(0);
        result.push([binary ? Buffer.alloc(0) : sample, binary]);
        remaining = undefined;
      }
    }
    if (
      (await completion) ||
      remaining !== undefined ||
      result.length !== names.length
    )
      return names.map(() => undefined);
    return result;
  } catch (error) {
    child.kill();
    await completion.catch(() => {});
    throw error;
  }
}
