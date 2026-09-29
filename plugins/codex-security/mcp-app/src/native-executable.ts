import { existsSync, promises as fs } from "node:fs";
import { configuredCodexHome } from "../../../../sdk/typescript/src/codex-home.js";
import { createRequire } from "node:module";
import {
  delimiter,
  dirname,
  isAbsolute,
  join,
  resolve,
  win32,
} from "node:path";
import {
  resolveTrustedExecutable,
  type TrustedExecutable,
} from "../../../../sdk/typescript/src/trusted-executable.js";

export async function resolveTrustedCodex(
  environment: NodeJS.ProcessEnv,
  protectedRoot: string,
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  originalCwd: string = process.cwd(),
): Promise<TrustedExecutable | null> {
  for (const candidate of codexPathCandidates(
    environment,
    platform,
    architecture,
    originalCwd,
  )) {
    const codex = await resolveTrustedExecutable(
      candidate,
      environment,
      protectedRoot,
    );
    if (codex !== null) return codex;
  }
  return null;
}

export async function snapshotNativeEnvironment(): Promise<
  Record<string, string>
> {
  const environment = Object.fromEntries(
    Object.entries(process.env)
      .filter((entry): entry is [string, string] => entry[1] !== undefined)
      .map(([name, value]) => [
        process.platform === "win32" ? name.toUpperCase() : name,
        value,
      ]),
  );
  const codexHome = environment.CODEX_HOME;
  if (codexHome !== undefined && codexHome.length > 0 && !codexHome.trim()) {
    delete environment.CODEX_HOME;
  } else if (codexHome !== undefined && codexHome.length > 0) {
    environment.CODEX_HOME = await fs.realpath(
      configuredCodexHome(environment),
    );
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  originalCwd: string = process.cwd(),
): string {
  return (
    codexPathCandidates(env, platform, architecture, originalCwd).next()
      .value ?? "codex"
  );
}

function* codexPathCandidates(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
  architecture: NodeJS.Architecture,
  originalCwd: string,
): Generator<string> {
  const searchPath = searchPathForPlatform(env, platform);
  const configured = environmentVariable(
    env,
    "CODEX_CLI_PATH",
    platform,
  )?.trim();
  if (configured && (platform !== "win32" || !isWindowsAppsPath(configured))) {
    if (platform === "win32" && /^(?:codex|codex\.exe)$/iu.test(configured)) {
      yield* resolveWindowsCodexFromSearchPath(
        searchPath,
        architecture,
        originalCwd,
      );
      return;
    }
    yield isBareCommandName(configured)
      ? configured
      : absoluteCodexPath(configured, platform, originalCwd);
    return;
  }

  if (platform !== "win32") {
    yield "codex";
    return;
  }

  const managedPackageRoot = environmentVariable(
    env,
    "CODEX_MANAGED_PACKAGE_ROOT",
    platform,
  )?.trim();
  if (managedPackageRoot) {
    const managedBinary = resolveWindowsPackageBinary(
      absoluteCodexPath(managedPackageRoot, platform, originalCwd),
      architecture,
    );
    if (managedBinary && !isWindowsAppsPath(managedBinary)) yield managedBinary;
  }

  yield* resolveWindowsCodexFromSearchPath(
    searchPath,
    architecture,
    originalCwd,
  );
}

function searchPathForPlatform(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): string | undefined {
  if (platform !== "win32") return env.PATH?.trim() ? env.PATH : undefined;
  return Object.entries(env).find(
    ([name, value]) => name.toLowerCase() === "path" && value?.trim(),
  )?.[1];
}

function environmentVariable(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform,
): string | undefined {
  const value = env[name];
  if (value !== undefined || platform !== "win32") return value;
  return Object.entries(env).find(([key]) => key.toUpperCase() === name)?.[1];
}

function isBareCommandName(value: string): boolean {
  return (
    !value.includes("/") && !value.includes("\\") && !/^[A-Za-z]:/.test(value)
  );
}

function* resolveWindowsCodexFromSearchPath(
  searchPath: string | undefined,
  architecture: NodeJS.Architecture,
  originalCwd: string,
): Generator<string> {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const absoluteDirectory = absoluteWindowsSearchDirectory(
      directory,
      originalCwd,
    );
    const directBinary = join(absoluteDirectory, "codex.exe");
    if (!isWindowsAppsPath(directBinary) && existsSync(directBinary))
      yield directBinary;

    const packageRoot = join(
      absoluteDirectory,
      "node_modules",
      "@openai",
      "codex",
    );
    const nativeBinary = resolveWindowsPackageBinary(packageRoot, architecture);
    if (nativeBinary && !isWindowsAppsPath(nativeBinary)) yield nativeBinary;
  }
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
}

function absoluteSearchDirectory(
  directory: string,
  originalCwd: string,
): string {
  return resolve(originalCwd, directory || ".");
}

function absoluteWindowsSearchDirectory(
  directory: string,
  originalCwd: string,
): string {
  if (directory.startsWith('"') && directory.endsWith('"')) {
    directory = directory.slice(1, -1);
  }
  return absoluteSearchDirectory(directory, originalCwd);
}

function absoluteCodexPath(
  value: string,
  platform: NodeJS.Platform,
  originalCwd: string,
): string {
  if (platform === "win32" && isNativeWindowsRootRelativePath(value)) {
    // A rooted Windows path still depends on the original drive.
    return win32.resolve(originalCwd, value);
  }
  if (isAbsolute(value) || (platform === "win32" && win32.isAbsolute(value))) {
    return value;
  }
  return resolve(originalCwd, value);
}

function isNativeWindowsRootRelativePath(value: string): boolean {
  if (process.platform !== "win32") return false;
  const root = win32.parse(value).root;
  return root === "\\" || root === "/";
}

function resolveWindowsPackageBinary(
  packageRoot: string,
  architecture: NodeJS.Architecture,
): string | undefined {
  const packageJson = join(packageRoot, "package.json");
  if (!existsSync(packageJson)) return undefined;

  const targetTriple =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : architecture === "x64"
        ? "x86_64-pc-windows-msvc"
        : undefined;
  if (!targetTriple) return undefined;

  try {
    const platformPackageJson = createRequire(packageJson).resolve(
      `@openai/codex-win32-${architecture}/package.json`,
    );
    const nativeBinary = join(
      dirname(platformPackageJson),
      "vendor",
      targetTriple,
      "bin",
      "codex.exe",
    );
    return existsSync(nativeBinary) ? nativeBinary : undefined;
  } catch {
    return undefined;
  }
}
