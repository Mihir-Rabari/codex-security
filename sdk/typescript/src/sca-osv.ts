import { execFile as execFileCallback, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  dirname,
  join,
  posix,
  relative,
  sep,
  win32,
} from "node:path";
import { finished } from "node:stream/promises";
import { promisify } from "node:util";
import { parse as parseYaml } from "yaml";
import { parse as parseToml } from "smol-toml";
import semverValid from "semver/functions/valid.js";
import { errorMessage } from "./errors.js";
import { executablePathForSpawn } from "./runtime.js";
import type {
  ScaComponent,
  ScaCoverage,
  ScaFile,
  ScaInput,
  ScaMatch,
  ScaScanner,
} from "./sca-types.js";
import {
  enclosingGitWorktreeRoot,
  gitMarkerRoot,
  isolatedGitEnvironment,
  normalizeRepository,
  relativePathIsOutside,
  validatedGitEnvironment,
} from "./targets.js";
import { resolveTrustedExecutable } from "./trusted-executable.js";

const execFile = promisify(execFileCallback);
const lockNames = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
]);

export interface OsvScanResult {
  scanner: ScaScanner;
  coverage: ScaCoverage;
  components: ScaComponent[];
  matches: ScaMatch[];
  diagnostics: string[];
  status: "completed" | "partial" | "failed";
}
export interface OsvProcessResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}
export interface OsvProcessOptions {
  cwd: string;
  environment: Record<string, string | undefined>;
  signal?: AbortSignal;
  stdoutPath?: string;
  stderrPath?: string;
}
export type OsvProcessRunner = (
  executable: string,
  argv: string[],
  options: OsvProcessOptions,
) => Promise<OsvProcessResult>;
export interface OsvDependencies {
  executable?: string;
  runProcess?: OsvProcessRunner;
  now?: () => string;
}

function digest(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
function stableId(prefix: string, values: unknown[]): string {
  return `${prefix}-${digest(JSON.stringify(values)).slice(0, 24)}`;
}
function slash(path: string): string {
  return path.split(sep).join("/");
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}
function unique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

interface PnpmLocalReference {
  sourcePath: string;
  name: string;
  version: string;
}

/** OSV omits pnpm links and cannot match directory references as registry versions. */
function pnpmLocalReferences(
  parsed: Record<string, unknown>,
  sourcePath: string,
): PnpmLocalReference[] {
  const references = new Map<string, PnpmLocalReference>();
  for (const section of [parsed["importers"], parsed["snapshots"]]) {
    if (!record(section)) continue;
    for (const project of Object.values(section)) {
      if (!record(project)) continue;
      for (const group of [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
      ]) {
        const dependencies = project[group];
        if (!record(dependencies)) continue;
        for (const [name, dependency] of Object.entries(dependencies)) {
          const version = record(dependency)
            ? dependency["version"]
            : dependency;
          if (typeof version !== "string" || !/^(?:file|link):/u.test(version))
            continue;
          references.set(JSON.stringify([name, version]), {
            sourcePath,
            name,
            version,
          });
        }
      }
    }
  }
  return [...references.values()];
}

function unobservedLocalReferences(
  references: PnpmLocalReference[],
  components: ScaComponent[],
): number {
  return references.filter(
    (reference) =>
      !components.some(
        (component) =>
          component.sourcePath === reference.sourcePath &&
          component.name === reference.name &&
          component.version !== null &&
          (component.version === reference.version ||
            reference.version.startsWith(`${component.version}(`)),
      ),
  ).length;
}

function caseInsensitiveField(
  value: Record<string, unknown>,
  name: string,
): unknown {
  return Object.entries(value).find(([key]) => key.toLowerCase() === name)?.[1];
}

/** Use the same tracked/untracked, non-ignored scope as other repository operations. */
async function repositoryFiles(
  repository: string,
  environment: Record<string, string | undefined>,
  signal?: AbortSignal,
): Promise<string[]> {
  if (await enclosingGitWorktreeRoot(repository, signal)) {
    validatedGitEnvironment(environment);
    const git = await resolveTrustedExecutable(
      "git",
      isolatedGitEnvironment(false, environment),
      (await gitMarkerRoot(repository, signal, "outermost")) ?? repository,
    );
    if (git === null)
      throw new Error(
        "Git is required to enumerate dependency inputs in this repository.",
      );
    const { stdout } = await execFile(
      git.executable,
      [
        "-c",
        "core.fsmonitor=false",
        "-C",
        repository,
        "ls-files",
        "--cached",
        "--others",
        "--exclude-standard",
        "--deduplicate",
        "-z",
        "--",
        ".",
      ],
      { env: git.environment, signal, maxBuffer: Infinity },
    );
    return stdout
      .split("\0")
      .filter(Boolean)
      .filter((path) => !path.split("/").includes("node_modules"));
  }
  const files: string[] = [];
  const pending = [repository];
  while (pending.length) {
    signal?.throwIfAborted();
    const directory = pending.pop()!;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else files.push(relative(repository, path));
    }
  }
  return files;
}

/** Select effective lockfiles before invoking OSV, which itself gives shrinkwrap precedence. */
export async function discoverScaInputs(
  repositoryPath: string,
  environment: Record<string, string | undefined> = process.env,
  signal?: AbortSignal,
): Promise<
  Pick<ScaCoverage, "inputs" | "configFiles" | "limitations"> & {
    packageExclusionSources: string[];
    localReferences: PnpmLocalReference[];
    diagnostics: string[];
  }
> {
  const repository = await normalizeRepository(repositoryPath, signal);
  const candidates = (await repositoryFiles(repository, environment, signal))
    .filter((path) => lockNames.has(basename(path)))
    .sort();
  const inputs: ScaInput[] = [];
  const configFiles: ScaFile[] = [];
  const localReferences: PnpmLocalReference[] = [];
  const diagnostics: string[] = [];
  const packageExclusions = new Map<string, boolean>();
  const limitations: string[] = [
    "Inventory covers observed package tuples in npm v2/v3 and pnpm v9 lockfiles, not every installed instance or a complete dependency graph.",
  ];
  for (const candidate of candidates) {
    signal?.throwIfAborted();
    const path = join(repository, candidate);
    const input: ScaInput = {
      path: slash(candidate),
      sha256: "",
      format: basename(path) === "pnpm-lock.yaml" ? "pnpm" : "npm",
      status: "scanned",
      reason: null,
    };
    inputs.push(input);
    try {
      const metadata = await lstat(path);
      if (
        !metadata.isFile() ||
        relativePathIsOutside(relative(repository, await realpath(path)))
      ) {
        input.status = "unsupported";
        input.reason =
          "Lockfile is not a regular file within the selected repository.";
        continue;
      }
      const content = await readFile(path);
      input.sha256 = digest(content);
      if (
        basename(path) === "package-lock.json" &&
        (await lstat(join(dirname(path), "npm-shrinkwrap.json")).then(
          () => true,
          (error: NodeJS.ErrnoException) => {
            if (error.code === "ENOENT") return false;
            throw error;
          },
        ))
      ) {
        input.status = "excluded";
        input.reason =
          "npm-shrinkwrap.json takes precedence in this directory.";
        // A gitignored shrinkwrap still changes npm and OSV interpretation.
        const shrinkwrap = slash(
          relative(repository, join(dirname(path), "npm-shrinkwrap.json")),
        );
        if (!candidates.includes(shrinkwrap)) {
          input.status = "unsupported";
          input.reason =
            "An npm-shrinkwrap.json outside the selected file scope takes precedence; the package-lock.json cannot be assessed as effective input.";
        }
        continue;
      }
      const parsed: unknown =
        input.format === "npm"
          ? JSON.parse(content.toString("utf8"))
          : parseYaml(content.toString("utf8"));
      const version = record(parsed) ? parsed["lockfileVersion"] : undefined;
      if (
        input.format === "npm"
          ? version !== 2 && version !== 3
          : String(version) !== "9.0" && String(version) !== "9"
      ) {
        input.status = "unsupported";
        input.reason = `Unsupported ${input.format} lockfile version: ${String(version)}.`;
      } else if (input.format === "pnpm" && record(parsed)) {
        const references = pnpmLocalReferences(parsed, input.path);
        localReferences.push(...references);
        if (references.length > 0)
          limitations.push(
            `${input.path} includes local dependency references outside npm registry matching: ${references.map((reference) => `${reference.name}@${reference.version}`).join(", ")}.`,
          );
      }
    } catch (error) {
      signal?.throwIfAborted();
      input.status = "failed";
      input.reason = errorMessage(error);
    }
  }
  const directories = unique(
    inputs
      .filter((input) => input.status === "scanned")
      .map((input) => dirname(join(repository, input.path))),
  );
  for (const directory of directories) {
    const path = join(directory, "osv-scanner.toml");
    const metadata = await lstat(path).catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return null;
      throw error;
    });
    if (metadata === null) continue;
    if (
      !metadata.isFile() ||
      relativePathIsOutside(relative(repository, await realpath(path)))
    )
      throw new Error(
        `OSV configuration must be a regular file within the selected repository: ${path}`,
      );
    const content = await readFile(path);
    configFiles.push({
      path: slash(relative(repository, path)),
      sha256: digest(content),
    });
    let config: Record<string, unknown>;
    try {
      config = parseToml(content.toString("utf8"));
    } catch (error) {
      diagnostics.push(
        `Unable to parse OSV configuration ${slash(relative(repository, path))}: ${errorMessage(error)}`,
      );
      continue;
    }
    const overrides = caseInsensitiveField(config, "packageoverrides");
    packageExclusions.set(
      directory,
      Array.isArray(overrides) &&
        overrides.some(
          (override) =>
            record(override) &&
            caseInsensitiveField(override, "ignore") === true,
        ),
    );
    if (
      caseInsensitiveField(config, "ignoredvulns") !== undefined ||
      overrides !== undefined
    )
      limitations.push(
        `OSV exclusions/overrides are configured in ${slash(relative(repository, path))}; results are evaluated after these settings. Exact suppressed counts are unavailable.`,
      );
  }
  const packageExclusionSources = inputs
    .filter(
      (input) =>
        packageExclusions.get(dirname(join(repository, input.path))) ?? false,
    )
    .map((input) => input.path);
  return {
    inputs,
    configFiles,
    limitations,
    packageExclusionSources,
    localReferences,
    diagnostics,
  };
}

/** Error diagnostics from the pinned scanner can accompany exit 0 and valid JSON. */
export function osvErrorDiagnostics(stderr: string): string[] {
  return stderr
    .split(/\r?\n/u)
    .filter((line) =>
      /Error during extraction:|could not load db for .+ ecosystem:|Ignored invalid config file at /u.test(
        line,
      ),
    );
}

function sourceRelativePath(repository: string, source: string): string {
  const windows = win32.isAbsolute(repository) && !posix.isAbsolute(repository);
  const paths = windows ? win32 : posix;
  const normalized = paths.relative(
    repository,
    paths.isAbsolute(source) ? source : paths.resolve(repository, source),
  );
  return windows ? normalized.replaceAll("\\", "/") : normalized;
}

/** Normalize scanner facts only. Every advisory is retained; aliases join groups transitively. */
export function normalizeOsvOutput(
  raw: unknown,
  options: { repositoryPath: string; inputs: readonly ScaInput[] },
): {
  components: ScaComponent[];
  matches: ScaMatch[];
  diagnostics: string[];
  unresolvedPackages: number;
} {
  const components: ScaComponent[] = [];
  const matches: ScaMatch[] = [];
  const diagnostics: string[] = [];
  let unresolvedPackages = 0;
  if (!record(raw) || !Array.isArray(raw["results"]))
    throw new Error("OSV output must contain a results array.");
  const selected = new Set(
    options.inputs
      .filter((input) => input.status === "scanned")
      .map((input) => input.path),
  );
  for (const source of raw["results"]) {
    if (
      !record(source) ||
      !record(source["source"]) ||
      typeof source["source"]["path"] !== "string" ||
      !Array.isArray(source["packages"])
    ) {
      diagnostics.push(
        "OSV result has missing source or packages fields; inspect retained raw output.",
      );
      continue;
    }
    const sourcePath = sourceRelativePath(
      options.repositoryPath,
      source["source"]["path"],
    );
    if (!selected.has(sourcePath)) {
      diagnostics.push(
        `OSV returned a source outside the selected inputs: ${sourcePath}.`,
      );
      continue;
    }
    for (const item of source["packages"]) {
      if (!record(item) || !record(item["package"])) {
        unresolvedPackages++;
        diagnostics.push(`OSV package identity is missing in ${sourcePath}.`);
        continue;
      }
      const pkg = item["package"];
      const name = typeof pkg["name"] === "string" ? pkg["name"] : "";
      const version =
        typeof pkg["version"] === "string" && pkg["version"] !== ""
          ? pkg["version"]
          : null;
      const ecosystem =
        typeof pkg["ecosystem"] === "string" && pkg["ecosystem"] !== ""
          ? pkg["ecosystem"]
          : null;
      if (
        name === "" ||
        version === null ||
        ecosystem !== "npm" ||
        semverValid(version) === null
      )
        unresolvedPackages++;
      if (ecosystem !== null && ecosystem !== "npm")
        diagnostics.push(
          `Package ${name} in ${sourcePath} uses ${ecosystem}; the MVP supports resolved npm registry identities. Raw scanner evidence is retained.`,
        );
      const id = stableId("component", [
        sourcePath,
        ecosystem,
        name,
        version,
        pkg["commit"] ?? null,
      ]);
      let component = components.find((candidate) => candidate.id === id);
      if (component === undefined) {
        component = {
          id,
          name,
          version,
          ecosystem,
          sourcePath,
          dependencyGroups: strings(item["dependency_groups"]),
        };
        components.push(component);
      } else
        component.dependencyGroups = unique([
          ...component.dependencyGroups,
          ...strings(item["dependency_groups"]),
        ]);
      if (
        item["vulnerabilities"] !== undefined &&
        !Array.isArray(item["vulnerabilities"])
      ) {
        diagnostics.push(
          `OSV vulnerabilities must be an array for ${sourcePath}:${name}.`,
        );
        continue;
      }
      const vulnerabilities = Array.isArray(item["vulnerabilities"])
        ? item["vulnerabilities"]
        : [];
      const validAdvisories = vulnerabilities.filter(
        (advisory): advisory is Record<string, unknown> =>
          record(advisory) &&
          typeof advisory["id"] === "string" &&
          advisory["id"] !== "",
      );
      if (validAdvisories.length !== vulnerabilities.length)
        diagnostics.push(
          `OSV advisory ID is missing for ${sourcePath}:${name}; inspect retained raw output.`,
        );
      const groups = Array.isArray(item["groups"])
        ? item["groups"].filter(record)
        : [];
      const buckets: {
        advisories: Record<string, unknown>[];
        ids: Set<string>;
        severity: string | null;
      }[] = [];
      for (const advisory of validAdvisories) {
        const advisoryId = advisory["id"] as string;
        const matchingGroups = groups.filter((group) =>
          strings(group["ids"]).includes(advisoryId),
        );
        const ids = new Set([
          advisoryId,
          ...strings(advisory["aliases"]),
          ...matchingGroups.flatMap((group) => [
            ...strings(group["ids"]),
            ...strings(group["aliases"]),
          ]),
        ]);
        const joined = buckets.filter((bucket) =>
          [...bucket.ids].some((value) => ids.has(value)),
        );
        for (const bucket of joined)
          for (const value of bucket.ids) ids.add(value);
        const severity =
          matchingGroups
            .map((group) => group["max_severity"])
            .find(
              (value): value is string =>
                typeof value === "string" && value !== "",
            ) ??
          joined.find((bucket) => bucket.severity !== null)?.severity ??
          null;
        for (const bucket of joined) buckets.splice(buckets.indexOf(bucket), 1);
        buckets.push({
          advisories: [
            ...joined.flatMap((bucket) => bucket.advisories),
            advisory,
          ],
          ids,
          severity,
        });
      }
      for (const bucket of buckets) {
        const advisoryIds = unique(
          bucket.advisories.map((advisory) => advisory["id"] as string),
        );
        const aliases = unique([...bucket.ids]);
        const fixedVersions: string[] = [];
        for (const advisory of bucket.advisories) {
          if (!Array.isArray(advisory["affected"])) continue;
          for (const affected of advisory["affected"]) {
            if (
              !record(affected) ||
              !record(affected["package"]) ||
              affected["package"]["name"] !== name ||
              affected["package"]["ecosystem"] !== ecosystem ||
              !Array.isArray(affected["ranges"])
            )
              continue;
            for (const range of affected["ranges"])
              if (
                record(range) &&
                (range["type"] === "SEMVER" || range["type"] === "ECOSYSTEM") &&
                Array.isArray(range["events"])
              )
                for (const event of range["events"])
                  if (record(event) && typeof event["fixed"] === "string")
                    fixedVersions.push(event["fixed"]);
          }
        }
        const match: ScaMatch = {
          id: stableId("match", [id, aliases]),
          componentId: id,
          advisoryIds,
          aliases,
          sourceAdvisories: bucket.advisories,
          severity: bucket.severity,
          fixedVersions: unique(fixedVersions),
          advisoryModifiedAt: unique(
            bucket.advisories
              .map((advisory) => advisory["modified"])
              .filter((value): value is string => typeof value === "string"),
          ),
        };
        const existing = matches.find((candidate) => candidate.id === match.id);
        if (existing === undefined) matches.push(match);
        else existing.sourceAdvisories.push(...match.sourceAdvisories);
      }
    }
  }
  return { components, matches, diagnostics, unresolvedPackages };
}

/** Keep stream files even if the child is interrupted. No shell or process-global mutation. */
export const runOsvProcess: OsvProcessRunner = async (
  executable,
  argv,
  options,
) => {
  options.signal?.throwIfAborted();
  const stdoutFile =
    options.stdoutPath === undefined
      ? null
      : createWriteStream(options.stdoutPath);
  const stderrFile =
    options.stderrPath === undefined
      ? null
      : createWriteStream(options.stderrPath);
  const files = [stdoutFile, stderrFile].filter((file) => file !== null);
  let processError: Error | undefined;
  for (const file of files)
    file.on("error", (error) => {
      processError = error;
    });
  const child = spawn(executablePathForSpawn(executable), argv, {
    cwd: options.cwd,
    env: options.environment,
    signal: options.signal,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    stdout += chunk;
    stdoutFile?.write(chunk);
  });
  child.stderr.on("data", (chunk: string) => {
    stderr += chunk;
    stderrFile?.write(chunk);
  });
  const exitCode = await new Promise<number | null>((finish) => {
    child.once("error", (error) => {
      processError = error;
    });
    child.once("close", finish);
  });
  for (const file of files) file.end();
  await Promise.all(files.map((file) => finished(file)));
  if (processError !== undefined) throw processError;
  return { stdout, stderr, exitCode };
};

export async function runOsvScan(
  options: {
    repositoryPath: string;
    outputDir: string;
    environment?: Record<string, string | undefined>;
    signal?: AbortSignal;
  },
  dependencies: OsvDependencies = {},
): Promise<OsvScanResult> {
  const now = dependencies.now ?? (() => new Date().toISOString());
  const scanner: ScaScanner = {
    name: "osv-scanner",
    version: null,
    argv: [],
    startedAt: now(),
    completedAt: "",
    exitCode: null,
    rawOutputPath: join(options.outputDir, "osv-output.json"),
    stderrPath: join(options.outputDir, "osv-stderr.log"),
    advisoryMode: "online",
    advisorySnapshotId: null,
  };
  const result: OsvScanResult = {
    scanner,
    coverage: {
      status: "failed",
      inputs: [],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [],
    matches: [],
    diagnostics: [],
    status: "failed",
  };
  await mkdir(options.outputDir, { recursive: true });
  await Promise.all([
    writeFile(scanner.rawOutputPath, ""),
    writeFile(scanner.stderrPath, ""),
  ]);
  const environment = { ...(options.environment ?? process.env) };
  let localReferences: PnpmLocalReference[] = [];
  try {
    options.signal?.throwIfAborted();
    const repository = await normalizeRepository(
      options.repositoryPath,
      options.signal,
    );
    const {
      packageExclusionSources,
      localReferences: discoveredLocalReferences,
      diagnostics,
      ...discovered
    } = await discoverScaInputs(repository, environment, options.signal);
    localReferences = discoveredLocalReferences;
    Object.assign(result.coverage, discovered);
    result.coverage.unresolvedPackages = localReferences.length;
    result.diagnostics.push(...diagnostics);
    const selected = result.coverage.inputs.filter(
      (input) => input.status === "scanned",
    );
    if (selected.length === 0) {
      result.diagnostics.push(
        "No supported effective dependency lockfiles were available.",
      );
      return result;
    }
    const executable = await resolveTrustedExecutable(
      dependencies.executable ?? "osv-scanner",
      environment,
      (await gitMarkerRoot(repository, options.signal, "outermost")) ??
        repository,
    );
    if (executable === null)
      throw new Error(
        "OSV-Scanner is not installed on the trusted PATH. Install OSV-Scanner v2.6.0 or a compatible version.",
      );
    const run = dependencies.runProcess ?? runOsvProcess;
    const processOptions = {
      cwd: repository,
      environment: executable.environment,
      signal: options.signal,
    };
    const version = await run(
      executable.executable,
      ["--version"],
      processOptions,
    );
    if (version.exitCode !== 0)
      throw new Error(
        `OSV version check failed with exit code ${version.exitCode}: ${version.stderr}`,
      );
    scanner.version = version.stdout.trim() || null;
    scanner.argv = [
      "scan",
      "source",
      "--format=json",
      "--all-packages",
      "--no-call-analysis=all",
      "--no-resolve",
      ...selected.map((input) => `--lockfile=:${join(repository, input.path)}`),
    ];
    const output = await run(executable.executable, scanner.argv, {
      ...processOptions,
      stdoutPath: scanner.rawOutputPath,
      stderrPath: scanner.stderrPath,
    });
    scanner.exitCode = output.exitCode;
    await Promise.all([
      writeFile(scanner.rawOutputPath, output.stdout),
      writeFile(scanner.stderrPath, output.stderr),
    ]);
    result.diagnostics.push(...osvErrorDiagnostics(output.stderr));
    if (output.stdout.trim() !== "") {
      const raw: unknown = JSON.parse(output.stdout);
      const normalized = normalizeOsvOutput(raw, {
        repositoryPath: repository,
        inputs: selected,
      });
      const sources = new Set(
        record(raw) && Array.isArray(raw["results"])
          ? raw["results"].flatMap((entry) =>
              record(entry) &&
              record(entry["source"]) &&
              typeof entry["source"]["path"] === "string"
                ? [sourceRelativePath(repository, entry["source"]["path"])]
                : [],
            )
          : [],
      );
      for (const input of selected) {
        if (sources.has(input.path)) continue;
        if (
          output.stderr.includes(
            `Scanned ${join(repository, input.path)} file and found 0 package`,
          )
        ) {
          input.reason = "OSV extracted no packages from this lockfile.";
        } else if (packageExclusionSources.includes(input.path)) {
          input.reason =
            "OSV returned no package tuples after applying configured package exclusions; suppressed counts are unavailable.";
        } else {
          input.status = "failed";
          input.reason =
            "The selected lockfile is absent from OSV output without evidence of an empty or excluded inventory.";
          result.diagnostics.push(`${input.path}: ${input.reason}`);
        }
      }
      result.components = normalized.components;
      result.matches = normalized.matches;
      result.coverage.unresolvedPackages =
        normalized.unresolvedPackages +
        unobservedLocalReferences(localReferences, normalized.components);
      result.diagnostics.push(...normalized.diagnostics);
    } else if (output.exitCode !== 128)
      result.diagnostics.push("OSV returned no JSON output.");
    if (output.exitCode === 128)
      result.diagnostics.push(
        "OSV found no packages in the selected effective inputs; this is not a clean-repository result.",
      );
    else if (output.exitCode !== 0 && output.exitCode !== 1)
      result.diagnostics.push(
        `OSV exited with code ${output.exitCode}. See ${scanner.stderrPath}.`,
      );
    if (output.exitCode === 1 && result.matches.length === 0)
      result.diagnostics.push(
        "OSV reported findings but no advisory matches could be normalized.",
      );
    if (result.coverage.unresolvedPackages > 0)
      result.coverage.limitations.push(
        `${result.coverage.unresolvedPackages} package identities or dependency references lack a resolved npm registry version; their advisory coverage is incomplete.`,
      );
    const incomplete =
      result.diagnostics.length > 0 ||
      result.coverage.unresolvedPackages > 0 ||
      result.coverage.inputs.some(
        (input) => input.status === "unsupported" || input.status === "failed",
      );
    result.status = incomplete
      ? result.components.length > 0
        ? "partial"
        : "failed"
      : "completed";
    result.coverage.status =
      result.status === "completed" ? "complete" : result.status;
    if (result.diagnostics.length > 0)
      for (const input of selected) {
        input.status = "failed";
        input.reason =
          "Scanner execution or matching was incomplete; inspect diagnostics and retained output.";
      }
    return result;
  } catch (error) {
    // Cancellation can occur after the complete scanner JSON reached disk.
    // Preserve those facts even when the process promise rejects.
    if (options.signal?.aborted && result.components.length === 0) {
      const retained = await readFile(scanner.rawOutputPath, "utf8");
      if (retained.trim()) {
        try {
          const normalized = normalizeOsvOutput(JSON.parse(retained), {
            repositoryPath: options.repositoryPath,
            inputs: result.coverage.inputs,
          });
          result.components = normalized.components;
          result.matches = normalized.matches;
          result.coverage.unresolvedPackages =
            normalized.unresolvedPackages +
            unobservedLocalReferences(localReferences, normalized.components);
          result.diagnostics.push(...normalized.diagnostics);
        } catch {
          // A truncated stream remains available as raw evidence, never a clean result.
        }
      }
    }
    result.diagnostics.push(errorMessage(error));
    result.status = result.components.length > 0 ? "partial" : "failed";
    result.coverage.status = result.status;
    for (const input of result.coverage.inputs)
      if (input.status === "scanned") {
        input.status = "failed";
        input.reason = errorMessage(error);
      }
    if (options.signal?.aborted)
      throw Object.assign(new Error(errorMessage(error), { cause: error }), {
        osvResult: result,
      });
    return result;
  } finally {
    scanner.completedAt = now();
  }
}
