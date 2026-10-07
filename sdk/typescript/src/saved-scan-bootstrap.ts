import { createRequire } from "node:module";
import { isAbsolute, join, resolve } from "node:path";
import { gitMarkerRoot } from "./targets.js";
import { CodexSecurityError } from "./errors.js";
import type { SavedScanDependencies } from "./saved-scan.js";
import {
  codexSecurityStateDirectory,
  resolvePluginPython,
  runWorkbench,
  workbenchEnvironment,
  type ProcessEnvironment,
} from "./runtime.js";

interface ScanTarget {
  id: string;
  target_path: string;
}

interface BootstrapDatabase {
  prepare(sql: string): {
    all(...parameters: (string | number)[]): ScanTarget[];
  };
  close(): void;
}

/** Read only enough history to protect Python discovery; the workbench still validates the scan. */
export async function savedScanWorkbench(
  requestedId: string | { workflowId: string },
  options: {
    environment: ProcessEnvironment;
    pluginRoot: string;
    currentDirectory: string;
    signal?: AbortSignal;
  },
): Promise<
  SavedScanDependencies["runWorkbench"] & { environment: ProcessEnvironment }
> {
  options.signal?.throwIfAborted();
  const environment: ProcessEnvironment = workbenchEnvironment(
    options.environment,
  );
  const targets = readTargets(requestedId, environment);
  const latest = requestedId === "latest" || typeof requestedId !== "string";
  if (targets.length === 0)
    throw new CodexSecurityError(
      latest
        ? "No completed saved scan was found for this repository."
        : "Codex Security scan not found.",
    );
  if (!latest && targets.length > 1)
    throw new CodexSecurityError(
      `Scan ID prefix "${requestedId}" matches multiple scans; use a longer prefix.`,
    );
  if (
    targets.some(
      (target) =>
        typeof target.target_path !== "string" ||
        !isAbsolute(target.target_path),
    )
  )
    throw new CodexSecurityError(
      "Saved scan history has no absolute repository target.",
    );

  const callerRoot = await gitMarkerRoot(
    options.currentDirectory,
    options.signal,
    "outermost",
  );
  let python: string | undefined;
  const workbench: SavedScanDependencies["runWorkbench"] = async (
    args,
    input,
    signal = options.signal,
  ) => {
    signal?.throwIfAborted();
    const target =
      args[0] === "get-scan"
        ? latest
          ? targets.find((row) => row.id === args[2])
          : targets[0]
        : undefined;
    if (args[0] === "get-scan" && !target)
      throw new CodexSecurityError(
        "Saved scan history changed during lookup. Retry the command.",
      );
    // Pin the interpreter selected with every candidate and the caller checkout protected.
    python ??= await resolvePluginPython({
      environment,
      protectedRoot: [
        ...(callerRoot === null ? [] : [callerRoot]),
        ...targets.map((row) => row.target_path),
      ],
      signal,
    });
    environment["PYTHON"] = python;
    const result = await runWorkbench(
      {
        environment,
        pluginRoot: options.pluginRoot,
        python,
        signal,
        failureMessage: "Could not read Codex Security scan history",
      },
      target ? ["get-scan", "--scan-id", target.id] : args,
      input,
    );
    if (target) {
      const scan = result["scan"];
      if (
        typeof scan !== "object" ||
        scan === null ||
        Array.isArray(scan) ||
        scan["scanId"] !== target.id ||
        typeof scan["targetPath"] !== "string" ||
        resolve(scan["targetPath"]) !== resolve(target.target_path)
      )
        throw new CodexSecurityError(
          "Saved scan history changed during lookup. Retry the command.",
        );
    }
    return result;
  };
  return Object.assign(workbench, { environment });
}

function readTargets(
  requestedId: string | { workflowId: string },
  environment: ProcessEnvironment,
): ScanTarget[] {
  const require = createRequire(import.meta.url);
  const bun = process.versions["bun"] !== undefined;
  const Database = (
    bun ? require("bun:sqlite").Database : require("node:sqlite").DatabaseSync
  ) as new (
    path: string,
    options: { readonly?: boolean; readOnly?: boolean },
  ) => BootstrapDatabase;
  let database: BootstrapDatabase | undefined;
  try {
    database = new Database(
      join(codexSecurityStateDirectory(environment), "workbench.sqlite3"),
      bun ? { readonly: true } : { readOnly: true },
    );
    if (typeof requestedId !== "string")
      return database.prepare("SELECT id, target_path FROM scans").all();
    if (requestedId === "latest")
      return database
        .prepare("SELECT id, target_path FROM scans WHERE status = 'complete'")
        .all();
    // Match uuid.UUID's accepted full-ID spellings before considering a prefix.
    const compact = requestedId
      .replace(/^urn:uuid:/, "")
      .replace(/^\{+|\}+$/g, "")
      .replaceAll("-", "");
    if (/^[0-9a-f]{32}$/i.test(compact)) {
      const id = compact
        .toLowerCase()
        .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
      return database
        .prepare("SELECT id, target_path FROM scans WHERE id = ?")
        .all(id);
    }
    if (requestedId.length < 8)
      throw new CodexSecurityError(
        "Scan ID prefixes must be at least eight characters.",
      );
    return database
      .prepare(
        "SELECT id, target_path FROM scans WHERE substr(id, 1, ?) = ? LIMIT 2",
      )
      .all(requestedId.length, requestedId.toLowerCase());
  } catch (error) {
    if (error instanceof CodexSecurityError) throw error;
    throw new CodexSecurityError(
      "Could not read saved scan targets before Python discovery.",
      { cause: error },
    );
  } finally {
    database?.close();
  }
}
