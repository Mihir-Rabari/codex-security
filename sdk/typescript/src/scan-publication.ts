import type { ScanArtifactRestorer } from "./runtime.js";
import {
  loadContract,
  readScanFile,
  requireScanFile,
  type ScanExpectation,
} from "./contract.js";
import { IncompleteScanError, OutputDirectoryError } from "./errors.js";
import { ScanPermissionError } from "./scan-execution.js";
import { ScanResult, type TurnResultMetadata } from "./result.js";
import type { ScanCost } from "./cost.js";
import type { JsonObject } from "./config.js";

export interface CompletedScanTurn {
  threadId: string | null;
  turnResult: TurnResultMetadata;
}

export interface ScanPublicationContext {
  scanId: string;
  scanDir: string;
  pluginRoot: string;
  expectation: ScanExpectation;
  signal: AbortSignal;
  workbench: (args: readonly string[]) => Promise<JsonObject>;
}

/** Seal and load the same contract for ordinary, composed and already-sealed scans. */
export async function publishScan(
  context: ScanPublicationContext,
  turn: CompletedScanTurn,
  cost: ScanCost | null,
  sealed: boolean,
): Promise<{
  result: ScanResult;
  warnings: { message: string; targetChanged: boolean }[];
}> {
  const { scanId, scanDir, pluginRoot, expectation, signal, workbench } =
    context;
  let preparation: JsonObject = {};
  if (!sealed) {
    try {
      preparation = await workbench([
        "prepare-scan-completion",
        "--scan-id",
        scanId,
      ]);
    } catch (error) {
      const saved = await workbench(["get-scan", "--scan-id", scanId]).catch(
        () => null,
      );
      const scan = isRecord(saved) ? saved["scan"] : undefined;
      const progress = isRecord(scan) ? scan["progress"] : undefined;
      const message = isRecord(scan) ? scan["failureMessage"] : undefined;
      if (
        isRecord(progress) &&
        progress["status"] === "failed" &&
        typeof message === "string" &&
        message.trim() !== ""
      ) {
        throw new IncompleteScanError(message);
      }
      throw error;
    }
  }
  const result = await collectResult(
    turn.turnResult,
    turn.threadId,
    scanDir,
    pluginRoot,
    expectation,
    signal,
    true,
  );
  const completion = await workbench([
    "complete-scan",
    "--scan-id",
    scanId,
    ...(cost === null ? [] : ["--cost-json", JSON.stringify(cost)]),
  ]);
  return { result, warnings: publicationWarnings(completion, preparation) };
}

/** Load a result that the workbench has already completed, without completing it again. */
export async function loadPublishedScanResult(
  context: ScanPublicationContext,
  turn: CompletedScanTurn,
  completion: JsonObject,
): Promise<{
  result: ScanResult;
  warnings: { message: string; targetChanged: boolean }[];
}> {
  const result = await collectResult(
    turn.turnResult,
    turn.threadId,
    context.scanDir,
    context.pluginRoot,
    context.expectation,
    context.signal,
    true,
  );
  return { result, warnings: publicationWarnings(completion) };
}

function publicationWarnings(
  completion: JsonObject,
  preparation: JsonObject = {},
) {
  const targetWarnings = new Set([
    ...strings(preparation["targetWarnings"]),
    ...strings(completion["targetWarnings"]),
  ]);
  const scan = completion["scan"];
  return strings(isRecord(scan) ? scan["warnings"] : undefined).map(
    (message) => ({
      message,
      targetChanged: targetWarnings.has(message),
    }),
  );
}

function strings(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export async function collectResult(
  turnResult: TurnResultMetadata,
  threadId: string | null,
  scanDir: string,
  pluginRoot: string,
  expectation: ScanExpectation,
  signal: AbortSignal,
  workbenchValidated = false,
): Promise<ScanResult> {
  const required = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
    "report.md",
  ];
  const missing: string[] = [];
  for (const name of required) {
    try {
      await requireScanFile(scanDir, name, name, signal);
    } catch (error) {
      if (signal.aborted) throw signal.reason ?? error;
      missing.push(name);
    }
  }
  if (missing.length > 0) {
    throw new IncompleteScanError(
      `Codex Security scan completed without required artifacts: ${missing.join(", ")}`,
    );
  }
  const { manifest, findings, coverage } = await loadContract(scanDir, {
    pluginRoot,
    expectation,
    workbenchValidated,
    signal,
  });
  let sarifPath: string | null = null;
  try {
    sarifPath = await requireScanFile(
      scanDir,
      "exports/results.sarif",
      "exports/results.sarif",
      signal,
    );
  } catch (error) {
    if (signal.aborted) throw signal.reason ?? error;
  }
  return new ScanResult({
    manifest,
    findings,
    coverage,
    scanDir,
    threadId,
    turnResult,
    sarifPath,
  });
}

export {
  writeSemanticScanDraft,
  writePreparedScanDraft,
} from "./scan-draft-publication.js";

/** Optional post-scan work may fail, but cannot replace the completed artifacts. */
export async function preservePublishedArtifacts(
  context: {
    result: ScanResult;
    pluginRoot: string;
    expectation: ScanExpectation;
    signal: AbortSignal;
    onRestorationError: (error: OutputDirectoryError) => void;
  },
  prepareRestorer: () => Promise<ScanArtifactRestorer>,
  run: () => Promise<void>,
): Promise<{ error: unknown } | undefined> {
  const { result, pluginRoot, expectation, signal } = context;
  const scanDir = result.scanDir;
  const artifacts = await Promise.all(
    [
      ...new Set([
        "scan-manifest.json",
        "findings.json",
        "coverage.json",
        "report.md",
        ...result.manifest.scan.artifacts.map((artifact) => artifact.path),
      ]),
    ].map(async (name) => ({
      name,
      contents: await readScanFile(scanDir, name, name, signal),
    })),
  );
  let restorer: ScanArtifactRestorer | null = null;
  try {
    restorer = await prepareRestorer();
    await run();
  } catch (error) {
    if (restorer !== null) {
      for (const artifact of artifacts) {
        try {
          await restorer.restore(artifact.name, artifact.contents);
        } catch (cause) {
          const failure = new OutputDirectoryError(
            "Cannot restore an artifact outside the scan directory.",
            { cause },
          );
          context.onRestorationError(failure);
          throw failure;
        }
      }
    }
    if (signal.aborted || error instanceof ScanPermissionError) throw error;
    await collectResult(
      result.turnResult,
      result.threadId,
      scanDir,
      pluginRoot,
      expectation,
      signal,
      true,
    );
    return { error };
  }
}
