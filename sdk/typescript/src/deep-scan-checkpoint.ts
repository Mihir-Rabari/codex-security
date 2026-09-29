import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { readScanFile } from "./contract.js";
import type { ScanCost } from "./cost.js";
import type { SemanticCoverage, SemanticScan } from "./semantic-models.js";

export const DEEP_SCAN_CHECKPOINT = "artifacts/deep-scan/checkpoint.json";

export interface DeepScanPass {
  directory: string;
  scanId?: string;
  failed?: true;
  /** The success and its effect on the error streak have been observed. */
  completed?: true;
  [extension: string]: unknown;
}

interface CompositionMetadata {
  version: 2;
  startedAt: string;
  passes: DeepScanPass[];
  mergedScanIds: string[];
  noNewStreak: number;
  consecutiveErrors: number;
  mergeFailures?: number;
  /** A discovery stop decision. Sealing and publication belong to the parent. */
  terminalReason?: "saturated" | "capped" | "failed" | "canceled";
  [extension: string]: unknown;
}

interface LegacyCompositionMetadata {
  discoveryRuns: number;
  cost?: ScanCost;
  originThreadId?: string | null;
  [extension: string]: unknown;
}

/** Version 2 is shared with workbench_composition.py; flags are not scan status. */
export interface DeepScanCheckpoint extends CompositionMetadata {
  aggregate: SemanticScan | null;
  legacy?: LegacyCompositionMetadata & { coverage: SemanticCoverage };
}

/** get-scan intentionally omits finding and coverage payloads from its response. */
export interface DeepScanCheckpointSummary extends CompositionMetadata {
  aggregate?: never;
  legacy?: LegacyCompositionMetadata & { coverage?: never };
}

export function newDeepScanCheckpoint(startedAt: string): DeepScanCheckpoint {
  return {
    version: 2,
    startedAt,
    passes: [],
    mergedScanIds: [],
    aggregate: null,
    noNewStreak: 0,
    consecutiveErrors: 0,
  };
}

/** The local workbench owns this document, including legacy coordinator conversion. */
export function decodeDeepScanCheckpoint(value: unknown): DeepScanCheckpoint {
  const checkpoint = value as DeepScanCheckpoint;
  requireCheckpointVersion(checkpoint);
  return checkpoint;
}

function requireCheckpointVersion(checkpoint: { version: unknown }): void {
  if (checkpoint.version !== 2)
    throw new Error("Unsupported saved Deep Scan checkpoint.");
}

export function compositionCheckpointFromWorkbench(
  response: Record<string, unknown>,
): DeepScanCheckpointSummary | null {
  const checkpoint = response["compositionCheckpoint"] as
    DeepScanCheckpointSummary | null | undefined;
  if (checkpoint == null) return null;
  requireCheckpointVersion(checkpoint);
  return checkpoint;
}

export async function loadDeepScanCheckpoint(
  scanDir: string,
): Promise<DeepScanCheckpoint | null> {
  try {
    return decodeDeepScanCheckpoint(
      JSON.parse(
        (
          await readScanFile(
            scanDir,
            DEEP_SCAN_CHECKPOINT,
            "Deep Scan checkpoint",
          )
        ).toString("utf8"),
      ),
    );
  } catch (error) {
    // Only an absent checkpoint starts a new composition. Preserve read/parse
    // errors, including the artifact reader's existing path protections.
    const exists = await lstat(join(scanDir, DEEP_SCAN_CHECKPOINT)).then(
      () => true,
      (cause: NodeJS.ErrnoException) => {
        if (cause.code === "ENOENT") return false;
        throw cause;
      },
    );
    if (exists) throw error;
    return null;
  }
}
