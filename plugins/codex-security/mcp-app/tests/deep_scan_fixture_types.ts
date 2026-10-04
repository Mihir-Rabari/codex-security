import type { CoordinatorOptions } from "../src/deep-scan/coordinator.js";
import type {
  DeepScanRunState,
  DeepScanStore,
  DeepScanWorkerMutation,
  PersistedDeepScanWorker,
  CodexWorkerDiagnostic,
} from "../src/deep-scan/types.js";

export type TestRun = DeepScanRunState & { persistedWorkerCount?: number };
export type TestWorker = PersistedDeepScanWorker &
  Pick<DeepScanWorkerMutation, "replaceableFailureKind">;
export type StoreInput<Method extends keyof DeepScanStore> = Parameters<
  DeepScanStore[Method]
>[0];
export type TestCoordinatorOptions = Omit<
  Partial<CoordinatorOptions>,
  "onComplete" | "clock"
> & {
  clock?: {
    now(): number;
    sleep(delayMs: number, signal: AbortSignal): Promise<unknown>;
  };
  onComplete?: (
    ...args: Parameters<NonNullable<CoordinatorOptions["onComplete"]>>
  ) => Promise<unknown>;
};
export interface ExecutorOptions {
  alwaysFailDiscovery?: boolean;
  alwaysInvalidDedupResult?: boolean;
  alwaysOmitDiscoveryArtifact?: boolean | string;
  blockDedup?: boolean;
  blockDedupAfterWrite?: boolean;
  blockDiscovery?: boolean;
  blockDiscoveryAfterWrite?: boolean;
  corruptAcceptedSource?: boolean;
  dropLastDedupFinding?: boolean;
  failFirstDiscoveryAttempt?: boolean;
  invalidFirstDedupResult?: boolean;
  invalidFirstDedupTraceability?: boolean;
  nonRetryableDiscovery?: boolean | string;
  omitFirstDedupCandidateLedger?: boolean;
  omitFirstDiscoveryArtifact?: boolean;
  writePartialBeforeFailure?: boolean;
  blockDiscoveryAfterCalls?: number;
  invalidDedupFromCall?: number;
  invalidDiscoveryAttempts?: number;
  malformedDiscoveryAttempts?: number;
  canonicalCandidateId?: string;
  discoveryCandidateId?: string;
  longDiscoveryFailure?: string;
  nonRetryableDiscoveryMessage?: string;
  dedupEvidenceByCall?: string[];
  failDiscoveryWorkersAfterGate?: string[];
  nonRetryableDiscoveryWorkers?: string[];
  policyRefusalWorkers?: string[];
  transientFailureWorkers?: string[];
  dedupNewFindings?: number[];
  dedupDiagnostics?: CodexWorkerDiagnostic[];
  discoveryDiagnostics?: CodexWorkerDiagnostic[];
  discoveryCandidates?: Record<string, string>;
  policyRefusalMessages?: Record<string, string>;
  discoveryGates?: Record<string, Promise<void>>;
  missingDedupResultsByLabel?: Record<string, number>;
}
