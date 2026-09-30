import { statSync } from "node:fs";
import { join } from "node:path";
import type {
  CoverageDocument,
  DeferredCoverage,
  Finding,
  FindingsDocument,
  ScanManifest,
  SeverityLevel,
} from "./models.js";
import { estimateScanCost, type ScanCost } from "./cost.js";
import { meetsSeverity, severityThresholdRank } from "./scan-settings.js";

export interface TurnResultMetadata {
  id?: string;
  status?: string;
  model?: string;
  durationMs?: number;
  finalResponse?: string;
  usage?: unknown;
  [key: string]: unknown;
}

export interface RepositoryFinding extends Pick<
  Finding,
  "findingId" | "occurrenceId" | "title" | "summary" | "severity"
> {
  scanId: string;
  targetId: string;
  status: "open" | "closed";
  confirmedInLatestScan: boolean;
  knownSince?: string;
  knownScanIds?: string[];
  matchedFindingIds?: string[];
  [key: string]: unknown;
}

export interface ScanResultOptions {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
  scanDir: string;
  threadId: string;
  turnResult: TurnResultMetadata;
  sarifPath?: string | null;
  repositoryFindings?: readonly RepositoryFinding[];
}

export class ScanResult {
  public readonly manifest: ScanManifest;
  public readonly findings: FindingsDocument;
  public readonly coverage: CoverageDocument;
  public readonly scanDir: string;
  public readonly threadId: string;
  public readonly turnResult: Readonly<TurnResultMetadata>;
  public readonly cost: Readonly<ScanCost> | null;
  public readonly sarifPath: string | null;
  public repositoryFindings: readonly RepositoryFinding[] | undefined;

  public constructor(options: ScanResultOptions) {
    this.manifest = options.manifest;
    this.findings = options.findings;
    this.coverage = options.coverage;
    this.scanDir = options.scanDir;
    this.threadId = options.threadId;
    this.turnResult = options.turnResult;
    this.repositoryFindings = options.repositoryFindings;
    this.cost = estimateScanCost(
      options.turnResult.model,
      options.turnResult.usage,
    );
    if (options.sarifPath !== undefined) {
      this.sarifPath = options.sarifPath;
    } else {
      const defaultSarifPath = join(
        options.scanDir,
        "exports",
        "results.sarif",
      );
      try {
        this.sarifPath = statSync(defaultSarifPath, {
          throwIfNoEntry: false,
        })?.isFile()
          ? defaultSarifPath
          : null;
      } catch {
        this.sarifPath = null;
      }
    }
  }

  public get reportPath(): string {
    return join(this.scanDir, "report.md");
  }

  public get pluginVersion(): string {
    return this.manifest.scan.producer.version;
  }

  public get manifestPath(): string {
    return join(this.scanDir, "scan-manifest.json");
  }

  public get findingsPath(): string {
    return join(this.scanDir, "findings.json");
  }

  public get coveragePath(): string {
    return join(this.scanDir, "coverage.json");
  }

  public get artifactsDir(): string {
    return join(this.scanDir, "artifacts");
  }

  /** Saved candidates still awaiting a decision, distinct within each logical worker. */
  public get unconfirmedCandidates(): readonly DeferredCoverage[] {
    const identity = (candidateId: string, sourceWorkerId: unknown): string =>
      JSON.stringify([sourceWorkerId ?? null, candidateId]);
    const resolved = new Set<string>();
    for (const finding of this.findings.findings) {
      const candidateId =
        finding.provenance["candidateId"] ?? finding.extensions?.candidateId;
      if (typeof candidateId === "string") {
        resolved.add(
          identity(
            candidateId,
            finding.provenance["sourceWorkerId"] ??
              finding.provenance["workerId"] ??
              finding.extensions?.["sourceWorkerId"],
          ),
        );
      }
    }
    for (const surface of [
      ...this.coverage.surfaces,
      ...this.coverage.explicitExclusions,
    ]) {
      if (
        typeof surface["candidateId"] === "string" &&
        (surface["disposition"] === "reported" ||
          surface["disposition"] === "rejected" ||
          surface["disposition"] === "not_applicable")
      ) {
        resolved.add(
          identity(surface["candidateId"], surface["sourceWorkerId"]),
        );
      }
    }
    const pending = new Map<string, DeferredCoverage>();
    for (const candidate of this.coverage.deferred) {
      if (candidate.candidateId === undefined) continue;
      const key = identity(candidate.candidateId, candidate.sourceWorkerId);
      if (!resolved.has(key) && !pending.has(key)) pending.set(key, candidate);
    }
    return [...pending.values()];
  }

  public get unconfirmedCandidateCount(): number {
    return this.unconfirmedCandidates.length;
  }

  public hasFindingsAtOrAbove(threshold: SeverityLevel): boolean {
    severityThresholdRank(threshold);
    return this.findings.findings.some((finding) =>
      meetsSeverity(finding, threshold),
    );
  }

  public toJSON(): Record<string, unknown> {
    return {
      manifest: this.manifest,
      repositoryFindings: this.repositoryFindings,
      findings: this.findings,
      coverage: this.coverage,
      unconfirmedCandidateCount: this.unconfirmedCandidateCount,
      unconfirmedCandidates: this.unconfirmedCandidates,
      scanDir: this.scanDir,
      threadId: this.threadId,
      reportPath: this.reportPath,
      artifactsDir: this.artifactsDir,
      sarifPath: this.sarifPath,
      cost: this.cost,
      turn: this.turnResult,
    };
  }
}
