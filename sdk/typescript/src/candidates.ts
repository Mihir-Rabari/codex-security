import type { CoverageDocument, DeferredCoverage, Finding } from "./models.js";

/** Candidate aliases in canonical precedence order. */
export function findingCandidateIds(
  finding: Pick<Finding, "provenance" | "extensions">,
): string[] {
  return [
    finding.provenance["candidateId"],
    finding.extensions?.candidateId,
    finding.extensions?.reportId,
    finding.extensions?.ledgerRowId,
  ].filter(
    (value): value is string =>
      typeof value === "string" && value.trim() !== "",
  );
}

export function findingCandidateOwner(
  finding: Pick<Finding, "provenance" | "extensions">,
): unknown {
  return (
    finding.provenance["sourceWorkerId"] ??
    finding.provenance["workerId"] ??
    finding.extensions?.["sourceWorkerId"]
  );
}

export function candidateIdentity(
  candidateId: string,
  sourceWorkerId: unknown,
): string {
  return JSON.stringify([sourceWorkerId ?? null, candidateId]);
}

/** Saved candidate identities without a finding or terminal disposition. */
export function unresolvedCandidates(
  coverage: CoverageDocument,
  findings: readonly Finding[],
): DeferredCoverage[] {
  const resolved = new Set<string>();
  for (const finding of findings) {
    const candidateId = findingCandidateIds(finding)[0];
    if (candidateId !== undefined) {
      resolved.add(
        candidateIdentity(candidateId, findingCandidateOwner(finding)),
      );
    }
  }
  // A reported surface can cover multiple candidates; findings confirm identities.
  for (const surface of [
    ...coverage.surfaces,
    ...coverage.explicitExclusions,
  ]) {
    if (
      typeof surface["candidateId"] === "string" &&
      (surface["disposition"] === "rejected" ||
        surface["disposition"] === "not_applicable")
    ) {
      resolved.add(
        candidateIdentity(surface["candidateId"], surface["sourceWorkerId"]),
      );
    }
  }
  const pending = new Map<string, DeferredCoverage>();
  for (const candidate of coverage.deferred) {
    if (candidate.candidateId === undefined) continue;
    const key = candidateIdentity(
      candidate.candidateId,
      candidate.sourceWorkerId,
    );
    if (!resolved.has(key) && !pending.has(key)) pending.set(key, candidate);
  }
  return [...pending.values()];
}
