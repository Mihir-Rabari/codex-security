import {
  findingCandidateId,
  isTerminalCandidateDecision,
  resolvedCandidateIds,
} from "./artifact-candidates.js";
import type { ArtifactContext } from "./artifact-context.js";
import { readArtifactJsonl } from "./artifact-io.js";
import type { ScanDraftInput } from "./artifact-scan-draft.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";

type JsonObject = Record<string, unknown>;

export async function readDiffCandidates(context: ArtifactContext) {
  if (context.mode !== "diff") return undefined;
  const label = "diff candidate ledger";
  try {
    return await readArtifactJsonl(
      context,
      ["artifacts", "02_discovery", "candidate_ledger.jsonl"],
      label,
      candidateSchemaV1.passthrough(),
    );
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === `${label}: the requested artifact is unavailable.`
    ) {
      return undefined;
    }
    throw error;
  }
}

export type DiffCandidates = Awaited<ReturnType<typeof readDiffCandidates>>;

/**
 * Project ledger dismissals before historical findings and follow-ups are merged.
 * Current findings remain authoritative if a checkpoint inherits an older final draft.
 */
export function preserveDiffCandidateDecisions(
  input: ScanDraftInput,
  candidates: DiffCandidates,
  previous: ScanDraftInput[] = [],
  currentFindings: JsonObject[] = input.findings,
): ScanDraftInput {
  if (candidates === undefined) return input;
  const resolved = resolvedCandidateIds({
    ...input,
    findings: currentFindings,
  });
  const currentFindingIds = new Set(currentFindings.map(findingCandidateId));
  const dismissed = new Set<string>();
  const surfaces = [...(input.coverage.surfaces as JsonObject[])];
  const exclusions = [...(input.coverage.explicitExclusions as JsonObject[])];
  const previousDecisions = new Map<
    string,
    { section: string; item: JsonObject }
  >();
  for (const source of previous) {
    for (const section of ["surfaces", "explicitExclusions"]) {
      for (const item of source.coverage[section] as JsonObject[]) {
        if (
          isTerminalCandidateDecision(item) &&
          !previousDecisions.has(item.candidateId)
        )
          previousDecisions.set(item.candidateId, { section, item });
      }
    }
  }
  for (const candidate of candidates) {
    const disposition = candidateDisposition(candidate);
    if (
      disposition === undefined ||
      currentFindingIds.has(candidate.candidate_id)
    )
      continue;
    dismissed.add(candidate.candidate_id);
    if (resolved.has(candidate.candidate_id)) continue;
    // An authored final decision keeps its rationale on later empty saves.
    const retained = previousDecisions.get(candidate.candidate_id);
    if (retained) {
      (retained.section === "surfaces" ? surfaces : exclusions).push(
        structuredClone(retained.item),
      );
    } else {
      surfaces.push({
        candidateId: candidate.candidate_id,
        candidate,
        label: candidate.summary,
        disposition,
        notes: terminalReason(candidate),
      });
    }
    resolved.add(candidate.candidate_id);
  }
  return {
    ...input,
    findings: input.findings.filter((finding) => {
      const candidateId = findingCandidateId(finding);
      return candidateId === undefined || !dismissed.has(candidateId);
    }),
    coverage: { ...input.coverage, surfaces, explicitExclusions: exclusions },
  };
}

/** Retain unresolved diff candidates alongside the final coverage evidence. */
export function preserveUnresolvedDiffCandidates(
  input: ScanDraftInput,
  candidates: DiffCandidates,
): ScanDraftInput {
  if (candidates === undefined) return input;
  const resolvedIds = resolvedCandidateIds(input);
  const pending = new Map(
    candidates
      .filter(
        (candidate) =>
          !resolvedIds.has(candidate.candidate_id) &&
          candidateDisposition(candidate) === undefined,
      )
      .map((candidate) => [candidate.candidate_id, candidate]),
  );
  const previous = new Map(
    (input.coverage.deferred as JsonObject[]).map((item) => [
      item.candidateId ?? item.id,
      item,
    ]),
  );
  const deferred = (input.coverage.deferred as JsonObject[])
    .filter((item) => {
      const candidateId = item.candidateId ?? item.id;
      return typeof candidateId !== "string" || !resolvedIds.has(candidateId);
    })
    .map((item) => {
      const candidateId = item.candidateId ?? item.id;
      const candidate =
        typeof candidateId === "string" ? pending.get(candidateId) : undefined;
      if (!candidate) return item;
      const previous = object(item.candidate);
      return {
        ...item,
        candidateId: candidate.candidate_id,
        candidate: { ...previous, ...candidate },
        reason:
          item.reason === candidateReason(previous ?? candidate)
            ? candidateReason(candidate)
            : item.reason,
      };
    });
  const recordedIds = new Set(
    deferred.map((item) => item.candidateId ?? item.id),
  );
  for (const candidate of pending.values()) {
    if (recordedIds.has(candidate.candidate_id)) continue;
    deferred.push({
      candidateId: candidate.candidate_id,
      candidate,
      reason: candidateReason(candidate),
      paths: [...new Set(candidate.locations.map((location) => location.path))],
    });
  }
  const surfaces = (input.coverage.surfaces as JsonObject[]).map((surface) => {
    const item = previous.get(surface.candidateId);
    const candidate = pending.get(surface.candidateId as string);
    const oldCandidate = object(item?.candidate);
    if (
      !candidate ||
      !oldCandidate ||
      surface.disposition !== "needs_follow_up" ||
      (input.coverage.deferred as JsonObject[]).some(
        (other) =>
          other !== item &&
          Array.isArray(other.surfaceIds) &&
          other.surfaceIds.includes(surface.id),
      )
    )
      return surface;
    return {
      ...surface,
      ...(surface.label === oldCandidate.summary
        ? { label: candidate.summary }
        : {}),
      ...(surface.notes === candidateReason(oldCandidate)
        ? { notes: candidateReason(candidate) }
        : {}),
    };
  });
  for (const item of deferred) {
    if (typeof item.candidateId !== "string") continue;
    const candidate = pending.get(item.candidateId);
    if (!candidate) continue;
    const surfaceIds = Array.isArray(item.surfaceIds) ? item.surfaceIds : [];
    if (
      surfaces.some(
        (surface) =>
          surface.candidateId === item.candidateId ||
          surfaceIds.includes(surface.id),
      )
    )
      continue;
    surfaces.push({
      candidateId: item.candidateId,
      label: candidate.summary,
      disposition: "needs_follow_up",
      notes: item.reason,
    });
  }
  return {
    ...input,
    coverage: {
      ...input.coverage,
      ...(deferred.length > 0 ? { completeness: "partial" } : {}),
      deferred,
      surfaces,
    },
  };
}

function candidateDisposition(
  candidate: JsonObject,
): "rejected" | "not_applicable" | undefined {
  const validation = object(candidate.validation)?.disposition;
  const attackPath = object(candidate.attack_path)?.decision;
  // Reportable ledger phases still need a matching saved finding.
  if (validation === "deferred" || attackPath === "deferred") return undefined;
  if (validation === "not_applicable") return "not_applicable";
  if (validation === "suppressed" || attackPath === "ignore") return "rejected";
  return undefined;
}

function terminalReason(candidate: JsonObject): string {
  const validation = object(candidate.validation);
  const attackPath = object(candidate.attack_path);
  return (
    [
      ...(attackPath?.decision === "ignore"
        ? [attackPath.counterevidence, attackPath.severity_rationale]
        : []),
      validation?.counterevidence_or_proof_gap,
    ].find(
      (value): value is string => typeof value === "string" && !!value.trim(),
    ) ?? `Candidate review concluded: ${candidate.summary}`
  );
}

function candidateReason(candidate: JsonObject): string {
  const validation = object(candidate.validation);
  const attackPath = object(candidate.attack_path);
  if (
    validation?.disposition === "reportable" &&
    attackPath?.decision === "reportable"
  ) {
    return `A reportable candidate has no saved finding: ${candidate.summary}`;
  }
  return (
    [
      attackPath?.proof_gap,
      validation?.counterevidence_or_proof_gap,
      validation?.remaining_uncertainty,
    ].find(
      (value): value is string =>
        typeof value === "string" && value.trim().length > 0,
    ) ?? `Candidate review is incomplete: ${candidate.summary}`
  );
}

function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}
