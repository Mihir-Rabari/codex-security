import type { ArtifactContext } from "./artifact-context.js";
import { readArtifactJsonl } from "./artifact-io.js";
import type { ScanDraftInput } from "./artifact-scan-draft.js";
import { candidateSchemaV1 } from "./deep-scan/artifact-contracts.js";

type JsonObject = Record<string, unknown>;

async function readDiffCandidates(context: ArtifactContext) {
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

/** Resolve dismissed historical candidates before their pending work downgrades coverage. */
export async function resolvedDiffCandidateIds(
  context: ArtifactContext,
): Promise<string[]> {
  const candidates = await readDiffCandidates(context);
  return (candidates ?? [])
    .filter((candidate) => !isUnconfirmed(candidate))
    .map((candidate) => candidate.candidate_id);
}

/** Retain unresolved diff candidates alongside the final coverage evidence. */
export async function preserveUnconfirmedDiffCandidates(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<ScanDraftInput> {
  const candidates = await readDiffCandidates(context);
  if (candidates === undefined) return input;

  const resolvedIds = new Set<string>();
  for (const finding of input.findings) {
    const provenance = object(finding.provenance);
    const extensions = object(finding.extensions);
    const candidateId = [
      provenance?.candidateId,
      extensions?.candidateId,
      extensions?.reportId,
      extensions?.ledgerRowId,
    ].find((value) => typeof value === "string" && value.trim());
    if (typeof candidateId === "string") resolvedIds.add(candidateId);
  }
  for (const surface of [
    ...(input.coverage.surfaces as JsonObject[]),
    ...(input.coverage.explicitExclusions as JsonObject[]),
  ]) {
    if (
      (surface.disposition === "rejected" ||
        surface.disposition === "not_applicable") &&
      typeof surface.candidateId === "string"
    ) {
      resolvedIds.add(surface.candidateId);
    }
  }

  const pending = new Map(
    candidates
      .filter((candidate) => {
        if (resolvedIds.has(candidate.candidate_id)) return false;
        if (isUnconfirmed(candidate)) return true;
        resolvedIds.add(candidate.candidate_id);
        return false;
      })
      .map((candidate) => [candidate.candidate_id, candidate]),
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
  const surfaces = [...(input.coverage.surfaces as JsonObject[])];
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

function isUnconfirmed(candidate: JsonObject): boolean {
  const validation = object(candidate.validation)?.disposition;
  const attackPath = object(candidate.attack_path)?.decision;
  // Reportable ledger phases still need a matching saved finding.
  if (validation === "deferred" || attackPath === "deferred") return true;
  return (
    validation !== "not_applicable" &&
    validation !== "suppressed" &&
    attackPath !== "ignore"
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
