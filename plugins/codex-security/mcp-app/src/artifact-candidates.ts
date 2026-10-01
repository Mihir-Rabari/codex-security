type JsonObject = Record<string, unknown>;

export function findingCandidateId(finding: JsonObject): string | undefined {
  const provenance = finding.provenance as JsonObject | undefined;
  const extensions = finding.extensions as JsonObject | undefined;
  return [
    provenance?.candidateId,
    extensions?.candidateId,
    extensions?.reportId,
    extensions?.ledgerRowId,
  ].find(
    (value): value is string => typeof value === "string" && !!value.trim(),
  );
}

export function isTerminalCandidateDecision(
  item: JsonObject,
): item is JsonObject & { candidateId: string } {
  return (
    typeof item.candidateId === "string" &&
    (item.disposition === "rejected" || item.disposition === "not_applicable")
  );
}

export function resolvedCandidateIds(input: {
  findings: JsonObject[];
  coverage: JsonObject;
}): Set<string> {
  return new Set(
    [
      ...input.findings.map(findingCandidateId),
      ...[
        ...(input.coverage.surfaces as JsonObject[]),
        ...(input.coverage.explicitExclusions as JsonObject[]),
      ]
        .filter(isTerminalCandidateDecision)
        .map((item) => item.candidateId),
    ].filter((value): value is string => typeof value === "string"),
  );
}
