"""Shared identity and resolution rules for saved scan candidates."""

from __future__ import annotations

from typing import Any

CandidateKey = tuple[str | None, str]


def candidate_owner(*values: Any) -> str | None:
    return next((value for value in values if isinstance(value, str) and value.strip()), None)


def candidate_key(candidate_id: Any, owner: Any = None) -> CandidateKey | None:
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        return None
    return candidate_owner(owner), candidate_id


def finding_candidate_id(finding: dict[str, Any]) -> str | None:
    provenance = finding.get("provenance")
    if (
        isinstance(provenance, dict)
        and isinstance(value := provenance.get("candidateId"), str)
        and value.strip()
    ):
        return value
    extensions = finding.get("extensions")
    if not isinstance(extensions, dict):
        return None
    return next(
        (
            value
            for field in ("candidateId", "reportId", "ledgerRowId")
            if isinstance(value := extensions.get(field), str) and value.strip()
        ),
        None,
    )


def finding_candidate_key(finding: dict[str, Any], owner: str | None = None) -> CandidateKey | None:
    provenance = finding.get("provenance")
    provenance = provenance if isinstance(provenance, dict) else {}
    extensions = finding.get("extensions")
    extensions = extensions if isinstance(extensions, dict) else {}
    # A worker result's actual owner overrides imported finding metadata.
    owner = candidate_owner(
        owner,
        provenance.get("sourceWorkerId"),
        provenance.get("workerId"),
        extensions.get("sourceWorkerId"),
    )
    return candidate_key(finding_candidate_id(finding), owner)


def coverage_candidate_key(item: dict[str, Any], owner: str | None = None) -> CandidateKey | None:
    source_owner = candidate_owner(owner) or item.get("sourceWorkerId")
    # A malformed coverage owner cannot resolve valid candidates before draft recovery.
    if source_owner is not None and not isinstance(source_owner, str):
        return None
    return candidate_key(item.get("candidateId"), source_owner)


def _deferred_owner(row: dict[str, Any], owner: str | None) -> str | None:
    return (
        candidate_owner(owner, row.get("sourceWorkerId"))
        if any(key in row for key in ("candidateId", "candidate", "finding"))
        else owner
    )


def _deferred_candidate_id(
    row: dict[str, Any],
    owner: str | None,
    ambiguous_deferred: set[tuple[str | None, str]],
) -> str | None:
    identity = row.get("candidateId") or row.get("id")
    if not isinstance(identity, str):
        return None
    if (owner, identity) in ambiguous_deferred and not any(
        key in row for key in ("candidateId", "candidate", "finding")
    ):
        return None
    return identity


def surface_reference_key(
    surface_id: Any, source: dict[str, Any], surfaces: list[dict[str, Any]]
) -> CandidateKey | None:
    """Prefer the matching owner for duplicate IDs; unique references may be shared."""
    matches = [surface for surface in surfaces if surface.get("id") == surface_id]
    target = next(
        (
            surface
            for surface in matches
            if candidate_owner(surface.get("sourceWorkerId"))
            == candidate_owner(source.get("sourceWorkerId"))
        ),
        matches[0] if len(matches) == 1 else source,
    )
    return candidate_key(surface_id, target.get("sourceWorkerId"))


def unresolved_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Select saved candidate identities without a finding or terminal disposition."""
    candidates: dict[CandidateKey, dict[str, Any]] = {}
    for item in unresolved_candidate_rows(coverage, findings):
        candidates.setdefault(coverage_candidate_key(item), item)
    return list(candidates.values())


def unresolved_candidate_rows(
    coverage: dict[str, Any], findings: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    """Keep each distinct saved proof gap while applying candidate resolutions."""

    def objects(value: Any) -> list[dict[str, Any]]:
        # Progress also reads incomplete, unsealed drafts before finalizer recovery.
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    resolved = {
        key for finding in objects(findings) if (key := finding_candidate_key(finding)) is not None
    }
    for field in ("surfaces", "explicitExclusions"):
        resolved.update(
            key
            for item in objects(coverage.get(field))
            if item.get("disposition") in ("rejected", "not_applicable")
            and (key := coverage_candidate_key(item)) is not None
        )
    candidates = []
    for item in objects(coverage.get("deferred")):
        key = coverage_candidate_key(item)
        if key is not None and key not in resolved and item not in candidates:
            candidates.append(item)
    return candidates


def diff_candidate_disposition(candidate: dict[str, Any]) -> str | None:
    """Return the terminal coverage disposition, with deferred phases taking precedence."""
    validation = candidate.get("validation")
    disposition = validation.get("disposition") if isinstance(validation, dict) else None
    attack_path = candidate.get("attack_path")
    decision = attack_path.get("decision") if isinstance(attack_path, dict) else None
    if disposition == "deferred" or decision == "deferred":
        return None
    if disposition == "not_applicable":
        return "not_applicable"
    if disposition == "suppressed" or decision == "ignore":
        return "rejected"
    return None


def resolved_candidate_surface_keys(
    sources: list[tuple[str, dict[str, Any], str | None]], candidates: set[CandidateKey]
) -> set[CandidateKey | None]:
    """Resolve each dismissed candidate's references in its saved surface context."""
    return {
        surface_reference_key(
            surface_id,
            item,
            [
                surface
                for surfaces in [draft["coverage"].get("surfaces")]
                if isinstance(surfaces, list)
                for surface in surfaces
                if isinstance(surface, dict)
            ],
        )
        for _, draft, worker_id in sources
        for items in [draft["coverage"].get("deferred", [])]
        if isinstance(items, list)
        for item in items
        if isinstance(item, dict) and coverage_candidate_key(item, worker_id) in candidates
        for surface_ids in [item.get("surfaceIds", [])]
        if isinstance(surface_ids, list)
        for surface_id in surface_ids
        if isinstance(surface_id, str)
    }
