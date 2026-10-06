"""Reconcile saved cost-limit coverage with Diff candidate ledger decisions."""

from __future__ import annotations

from typing import Any

from candidate_identity import (
    candidate_key,
    coverage_candidate_key,
    diff_candidate_disposition,
    finding_candidate_key,
    surface_reference_key,
)


def _generated_budget_candidate_surface(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    return (
        isinstance(candidate, dict)
        and item.get("candidateId") == candidate.get("candidate_id")
        and item.get("disposition") == (diff_candidate_disposition(candidate) or "needs_follow_up")
        and item.get("label") == candidate.get("summary")
        and item.get("notes") == candidate.get("evidence")
    )


def preserve_budget_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]], candidates: list[dict[str, Any]]
) -> None:
    """Reconcile ledger candidates with the saved cost-limit draft's decisions."""
    findings_by_candidate = {
        key
        for finding in findings
        if isinstance(finding, dict) and (key := finding_candidate_key(finding)) is not None
    }

    terminal_decisions = {
        coverage_candidate_key(item): item["disposition"]
        for field in ("surfaces", "explicitExclusions")
        for item in coverage[field]
        if isinstance(item, dict)
        and item.get("disposition") in ("rejected", "not_applicable")
        and (field != "surfaces" or not _generated_budget_candidate_surface(item))
    }
    dispositions = {
        (None, candidate["candidate_id"]): (
            "reported"
            if (None, candidate["candidate_id"]) in findings_by_candidate
            else terminal_decisions.get((None, candidate["candidate_id"]))
            or diff_candidate_disposition(candidate)
            or "needs_follow_up"
        )
        for candidate in candidates
    }
    deferred_by_candidate = {}
    surfaces_by_candidate = {}
    surfaces_by_id = {}
    for field, index in (
        ("deferred", deferred_by_candidate),
        ("surfaces", surfaces_by_candidate),
    ):
        for item in coverage[field]:
            if isinstance(item, dict) and (key := coverage_candidate_key(item)) is not None:
                index.setdefault(key, []).append(item)
    for surface in coverage["surfaces"]:
        if isinstance(surface, dict) and isinstance(surface.get("id"), str):
            surfaces_by_id.setdefault(surface["id"], []).append(surface)
    coverage["deferred"] = [
        item
        for item in coverage["deferred"]
        if not isinstance(item, dict)
        or dispositions.get(coverage_candidate_key(item), "needs_follow_up") == "needs_follow_up"
    ]
    # Only surviving references protect shared surfaces. Index by ID while retaining
    # owner-specific rows, so each reference need not scan every saved surface.
    referenced = {
        surface_reference_key(surface_id, item, surfaces_by_id.get(surface_id, []))
        for item in coverage["deferred"]
        if isinstance(item, dict)
        for surface_ids in [item.get("surfaceIds", [])]
        if isinstance(surface_ids, list)
        for surface_id in surface_ids
        if isinstance(surface_id, str)
    }
    used_ids = {
        field: {
            item["id"]
            for item in coverage[field]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        for field in ("surfaces", "deferred")
    }

    def available_id(prefix: str, field: str) -> str:
        existing = used_ids[field]
        result, suffix = prefix, 1
        while result in existing:
            suffix += 1
            result = f"{prefix}-{suffix}"
        existing.add(result)
        return result

    for candidate in candidates:
        candidate_id = candidate["candidate_id"]
        key = (None, candidate_id)
        deferred = deferred_by_candidate.get(key, [])
        disposition = dispositions[key]
        # An interrupted budget completion can leave generated candidate rows.
        # Refresh them before retaining pending work, including shared surfaces.
        for surface in surfaces_by_candidate.get(key, []):
            if _generated_budget_candidate_surface(surface):
                surface.update(
                    label=candidate["summary"],
                    disposition=disposition,
                    notes=candidate["evidence"],
                    candidate={
                        **{
                            k: v
                            for k, v in surface["candidate"].items()
                            if k not in {"validation", "attack_path"}
                        },
                        **candidate,
                    },
                )
        if disposition == "needs_follow_up" and deferred:
            for item in deferred:
                item.setdefault("candidate", candidate)
            continue
        # A surface may also carry evidence for unfinished work from another
        # candidate or owner. Preserve those shared rows and add a dedicated decision.
        surfaces = [
            item
            for item in surfaces_by_candidate.get(key, [])
            if isinstance(item.get("id"), str)
            and item["id"].strip()
            and (item.get("disposition") != "reported" or disposition == "reported")
            and candidate_key(item["id"], item.get("sourceWorkerId")) not in referenced
        ]
        if not surfaces:
            surface = {
                "id": available_id(f"candidate-{candidate_id}", "surfaces"),
                "candidateId": candidate_id,
                "label": candidate["summary"],
                "disposition": disposition,
                "notes": candidate["evidence"],
                "receiptRefs": [],
            }
            coverage["surfaces"].append(surface)
            surfaces = [surface]
        retained_candidate = {}
        for item in [*deferred, *surfaces]:
            previous = item.get("candidate")
            if isinstance(previous, dict):
                retained_candidate.update(
                    {k: v for k, v in previous.items() if k not in {"validation", "attack_path"}}
                )
        previous_findings = [
            item["finding"] for item in deferred if isinstance(item.get("finding"), dict)
        ]
        for surface in surfaces:
            if disposition == "reported" or surface.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                surface["disposition"] = disposition
            surface["candidate"] = {**retained_candidate, **candidate}
            if previous_findings:
                if not isinstance(surface.get("previousFindings"), list):
                    surface["previousFindings"] = []
                for finding in previous_findings:
                    if finding not in surface["previousFindings"]:
                        surface["previousFindings"].append(finding)
        if disposition != "needs_follow_up":
            continue
        paths = list(dict.fromkeys(location["path"] for location in candidate["locations"]))
        coverage["deferred"].append(
            {
                "id": available_id(candidate_id, "deferred"),
                "candidateId": candidate_id,
                "candidate": candidate,
                "reason": (
                    "Validation was deferred because the scan reached its cost limit: "
                    f"{candidate['summary']}. Evidence: {candidate['evidence']}"
                ),
                "paths": paths,
                "surfaceIds": [surface["id"] for surface in surfaces],
            }
        )
