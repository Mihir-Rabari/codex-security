"""Reconcile saved cost-limit coverage with Diff candidate ledger decisions."""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

from candidate_identity import (
    candidate_key,
    coverage_candidate_key,
    diff_candidate_disposition,
    finding_candidate_key,
    surface_reference_key,
)
from finalize_scan_contract import (
    ContractError,
    _recover_unsealed_coverage,
    _require_portable_relative_path,
    _require_scan_local_file,
)


def recover_candidate_receipts(
    parent: dict[str, Any] | None,
    scan_dir: Path,
    warnings: list[str],
    source: str | None = None,
) -> dict[str, Any] | None:
    if parent is None:
        return parent
    surfaces = parent["coverage"].get("surfaces")
    if not isinstance(surfaces, list) or not any(
        isinstance(row, dict)
        and row.get("disposition") in ("rejected", "not_applicable")
        and (
            not isinstance(row.get("label"), str)
            or not row["label"]
            or row.get("receiptRefs")
            or ("receiptRefs" in row and not isinstance(row["receiptRefs"], list))
        )
        for row in surfaces
    ):
        return parent
    # Receipt recovery must precede resolution of the candidate's saved proof gaps.
    if source is not None:
        directory = scan_dir / Path(source).parent
        scan_dir = directory.parent if directory.name == "checkpoints" else directory
    parent = copy.deepcopy(parent)
    if source is not None:
        coverage = parent["coverage"]
        for index, row in enumerate(coverage["surfaces"]):
            if not isinstance(row, dict) or row.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                continue
            refs = row.get("receiptRefs", [])
            invalid = not isinstance(row.get("label"), str) or not row["label"]
            recovered = []
            if not isinstance(refs, list):
                warnings.append(
                    f"Skipped malformed receipt references for coverage surface {index + 1}: expected an array."
                )
                invalid = True
            for position, ref in enumerate(refs if isinstance(refs, list) else []):
                context = f"coverage.surfaces[{index}].receiptRefs[{position}]"
                try:
                    if not isinstance(ref, str):
                        raise ContractError(f"{context}: expected a string")
                    ref = _require_portable_relative_path(ref, context)
                    if not ref.startswith("artifacts/"):
                        raise ContractError(f"{context}: expected a file under artifacts/")
                    _require_scan_local_file(scan_dir, ref, context)
                except ContractError as exc:
                    warnings.append(
                        f"Skipped malformed coverage receipt {index + 1}.{position + 1}: {exc}."
                    )
                    invalid = True
                    continue
                recovered.append(ref)
            row["receiptRefs"] = recovered
            if invalid:
                row["disposition"] = "needs_follow_up"
                coverage["completeness"] = "partial"
        return parent
    _recover_unsealed_coverage(
        parent["coverage"],
        Path(__file__).resolve().parent.parent / "schemas",
        scan_dir,
        warnings,
        [],
    )
    return parent


def archive_candidate_payloads(destination: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    for row in rows:
        for field, archive in (
            ("candidate", "originalCandidates"),
            ("finding", "previousFindings"),
        ):
            values = (
                [row[field]]
                if field in row and (field not in destination or row[field] != destination[field])
                else []
            )
            if isinstance(row.get(archive), list):
                values.extend(row[archive])
            if not values:
                continue
            if not isinstance(destination.get(archive), list):
                destination[archive] = []
            for value in values:
                if value not in destination[archive]:
                    destination[archive].append(copy.deepcopy(value))


def project_resolved_candidate_rows(
    rows: list[Any], field: str, owner: str | None, states: dict[Any, tuple[str, dict[str, Any]]]
) -> list[Any]:
    retained = []
    for row in rows:
        state = states.get(coverage_candidate_key(row, owner)) if isinstance(row, dict) else None
        if state is None or (
            field != "deferred" and row.get("disposition") not in ("rejected", "not_applicable")
        ):
            retained.append(row)
        else:
            destination = state[1]["provenance"] if state[0] == "reported" else state[1]
            archive_candidate_payloads(destination, [row])
    return retained


def archive_resolved_deferred_payloads(
    coverage: dict[str, Any],
    findings: list[dict[str, Any]],
    resolved: dict[Any, str],
    valid_finding: Callable[[dict[str, Any]], bool],
) -> None:
    states = {
        key: ("reported", finding)
        for finding in findings
        if isinstance(finding, dict)
        and valid_finding(finding)
        and (key := finding_candidate_key(finding)) is not None
        and resolved.get(key) == "reported"
    }
    for field in ("surfaces", "explicitExclusions"):
        rows = coverage.get(field)
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict) and (key := coverage_candidate_key(row)) is not None:
                if (
                    resolved.get(key) in ("rejected", "not_applicable")
                    and row.get("disposition") == resolved[key]
                ):
                    states[key] = (resolved[key], row)
    # Preserve the evidence before the caller removes resolved proof gaps.
    project_resolved_candidate_rows(coverage["deferred"], "deferred", None, states)


def archive_resolved_diff_payloads(
    coverage: dict[str, Any], findings: list[dict[str, Any]], submitted_coverage: dict[str, Any]
) -> None:
    submitted: dict[str, list[dict[str, Any]]] = {}
    rows = submitted_coverage.get("deferred")
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict) and (key := coverage_candidate_key(row)) and key[0] is None:
            submitted.setdefault(key[1], []).append(row)
    for item in coverage["surfaces"] + coverage["explicitExclusions"]:
        if (key := coverage_candidate_key(item)) is not None:
            archive_candidate_payloads(item, submitted.get(key[1], []))
    for finding in findings:
        if (key := finding_candidate_key(finding)) is not None:
            archive_candidate_payloads(finding["provenance"], submitted.get(key[1], []))


def _generated_budget_candidate_surface(item: dict[str, Any]) -> bool:
    candidate = item.get("candidate")
    return (
        isinstance(candidate, dict)
        and isinstance(candidate.get("locations"), list)
        and all(
            isinstance(location, dict) and isinstance(location.get("path"), str)
            for location in candidate["locations"]
        )
        and item.get("candidateId") == candidate.get("candidate_id")
        and item.get("disposition") == (diff_candidate_disposition(candidate) or "needs_follow_up")
        and item.get("label") == candidate.get("summary")
        and item.get("notes") == candidate.get("evidence")
    )


def _budget_candidate_deferred(candidate: dict[str, Any], surface_ids: list[str]) -> dict[str, Any]:
    return {
        "candidate": candidate,
        "reason": (
            "Validation was deferred because the scan reached its cost limit: "
            f"{candidate['summary']}. Evidence: {candidate['evidence']}"
        ),
        "paths": list(dict.fromkeys(location["path"] for location in candidate["locations"])),
        "surfaceIds": surface_ids,
    }


def preserve_budget_candidates(
    coverage: dict[str, Any], findings: list[dict[str, Any]], candidates: list[dict[str, Any]]
) -> None:
    """Reconcile ledger candidates with the saved cost-limit draft's decisions."""
    findings_by_candidate = {
        key
        for finding in findings
        if isinstance(finding, dict) and (key := finding_candidate_key(finding)) is not None
    }

    candidates_by_surface_id = {
        f"candidate-{candidate['candidate_id']}": candidate for candidate in candidates
    }
    legacy_generated = set()
    for surface in coverage["surfaces"]:
        if not isinstance(surface, dict):
            continue
        surface_id = surface.get("id")
        candidate = (
            candidates_by_surface_id.get(surface_id) if isinstance(surface_id, str) else None
        )
        if (
            candidate is not None
            and surface.get("candidateId") is None
            and surface.get("candidate") is None
            and surface.get("sourceWorkerId") is None
            and (
                (
                    surface.get("label") == candidate["summary"]
                    and surface.get("notes") == candidate["evidence"]
                )
                or any(
                    isinstance(row, dict)
                    and coverage_candidate_key(row) == (None, candidate["candidate_id"])
                    and row.get("surfaceIds") == [surface_id]
                    and row.get("reason")
                    == (
                        "Validation was deferred because the scan reached its cost limit: "
                        f"{surface.get('label')}. Evidence: {surface.get('notes')}"
                    )
                    for row in coverage["deferred"]
                )
            )
            and surface.get("disposition") in ("needs_follow_up", "rejected", "not_applicable")
        ):
            surface["candidateId"] = candidate["candidate_id"]
            legacy_generated.add(id(surface))

    def generated_surface(item: dict[str, Any]) -> bool:
        return id(item) in legacy_generated or _generated_budget_candidate_surface(item)

    terminal_decisions = {
        coverage_candidate_key(item): item["disposition"]
        for field in ("surfaces", "explicitExclusions")
        for item in coverage[field]
        if isinstance(item, dict)
        and item.get("disposition") in ("rejected", "not_applicable")
        and (field != "surfaces" or not generated_surface(item))
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
        generated_surfaces = [
            surface for surface in surfaces_by_candidate.get(key, []) if generated_surface(surface)
        ]
        legacy_deferred = {
            id(item)
            for surface in generated_surfaces
            if id(surface) in legacy_generated
            for item in deferred
            if item.get("candidate") is None
            and item.get("surfaceIds") == [surface.get("id")]
            and item.get("reason")
            == (
                "Validation was deferred because the scan reached its cost limit: "
                f"{surface.get('label')}. Evidence: {surface.get('notes')}"
            )
            and isinstance(item.get("paths"), list)
        }
        previous_candidates = [
            surface["candidate"]
            for surface in generated_surfaces
            if isinstance(surface.get("candidate"), dict)
        ]
        generated_surface_ids = [
            surface["id"] for surface in generated_surfaces if isinstance(surface.get("id"), str)
        ]
        for surface in generated_surfaces:
            previous = copy.deepcopy(surface.get("candidate"))
            surface.update(
                label=candidate["summary"],
                disposition=disposition,
                notes=candidate["evidence"],
                candidate={
                    **{
                        k: v
                        for k, v in (surface.get("candidate") or {}).items()
                        if k not in {"validation", "attack_path"}
                    },
                    **candidate,
                },
            )
            if isinstance(previous, dict):
                archive_candidate_payloads(surface, [{"candidate": previous}])
        if disposition == "needs_follow_up" and deferred:
            for item in deferred:
                previous = item.get("candidate")
                if isinstance(previous, dict) and previous in previous_candidates:
                    saved_ids = item.get("surfaceIds")
                    if not (
                        isinstance(saved_ids, list)
                        and saved_ids
                        and all(surface_id in generated_surface_ids for surface_id in saved_ids)
                    ):
                        continue
                    generated = _budget_candidate_deferred(previous, saved_ids)
                    if all(item.get(field) == value for field, value in generated.items()):
                        refreshed = {
                            **{
                                field: value
                                for field, value in previous.items()
                                if field not in {"validation", "attack_path"}
                            },
                            **candidate,
                        }
                        item.update(_budget_candidate_deferred(refreshed, saved_ids))
                elif id(item) in legacy_deferred:
                    refreshed = _budget_candidate_deferred(candidate, item["surfaceIds"])
                    # Legacy rows have no prior snapshot to distinguish authored paths.
                    refreshed["paths"] = list(dict.fromkeys([*item["paths"], *refreshed["paths"]]))
                    item.update(refreshed)
                else:
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
        for surface in surfaces:
            if disposition == "reported" or surface.get("disposition") not in (
                "rejected",
                "not_applicable",
            ):
                surface["disposition"] = disposition
            had_candidate = "candidate" in surface
            previous = surface.get("candidate")
            surface["candidate"] = {**retained_candidate, **candidate}
            if had_candidate:
                archive_candidate_payloads(surface, [{"candidate": previous}])
            archive_candidate_payloads(surface, deferred)
        if disposition != "needs_follow_up":
            continue
        coverage["deferred"].append(
            {
                "id": available_id(candidate_id, "deferred"),
                "candidateId": candidate_id,
                **_budget_candidate_deferred(candidate, [surface["id"] for surface in surfaces]),
            }
        )


def _diff_candidate_phase_snapshot(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        phase: candidate[phase] for phase in ("validation", "attack_path") if phase in candidate
    }


def _diff_candidate_reason(candidate: dict[str, Any]) -> str:
    validation = candidate.get("validation")
    validation = validation if isinstance(validation, dict) else {}
    attack_path = candidate.get("attack_path")
    attack_path = attack_path if isinstance(attack_path, dict) else {}
    if (
        validation.get("disposition") == "reportable"
        and attack_path.get("decision") == "reportable"
    ):
        return f"A reportable candidate has no saved finding: {candidate.get('summary')}"
    return next(
        value
        for value in (
            attack_path.get("proof_gap"),
            validation.get("counterevidence_or_proof_gap"),
            validation.get("remaining_uncertainty"),
            f"Candidate review is incomplete: {candidate.get('summary')}",
        )
        if isinstance(value, str) and value.strip()
    )


def _diff_candidate_decision(candidate: dict[str, Any]) -> dict[str, Any] | None:
    """Project a terminal Diff ledger decision; either deferred phase remains unresolved."""
    validation = candidate.get("validation") or {}
    attack_path = candidate.get("attack_path") or {}
    if not isinstance(validation, dict) or not isinstance(attack_path, dict):
        raise ValueError("Diff candidate phase records must be objects.")
    disposition = diff_candidate_disposition(candidate)
    if disposition is None:
        return None
    summary = candidate.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        raise ValueError("Diff candidate summary is missing.")
    return {
        "candidateId": candidate["candidate_id"],
        "label": summary,
        "disposition": disposition,
        "notes": next(
            value
            for value in (
                *(
                    [attack_path.get("counterevidence"), attack_path.get("severity_rationale")]
                    if attack_path.get("decision") == "ignore"
                    else []
                ),
                validation.get("counterevidence_or_proof_gap"),
                f"Candidate review concluded: {summary}",
            )
            if isinstance(value, str) and value.strip()
        ),
        "candidate": candidate,
    }
