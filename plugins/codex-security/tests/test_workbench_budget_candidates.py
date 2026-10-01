from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from test_workbench_db import budget_scan_fixture, complete_budget_scan
from workbench_test_support import run_workbench, write_completed_contract


@pytest.mark.parametrize(
    "decision",
    [
        "reported",
        "suppressed",
        "not_applicable",
        "ignore",
        "deferred",
        "other-owner",
        "existing-terminal",
    ],
)
def test_budget_exhaustion_reconciles_saved_candidate_rows_without_losing_other_work(
    tmp_path: Path, decision: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    previous = {**candidate, "context": "Saved source context."}
    if decision == "ignore":
        candidate["attack_path"] = {"decision": "ignore"}
    else:
        candidate["validation"] = {
            "disposition": "reportable"
            if decision in {"reported", "other-owner", "existing-terminal"}
            else decision
        }
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    if decision in {"reported", "other-owner"}:
        findings_path = scan_dir / "findings.json"
        findings = json.loads(findings_path.read_text())
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
        if decision == "other-owner":
            findings["findings"][0]["provenance"]["sourceWorkerId"] = "worker-other"
        findings_path.write_text(json.dumps(findings))
    surface = {
        "id": "candidate-candidate-1",
        "candidateId": candidate["candidate_id"],
        "label": "Authored candidate review",
        "disposition": "needs_follow_up",
        "notes": "Saved authored evidence.",
        "receiptRefs": [],
        "reviewContext": "Keep this annotation.",
    }
    if decision == "existing-terminal":
        surface["disposition"] = "rejected"
    shared = {**surface, "id": "shared-review", "sourceWorkerId": " "}
    other_owner = {
        **surface,
        "id": "other-owner-review",
        "sourceWorkerId": "worker-other",
        "disposition": "needs_follow_up",
    }
    generic = {
        "id": "general-review",
        "reason": "Independent unfinished review.",
        "surfaceIds": [shared["id"]],
    }
    independent = {
        "id": "other-owner-candidate",
        "candidateId": candidate["candidate_id"],
        "sourceWorkerId": "worker-other",
        "reason": "A different worker's unfinished review.",
        "surfaceIds": [other_owner["id"]],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"] = [surface, shared, other_owner]
    coverage["deferred"] = [
        {
            "id": "candidate-1",
            "candidateId": candidate["candidate_id"],
            "candidate": previous,
            "reason": "Authored unresolved evidence.",
            "surfaceIds": [surface["id"]],
        },
        generic,
        independent,
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    preserved = json.loads(coverage_path.read_text())
    assert generic in preserved["deferred"]
    assert independent in preserved["deferred"]
    assert shared in preserved["surfaces"]
    assert other_owner in preserved["surfaces"]
    expected_disposition = {
        "reported": "reported",
        "suppressed": "rejected",
        "not_applicable": "not_applicable",
        "ignore": "rejected",
        "deferred": "needs_follow_up",
        "other-owner": "needs_follow_up",
        "existing-terminal": "rejected",
    }[decision]
    retained = next(row for row in preserved["surfaces"] if row["id"] == surface["id"])
    assert retained["disposition"] == expected_disposition
    assert retained["notes"] == surface["notes"]
    assert retained["reviewContext"] == surface["reviewContext"]
    pending = [
        row
        for row in preserved["deferred"]
        if row.get("candidateId") == candidate["candidate_id"] and not row.get("sourceWorkerId")
    ]
    assert bool(pending) is (decision in {"deferred", "other-owner"})
    assert completed["progress"]["candidates"]["unresolved"] == (2 if decision == "deferred" else 1)
    if decision in {"deferred", "other-owner"}:
        assert pending[0] == coverage["deferred"][0]
    else:
        assert retained["candidate"] == {**previous, **candidate}


@pytest.mark.parametrize("decision", ["reported", "suppressed", "not_applicable"])
def test_budget_exhaustion_retains_original_deferred_finding_evidence(
    tmp_path: Path, decision: str
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "reportable" if decision == "reported" else decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = scan_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    original = dict(findings["findings"][0])
    original["summary"] = "Original detailed finding evidence from the deferred review."
    original["evidence"] = {"context": "Additional synthetic source review evidence."}
    if decision == "reported":
        findings["findings"][0]["provenance"]["candidateId"] = candidate["candidate_id"]
    else:
        findings["findings"] = []
    findings_path.write_text(json.dumps(findings))
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["deferred"] = [
        {
            "id": "pending-candidate",
            "candidateId": candidate["candidate_id"],
            "candidate": candidate,
            "finding": original,
            "reason": "Authored review gap.",
        }
    ]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["progress"]["candidates"]["unresolved"] == 0
    preserved = json.loads(coverage_path.read_text())
    assert not any(
        row.get("candidateId") == candidate["candidate_id"] for row in preserved["deferred"]
    )
    surface = next(
        row for row in preserved["surfaces"] if row.get("candidateId") == candidate["candidate_id"]
    )
    assert original in surface["previousFindings"]


@pytest.mark.parametrize("decision", ["suppressed", "deferred"])
def test_budget_exhaustion_preserves_shared_reported_surface(tmp_path: Path, decision: str) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": decision}
    ledger.write_text(json.dumps(candidate) + "\n")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    shared = {
        "id": "shared-reported",
        "candidateId": candidate["candidate_id"],
        "label": "Shared reviewed surface",
        "disposition": "reported",
        "notes": "This surface includes a confirmed finding and another candidate.",
        "receiptRefs": [],
    }
    coverage.update(surfaces=[shared], deferred=[])
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["findingCount"] == 1
    preserved = json.loads(coverage_path.read_text())
    assert shared in preserved["surfaces"]
    candidate_surfaces = [
        row
        for row in preserved["surfaces"]
        if row["id"] != shared["id"] and row.get("candidateId") == candidate["candidate_id"]
    ]
    assert len(candidate_surfaces) == 1
    assert candidate_surfaces[0]["disposition"] == (
        "rejected" if decision == "suppressed" else "needs_follow_up"
    )
    assert completed["progress"]["candidates"]["unresolved"] == int(decision == "deferred")


@pytest.mark.parametrize("malformed", [{"surfaceIds": None}, {"id": {}}])
def test_budget_exhaustion_keeps_failure_recovery_for_malformed_coverage(
    tmp_path: Path, malformed: dict[str, Any]
) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path)
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    invalid = {"id": "malformed-review", "reason": "Unrelated saved review.", **malformed}
    coverage["deferred"] = [invalid]
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == 1
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert invalid not in json.loads(coverage_path.read_text())["deferred"]


@pytest.mark.parametrize("disposition", [{}, []])
def test_budget_exhaustion_preserves_structured_exclusion_extensions(
    tmp_path: Path, disposition: Any
) -> None:
    state_dir, target, scan_dir, scan_id, _ = budget_scan_fixture(tmp_path, candidates=[])
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    exclusion = {
        "pattern": "synthetic-exclusion/**",
        "reason": "Unrelated scope exclusion.",
        "disposition": disposition,
    }
    coverage["explicitExclusions"] = [exclusion]
    coverage_path.write_text(json.dumps(coverage))

    completed = complete_budget_scan(state_dir, scan_id)["scan"]

    assert completed["progress"]["status"] == "complete"
    assert completed["findingCount"] == 1
    assert exclusion in json.loads(coverage_path.read_text())["explicitExclusions"]
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


def test_budget_exhaustion_retains_ledger_candidate_when_recovering_nonobject_surface(
    tmp_path: Path,
) -> None:
    state_dir, target, scan_dir, scan_id, ledger = budget_scan_fixture(tmp_path)
    candidate = json.loads(ledger.read_text())
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"].append(None)
    generic = {
        "id": "general-review",
        "reason": "Unrelated review remains pending.",
        "surfaceIds": [coverage["surfaces"][0]["id"]],
    }
    coverage["deferred"] = [generic]
    coverage_path.write_text(json.dumps(coverage))

    result = complete_budget_scan(state_dir, scan_id, check=False)

    assert result["returncode"] != 0
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["status"] == "failed"
    assert scan["findingCount"] == 1
    assert scan["progress"]["candidates"]["unresolved"] == 1
    recovered = json.loads(coverage_path.read_text())
    assert generic in recovered["deferred"]
    pending = next(row for row in recovered["deferred"] if row.get("candidateId"))
    assert pending["candidate"] == candidate
    assert None not in recovered["surfaces"]
    assert json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["sealedAt"]


def test_budget_candidate_projection_preserves_owner_references_and_unique_ids_at_scale(
    workbench_api,
) -> None:
    candidates = [
        {
            "candidate_id": f"synthetic-{index}",
            "summary": "Synthetic candidate review.",
            "evidence": "Synthetic source context.",
            "locations": [{"path": "app.py"}],
        }
        for index in range(1000)
    ]
    shared = {
        "id": "shared-surface",
        "candidateId": candidates[0]["candidate_id"],
        "disposition": "needs_follow_up",
        "notes": "Keep shared evidence.",
    }
    worker = {**shared, "sourceWorkerId": "worker-other"}
    generic = {"id": "generic-review", "surfaceIds": [shared["id"]]}
    collision = {"id": "candidate-synthetic-1", "notes": "Unrelated coverage."}
    coverage = {
        "surfaces": [shared, worker, collision],
        "deferred": [generic, {"id": "synthetic-1", "reason": "Unrelated review."}],
        "explicitExclusions": [],
    }

    workbench_api["saved_results"].preserve_budget_candidates(coverage, [], candidates)

    assert shared in coverage["surfaces"]
    assert worker in coverage["surfaces"]
    assert collision in coverage["surfaces"]
    assert "candidate" not in shared
    assert "candidate" not in worker
    assert generic in coverage["deferred"]
    pending = [row for row in coverage["deferred"] if row.get("candidateId")]
    assert len(pending) == len(candidates)
    assert {row["candidateId"] for row in pending} == {
        candidate["candidate_id"] for candidate in candidates
    }
    for field in ("surfaces", "deferred"):
        keys = {(row.get("sourceWorkerId"), row["id"]) for row in coverage[field]}
        assert len(keys) == len(coverage[field])
    surface_ids = {row["id"] for row in coverage["surfaces"]}
    assert all(set(row["surfaceIds"]) <= surface_ids for row in pending)
