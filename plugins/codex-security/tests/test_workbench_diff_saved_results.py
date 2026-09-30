from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from workbench_test_support import (
    initialize_git_repository,
    run_workbench,
    start_delivered_scan,
    write_checkpoint,
)


def saved_diff_candidate(
    tmp_path: Path, *, pending: bool = True, complete: bool = False
) -> tuple[Path, Path, str, Path, dict]:
    state_dir = tmp_path / "state"
    target = tmp_path / "target"
    revision = initialize_git_repository(target)
    workspace_id = str(uuid.uuid4())
    run_workbench(state_dir, "create-workspace", "--workspace-id", workspace_id)
    run_workbench(
        state_dir,
        "save-workspace",
        "--workspace-id",
        workspace_id,
        "--target-path",
        str(target),
        "--scope",
        ".",
        "--mode",
        "diff",
        "--diff-target-kind",
        "commit",
        "--diff-head-revision",
        revision,
    )
    started = start_delivered_scan(
        state_dir, "--workspace-id", workspace_id, "--scan-root", str(tmp_path / "scans")
    )["results"]
    scan_id, scan_dir = started["scanId"], Path(started["scanDir"])
    candidate = {
        "candidate_id": "candidate-synthetic",
        "summary": "Synthetic candidate requiring review.",
        "evidence": "Synthetic source review evidence.",
        "cwe_ids": [],
        "locations": [{"path": "README.md", "start_line": 1, "end_line": 1, "role": "evidence"}],
    }
    ledger = scan_dir / "artifacts/02_discovery/candidate_ledger.jsonl"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(json.dumps(candidate) + "\n")
    # This is the checkpoint emitted when the Diff draft writer automatically retains
    # a ledger candidate omitted from the submitted draft.
    checkpoint = {
        "scanId": scan_id,
        "complete": complete,
        "findings": [],
        "coverage": {
            "completeness": "partial",
            "surfaces": [
                {
                    "candidateId": candidate["candidate_id"],
                    "label": candidate["summary"],
                    "disposition": "needs_follow_up",
                    "notes": "Candidate review is incomplete.",
                }
            ],
            "explicitExclusions": [],
            "deferred": [
                {
                    "candidateId": candidate["candidate_id"],
                    "candidate": candidate,
                    "reason": "Candidate review is incomplete.",
                },
                {"id": "other-review", "reason": "Independent review remains pending."},
            ],
        },
    }
    if not pending:
        checkpoint["coverage"]["surfaces"] = []
        checkpoint["coverage"]["deferred"].pop(0)
    write_checkpoint(scan_dir / "checkpoints", checkpoint)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.parent.mkdir()
    coverage = copy.deepcopy(checkpoint["coverage"])
    coverage["inventoryStrategy"] = "diff"
    for field in ("surfaces", "deferred"):
        for item in coverage[field]:
            item.setdefault("id", item.get("candidateId"))
            if field == "surfaces":
                item["receiptRefs"] = []
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": complete}},
                "findings": {"findings": []},
                "coverage": coverage,
            }
        )
    )
    run_workbench(state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unconfirmed"] == int(pending)
    return state_dir, scan_dir, scan_id, ledger, checkpoint


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize(
    ("validation", "attack_path", "expected_count", "expected_disposition"),
    [
        ("suppressed", None, 0, "rejected"),
        ("not_applicable", None, 0, "not_applicable"),
        ("reportable", "ignore", 0, "rejected"),
        ("suppressed", "deferred", 1, "needs_follow_up"),
        ("not_applicable", "deferred", 1, "needs_follow_up"),
        ("deferred", "ignore", 1, "needs_follow_up"),
        ("reportable", "reportable", 1, "needs_follow_up"),
    ],
)
def test_stopped_diff_reconciles_and_freezes_saved_candidate_decisions(
    tmp_path: Path,
    termination: str,
    validation: str,
    attack_path: str | None,
    expected_count: int,
    expected_disposition: str,
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {
        "disposition": validation,
        "counterevidence_or_proof_gap": "Synthetic validation decision.",
    }
    if attack_path:
        candidate["attack_path"] = {
            "decision": attack_path,
            "proof_gap": "Synthetic path decision.",
        }
    ledger.write_text(json.dumps(candidate) + "\n")
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unconfirmed"] == expected_count
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        candidate_surfaces = [
            item
            for item in coverage["surfaces"]
            if item.get("candidateId") == "candidate-synthetic"
        ]
        assert {item["disposition"] for item in candidate_surfaces} == {expected_disposition}
        assert any(item.get("id") == "other-review" for item in coverage["deferred"])
        assert any(item.get("id") == "scan-stopped" for item in coverage["deferred"])

    assert_retained()
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    snapshots = [
        json.loads((scan_dir / path).read_text())
        for path in manifest["scan"]["preservedSources"]
        if json.loads((scan_dir / path).read_text())["coverage"].get(
            "stoppedDiffCandidateDecisions"
        )
    ]
    assert len(snapshots) == 1
    assert len(snapshots[0]["coverage"]["surfaces"]) == (0 if expected_count else 1)
    if expected_count:
        candidate["validation"]["disposition"] = "suppressed"
        candidate.pop("attack_path", None)
        ledger.write_text(json.dumps(candidate) + "\n")
    else:
        ledger.unlink()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()
    if termination == "fail-scan":
        # Force an actual replay, admitting a new ordinary checkpoint while the
        # ledger has changed. The original decision snapshot remains authoritative.
        late = copy.deepcopy(checkpoint)
        late["coverage"]["deferred"].append({"id": "late-review", "reason": "Late saved review."})
        write_checkpoint(scan_dir / "checkpoints", late)
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
        assert_retained()
        assert any(
            item.get("id") == "late-review"
            for item in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
        )


@pytest.mark.parametrize("publication_failure", ["before_freeze", "after_freeze"])
def test_stopped_diff_retries_saved_decisions_after_publication_failure(
    tmp_path: Path, publication_failure: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    wrapper = tmp_path / "fail_publication.py"
    injected = (
        "original = workbench_saved_results.merge_saved_results\n"
        "def fail_publication(*args, **kwargs):\n"
        "    original(*args, **kwargs)\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results.merge_saved_results = fail_publication\n"
        if publication_failure == "before_freeze"
        else "def fail_publication(*args, **kwargs):\n"
        "    raise OSError('injected publication failure')\n"
        "workbench_saved_results._write_prepared_scan_finalization = fail_publication\n"
    )
    wrapper.write_text(
        f"import sys\nsys.path.insert(0, {str(scripts_dir)!r})\n"
        "import workbench_db\nimport workbench_saved_results\n"
        + injected
        + "raise SystemExit(workbench_db.main())\n"
    )
    failed = subprocess.run(
        [sys.executable, str(wrapper), "fail-scan", "--scan-id", scan_id, "--message", "Stopped."],
        capture_output=True,
        text=True,
        env={**os.environ, "CODEX_SECURITY_STATE_DIR": str(state_dir)},
    )
    assert failed.returncode == 0, failed.stderr
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        frozen = connection.execute(
            "SELECT retained_source_digests_json FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()[0]
    assert (frozen is None) is (publication_failure == "before_freeze")
    ledger.unlink()
    run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unconfirmed"] == 0
    assert not any("publication needs follow-up" in warning for warning in scan["warnings"])


def test_stopped_diff_keeps_decision_evidence_when_parent_supersedes_checkpoints(
    tmp_path: Path,
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path, complete=True)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert not any(item.get("candidateId") for item in coverage["deferred"])
    assert {item["disposition"] for item in coverage["surfaces"]} == {"rejected"}


@pytest.mark.parametrize("invalid", ["phase", "summary", "json"])
def test_stopped_diff_preserves_pending_evidence_when_ledger_is_unusable(
    tmp_path: Path, invalid: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    if invalid == "phase":
        candidate["validation"] = "incomplete phase output"
    elif invalid == "summary":
        del candidate["summary"]
    ledger.write_text("{incomplete" if invalid == "json" else json.dumps(candidate) + "\n")
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unconfirmed"] == 1
    assert any(
        "Could not reconcile the saved Diff candidates" in warning for warning in scan["warnings"]
    )
    assert (scan_dir / "report.md").is_file()


def test_stopped_diff_without_saved_candidates_does_not_consult_ledger(tmp_path: Path) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path, pending=False)
    ledger.write_text("{unrelated incomplete ledger")
    run_workbench(state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped.")
    scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["progress"]["candidates"]["unconfirmed"] == 0
    assert not any("Diff candidates" in warning for warning in scan["warnings"])
    assert not any(
        json.loads(path.read_text())["coverage"].get("stoppedDiffCandidateDecisions")
        for path in (scan_dir / "checkpoints").glob("*.json")
    )


@pytest.mark.parametrize("metadata", [["worker-one"], {"worker": "worker-one"}])
def test_stopped_diff_retains_imported_surface_owner_when_dismissing_candidate(
    tmp_path: Path, metadata: object
) -> None:
    state_dir, scan_dir, scan_id, ledger, _ = saved_diff_candidate(tmp_path)
    imported_surface = {
        "id": "imported-follow-up",
        "candidateId": "imported-candidate",
        "sourceWorkerId": metadata,
        "label": "Imported synthetic coverage",
        "disposition": "needs_follow_up",
        "notes": "Retain the imported ownership metadata.",
        "receiptRefs": [],
    }
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage["surfaces"].append(imported_surface)
    coverage_path.write_text(json.dumps(coverage))
    candidate = json.loads(ledger.read_text())
    candidate["validation"] = {"disposition": "suppressed"}
    ledger.write_text(json.dumps(candidate) + "\n")

    run_workbench(
        state_dir, "fail-scan", "--scan-id", scan_id, "--message", "Stopped after review."
    )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["progress"]["candidates"]["unconfirmed"] == 0
    sources = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"]
    assert any(
        imported_surface in json.loads((scan_dir / path).read_text())["coverage"]["surfaces"]
        for path in sources
    )
    assert any("Skipped malformed coverage surface" in warning for warning in stopped["warnings"])
    assert not any("publication needs follow-up" in warning for warning in stopped["warnings"])
    assert (scan_dir / "report.md").is_file()


@pytest.mark.parametrize("termination", ["fail-scan", "cancel-scan"])
@pytest.mark.parametrize("source", ["parent", "checkpoint"])
@pytest.mark.parametrize(
    "scenario", ["shared", "direct-only", "all-resolved", "linked-only", "other-owner"]
)
def test_stopped_diff_preserves_shared_follow_up_evidence(
    tmp_path: Path, termination: str, source: str, scenario: str
) -> None:
    state_dir, scan_dir, scan_id, ledger, checkpoint = saved_diff_candidate(tmp_path)
    first = json.loads(ledger.read_text())
    second = {**first, "candidate_id": "candidate-pending", "summary": "Second synthetic review."}
    receipt_path = scan_dir / "artifacts/shared-evidence.txt"
    receipt_path.write_text("Synthetic shared route evidence.\n")
    shared = {
        "id": "shared-follow-up",
        "candidateId": first["candidate_id"],
        "label": "Shared synthetic route",
        "disposition": "needs_follow_up",
        "notes": "Both candidates depend on this saved route evidence.",
        "receiptRefs": ["artifacts/shared-evidence.txt"],
    }
    if scenario == "linked-only":
        shared.pop("candidateId")
    elif scenario == "other-owner":
        shared["sourceWorkerId"] = "different-worker"
    deferred = [
        {
            "id": candidate["candidate_id"],
            "candidateId": candidate["candidate_id"],
            "candidate": candidate,
            "reason": "Synthetic validation remains unfinished.",
            "surfaceIds": [shared["id"]],
        }
        for candidate in (first, second)
    ]
    if scenario in {"direct-only", "other-owner"}:
        deferred[1]["surfaceIds"] = []
    checkpoint["coverage"].update(surfaces=[shared], deferred=deferred)
    staged = scan_dir / "drafts" / f"{uuid.uuid4()}.json"
    staged.write_text(
        json.dumps(
            {
                "manifest": {"scan": {"complete": False}},
                "findings": {"findings": []},
                "coverage": {**checkpoint["coverage"], "inventoryStrategy": "diff"},
            }
        )
    )
    run_workbench(state_dir, "write-scan-draft", "--scan-id", scan_id, "--draft-path", str(staged))
    checkpoint_path = write_checkpoint(scan_dir / "checkpoints", checkpoint)
    checkpoint_bytes = checkpoint_path.read_bytes()
    if source == "checkpoint":
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan_dir / name).unlink()
    first["validation"] = {"disposition": "suppressed"}
    second["validation"] = {
        "disposition": "suppressed" if scenario == "all-resolved" else "deferred"
    }
    ledger.write_text("\n".join(json.dumps(candidate) for candidate in (first, second)) + "\n")
    arguments = ["--message", "Synthetic interruption."] if termination == "fail-scan" else []
    run_workbench(state_dir, termination, "--scan-id", scan_id, *arguments)

    def assert_retained() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["progress"]["candidates"]["unconfirmed"] == int(scenario != "all-resolved")
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        pending = [row for row in coverage["deferred"] if row.get("candidateId")]
        assert [row["candidateId"] for row in pending] == (
            [] if scenario == "all-resolved" else [second["candidate_id"]]
        )
        retained = [row for row in coverage["surfaces"] if row["id"] == shared["id"]]
        if scenario in {"shared", "linked-only", "other-owner"}:
            assert retained == [shared]
        else:
            assert retained == []
        assert checkpoint_path.read_bytes() == checkpoint_bytes
        assert receipt_path.read_text() == "Synthetic shared route evidence.\n"

    assert_retained()
    first.pop("validation")
    second["validation"] = {"disposition": "suppressed"}
    ledger.write_text("\n".join(json.dumps(candidate) for candidate in (first, second)) + "\n")
    if termination == "fail-scan":
        # Admit new saved work to force replay of the original frozen decision and
        # surface checkpoints after the live ledger has changed.
        late = copy.deepcopy(checkpoint)
        late["coverage"].update(
            surfaces=[], deferred=[{"id": "late-review", "reason": "Additional saved work."}]
        )
        write_checkpoint(scan_dir / "checkpoints", late)
        run_workbench(state_dir, "recover-scan-results", "--scan-id", scan_id)
        assert any(
            row.get("id") == "late-review"
            for row in json.loads((scan_dir / "coverage.json").read_text())["deferred"]
        )
    else:
        run_workbench(state_dir, "preserve-scan-results", "--scan-id", scan_id)
    assert_retained()
