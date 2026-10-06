from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    committed_standard_reducer,
    deep_scan_fixture,
)
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("same_worker", [True, False])
def test_legacy_stopped_parent_yields_to_current_worker_resolution(
    tmp_path: Path, disposition: str, same_worker: bool
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    current = json.loads(result_path.read_text())
    result_path.unlink()
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(
        contract_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    findings_path = contract_dir / "findings.json"
    findings = json.loads(findings_path.read_text())
    finding = findings["findings"][0]
    finding["provenance"].update(
        candidateId="candidate-one", workerId=worker_id if same_worker else str(uuid.uuid4())
    )
    findings_path.write_text(json.dumps(findings))
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    subprocess.run(
        [
            sys.executable,
            str(scripts_dir / "finalize_scan_contract.py"),
            "--scan-dir",
            str(contract_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    for filename in ("findings.json", "coverage.json", "scan-manifest.json"):
        (scan_dir / filename).write_bytes((contract_dir / filename).read_bytes())
    sealed_manifest = (scan_dir / "scan-manifest.json").read_bytes()
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET seal_manifest_digest = ? WHERE id = ?",
            (f"sha256:{hashlib.sha256(sealed_manifest).hexdigest()}", scan_id),
        )
    environment = {"CODEX_HOME": str(codex_home)}
    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        environment=environment,
    )
    assert (
        json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]["preservedSources"] == {}
    )
    current["coverage"]["surfaces"] = [
        {
            "label": "Reviewed candidate",
            "candidateId": "candidate-one",
            "disposition": disposition,
            "notes": "Current worker validation resolved this candidate.",
        }
    ]
    result_path.write_text(json.dumps(current))

    recovered = run_workbench(
        state_dir, "recover-scan-results", "--scan-id", scan_id, environment=environment
    )["scan"]

    assert recovered["findingCount"] == (0 if same_worker else 1)
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    resolution = next(
        item for item in coverage["surfaces"] if item.get("candidateId") == "candidate-one"
    )
    assert resolution["disposition"] == disposition
    assert resolution["sourceWorkerId"] == worker_id
    assert len(resolution.get("previousFindings", [])) == (1 if same_worker else 0)


@pytest.mark.parametrize("pending_candidate_id", ["candidate-one", "candidate-two"])
def test_stopped_recovery_resolves_reported_candidates_from_findings(
    tmp_path: Path, pending_candidate_id: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    _, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    contract_dir = tmp_path / "contract"
    contract_dir.mkdir()
    write_completed_contract(contract_dir, scan_id, target, relative_path="app.py")
    finding = json.loads((contract_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"]["candidateId"] = "candidate-two"
    current = json.loads(result_path.read_text())
    current["findings"] = [finding]
    current["coverage"]["deferred"] = [
        {"candidateId": pending_candidate_id, "reason": "This candidate still needs validation."}
    ]
    current["coverage"]["surfaces"] = [
        {
            "label": "Shared candidate surface",
            "candidateId": pending_candidate_id,
            "disposition": "reported",
            "notes": "The surface contains a reported candidate and unfinished validation.",
        }
    ]
    result_path.write_text(json.dumps(current))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Worker stopped.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    assert [item["candidateId"] for item in pending] == (
        ["candidate-one"] if pending_candidate_id == "candidate-one" else []
    )
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["provenance"]["candidateId"] == "candidate-two"


@pytest.mark.parametrize("scope", [".", "app.py"])
def test_stopped_reducer_candidates_without_coverage_preserve_scope(
    tmp_path: Path, scope: str
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path)
    worker_id, result_path = accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id)
    _, reducer_path, _ = committed_standard_reducer(
        state_dir, codex_home, scan_dir, scan_id, worker_id, result_path
    )
    with sqlite3.connect(state_dir / "workbench.sqlite3") as connection:
        connection.execute("UPDATE scans SET scope = ? WHERE id = ?", (scope, scan_id))
    reduced = json.loads(reducer_path.read_text())
    reduced.pop("coverage")
    reduced["unresolvedCandidates"] = [
        {
            "candidateId": "pending-reducer",
            "sourceWorkerId": worker_id,
            "candidate": {"title": "Review parser bounds"},
            "reason": "The parser route still needs validation.",
        }
    ]
    reducer_path.write_text(json.dumps(reduced))
    reducer_bytes = reducer_path.read_bytes()

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped before the parent draft was written.",
        environment={"CODEX_HOME": str(codex_home)},
    )

    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
    assert stopped["progress"]["candidates"]["unresolved"] == 1
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert coverage["inventoryStrategy"] == ("repository" if scope == "." else "scoped_path")
    assert coverage["includePaths"] == [scope]
    assert coverage["completeness"] == "partial"
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    assert len(pending) == 1
    assert pending[0]["candidateId"] == "pending-reducer"
    assert pending[0]["sourceWorkerId"] == worker_id
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["sealedAt"]
    assert manifest["scan"]["status"] == "failed"
    assert "| Unresolved candidates | 1 |" in (scan_dir / "report.md").read_text()
    assert reducer_path.read_bytes() == reducer_bytes


@pytest.mark.parametrize("resolve_first", [False, True])
def test_recovery_keeps_pending_candidate_identity_scoped_to_its_worker(
    tmp_path: Path, resolve_first: bool
) -> None:
    state_dir, codex_home, _, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    workers = [
        accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, name=f"worker-{index}")
        for index in range(2)
    ]
    for index, (_, result_path) in enumerate(workers):
        draft = json.loads(result_path.read_text())
        draft["coverage"].update(
            completeness="partial",
            deferred=[
                {
                    "candidateId": "candidate-one",
                    "reason": "The parser route still needs validation.",
                    "candidate": {"title": "Review parser bounds"},
                }
            ],
        )
        write_checkpoint(result_path.parent / "checkpoints", draft)
        if index == 0 and resolve_first:
            draft["coverage"].update(
                completeness="complete",
                deferred=[],
                surfaces=[
                    {
                        "candidateId": "candidate-one",
                        "label": "Parser route",
                        "disposition": "rejected",
                        "notes": "The existing bounds check covers this route.",
                    }
                ],
            )
        result_path.write_text(json.dumps(draft))

    run_workbench(
        state_dir,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped after candidate checkpoints.",
        environment={"CODEX_HOME": str(codex_home)},
    )
    stopped = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]

    coverage = json.loads((scan_dir / "coverage.json").read_text())
    pending = [item for item in coverage["deferred"] if item.get("candidateId")]
    expected_owners = {workers[1][0]} if resolve_first else {worker[0] for worker in workers}
    assert {item["sourceWorkerId"] for item in pending} == expected_owners
    assert stopped["progress"]["candidates"]["unresolved"] == len(expected_owners)


@pytest.mark.parametrize("owner_field", ["workerId", "sourceWorkerId"])
@pytest.mark.parametrize("termination", ["failed", "canceled"])
@pytest.mark.parametrize("source", ["worker", "legacy-reducer"])
def test_recovery_preserves_bound_worker_owner_over_imported_metadata(
    tmp_path: Path, owner_field: str, termination: str, source: str
) -> None:
    state_dir, codex_home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    workers = [
        accepted_standard_worker(state_dir, codex_home, scan_dir, scan_id, name=f"worker-{index}")
        for index in range(2)
    ]
    owner_a, result_a = workers[0]
    owner_b, result_b = workers[1]
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, target, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(candidateId="shared-candidate", **{owner_field: owner_b})
    finding["summary"] = "Stronger current worker finding."
    draft_a = json.loads(result_a.read_text())
    draft_a["findings"] = [finding]
    earlier = copy.deepcopy(draft_a)
    earlier["findings"][0]["severity"]["level"] = "low"
    earlier["findings"][0]["summary"] = "Earlier weaker worker finding."
    checkpoint = write_checkpoint(result_a.parent / "checkpoints", earlier)
    result_a.write_text(json.dumps(draft_a))
    draft_b = json.loads(result_b.read_text())
    draft_b["coverage"].update(
        completeness="partial",
        deferred=[
            {
                "candidateId": "shared-candidate",
                "reason": "Independent worker review remains pending.",
                "candidate": {"title": "Independent saved candidate"},
            }
        ],
    )
    result_b.write_text(json.dumps(draft_b))
    source_paths = [result_a, result_b, checkpoint]
    if source == "legacy-reducer":
        _, reducer_path, _ = committed_standard_reducer(
            state_dir,
            codex_home,
            scan_dir,
            scan_id,
            owner_a,
            result_a,
            additional_worker_ids=(owner_b,),
        )
        reduced = copy.deepcopy(draft_a)
        reduced["findings"][0]["provenance"]["sourceFindings"] = [
            {"id": f"{owner_a}:0", "finding": copy.deepcopy(finding)}
        ]
        reduced["coverage"] = copy.deepcopy(draft_b["coverage"])
        reduced["coverage"]["deferred"][0]["sourceWorkerId"] = owner_b
        reducer_path.write_text(json.dumps(reduced))
        source_paths.extend(
            [reducer_path, write_checkpoint(reducer_path.parent / "checkpoints", reduced)]
        )
    originals = {path: path.read_bytes() for path in source_paths}
    environment = {"CODEX_HOME": str(codex_home)}
    if termination == "canceled":
        run_workbench(
            state_dir,
            "cancel-scan",
            "--scan-id",
            scan_id,
            "--thread-id",
            "standard-worker-thread",
            environment=environment,
        )
    else:
        run_workbench(
            state_dir,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Stopped after worker review.",
            environment=environment,
        )

    def assert_owned_results() -> None:
        scan = run_workbench(state_dir, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 1
        assert scan["progress"]["candidates"]["unresolved"] == 1
        history = run_workbench(state_dir, "list-scans")["scans"][0]
        assert "unresolved" not in history["progress"]["candidates"]
        retained = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
        assert retained["summary"] == finding["summary"]
        assert retained["provenance"]["sourceWorkerId"] == owner_a
        if owner_field == "workerId":
            assert retained["provenance"][owner_field] == owner_b
        else:
            originals_in_history = retained["provenance"].get("previousFindings", []) + [
                source["finding"] for source in retained["provenance"].get("sourceFindings", [])
            ]
            assert finding in originals_in_history
        if source == "legacy-reducer":
            assert (
                retained["provenance"]["sourceFindings"]
                == reduced["findings"][0]["provenance"]["sourceFindings"]
            )
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        pending = [item for item in coverage["deferred"] if item.get("candidateId")]
        assert len(pending) == 1
        assert pending[0]["sourceWorkerId"] == owner_b
        report = (scan_dir / "report.md").read_text()
        assert "| Unresolved candidates | 1 |" in report
        assert f"| shared-candidate | {owner_b} |" in report
        assert "- Independent worker review remains pending." in report
        assert all(path.read_bytes() == content for path, content in originals.items())

    assert_owned_results()
    frozen = {
        scan_dir / relative: (scan_dir / relative).read_bytes()
        for relative in json.loads((scan_dir / "scan-manifest.json").read_text())["scan"][
            "preservedSources"
        ]
    }
    if termination == "failed":
        later = copy.deepcopy(draft_a)
        later.update(complete=False, findings=[])
        later["coverage"]["deferred"] = [{"id": "later-work", "reason": "Later saved work."}]
        write_checkpoint(result_a.parent / "checkpoints", later)
        run_workbench(
            state_dir, "recover-scan-results", "--scan-id", scan_id, environment=environment
        )
    else:
        run_workbench(
            state_dir, "preserve-scan-results", "--scan-id", scan_id, environment=environment
        )
    assert_owned_results()
    assert all(path.read_bytes() == content for path, content in frozen.items())


@pytest.mark.parametrize("disposition", ["rejected", "not_applicable"])
@pytest.mark.parametrize("owner_field", ["workerId", "sourceWorkerId"])
@pytest.mark.parametrize("same_worker", [False, True])
def test_stopped_recovery_applies_worker_decisions_to_parent_checkpoints(
    tmp_path: Path, disposition: str, owner_field: str, same_worker: bool
) -> None:
    scripts_dir = Path(__file__).resolve().parents[1] / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    import workbench_saved_results

    target = tmp_path.resolve() / "target"
    target.mkdir()
    (target / "app.py").write_text("value = 1\n")
    scan_dir = tmp_path.resolve() / "scan"
    scan_dir.mkdir()
    scan_id = "stopped-worker-decision"
    write_completed_contract(
        scan_dir, scan_id, target, relative_path="app.py", coverage_mode="deep_repository"
    )
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())
    manifest["scan"]["complete"] = True
    (scan_dir / "scan-manifest.json").write_text(json.dumps(manifest))
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    finding["provenance"].update(
        candidateId="candidate-one",
        **{owner_field: "worker-one" if same_worker else "worker-two"},
    )
    coverage = json.loads((scan_dir / "coverage.json").read_text())
    checkpoint = write_checkpoint(
        scan_dir / "checkpoints",
        {"scanId": scan_id, "complete": False, "findings": [finding], "coverage": coverage},
    )
    checkpoint_bytes = checkpoint.read_bytes()
    (scan_dir / "findings.json").write_text(json.dumps({"scanId": scan_id, "findings": []}))
    coverage["surfaces"] = [
        {
            "label": "Reviewed candidate",
            "candidateId": "candidate-one",
            "sourceWorkerId": "worker-one",
            "disposition": disposition,
            "notes": "The completed review dismissed this worker's candidate.",
        }
    ]
    (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    binding = {
        "status": "failed",
        "allowedTargetKinds": ["directory_snapshot"],
        "target": manifest["scan"]["target"],
        "scope": manifest["scan"]["scope"],
        "coverageMode": "deep_repository",
    }
    warnings: list[str] = []

    result = workbench_saved_results.merge_saved_results(
        scan_dir, scan_id, binding, [], warnings, stopped=True, reason="Stopped after review."
    )

    assert result is not None
    assert warnings == []
    recovered = result[1]["findings"]
    assert len(recovered) == (0 if same_worker else 1)
    if same_worker:
        assert result[2]["surfaces"][0]["previousFindings"] == [finding]
    else:
        assert recovered[0]["provenance"][owner_field] == "worker-two"
        assert recovered[0]["summary"] == finding["summary"]
    assert checkpoint.read_bytes() == checkpoint_bytes
