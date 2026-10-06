from __future__ import annotations

import copy
import json
import os
import re
from itertools import permutations
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    committed_standard_reducer,
    deep_scan_fixture,
    run_workbench_with_fault,
)
from workbench_test_support import (
    create_saved_workspace,
    run_workbench,
    saved_draft,
    start_saved_scan,
    start_workspace_scan,
    write_checkpoint,
    write_completed_contract,
)


def draft_fixture(tmp_path: Path, *, deep: bool = False, workers: int = 1):
    if deep:
        state, home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=workers)
    else:
        state, home, target = tmp_path / "state", tmp_path / "home", tmp_path / "target"
        target.mkdir()
        (target / "app.py").write_text("value = 1\n")
        scan_id, scan_dir = start_saved_scan(state, target, tmp_path / "scans")
    write_completed_contract(
        scan_dir,
        scan_id,
        target,
        relative_path="app.py",
        coverage_mode="deep_repository" if deep else "repository",
    )
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())["scan"]
    manifest_path.write_text(
        json.dumps({"scan": {key: manifest[key] for key in ("target", "scope")}})
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="complete", surfaces=[], deferred=[])
    coverage_path.write_text(json.dumps(coverage))
    return state, home, scan_dir, scan_id


def stop_draft(tmp_path, state, home, scan_id, *, deep=False, retry=False):
    args = (
        "fail-deep-scan" if deep else "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
    )
    if retry:
        failed = run_workbench_with_fault(
            tmp_path / "fault.py",
            state,
            home,
            "def fail(*args, **kwargs):\n    raise OSError('injected publication failure')\n"
            "workbench_saved_results._write_prepared_scan_finalization = fail\n",
            *args,
        )
        assert failed.returncode == 0
        assert run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"][
            "resultsRecoveryNeeded"
        ]
        args = ("recover-scan-results", "--scan-id", scan_id)
    run_workbench(state, *args, environment={"CODEX_HOME": str(home)})


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("parent", ["checkpoint", "canonical"])
@pytest.mark.parametrize("location", ["src/inside.py", "vendor/outside.py"])
def test_recovered_parent_checkpoint_preserves_scope_filter(
    tmp_path: Path, retry: bool, parent: str, location: str
):
    state, home, target = tmp_path / "state", tmp_path / "home", tmp_path / "target"
    for path in ("src/inside.py", "vendor/outside.py"):
        file = target / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("value = 1\n")
    workspace = create_saved_workspace(state, target)
    run_workbench(
        state,
        "save-workspace",
        "--workspace-id",
        workspace["id"],
        "--target-path",
        str(target),
        "--scope",
        "src",
        "--mode",
        "standard",
        "--user-context",
        "Scoped fixture.",
    )
    scan_id, scan_dir = start_workspace_scan(state, workspace["id"], tmp_path / "scans")
    write_completed_contract(
        scan_dir, scan_id, target, relative_path=location, include_paths=["src"]
    )
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())["scan"]
    manifest_path.write_text(
        json.dumps({"scan": {key: manifest[key] for key in ("target", "scope")}})
    )
    coverage_path = scan_dir / "coverage.json"
    coverage = json.loads(coverage_path.read_text())
    coverage.update(completeness="complete", surfaces=[], deferred=[])
    coverage_path.write_text(json.dumps(coverage))
    if parent == "checkpoint":
        checkpoint = write_checkpoint(
            scan_dir / "checkpoints",
            {**saved_draft(scan_id, findings=[finding]), "coverage": coverage},
        )
        (scan_dir / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
        for name in ("findings.json", "scan-manifest.json", "coverage.json"):
            (scan_dir / name).unlink()
    stop_draft(tmp_path, state, home, scan_id, retry=retry)
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    # Existing canonical documents are authoritative on their first publication.
    retained = location.startswith("src/") or (parent == "canonical" and not retry)
    assert scan["findingCount"] == int(retained)
    if retained:
        assert scan["findings"][0]["locations"][0]["path"] == location
    else:
        assert any("out-of-scope" in warning for warning in scan["warnings"])
    assert not scan["resultsRecoveryNeeded"]


def test_checkpoint_history_recovery_reuses_repeated_observations(tmp_path: Path):
    calls = []
    for length in (5, 10):
        case = tmp_path / str(length)
        case.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(case)
        original = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
        coverage = json.loads((scan_dir / "coverage.json").read_text())
        history = []
        for index in range(length):
            raw = copy.deepcopy(original)
            raw["summary"] = f"Observation {index}"
            raw["provenance"]["candidateId"] = "candidate-a"
            finding = copy.deepcopy(raw)
            finding["provenance"]["previousFindings"] = copy.deepcopy(history)
            history.append(raw)
            checkpoint = write_checkpoint(
                scan_dir / "checkpoints",
                {**saved_draft(scan_id, findings=[finding]), "coverage": coverage},
            )
        (scan_dir / "checkpoint-head.json").write_text(json.dumps({"checkpoint": checkpoint.name}))
        count_path = case / "recovery-count.txt"
        result = run_workbench_with_fault(
            case / "count.py",
            state,
            home,
            "import atexit, pathlib\n"
            "calls = 0\n"
            "original = workbench_saved_results._recover_unsealed_findings\n"
            "def counted(*args, **kwargs):\n"
            "    global calls\n"
            "    calls += 1\n"
            "    return original(*args, **kwargs)\n"
            "workbench_saved_results._recover_unsealed_findings = counted\n"
            f"atexit.register(lambda: pathlib.Path({str(count_path)!r}).write_text(str(calls)))\n",
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Stopped for test",
        )
        assert result.returncode == 0, result.stderr
        scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
        assert scan["findingCount"] == 1
        assert not scan["resultsRecoveryNeeded"]
        calls.append(int(count_path.read_text()))
    # Doubling the retained history must not repeatedly validate its shared prefix.
    assert calls[1] <= 2 * calls[0]


@pytest.mark.parametrize("operation", ["complete-scan", "fail-scan", "cancel-scan", "recover"])
def test_empty_artifact_inventory_remains_an_unsealed_draft(tmp_path: Path, operation: str):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path)
    environment = {"CODEX_HOME": str(home)}
    manifest_path = scan_dir / "scan-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scan"]["artifacts"] = []
    manifest_path.write_text(json.dumps(manifest))
    run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan_id,
        "--artifact-path",
        "artifacts/note.txt",
        input_text="saved evidence",
        environment=environment,
    )
    if operation == "recover":
        failed = run_workbench_with_fault(
            tmp_path / "fault.py",
            state,
            home,
            "def fail(*args, **kwargs):\n    raise OSError('injected publication failure')\n"
            "workbench_saved_results._write_prepared_scan_finalization = fail\n",
            "fail-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Stopped for test",
        )
        assert failed.returncode == 0
        run_workbench(state, "recover-scan-results", "--scan-id", scan_id, environment=environment)
    else:
        run_workbench(
            state,
            operation,
            "--scan-id",
            scan_id,
            *(["--message", "Stopped for test"] if operation == "fail-scan" else []),
            environment=environment,
        )
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 1
    assert not scan["resultsRecoveryNeeded"]
    sealed = manifest_path.read_bytes()
    rejected = run_workbench(
        state,
        "save-scan-artifact",
        "--scan-id",
        scan_id,
        "--artifact-path",
        "artifacts/note.txt",
        input_text="late overwrite",
        check=False,
        environment=environment,
    )
    assert rejected["returncode"] != 0
    assert manifest_path.read_bytes() == sealed
    assert (scan_dir / "artifacts/note.txt").read_text() == "saved evidence"


@pytest.mark.parametrize("field", ["disposition", "parent completeness", "worker completeness"])
@pytest.mark.parametrize("invalid", [[], {}])
def test_stopped_results_recover_valid_findings_beside_malformed_coverage(
    tmp_path: Path,
    field: str,
    invalid: object,
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    names = ("scan-manifest.json", "findings.json", "coverage.json")
    documents = {name: (scan_dir / name).read_text() for name in names}
    for name in names:
        (scan_dir / name).unlink()
    _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    draft = json.loads(result_path.read_text())
    draft["findings"] = json.loads(documents["findings.json"])["findings"]
    if field == "disposition":
        draft["coverage"]["surfaces"] = [
            {
                "id": "surface-a",
                "label": "API",
                "candidateId": "candidate-a",
                "disposition": invalid,
            }
        ]
    elif field == "worker completeness":
        draft["coverage"]["completeness"] = invalid
    else:
        draft["complete"] = False
        for name, contents in documents.items():
            (scan_dir / name).write_text(contents)
        coverage = json.loads(documents["coverage.json"])
        coverage["completeness"] = invalid
        (scan_dir / "coverage.json").write_text(json.dumps(coverage))
    result_path.write_text(json.dumps(draft))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 1
    if field == "disposition":
        assert scan["warnings"]
    assert not any("publication needs follow-up" in warning for warning in scan["warnings"])
    assert json.loads((scan_dir / "coverage.json").read_text())["completeness"] == "partial"


def test_missing_finding_identity_is_stable_across_publication_retry(tmp_path: Path):
    identities = []
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root, deep=True)
        path = scan_dir / "findings.json"
        document = json.loads(path.read_text())
        del document["findings"][0]["identity"]
        path.write_text(json.dumps(document))
        if retry:
            result = run_workbench_with_fault(
                root / "fault.py",
                state,
                home,
                "def fail(*args, **kwargs):\n    raise OSError('injected publication failure')\n"
                "workbench_saved_results._write_prepared_scan_finalization = fail\n",
                "fail-deep-scan",
                "--scan-id",
                scan_id,
                "--message",
                "Stopped for test",
            )
            assert result.returncode == 0
            args = ("recover-scan-results", "--scan-id", scan_id)
        else:
            args = ("fail-deep-scan", "--scan-id", scan_id, "--message", "Stopped for test")
        run_workbench(state, *args, environment={"CODEX_HOME": str(home)})
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert len(findings) == 1
        identities.append(findings[0]["identity"])
    assert identities[0] == identities[1]


def test_legacy_checkpoint_keeps_its_published_identity(tmp_path: Path):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path)
    path = scan_dir / "findings.json"
    document = json.loads(path.read_text())
    finding = document["findings"][0]
    finding["title"] = "Legacy candidate title"
    finding["identity"] = {"anchor": "legacy-candidate-title"}
    finding["provenance"]["candidateId"] = "candidate-a"
    path.write_text(json.dumps(document))
    raw = {key: value for key, value in finding.items() if key != "identity"}
    write_checkpoint(scan_dir / "checkpoints", saved_draft(scan_id, findings=[raw]))
    run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 1
    assert findings[0]["identity"] == finding["identity"]


@pytest.mark.parametrize("separate_workers", [False, True])
def test_stopped_worker_candidates_remain_distinct(tmp_path: Path, separate_workers: bool):
    state, home, scan_dir, scan_id = draft_fixture(
        tmp_path, deep=True, workers=2 if separate_workers else 1
    )
    template = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    del template["identity"]
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    for index in range(2):
        if separate_workers and index:
            worker_id, result_path = accepted_standard_worker(
                state, home, scan_dir, scan_id, name="second-worker"
            )
        document = json.loads(result_path.read_text())
        finding = json.loads(json.dumps(template))
        finding["title"] = f"Worker finding {index if separate_workers else 0}"
        finding["provenance"]["candidateId"] = f"candidate-{0 if separate_workers else index}"
        document["findings"].append(finding)
        result_path.write_text(json.dumps(document))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 2


def test_unhashable_progress_and_usage_enums_use_existing_validation_errors(tmp_path: Path):
    state, home, _, scan_id = draft_fixture(tmp_path)
    issue = {
        "capability": "command",
        "reason": "Unavailable",
        "severity": "warn",
        "status": "unknown",
    }
    for field in ("severity", "status", "usage"):
        for invalid in ([], {}):
            args = (
                (
                    "complete-scan",
                    "--cost-json",
                    json.dumps(
                        {
                            "usage": {
                                "coverage": invalid,
                                "source": "codex_rollout",
                                "threadCount": 0,
                            }
                        }
                    ),
                )
                if field == "usage"
                else (
                    "update-progress",
                    "--preflight-issues-json",
                    json.dumps([{**issue, field: invalid}]),
                )
            )
            result = run_workbench(state, *args, "--scan-id", scan_id, check=False)
            assert result["returncode"] != 0
            assert "invalid" in str(result["stderr"]).lower()
            assert "Traceback" not in str(result["stderr"])
    run_workbench(
        state,
        "update-progress",
        "--scan-id",
        scan_id,
        "--preflight-issues-json",
        json.dumps([issue]),
    )
    run_workbench(
        state,
        "complete-scan",
        "--scan-id",
        scan_id,
        "--cost-json",
        json.dumps(
            {"usage": {"coverage": "unavailable", "source": "codex_rollout", "threadCount": 0}}
        ),
        environment={"CODEX_HOME": str(home)},
    )


@pytest.mark.parametrize("candidate_ids", [("candidate:a", "candidate-a"), ("CAND-1", "cand-1")])
def test_candidate_normalization_does_not_merge_distinct_findings(tmp_path: Path, candidate_ids):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    template = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    template.pop("identity")
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    document = json.loads(result_path.read_text())
    document["findings"] = [
        {
            **template,
            "title": f"Independent issue {index}",
            "provenance": {**template["provenance"], "candidateId": candidate},
        }
        for index, candidate in enumerate(candidate_ids)
    ]
    result_path.write_text(json.dumps(document))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert {finding["title"] for finding in findings} == {
        "Independent issue 0",
        "Independent issue 1",
    }


@pytest.mark.parametrize("historical_version", [False, True])
def test_retained_identityless_worker_source_is_not_republished(tmp_path: Path, historical_version):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    original = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    original.pop("identity")
    original["provenance"]["candidateId"] = "candidate-a"
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    document = json.loads(result_path.read_text())
    reduced = json.loads(json.dumps(original))
    reduced["identity"] = {"anchor": "reduced-finding"}
    if historical_version:
        reduced["provenance"]["candidateId"] = "canonical-candidate"
    reduced["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": original}]
    document["findings"] = [reduced]
    result_path.write_text(json.dumps(document))
    committed_standard_reducer(state, home, scan_dir, scan_id, worker_id, result_path)
    document["findings"] = [original]
    result_path.write_text(json.dumps(document))
    if historical_version:
        historical = json.loads(json.dumps(original))
        historical["summary"] = "Earlier observation before reducer review."
        write_checkpoint(
            result_path.parent / "checkpoints",
            {**document, "complete": False, "findings": [historical]},
        )
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 1
    assert findings[0]["identity"] == reduced["identity"]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("distinct_parent_candidate", [False, True])
def test_canonical_worker_update_keeps_independent_alias_sibling(
    tmp_path: Path, reverse: bool, retry: bool, distinct_parent_candidate: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    finding_path = scan_dir / "findings.json"
    document = json.loads(finding_path.read_text())
    original = document["findings"][0]
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    independent = json.loads(json.dumps(original))
    independent.update(
        identity={"anchor": "reviewed-a"}, title="Beta", summary="Independent candidate A."
    )
    independent["severity"]["level"] = "medium"
    independent["provenance"]["candidateId"] = "candidate-a"
    earlier = json.loads(json.dumps(independent))
    earlier.pop("identity")
    independent["provenance"]["previousFindings"] = [earlier]
    canonical = json.loads(json.dumps(original))
    canonical.update(identity={"anchor": "beta"}, title="Beta", summary="Candidate B.")
    canonical["severity"]["level"] = "low"
    canonical["provenance"].update(candidateId="candidate-b", workerId=worker_id)
    historical = json.loads(json.dumps(canonical))
    canonical["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": historical}]
    if distinct_parent_candidate:
        canonical["provenance"]["candidateId"] = "canonical-b"
    document["findings"] = [canonical, independent] if reverse else [independent, canonical]
    finding_path.write_text(json.dumps(document))
    historical["severity"]["level"] = "high"
    historical["summary"] = "Stronger candidate B observation."
    worker = json.loads(result_path.read_text())
    worker["findings"] = [historical]
    result_path.write_text(json.dumps(worker))

    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=retry)

    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 2
    assert {row["provenance"]["candidateId"] for row in findings} == {
        "candidate-a",
        "candidate-b",
    }
    assert {row["summary"] for row in findings} == {
        "Independent candidate A.",
        "Stronger candidate B observation.",
    }


@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("alias", [{"anchor": []}, {"anchor": "finding", "instance": {}}])
def test_worker_update_preserves_structured_historical_identity(
    tmp_path: Path, retry: bool, alias: dict
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    finding_path = scan_dir / "findings.json"
    document = json.loads(finding_path.read_text())
    finding = document["findings"][0]
    finding["provenance"].update(
        candidateId="candidate-a", workerId=worker_id, preservedIdentity=alias
    )
    finding["severity"]["level"] = "low"
    finding_path.write_text(json.dumps(document))
    updated = copy.deepcopy(finding)
    updated["severity"]["level"] = "high"
    updated["summary"] = "Stronger retained observation."
    worker = json.loads(result_path.read_text())
    worker["findings"] = [updated]
    result_path.write_text(json.dumps(worker))

    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=retry)

    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 1
    assert not scan["resultsRecoveryNeeded"]
    retained = scan["findings"][0]
    assert retained["summary"] == updated["summary"]
    assert retained["severity"]["level"] == "high"
    assert retained["provenance"]["preservedIdentity"] == alias


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("retry", [False, True])
def test_exact_worker_location_precedes_a_canonical_candidate_alias(
    tmp_path: Path, reverse: bool, retry: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    finding_path = scan_dir / "findings.json"
    parent = json.loads(finding_path.read_text())
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    original = parent["findings"][0]
    original.update(identity={"anchor": "shared"}, summary="First independent location.")
    original["severity"]["level"] = "low"
    original["locations"][0].update(startLine=1, endLine=1)
    original["provenance"].update(candidateId="shared-candidate", workerId=worker_id)
    reduced = copy.deepcopy(original)
    reduced["identity"] = {"anchor": "reviewed-first"}
    reduced["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": original}]
    second = copy.deepcopy(original)
    second["locations"][0].update(startLine=2, endLine=2)
    second["summary"] = "Second independent location."
    parent["findings"] = [second, reduced] if reverse else [reduced, second]
    finding_path.write_text(json.dumps(parent))
    current = copy.deepcopy(second)
    current["severity"]["level"] = "high"
    current["summary"] = "Stronger second location."
    worker = json.loads(result_path.read_text())
    worker["findings"] = [current]
    result_path.write_text(json.dumps(worker))

    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=retry)

    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 2
    assert {row["locations"][0]["startLine"]: row["summary"] for row in findings} == {
        1: original["summary"],
        2: current["summary"],
    }


@pytest.mark.parametrize("renamed", [False, True])
@pytest.mark.parametrize("retry", [False, True])
@pytest.mark.parametrize("history", ["sourceFindings", "previousFindings"])
def test_canonical_worker_slot_survives_a_stronger_replacement(
    tmp_path: Path, renamed: bool, retry: bool, history: str
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    finding_path = scan_dir / "findings.json"
    parent = json.loads(finding_path.read_text())
    worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    original = parent["findings"][0]
    original.update(identity={"anchor": "finding"}, title="Finding")
    original["severity"]["level"] = "low"
    original["provenance"].update(candidateId="worker-candidate", workerId=worker_id)
    historical = json.loads(json.dumps(original))
    if renamed:
        original["provenance"]["candidateId"] = "canonical-candidate"
    original["provenance"][history] = (
        [{"id": f"{worker_id}:0", "finding": historical}]
        if history == "sourceFindings"
        else [historical]
    )
    finding_path.write_text(json.dumps(parent))
    worker = json.loads(result_path.read_text())
    if history == "sourceFindings":
        write_checkpoint(
            result_path.parent / "checkpoints",
            {**worker, "complete": False, "findings": [historical]},
        )
    current = json.loads(json.dumps(historical))
    current["severity"]["level"] = "high"
    current["summary"] = "Stronger current worker observation."
    if history == "sourceFindings":
        current["locations"][0].update(startLine=2, endLine=2)
    worker["findings"] = [current]
    result_path.write_text(json.dumps(worker))

    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=retry)

    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 1
    assert findings[0]["summary"] == current["summary"]
    assert findings[0]["locations"][0]["startLine"] == current["locations"][0]["startLine"]


@pytest.mark.parametrize(
    "case",
    [
        "foreign-owner",
        "split-owners",
        "explicit-priority",
        "interleaved-explicit",
        "raw-stronger",
        "explicit-stronger",
    ],
)
def test_frozen_recovery_preserves_worker_ownership_and_explicit_identity_priority(
    tmp_path: Path, case: str
):
    snapshots = []
    for retry in (False, True):
        directory = tmp_path / str(retry)
        directory.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(directory)
        finding_path = scan_dir / "findings.json"
        document = json.loads(finding_path.read_text())
        original = document["findings"][0]
        original.update(identity={"anchor": "finding"}, title="Finding")
        if case == "foreign-owner":
            observations = [
                ("B", "worker-a", "low"),
                ("A", "worker-a", "high"),
                (None, "worker-b", "high"),
            ]
        elif case == "split-owners":
            observations = [
                ("A", "worker-a", "low"),
                (None, "worker-a", "high"),
                ("B", "worker-b", "low"),
            ]
        else:
            observations = [
                ("A", None, "high" if case == "raw-stronger" else "low"),
                ("A", None, "high" if case == "explicit-stronger" else "low"),
                ("B", None, "low"),
            ]
        findings = []
        for index, (candidate, owner, level) in enumerate(observations):
            finding = json.loads(json.dumps(original))
            finding["severity"]["level"] = level
            finding["provenance"].pop("candidateId", None)
            if candidate:
                finding["provenance"]["candidateId"] = candidate
            if owner:
                finding["provenance"]["workerId"] = owner
            elif index == 0:
                finding.pop("identity")
            findings.append(finding)
        if case == "interleaved-explicit":
            findings[1], findings[2] = findings[2], findings[1]
        document["findings"] = findings
        finding_path.write_text(json.dumps(document))
        stop_draft(directory, state, home, scan_id, retry=retry)
        recovered = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        expected = 3 if case == "foreign-owner" else 2
        assert len(recovered) == expected
        snapshots.append(
            {
                (
                    finding["provenance"].get("workerId"),
                    finding["provenance"].get("candidateId"),
                ): finding["identity"]
                for finding in recovered
            }
        )
    assert snapshots[0] == snapshots[1]
    if case == "interleaved-explicit":
        assert snapshots[0][None, "B"] == {"anchor": "finding"}


def test_recovered_identity_does_not_depend_on_worker_assignment(tmp_path: Path):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    finding = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    finding.pop("identity")
    finding["provenance"]["candidateId"] = "candidate-a"
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    finding_ids = []
    for index in range(2):
        if index:
            begun = run_workbench(
                state,
                "begin-deep-scan",
                "--thread-id",
                "second-scan",
                "--target-path",
                str(tmp_path / "target"),
                "--scope",
                ".",
                "--scan-root",
                str(tmp_path / "scans"),
                "--available-parallelism",
                "16",
                environment={"CODEX_HOME": str(home)},
            )["deepScan"]
            scan_id, scan_dir = begun["scanId"], Path(begun["scanDir"])
        _, result_path = accepted_standard_worker(
            state, home, scan_dir, scan_id, name=f"worker-{index}"
        )
        document = json.loads(result_path.read_text())
        document["findings"] = [finding]
        result_path.write_text(json.dumps(document))
        run_workbench(
            state,
            "fail-deep-scan",
            "--scan-id",
            scan_id,
            "--message",
            "Stopped for test",
            environment={"CODEX_HOME": str(home)},
        )
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert len(findings) == 1
        finding_ids.append(findings[0]["findingId"])
    assert finding_ids[0] == finding_ids[1]


def test_recovery_reserves_every_generated_sibling_identity(tmp_path: Path):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    template = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    template.pop("identity")
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    document = json.loads(result_path.read_text())
    for index in range(4):
        finding = json.loads(json.dumps(template))
        finding["provenance"]["candidateId"] = f"candidate-{index}"
        finding["locations"][0].update(startLine=1 + index % 2, endLine=1 + index % 2)
        document["findings"].append(finding)
    result_path.write_text(json.dumps(document))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert {finding["provenance"]["candidateId"] for finding in findings} == {
        f"candidate-{index}" for index in range(4)
    }


@pytest.mark.parametrize("reverse", [False, True])
def test_restored_identity_keeps_an_independent_identityless_observation(
    tmp_path: Path, reverse: bool
):
    published = []
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root)
        path = scan_dir / "findings.json"
        document = json.loads(path.read_text())
        stronger = document["findings"][0]
        stronger.update(
            title="Synthetic finding",
            summary="Stronger reviewed finding.",
            identity={"anchor": "reviewed-anchor"},
        )
        stronger["severity"]["level"] = "high"
        stronger["provenance"]["candidateId"] = "candidate-a"
        weaker = json.loads(json.dumps(stronger))
        weaker.pop("identity")
        weaker["summary"] = "Independent weaker observation."
        weaker["severity"]["level"] = "low"
        raw = json.loads(json.dumps(stronger))
        raw.pop("identity")
        document["findings"] = [weaker, stronger] if reverse else [stronger, weaker]
        path.write_text(json.dumps(document))
        write_checkpoint(scan_dir / "checkpoints", saved_draft(scan_id, findings=[raw]))
        stop_draft(root, state, home, scan_id, retry=retry)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert len(findings) == 2
        observed = {
            finding["identity"]["anchor"]: (
                finding["summary"],
                finding["severity"]["level"],
            )
            for finding in findings
        }
        assert observed == {
            "reviewed-anchor": ("Stronger reviewed finding.", "high"),
            "synthetic-finding": ("Independent weaker observation.", "low"),
        }
        published.append(observed)
    assert published[0] == published[1]


@pytest.mark.parametrize("operation", ["complete-scan", "fail-scan", "cancel-scan"])
@pytest.mark.parametrize("candidate_siblings", [False, True, "saved alias"])
def test_raw_checkpoint_and_published_rows_reuse_saved_identities(
    tmp_path: Path, operation: str, candidate_siblings: bool | str
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path)
    path = scan_dir / "findings.json"
    document = json.loads(path.read_text())
    finding = document["findings"][0]
    expected_anchor = "saved-original"
    finding["identity"] = {"anchor": expected_anchor}
    if candidate_siblings:
        finding["identity"]["anchor"] = re.sub(
            r"[^a-z0-9._/-]+", "-", finding["title"].lower()
        ).strip("._/-")
        expected_anchor = finding["identity"]["anchor"]
        finding["provenance"]["candidateId"] = "candidate-a"
        second = json.loads(json.dumps(finding))
        second["identity"]["instance"] = "saved-2"
        second["provenance"]["candidateId"] = "candidate-b"
        if candidate_siblings == "saved alias":
            second["provenance"]["preservedIdentity"] = {"anchor": expected_anchor}
        document["findings"].append(second)
        raw = json.loads(json.dumps(second))
        del raw["identity"]
        raw["provenance"].pop("preservedIdentity", None)
        write_checkpoint(scan_dir / "checkpoints", saved_draft(scan_id, findings=[raw]))
    else:
        finding["provenance"].pop("candidateId", None)
        write_checkpoint(scan_dir / "checkpoints", saved_draft(scan_id, findings=[finding]))
        del finding["identity"]
    path.write_text(json.dumps(document))
    coverage = scan_dir / "coverage.json"
    coverage.write_bytes(coverage.read_bytes())
    run_workbench(
        state,
        operation,
        "--scan-id",
        scan_id,
        *(["--message", "Stopped for test"] if operation == "fail-scan" else []),
        environment={"CODEX_HOME": str(home)},
    )
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["findingCount"] == (2 if candidate_siblings else 1)
    assert not saved["resultsRecoveryNeeded"]
    identities = [row["identity"] for row in saved["findings"]]
    assert {"anchor": expected_anchor} in identities
    if candidate_siblings:
        assert {"anchor": expected_anchor, "instance": "saved-2"} in identities


@pytest.mark.parametrize(
    "discriminator,source",
    [
        ("reportId", "worker"),
        ("ledgerRowId", "worker"),
        ("saved anchor", "worker"),
        ("saved anchor", "parent"),
    ],
)
def test_saved_identity_reuse_preserves_independent_worker_findings(
    tmp_path: Path, discriminator: str, source: str
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=source == "worker")
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    first.update(title="Synthetic finding", identity={"anchor": "synthetic-finding"})
    first["provenance"]["candidateId"] = "candidate-a"
    second = json.loads(json.dumps(first))
    del second["identity"]
    result_path = scan_dir / "findings.json"
    if source == "worker":
        for name in ("findings.json", "scan-manifest.json", "coverage.json"):
            (scan_dir / name).unlink()
        _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    if discriminator == "saved anchor":
        del first["identity"]
        second["title"] = "Other finding"
        second["provenance"]["candidateId"] = "candidate-b"
        saved = {**second, "identity": {"anchor": "synthetic-finding"}}
        write_checkpoint(result_path.parent / "checkpoints", saved_draft(scan_id, findings=[saved]))
    else:
        first["identity"]["instance"] = "report-a"
        first["extensions"] = {discriminator: "report-a"}
        second["extensions"] = {discriminator: "report-b"}
    document = json.loads(result_path.read_text())
    document["findings"] = [first, second]
    result_path.write_text(json.dumps(document))
    run_workbench(
        state,
        "fail-deep-scan" if source == "worker" else "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert len(findings) == 2
    if discriminator == "saved anchor":
        assert {finding["provenance"]["candidateId"] for finding in findings} == {
            "candidate-a",
            "candidate-b",
        }
    else:
        published = json.loads((scan_dir / "findings.json").read_text())["findings"]
        assert {finding["extensions"][discriminator] for finding in published} == {
            "report-a",
            "report-b",
        }


@pytest.mark.parametrize(
    "history", ["identityless observation", "identified observation", "worker source"]
)
@pytest.mark.parametrize("retry", [False, True])
def test_stopped_recovery_keeps_reviewed_outcome_over_historical_observation(
    tmp_path: Path, history: str, retry: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=history == "worker source")
    path = scan_dir / "findings.json"
    document = json.loads(path.read_text())
    reviewed = document["findings"][0]
    reviewed.update(title="Reviewed finding", identity={"anchor": "reviewed-finding"})
    reviewed["provenance"]["candidateId"] = "candidate-a"
    reviewed["severity"]["level"] = "medium"
    historical = json.loads(json.dumps(reviewed))
    historical.pop("identity")
    historical["title"] = "Earlier observation"
    historical["severity"]["level"] = "critical"
    if history != "identityless observation":
        del reviewed["identity"]
        historical["identity"] = {"anchor": "earlier-observation"}
    if history == "worker source":
        worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
        for finding in (reviewed, historical):
            finding["provenance"]["workerId"] = worker_id
        reviewed["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": historical}]
        worker = json.loads(result_path.read_text())
        worker["findings"] = [historical]
        result_path.write_text(json.dumps(worker))
    else:
        reviewed["provenance"]["previousFindings"] = [historical]
        write_checkpoint(scan_dir / "checkpoints", saved_draft(scan_id, findings=[historical]))
    path.write_text(json.dumps(document))
    stop_draft(tmp_path, state, home, scan_id, deep=history == "worker source", retry=retry)
    saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert saved["findingCount"] == 1
    assert saved["findings"][0]["severity"]["level"] == "medium"
    assert saved["findings"][0]["title"] == "Reviewed finding"


@pytest.mark.parametrize("first_candidate", ["candidate-a", "candidate-b"])
def test_interleaved_candidate_observations_reuse_identities(tmp_path: Path, first_candidate: str):
    published = []
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root)
        path = scan_dir / "findings.json"
        document = json.loads(path.read_text())
        template = document["findings"][0]
        del template["identity"]
        other_candidate = "candidate-b" if first_candidate == "candidate-a" else "candidate-a"
        document["findings"] = []
        for candidate, severity in (
            (first_candidate, "low"),
            (other_candidate, "medium"),
            (first_candidate, "high"),
        ):
            finding = json.loads(json.dumps(template))
            finding["provenance"]["candidateId"] = candidate
            finding["severity"]["level"] = severity
            document["findings"].append(finding)
        path.write_text(json.dumps(document))
        stop_draft(root, state, home, scan_id, retry=retry)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert len(findings) == 2
        by_candidate = {
            finding["provenance"]["candidateId"]: (
                finding["severity"]["level"],
                finding["identity"],
            )
            for finding in findings
        }
        assert by_candidate[first_candidate][0] == "high"
        assert by_candidate[other_candidate][0] == "medium"
        published.append(by_candidate)
    assert published[0] == published[1]


@pytest.mark.parametrize("source", ["parent", "worker"])
@pytest.mark.parametrize("explicit_first", [False, True])
def test_same_candidate_siblings_do_not_borrow_identities(
    tmp_path: Path, source: str, explicit_first: bool
):
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root, deep=source == "worker")
        path = scan_dir / "findings.json"
        document = json.loads(path.read_text())
        first = document["findings"][0]
        del first["identity"]
        first["title"] = "Alpha"
        first["provenance"]["candidateId"] = "shared-candidate"
        second = json.loads(json.dumps(first))
        second.update(title="Beta", identity={"anchor": "beta"})
        if source == "worker":
            for name in ("findings.json", "scan-manifest.json", "coverage.json"):
                (scan_dir / name).unlink()
            _, path = accepted_standard_worker(state, home, scan_dir, scan_id)
            document = json.loads(path.read_text())
        document["findings"] = [second, first] if explicit_first else [first, second]
        path.write_text(json.dumps(document))
        stop_draft(root, state, home, scan_id, deep=source == "worker", retry=retry)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert {finding["title"]: finding["identity"] for finding in findings} == {
            "Alpha": {"anchor": "alpha"},
            "Beta": {"anchor": "beta"},
        }


@pytest.mark.parametrize("source", ["parent", "worker"])
@pytest.mark.parametrize("reverse", [False, True])
def test_restored_identity_does_not_absorb_a_sibling_without_candidate(
    tmp_path: Path, source: str, reverse: bool
):
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root, deep=source == "worker")
        path = scan_dir / "findings.json"
        document = json.loads(path.read_text())
        first = document["findings"][0]
        del first["identity"]
        first["title"] = "Alpha"
        first["provenance"]["candidateId"] = "candidate-a"
        second = json.loads(json.dumps(first))
        second["title"] = "Beta"
        second["severity"]["level"] = "high"
        del second["provenance"]["candidateId"]
        if source == "worker":
            for name in ("findings.json", "scan-manifest.json", "coverage.json"):
                (scan_dir / name).unlink()
            _, path = accepted_standard_worker(state, home, scan_dir, scan_id)
            document = json.loads(path.read_text())
        write_checkpoint(
            path.parent / "checkpoints",
            saved_draft(scan_id, findings=[{**first, "identity": {"anchor": "beta"}}]),
        )
        document["findings"] = [second, first] if reverse else [first, second]
        path.write_text(json.dumps(document))
        stop_draft(root, state, home, scan_id, deep=source == "worker", retry=retry)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert {finding["title"] for finding in findings} == {"Alpha", "Beta"}


@pytest.mark.parametrize("same_location", [False, True])
@pytest.mark.parametrize("normalized_field", ["anchor", "ruleId"])
def test_restored_history_uses_normalized_identity(
    tmp_path: Path, same_location: bool, normalized_field: str
):
    observed = []
    for retry in (False, True):
        root = tmp_path / str(retry)
        root.mkdir()
        state, home, scan_dir, scan_id = draft_fixture(root, deep=True)
        template = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
        for name in ("scan-manifest.json", "findings.json", "coverage.json"):
            (scan_dir / name).unlink()
        _, path = accepted_standard_worker(state, home, scan_dir, scan_id)
        draft = json.loads(path.read_text())
        first = json.loads(json.dumps(template))
        first.pop("identity")
        first["title"] = "Alpha"
        first["provenance"]["candidateId"] = "candidate-a"
        if normalized_field == "ruleId":
            first["ruleId"] = "." + first["ruleId"]
        historical = json.loads(json.dumps(first))
        historical["identity"] = {"anchor": ".beta" if normalized_field == "anchor" else "beta"}
        first["provenance"]["previousFindings"] = [historical]
        second = json.loads(json.dumps(template))
        second.update(title="Beta", identity={"anchor": "beta"})
        second["provenance"]["candidateId"] = "candidate-b"
        if not same_location:
            second["locations"][0]["startLine"] += 1
            second["locations"][0]["endLine"] += 1
        draft["findings"] = [first, second]
        path.write_text(json.dumps(draft))
        stop_draft(root, state, home, scan_id, deep=True, retry=retry)
        scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
        findings = scan["findings"]
        assert len(findings) == 2
        assert {finding["title"] for finding in findings} == {"Alpha", "Beta"}
        if normalized_field == "ruleId":
            assert any("normalized rule identifier" in warning for warning in scan["warnings"])
        saved = json.loads((scan_dir / "findings.json").read_text())["findings"]
        alpha = next(finding for finding in saved if finding["title"] == "Alpha")
        assert alpha["provenance"]["previousFindings"][0]["identity"] == historical["identity"]
        assert alpha["provenance"]["previousFindings"][0]["ruleId"] == historical["ruleId"]
        observed.append({finding["title"]: finding["identity"] for finding in findings})
    assert observed[0] == observed[1]


@pytest.mark.parametrize("candidate_count", [1, 2])
@pytest.mark.parametrize("candidate_scope", ["candidate", "worker"])
def test_candidate_less_identity_preserves_ambiguous_candidates(
    tmp_path: Path, candidate_count: int, candidate_scope: str
):
    observed = []
    for order in permutations(range(candidate_count + 1)):
        for retry in (False, True):
            root = tmp_path / f"{order}-{retry}"
            root.mkdir()
            state, home, scan_dir, scan_id = draft_fixture(root)
            path = scan_dir / "findings.json"
            draft = json.loads(path.read_text())
            template = draft["findings"][0]
            template.update(title="Synthetic finding", identity={"anchor": "synthetic-finding"})
            items = []
            for index in range(candidate_count + 1):
                finding = json.loads(json.dumps(template))
                finding["severity"]["level"] = (
                    "high" if index == 1 and index < candidate_count else "low"
                )
                finding["provenance"].pop("candidateId", None)
                if index < candidate_count:
                    finding.pop("identity")
                    finding["provenance"]["candidateId"] = (
                        f"candidate-{index}" if candidate_scope == "candidate" else "candidate"
                    )
                    if candidate_scope == "worker":
                        finding["provenance"]["workerId"] = f"worker-{index}"
                items.append(finding)
            draft["findings"] = [items[index] for index in order]
            path.write_text(json.dumps(draft))
            stop_draft(root, state, home, scan_id, retry=retry)
            findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
            if candidate_count == 1:
                assert len(findings) == 1
                assert findings[0]["identity"] == {"anchor": "synthetic-finding"}
                continue
            assert len(findings) == 3
            current = {
                (finding["provenance"].get("candidateId"), finding["provenance"].get("workerId")): (
                    finding["identity"],
                    finding["severity"]["level"],
                )
                for finding in findings
            }
            known = (
                [("candidate-0", None), ("candidate-1", None)]
                if candidate_scope == "candidate"
                else [("candidate", "worker-0"), ("candidate", "worker-1")]
            )
            assert set(current) == {(None, None), *known}
            assert current[(None, None)] == ({"anchor": "synthetic-finding"}, "low")
            assert current[known[0]][1] == "low"
            assert current[known[1]][1] == "high"
            assert (
                len({json.dumps(identity, sort_keys=True) for identity, _ in current.values()}) == 3
            )
            observed.append(current)
    assert all(current == observed[0] for current in observed)


@pytest.mark.parametrize("worker_history", [False, True])
def test_identity_restoration_matches_retained_history(tmp_path: Path, worker_history: bool):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=worker_history)
    path = scan_dir / "findings.json"
    document = json.loads(path.read_text())
    reviewed = document["findings"][0]
    reviewed.update(title="Reviewed finding", identity={"anchor": "reviewed"})
    reviewed["severity"]["level"] = "medium"
    reviewed["provenance"]["candidateId"] = "candidate-a"
    historical = json.loads(json.dumps(reviewed))
    del historical["identity"]
    historical["title"] = "Historical finding"
    historical["severity"]["level"] = "critical"
    checkpoint_dir = scan_dir / "checkpoints"
    if worker_history:
        worker_id, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
        reviewed["provenance"]["sourceFindings"] = [{"id": f"{worker_id}:0", "finding": historical}]
        checkpoint_dir = result_path.parent / "checkpoints"
        worker = json.loads(result_path.read_text())
        worker["findings"] = [historical]
        result_path.write_text(json.dumps(worker))
    else:
        reviewed["provenance"]["previousFindings"] = [historical]
    checkpoint = write_checkpoint(
        checkpoint_dir,
        saved_draft(
            scan_id,
            findings=[
                {**historical, "identity": {"anchor": "historical-finding", "instance": "saved"}}
            ],
        ),
    )
    os.utime(checkpoint, (10, 10))
    path.write_text(json.dumps(document))
    raw = write_checkpoint(checkpoint_dir, saved_draft(scan_id, findings=[historical]))
    later = path.stat().st_mtime + 1
    os.utime(raw, (later, later))
    if worker_history:
        stop_draft(tmp_path, state, home, scan_id, deep=True, retry=True)
    else:
        run_workbench(state, "complete-scan", "--scan-id", scan_id)
    findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
    assert [(finding["title"], finding["severity"]["level"]) for finding in findings] == [
        ("Reviewed finding", "medium")
    ]


@pytest.mark.parametrize("explicit_first", [False, True])
@pytest.mark.parametrize("same_title", [False, True])
@pytest.mark.parametrize("source", ["parent", "worker"])
def test_saved_identity_reuse_preserves_explicit_sibling(
    tmp_path: Path, explicit_first: bool, same_title: bool, source: str
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=source == "worker")
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    del first["identity"]
    first["title"] = "Beta" if same_title else "Alpha"
    first["provenance"]["candidateId"] = "candidate-a"
    second = json.loads(json.dumps(first))
    second.update(title="Beta", identity={"anchor": "beta"})
    second["provenance"]["candidateId"] = "candidate-b"
    result_path = scan_dir / "findings.json"
    if source == "worker":
        for name in ("findings.json", "scan-manifest.json", "coverage.json"):
            (scan_dir / name).unlink()
        _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    write_checkpoint(
        result_path.parent / "checkpoints",
        saved_draft(scan_id, findings=[{**first, "identity": {"anchor": "beta"}}]),
    )
    worker = json.loads(result_path.read_text())
    worker["findings"] = [second, first] if explicit_first else [first, second]
    result_path.write_text(json.dumps(worker))
    run_workbench(
        state,
        "fail-deep-scan" if source == "worker" else "fail-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    for retry in (False, True):
        if retry:
            run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
        published = json.loads((scan_dir / "findings.json").read_text())["findings"]
        assert [finding["provenance"]["candidateId"] for finding in published] == (
            ["candidate-b", "candidate-a"] if explicit_first else ["candidate-a", "candidate-b"]
        )
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert len(findings) == 2
        assert {finding["provenance"]["candidateId"] for finding in findings} == {
            "candidate-a",
            "candidate-b",
        }
        explicit = next(
            finding for finding in findings if finding["provenance"]["candidateId"] == "candidate-b"
        )
        assert explicit["identity"] == {"anchor": "beta"}


@pytest.mark.parametrize("same_identity", [False, True])
@pytest.mark.parametrize("successor_explicit", [False, True])
def test_stopped_recovery_keeps_first_position_when_a_duplicate_is_later(
    tmp_path: Path, same_identity: bool, successor_explicit: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    first.pop("identity")
    first.update(title="Alpha", provenance={"source": "local_plugin", "candidateId": "candidate-a"})
    first["severity"]["level"] = "low"
    explicit = json.loads(json.dumps(first))
    if successor_explicit:
        explicit["identity"] = {"anchor": "alpha"}
    explicit["severity"]["level"] = "high"
    middle = json.loads(json.dumps(first))
    middle.update(title="Middle", identity={"anchor": "alpha" if same_identity else "middle"})
    middle["provenance"]["candidateId"] = "candidate-b"
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    worker = json.loads(result_path.read_text())
    worker["findings"] = [first, middle, explicit]
    result_path.write_text(json.dumps(worker))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    for retry in (False, True):
        if retry:
            run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
        published = json.loads((scan_dir / "findings.json").read_text())["findings"]
        assert [finding["provenance"]["candidateId"] for finding in published] == [
            "candidate-a",
            "candidate-b",
        ]
        assert published[0]["severity"]["level"] == "high"


@pytest.mark.parametrize("explicit_first", [False, True])
@pytest.mark.parametrize("same_title", [False, True])
def test_saved_identity_collision_across_workers_preserves_explicit_sibling(
    tmp_path: Path, explicit_first: bool, same_title: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True, workers=2)
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    first.pop("identity")
    first["title"] = "Beta" if same_title else "Alpha"
    first["provenance"]["candidateId"] = "candidate-a"
    first["severity"]["level"] = "low"
    second = json.loads(json.dumps(first))
    second.update(title="Beta", identity={"anchor": "beta"})
    second["provenance"]["candidateId"] = "candidate-b"
    second["severity"]["level"] = "high"
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    observations = [second, first] if explicit_first else [first, second]
    for index, finding in enumerate(observations):
        _, result_path = accepted_standard_worker(
            state, home, scan_dir, scan_id, name=f"worker-{index}"
        )
        if "identity" not in finding:
            write_checkpoint(
                result_path.parent / "checkpoints",
                saved_draft(scan_id, findings=[{**finding, "identity": {"anchor": "beta"}}]),
            )
        worker = json.loads(result_path.read_text())
        worker["findings"] = [finding]
        result_path.write_text(json.dumps(worker))
    run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Stopped for test",
        environment={"CODEX_HOME": str(home)},
    )
    for retry in (False, True):
        if retry:
            run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
        saved = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
        assert not saved["resultsRecoveryNeeded"]
        assert saved["findingCount"] == 2
        assert {finding["provenance"]["candidateId"] for finding in saved["findings"]} == {
            "candidate-a",
            "candidate-b",
        }
        explicit = next(
            finding
            for finding in saved["findings"]
            if finding["provenance"]["candidateId"] == "candidate-b"
        )
        assert explicit["identity"] == {"anchor": "beta"}


@pytest.mark.parametrize(
    "discriminator", ["anchor", "instance", "anchor without candidate", "restored instances"]
)
@pytest.mark.parametrize("retry", [False, True])
def test_raw_checkpoint_preserves_explicit_sibling_identity(
    tmp_path: Path, discriminator: str, retry: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True)
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    first.update(title="Shared title", summary="First independent report")
    first["severity"]["level"] = "low"
    first["identity"] = {"anchor": "saved-original"}
    first["provenance"]["candidateId"] = "shared-candidate"
    second = json.loads(json.dumps(first))
    second.update(summary="Stronger independent report", identity={"anchor": "shared-title"})
    second["severity"]["level"] = "high"
    if discriminator in {"instance", "restored instances"}:
        first["identity"] = {"anchor": "shared-title", "instance": "sibling-a"}
        if discriminator == "restored instances":
            second["identity"] = {"anchor": "shared-title", "instance": "sibling-b"}
    elif discriminator == "anchor without candidate":
        del first["provenance"]["candidateId"]
        del second["provenance"]["candidateId"]
    raw = json.loads(json.dumps(first))
    del raw["identity"]
    earlier = [raw]
    if discriminator == "restored instances":
        earlier.append({key: value for key, value in second.items() if key != "identity"})
    expected = {finding["summary"]: finding["identity"] for finding in (first, second)}
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    _, result_path = accepted_standard_worker(state, home, scan_dir, scan_id)
    document = json.loads(result_path.read_text())
    document["findings"] = [first, second]
    write_checkpoint(result_path.parent / "checkpoints", saved_draft(scan_id, findings=earlier))
    result_path.write_text(json.dumps(document))
    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=retry)
    published_ids = None
    for replay in (False, True):
        if replay:
            run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert {finding["summary"]: finding["identity"] for finding in findings} == expected
        identities = {finding["summary"]: finding["findingId"] for finding in findings}
        if published_ids is not None:
            assert identities == published_ids
        published_ids = identities


@pytest.mark.parametrize("different_worker", [False, True])
def test_restored_identity_does_not_reserve_another_candidates_alias(
    tmp_path: Path, different_worker: bool
):
    state, home, scan_dir, scan_id = draft_fixture(tmp_path, deep=True, workers=2)
    first = json.loads((scan_dir / "findings.json").read_text())["findings"][0]
    del first["identity"]
    first["title"] = "Alpha"
    first["provenance"]["candidateId"] = "candidate-a"
    second = json.loads(json.dumps(first))
    second["title"] = "Beta"
    second["severity"]["level"] = "high"
    del second["provenance"]["candidateId"]
    independent = json.loads(json.dumps(first))
    independent.update(title="Independent finding", identity={"anchor": "alpha"})
    if not different_worker:
        independent["provenance"]["candidateId"] = "candidate-b"
    for name in ("findings.json", "scan-manifest.json", "coverage.json"):
        (scan_dir / name).unlink()
    _, path = accepted_standard_worker(state, home, scan_dir, scan_id)
    document = json.loads(path.read_text())
    write_checkpoint(
        path.parent / "checkpoints",
        saved_draft(scan_id, findings=[{**first, "identity": {"anchor": "beta"}}]),
    )
    document["findings"] = [first, second]
    if different_worker:
        _, other_path = accepted_standard_worker(
            state, home, scan_dir, scan_id, name="other-worker"
        )
        other = json.loads(other_path.read_text())
        other["findings"] = [independent]
        other_path.write_text(json.dumps(other))
    else:
        document["findings"].append(independent)
    path.write_text(json.dumps(document))
    stop_draft(tmp_path, state, home, scan_id, deep=True, retry=True)
    for replay in (False, True):
        if replay:
            run_workbench(state, "recover-scan-results", "--scan-id", scan_id)
        findings = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]["findings"]
        assert {finding["title"] for finding in findings} == {
            "Alpha",
            "Beta",
            "Independent finding",
        }
