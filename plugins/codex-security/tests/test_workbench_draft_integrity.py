from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_workbench_standard_deep_results import (
    accepted_standard_worker,
    committed_standard_reducer,
    deep_scan_fixture,
    run_workbench_with_fault,
)
from workbench_test_support import (
    run_workbench,
    saved_draft,
    start_saved_scan,
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
