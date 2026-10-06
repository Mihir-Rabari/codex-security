from __future__ import annotations

import copy
import json
import os
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan
from test_workbench_standard_deep_results import deep_scan_fixture, worker_paths
from workbench_test_support import run_workbench, write_checkpoint, write_completed_contract


def test_public_stop_retains_accepted_partial_evidence_and_newer_rejection(tmp_path):
    state, home, target, scan_dir, scan_id = deep_scan_fixture(tmp_path, workers=2)
    environment = {"CODEX_HOME": str(home)}
    contract = tmp_path / "contract"
    contract.mkdir()
    write_completed_contract(contract, scan_id, target, relative_path="app.py")
    finding = json.loads((contract / "findings.json").read_text())["findings"][0]
    deferred = {
        "candidateId": "pending-query",
        "reason": "Validation is pending.",
        "paths": ["app.py"],
    }
    coverage = {
        "completeness": "partial",
        "surfaces": [],
        "explicitExclusions": [],
        "deferred": [deferred],
    }
    workers = []
    for accepted in (True, False):
        name = "accepted" if accepted else "interrupted"
        prompt, output, result = worker_paths(scan_dir, name)
        worker_id = str(uuid.uuid4())
        worker_args = (
            "upsert-deep-scan-worker",
            "--scan-id",
            scan_id,
            "--worker-id",
            worker_id,
            "--kind",
            "discovery",
            "--prompt-path",
            str(prompt),
            "--artifact-dir",
            str(output),
            "--attempt",
            "1",
        )
        run_workbench(state, *worker_args, "--status", "running", environment=environment)
        current = copy.deepcopy(finding)
        current["identity"]["anchor"] = name
        current["extensions"] = {"candidateId": name}
        draft = {"scanId": scan_id, "complete": True, "findings": [current], "coverage": coverage}
        result.write_text(json.dumps(draft))
        write_checkpoint(output / "checkpoints", draft)
        if accepted:
            run_workbench(
                state,
                *worker_args,
                "--status",
                "succeeded",
                "--result-manifest-path",
                str(result),
                environment=environment,
            )
        else:
            rejected = {
                **draft,
                "complete": False,
                "findings": [],
                "coverage": {
                    **coverage,
                    "surfaces": [
                        {
                            "candidateId": name,
                            "label": "Reviewed candidate",
                            "disposition": "rejected",
                            "receiptRefs": [],
                        }
                    ],
                },
            }
            head = write_checkpoint(output / "checkpoints", rejected)
            (output / "checkpoint-head.json").write_text(json.dumps({"checkpoint": head.name}))
        workers.append(worker_id)

    stopped = run_workbench(
        state,
        "fail-deep-scan",
        "--scan-id",
        scan_id,
        "--message",
        "Original worker failure.",
        "--deep-status",
        "interrupted",
        environment=environment,
    )["deepScan"]
    assert stopped["status"] == "interrupted"
    scan = run_workbench(state, "get-scan", "--scan-id", scan_id)["scan"]
    assert scan["findingCount"] == 1
    findings = json.loads((scan_dir / "findings.json").read_text())["findings"]
    assert [item["identity"]["anchor"] for item in findings] == ["accepted"]
    retained_coverage = json.loads((scan_dir / "coverage.json").read_text())
    assert retained_coverage["completeness"] == "partial"
    assert any(item.get("candidateId") == "pending-query" for item in retained_coverage["deferred"])
    assert any(
        item.get("candidateId") == "interrupted" and item["disposition"] == "rejected"
        for item in retained_coverage["surfaces"]
    )
    assert scan["failureMessage"] == "Original worker failure."
    assert {worker["id"]: worker["status"] for worker in stopped["workers"]} == {
        workers[0]: "succeeded",
        workers[1]: "canceled",
    }


@pytest.mark.parametrize("archived", [False, True], ids=["current", "archived"])
@pytest.mark.parametrize("has_head", [True, False], ids=["committed-head", "legacy"])
@pytest.mark.parametrize("complete", [False, True], ids=["checkpoint", "complete"])
def test_recovery_honors_rejection_committed_before_result_replacement(
    workbench_api, workbench_db, publication_scan, archived, has_head, complete
):
    scan = publication_scan()
    provisional = copy.deepcopy(scan.findings[0])
    provisional["extensions"] = {"candidateId": "candidate-rejected"}
    retained = copy.deepcopy(scan.findings[0])
    retained["identity"]["anchor"] = "independent-finding"
    retained["extensions"] = {"candidateId": "candidate-retained"}
    retained["locations"][0]["startLine"] = 20
    retained["locations"][0]["endLine"] = 21
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result_path = add_worker(workbench_db, scan, status="canceled")
    if archived:
        result_path = result_path.parent / "attempts" / "attempt-1" / "result.json"
        result_path.parent.mkdir(parents=True)
    previous = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [provisional, retained],
        "coverage": scan.coverage,
    }
    result_path.write_text(json.dumps(previous))
    old_checkpoint = write_checkpoint(result_path.parent / "checkpoints", previous)
    rejected = {
        **previous,
        "complete": complete,
        "findings": [retained],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-rejected",
                    "label": "Validated candidate disposition",
                    "disposition": "rejected",
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(result_path.parent / "checkpoints", rejected)
    if has_head:
        head = result_path.parent / "checkpoint-head.json"
        head.write_text(json.dumps({"checkpoint": checkpoint.name}))
        # Model a committed replacement after the older result, even when the
        # filesystem assigns the same timestamp to these consecutive writes.
        observed = max(result_path.stat().st_mtime_ns, checkpoint.stat().st_mtime_ns) + 1
        os.utime(head, ns=(observed, observed))
    saved_bytes = {path: path.read_bytes() for path in (result_path, old_checkpoint, checkpoint)}

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    findings = json.loads((scan.scan_dir / "findings.json").read_text())["findings"]
    assert stopped["findingCount"] == len(findings) == (1 if has_head else 2)
    assert any(finding["identity"]["anchor"] == "independent-finding" for finding in findings)
    assert all(path.read_bytes() == contents for path, contents in saved_bytes.items())
    if has_head:
        coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
        assert any(
            surface.get("candidateId") == "candidate-rejected"
            and surface.get("disposition") == "rejected"
            for surface in coverage["surfaces"]
        )


def save_disposition(scan, directory, disposition):
    directory.mkdir(parents=True, exist_ok=True)
    finding = copy.deepcopy(scan.findings[0])
    finding["extensions"] = {"candidateId": "candidate-disposition"}
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [finding] if disposition == "reported" else [],
        "coverage": {
            **scan.coverage,
            "surfaces": [
                {
                    "candidateId": "candidate-disposition",
                    "label": "Validated candidate disposition",
                    "disposition": disposition,
                    "receiptRefs": [],
                }
            ],
        },
    }
    checkpoint = write_checkpoint(directory / "checkpoints", draft)
    head = directory / "checkpoint-head.json"
    head.write_text(json.dumps({"checkpoint": checkpoint.name}))
    result = directory / "result.json"
    observed = (
        max(
            checkpoint.stat().st_mtime_ns,
            result.stat().st_mtime_ns if result.exists() else 0,
        )
        + 1
    )
    os.utime(head, ns=(observed, observed))
    return draft


@pytest.mark.parametrize("archived", [False, True], ids=["current-head", "newer-archive"])
@pytest.mark.parametrize("disposition", ["reported", "rejected"])
def test_newer_checkpoint_disposition_precedes_older_archived_head(
    workbench_api, workbench_db, publication_scan, archived, disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    with workbench_db:
        workbench_db.execute(
            "UPDATE deep_scan_workers SET attempt = 3 WHERE scan_id = ?", (scan.scan_id,)
        )
    old = result.parent / "attempts" / "attempt-2"
    save_disposition(scan, old, "rejected" if disposition == "reported" else "reported")
    current = result.parent / "attempts" / "attempt-10" if archived else result.parent
    draft = save_disposition(scan, current, disposition)
    (current / "result.json").write_text(json.dumps(draft))

    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]

    assert stopped["findingCount"] == (1 if disposition == "reported" else 0)


@pytest.mark.parametrize("head_change", ["replaced", "removed", "missing-checkpoint"])
def test_frozen_stopped_replay_ignores_later_worker_head_changes(
    workbench_api, workbench_db, publication_scan, monkeypatch, head_change
):
    import finalize_scan_contract

    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    checkpoint_name = json.loads((result.parent / "checkpoint-head.json").read_text())["checkpoint"]
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    expected_heads = {directory: f"{directory}/checkpoints/{checkpoint_name}"}
    original_outputs = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    }
    write_bytes = finalize_scan_contract.write_scan_local_bytes
    failed_writes = []

    def fail_coverage_write(directory, relative, payload, **kwargs):
        if relative != "coverage.json" or failed_writes:
            return write_bytes(directory, relative, payload, **kwargs)
        # Exercise the real writer after findings have reached disk. Remove the
        # temporary obstruction before the publisher restores its old outputs.
        failed_writes.append(json.loads((directory / "findings.json").read_text()))
        path = directory / relative
        previous_bytes = path.read_bytes()
        path.unlink()
        path.mkdir()
        try:
            return write_bytes(directory, relative, payload, **kwargs)
        finally:
            path.rmdir()
            path.write_bytes(previous_bytes)

    with monkeypatch.context() as patch:
        patch.setattr(finalize_scan_contract, "write_scan_local_bytes", fail_coverage_write)
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert len(failed_writes) == 1
    assert "scanId" in failed_writes[0]
    assert row["status"] == "failed"
    assert row["failure_message"] == "Audit stopped."
    assert row["retained_source_digests_json"]
    assert row["seal_manifest_digest"] is None
    assert all(
        (scan.scan_dir / name).read_bytes() == contents
        for name, contents in original_outputs.items()
    )
    original_sources = row["retained_source_digests_json"]
    original_run = dict(
        workbench_db.execute(
            "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
        ).fetchone()
    )
    head = result.parent / "checkpoint-head.json"
    if head_change == "replaced":
        save_disposition(scan, result.parent, "reported")
    elif head_change == "removed":
        head.unlink()
    else:
        head.write_text(json.dumps({"checkpoint": "a" * 64 + ".json"}))

    replayed = workbench_api["saved_results"].preserve_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]

    assert replayed["findingCount"] == 0
    assert json.loads((scan.scan_dir / "findings.json").read_text())["findings"] == []
    assert json.loads(result.read_text()) == previous
    row = workbench_db.execute("SELECT * FROM scans WHERE id = ?", (scan.scan_id,)).fetchone()
    assert row["failure_message"] == "Audit stopped."
    assert row["retained_source_digests_json"] == original_sources
    assert json.loads(row["retained_checkpoint_heads_json"]) == expected_heads
    assert row["seal_manifest_digest"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())
    assert manifest["scan"]["preservedCheckpointHeads"] == expected_heads
    assert (
        dict(
            workbench_db.execute(
                "SELECT * FROM deep_scan_runs WHERE scan_id = ?", (scan.scan_id,)
            ).fetchone()
        )
        == original_run
    )


def test_explicit_recovery_observes_head_change_between_existing_checkpoints(
    workbench_api, workbench_db, publication_scan
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    stopped = workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )["scan"]
    assert stopped["findingCount"] == 0

    save_disposition(scan, result.parent, "reported")

    context = workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]
    assert context["resultsRecoveryNeeded"] is True
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


def test_legacy_frozen_publication_keeps_result_fallback_without_saved_heads(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    previous = save_disposition(scan, result.parent, "reported")
    result.write_text(json.dumps(previous))
    save_disposition(scan, result.parent, "rejected")
    (result.parent / "checkpoint-head.json").unlink()

    def fail_before_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(
            workbench_api["saved_results"],
            "_write_prepared_scan_finalization",
            fail_before_publication,
        )
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    save_disposition(scan, result.parent, "rejected")

    replayed = workbench_api["saved_results"].preserve_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(
            scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
        ),
    )["scan"]

    assert replayed["findingCount"] == 1


@pytest.mark.parametrize("head_time", [0, 1, -1], ids=["tie", "newer", "older"])
def test_recovery_uses_live_selection_regardless_of_head_timestamp(
    workbench_api, workbench_db, publication_scan, head_time
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    head = result.parent / "checkpoint-head.json"
    observed = head.stat().st_mtime_ns
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    save_disposition(scan, result.parent, "reported")
    os.utime(head, ns=(observed + head_time, observed + head_time))
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False


def test_publication_metadata_uses_the_captured_head(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    saved = workbench_api["saved_results"]
    capture = saved._capture_saved_source
    relative_head = (result.parent / "checkpoint-head.json").relative_to(scan.scan_dir).as_posix()

    changed = False

    def replace_before_capture(directory, relative, *args, **kwargs):
        nonlocal changed
        if relative == relative_head and not changed:
            changed = True
            save_disposition(scan, result.parent, "rejected")
        return capture(directory, relative, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_capture_saved_source", replace_before_capture)
        stopped = workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    selected = json.loads((result.parent / "checkpoint-head.json").read_text())["checkpoint"]
    directory = result.parent.relative_to(scan.scan_dir).as_posix()
    assert manifest["preservedCheckpointHeads"] == {
        directory: f"{directory}/checkpoints/{selected}"
    }
    assert stopped["findingCount"] == 0
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is False
    )


@pytest.mark.parametrize("legacy_state", ["published", "failed-publication"])
def test_legacy_checkpoint_selection_is_reconstructed_from_frozen_sources(
    workbench_api, workbench_db, publication_scan, monkeypatch, legacy_state
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        if legacy_state == "published":
            patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
        else:
            patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    if legacy_state == "failed-publication":
        saved.preserve_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
            ),
        )
    context = workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]
    assert context["findingCount"] == 0
    assert context["resultsRecoveryNeeded"] is False


@pytest.mark.parametrize("retry", ["preserve", "recover"])
def test_failed_explicit_recovery_replays_its_frozen_selection(
    workbench_api, workbench_db, publication_scan, monkeypatch, retry
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    original = {
        name: (scan.scan_dir / name).read_bytes()
        for name in ("findings.json", "coverage.json", "scan-manifest.json")
    }
    original_digest = workbench_db.execute(
        "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
    ).fetchone()[0]
    save_disposition(scan, result.parent, "reported")
    saved = workbench_api["saved_results"]

    def fail_publication(*args, **kwargs):
        raise OSError("Synthetic publication interruption")

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        with pytest.raises(OSError, match="Synthetic publication interruption"):
            workbench_api["recover_scan_results"](workbench_db, Namespace(scan_id=scan.scan_id))
    assert all((scan.scan_dir / name).read_bytes() == data for name, data in original.items())
    assert (
        workbench_db.execute(
            "SELECT seal_manifest_digest FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
        == original_digest
    )
    # The live head returns to the prior published disposition; pending recovery
    # still needs to publish the selection made before the failed write.
    save_disposition(scan, result.parent, "rejected")
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    if retry == "recover":
        recovered = workbench_api["recover_scan_results"](
            workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
    else:
        recovered = saved.preserve_scan_results(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, thread_id=None, coordinator_generation=None
            ),
        )["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["failureMessage"] == "Audit stopped."
    retained = json.loads(
        workbench_db.execute(
            "SELECT retained_checkpoint_heads_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert "recoveryBaseDigest" not in retained


@pytest.mark.parametrize("bad_head", ["malformed", "missing-checkpoint"])
@pytest.mark.parametrize("prior_disposition", ["reported", "rejected"])
def test_unreadable_worker_head_does_not_hide_other_recoverable_evidence(
    workbench_api, workbench_db, publication_scan, bad_head, prior_disposition
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    bad = add_worker(workbench_db, scan, status="canceled")
    bad.write_text(json.dumps(save_disposition(scan, bad.parent, "reported")))
    save_disposition(scan, bad.parent, prior_disposition)
    prior_head = json.loads((bad.parent / "checkpoint-head.json").read_text())["checkpoint"]
    scan.findings[0]["identity"]["anchor"] = "independent-worker"
    scan.findings[0]["locations"][0]["startLine"] = 20
    scan.findings[0]["locations"][0]["endLine"] = 21
    good = add_worker(workbench_db, scan, status="canceled")
    save_disposition(scan, good.parent, "rejected")
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    (bad.parent / "checkpoint-head.json").write_text(
        "{" if bad_head == "malformed" else json.dumps({"checkpoint": "a" * 64 + ".json"})
    )
    save_disposition(scan, good.parent, "reported")
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == (2 if prior_disposition == "reported" else 1)
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    directory = bad.parent.relative_to(scan.scan_dir).as_posix()
    assert (
        manifest["preservedCheckpointHeads"][directory] == f"{directory}/checkpoints/{prior_head}"
    )


def test_failed_head_snapshot_does_not_claim_uncaptured_authority(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    write = saved.write_scan_local_bytes
    directory = result.parent.relative_to(scan.scan_dir).as_posix()

    def fail_snapshot(root, relative, *args, **kwargs):
        if relative.startswith(f"{directory}/checkpoint-heads/"):
            raise OSError("Synthetic snapshot write failure")
        return write(root, relative, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", fail_snapshot)
        stopped = workbench_api["fail_scan"](
            workbench_db,
            Namespace(
                scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."
            ),
        )["scan"]
    manifest = json.loads((scan.scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["preservedCheckpointHeads"][directory] is None
    assert stopped["findingCount"] == 0
    warnings = json.loads(
        workbench_db.execute(
            "SELECT completion_warnings_json FROM scans WHERE id = ?", (scan.scan_id,)
        ).fetchone()[0]
    )
    assert any("Synthetic snapshot write failure" in warning for warning in warnings)


def test_legacy_recovery_can_reselect_an_already_frozen_head(
    workbench_api, workbench_db, publication_scan, monkeypatch
):
    scan = publication_scan()
    (scan.scan_dir / "findings.json").write_text(json.dumps({"findings": []}))
    result = add_worker(workbench_db, scan, status="canceled")
    result.write_text(json.dumps(save_disposition(scan, result.parent, "reported")))
    head = result.parent / "checkpoint-head.json"
    original_head, original_time = head.read_bytes(), head.stat().st_mtime_ns
    workbench_api["fail_scan"](
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Audit stopped."),
    )
    save_disposition(scan, result.parent, "rejected")
    saved = workbench_api["saved_results"]
    prepare = saved._prepare_scan_finalization

    def legacy_documents(*args, **kwargs):
        kwargs["draft_documents"][0]["scan"].pop("preservedCheckpointHeads")
        return prepare(*args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_prepare_scan_finalization", legacy_documents)
        rejected = workbench_api["recover_scan_results"](
            workbench_db, Namespace(scan_id=scan.scan_id)
        )["scan"]
    assert rejected["findingCount"] == 0
    with workbench_db:
        workbench_db.execute(
            "UPDATE scans SET retained_checkpoint_heads_json = NULL WHERE id = ?", (scan.scan_id,)
        )
    head.write_bytes(original_head)
    os.utime(head, ns=(original_time, original_time))
    assert (
        workbench_api["scan_context"](workbench_db, scan.scan_id)["scan"]["resultsRecoveryNeeded"]
        is True
    )
    recovered = workbench_api["recover_scan_results"](
        workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert recovered["findingCount"] == 1
    assert recovered["resultsRecoveryNeeded"] is False
