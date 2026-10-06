from __future__ import annotations

import copy
import json
import uuid
from argparse import Namespace

import pytest
from test_deep_scan_successful_publication import add_worker
from test_deep_scan_successful_publication import publication_scan as publication_scan


@pytest.mark.parametrize("retained", [False, True], ids=["missing", "retained"])
@pytest.mark.parametrize("optional_ids", [False, True], ids=["absent-ids", "present-ids"])
@pytest.mark.parametrize("field", ["surfaces", "deferred", "explicitExclusions", "openQuestions"])
def test_recovery_preserves_descriptive_provenance(
    workbench_api, workbench_db, publication_scan, retained, optional_ids, field
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    prefix = f"{worker_id}-attempt-1"
    descriptions = {
        "description": "Synthetic source note.",
        "details": {"basis": ["source review"], "resolved": False},
        "optional": None,
    }
    imported = {
        **descriptions,
        "workerId": "imported-worker",
        "attempt": 999,
        "sourceId": "imported-source",
        "candidateId": "imported-candidate",
    }
    records = {
        "surfaces": {
            "id": "source-surface",
            "label": "Synthetic surface",
            "disposition": "needs_follow_up",
            "receiptRefs": [],
        },
        "deferred": {
            "id": "source-deferred",
            "reason": "Synthetic follow-up remains unresolved.",
            "surfaceIds": ["source-surface"],
        },
        "explicitExclusions": {"pattern": "vendor/**", "reason": "Review separately."},
        "openQuestions": {"question": "Which deployment controls apply?"},
    }
    item = records[field]
    if optional_ids:
        item.setdefault("id", "source-record")
        item["candidateId"] = "source-candidate"
    item["provenance"] = copy.deepcopy(imported)
    expected = copy.deepcopy(item)
    expected["provenance"] = {**descriptions, "workerId": worker_id, "attempt": 1}
    if "id" in item:
        expected["provenance"]["sourceId"] = item["id"]
    if optional_ids:
        expected["provenance"]["candidateId"] = "source-candidate"
    if field == "surfaces":
        expected["id"] = f"{prefix}-surface-1"
    elif field == "deferred":
        expected["id"] = f"{prefix}-deferred-1"
        expected["surfaceIds"] = [f"{prefix}-surface-1"]
        if optional_ids:
            expected["candidateId"] = f"{prefix}-candidate-1"
    source_coverage = {**scan.coverage, field: [item]}
    if field == "deferred":
        source_coverage["surfaces"] = [records["surfaces"]]
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": source_coverage,
            }
        )
    )
    original = result.read_bytes()
    parent = {
        **scan.coverage,
        field: [expected] if retained else [],
        "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
    }
    if field == "deferred" and retained:
        parent["surfaces"] = [
            {
                **records["surfaces"],
                "id": f"{prefix}-surface-1",
                "provenance": {
                    "workerId": worker_id,
                    "attempt": 1,
                    "sourceId": "source-surface",
                },
            }
        ]
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    actual = coverage[field]
    if field == "deferred":
        actual = [record for record in actual if record.get("id") != "scan-stopped"]
        assert actual[0]["surfaceIds"] == [coverage["surfaces"][0]["id"]]
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published
    assert result.read_bytes() == original
    if field == "explicitExclusions" and not retained and not optional_ids:
        assert actual[0].pop("id").startswith("saved-")
    assert actual == [expected]


@pytest.mark.parametrize("parent_review", [False, True], ids=["reconstructed", "retained"])
@pytest.mark.parametrize("retry_publication", [False, True], ids=["direct", "failed-retry"])
def test_recovery_uses_host_reviews_without_discovery_review_extensions(
    workbench_api, workbench_db, publication_scan, monkeypatch, parent_review, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    host_review = {"workerId": worker_id, "attempt": 1, "completeness": "complete"}
    imported_review = {
        "workerId": "synthetic-other-worker",
        "attempt": 99,
        "completeness": "complete",
    }
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "reviews": [imported_review]},
            }
        )
    )
    original = result.read_bytes()
    if parent_review:
        (scan.scan_dir / "coverage.json").write_text(
            json.dumps({**scan.coverage, "reviews": [host_review]})
        )
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication failure.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        stopped = saved.fail_scan(
            context,
            workbench_db,
            Namespace(
                scan_id=scan.scan_id,
                claim_token=None,
                cost_json=None,
                message="Stopped.",
            ),
        )
    assert stopped["scan"]["resultsRecoveryNeeded"] is retry_publication
    recovered = saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert recovered["scan"]["resultsRecoveryNeeded"] is False
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["reviews"] == [host_review]
    assert imported_review not in coverage["reviews"]
    assert result.read_bytes() == original
    published = (scan.scan_dir / "coverage.json").read_bytes()
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("missing_completeness", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_malformed_saved_completeness_preserves_other_valid_coverage(
    workbench_api,
    workbench_db,
    publication_scan,
    monkeypatch,
    missing_completeness,
    retry_publication,
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    source = {
        **scan.coverage,
        "surfaces": [
            {"id": "reviewed", "label": "Retained evidence", "disposition": "no_issue_found"}
        ],
    }
    if missing_completeness:
        source.pop("completeness")
    result.write_text(
        json.dumps({"scanId": scan.scan_id, "complete": True, "findings": [], "coverage": source})
    )
    original = result.read_bytes()
    saved = workbench_api["saved_results"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    recovered = saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )["scan"]
    assert not recovered["resultsRecoveryNeeded"]
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert any(row["label"] == "Retained evidence" for row in coverage["surfaces"])
    assert coverage["completeness"] == "partial"
    assert result.read_bytes() == original


@pytest.mark.parametrize("retained_attempt", [1, 2])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_missing_deferred_uses_retained_surface_from_its_reviewed_attempt(
    workbench_api, workbench_db, publication_scan, monkeypatch, retained_attempt, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
    surface = {
        "id": "retained",
        "label": "Retained surface",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    deferred = {"id": "new-gap", "reason": "Verify retained surface.", "surfaceIds": ["retained"]}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": [surface],
                    "deferred": [deferred],
                },
            }
        )
    )
    projected_id = f"{worker_id}-attempt-{retained_attempt}-surface-1"
    parent = {
        **scan.coverage,
        "completeness": "partial",
        "surfaces": [
            {
                **surface,
                "id": projected_id,
                "provenance": {
                    "workerId": worker_id,
                    "attempt": retained_attempt,
                    "sourceId": "retained",
                },
            }
        ],
        "deferred": [],
        "reviews": [
            {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
            for attempt in {retained_attempt, 2}
        ],
    }
    (scan.scan_dir / "coverage.json").write_text(json.dumps(parent))
    original = result.read_bytes()
    saved = workbench_api["saved_results"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            workbench_api["_WORKBENCH_DB_CONTEXT"],
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )
    published = (scan.scan_dir / "coverage.json").read_bytes()
    coverage = json.loads(published)
    task = next(row for row in coverage["deferred"] if row["reason"] == deferred["reason"])
    assert task["surfaceIds"] == [projected_id]
    assert projected_id in {row["id"] for row in coverage["surfaces"]}
    assert result.read_bytes() == original
    saved.recover_scan_results(
        workbench_api["_WORKBENCH_DB_CONTEXT"], workbench_db, Namespace(scan_id=scan.scan_id)
    )
    assert (scan.scan_dir / "coverage.json").read_bytes() == published


@pytest.mark.parametrize("missing_surface", [False, True])
@pytest.mark.parametrize("retry_publication", [False, True])
def test_retry_recovery_restores_original_attempt_and_retained_deferral(
    workbench_api, workbench_db, publication_scan, monkeypatch, missing_surface, retry_publication
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    with workbench_db:
        workbench_db.execute("UPDATE deep_scan_workers SET attempt = 2 WHERE id = ?", (worker_id,))
    surface = {
        "id": "first-surface",
        "label": "First attempt evidence",
        "disposition": "needs_follow_up",
        "receiptRefs": [],
    }
    deferred = {
        "id": "first-gap",
        "reason": "First attempt still needs validation.",
        "surfaceIds": [surface["id"]],
    }
    draft = {
        "scanId": scan.scan_id,
        "complete": True,
        "findings": [],
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [surface],
            "deferred": [deferred],
        },
    }
    archived = result.parent / "attempts" / "attempt-1" / "result.json"
    archived.parent.mkdir(parents=True)
    archived.write_text(json.dumps({**draft, "complete": False}))
    result.write_text(json.dumps(draft))
    prefix = f"{worker_id}-attempt-1"
    projected_surface = {
        **surface,
        "id": f"{prefix}-surface-1",
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": surface["id"]},
    }
    projected_deferred = {
        **deferred,
        "id": f"{prefix}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": deferred["id"]},
    }
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "completeness": "partial",
                "surfaces": [] if missing_surface else [projected_surface],
                "deferred": [projected_deferred],
                "reviews": [
                    {"workerId": worker_id, "attempt": attempt, "completeness": "partial"}
                    for attempt in (1, 2)
                ],
            }
        )
    )
    originals = {path: path.read_bytes() for path in (result, archived)}
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    with monkeypatch.context() as interrupted:
        if retry_publication:

            def fail_publication(*args, **kwargs):
                raise OSError("Synthetic publication interruption.")

            interrupted.setattr(saved, "_write_prepared_scan_finalization", fail_publication)
        saved.fail_scan(
            context,
            workbench_db,
            Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
        )
    saved.recover_scan_results(context, workbench_db, Namespace(scan_id=scan.scan_id))
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"] == [projected_surface]
    tasks = [row for row in coverage["deferred"] if row.get("reason") == deferred["reason"]]
    assert tasks == [projected_deferred]
    assert all(path.read_bytes() == contents for path, contents in originals.items())


@pytest.mark.parametrize("interrupted_parent", [False, True])
def test_selected_parent_checkpoint_supplies_review_projection(
    workbench_api, workbench_db, publication_scan, monkeypatch, interrupted_parent
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    surface = {"id": "review", "label": "Reviewed surface", "disposition": "needs_follow_up"}
    deferred = {"id": "gap", "reason": "Validate the reviewed surface.", "surfaceIds": ["review"]}
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {
                    **scan.coverage,
                    "completeness": "partial",
                    "surfaces": [surface],
                    "deferred": [deferred],
                },
            }
        )
    )
    prefix = f"{worker_id}-attempt-1"
    projected_surface = {
        **surface,
        "id": f"{prefix}-surface-1",
        "receiptRefs": [],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "review"},
    }
    projected_deferred = {
        **deferred,
        "id": f"{prefix}-deferred-1",
        "surfaceIds": [projected_surface["id"]],
        "provenance": {"workerId": worker_id, "attempt": 1, "sourceId": "gap"},
    }
    documents = {
        "manifest": json.loads((scan.scan_dir / "scan-manifest.json").read_text()),
        "findings": {"findings": []},
        "coverage": {
            **scan.coverage,
            "completeness": "partial",
            "surfaces": [projected_surface],
            "deferred": [projected_deferred],
            "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "partial"}],
        },
    }
    drafts = scan.scan_dir / "drafts"
    drafts.mkdir()
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps(documents))
    saved = workbench_api["saved_results"]
    context = workbench_api["_WORKBENCH_DB_CONTEXT"]
    original_write = saved.write_scan_local_bytes

    def interrupt_coverage(root, relative, contents):
        if relative == "coverage.json":
            raise OSError("Synthetic parent publication interruption.")
        original_write(root, relative, contents)

    with monkeypatch.context() as interrupted:
        if interrupted_parent:
            interrupted.setattr(saved, "write_scan_local_bytes", interrupt_coverage)
        args = Namespace(
            scan_id=scan.scan_id,
            claim_token=None,
            draft_path=str(staged),
            checkpoint_path=None,
            expected_draft_digest=None,
        )
        if interrupted_parent:
            with pytest.raises(OSError, match="Synthetic parent publication interruption"):
                saved.write_scan_draft(context, workbench_db, args)
        else:
            saved.write_scan_draft(context, workbench_db, args)
    saved.fail_scan(
        context,
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["surfaces"] == [projected_surface]
    assert [row for row in coverage["deferred"] if row.get("reason") == deferred["reason"]] == [
        projected_deferred
    ]


@pytest.mark.parametrize("padded", [False, True])
def test_retained_worker_string_question_is_not_duplicated(
    workbench_api, workbench_db, publication_scan, padded
):
    scan = publication_scan()
    result = add_worker(workbench_db, scan)
    worker_id = result.parent.name
    question = (
        "  Which deployment controls apply?  " if padded else "Which deployment controls apply?"
    )
    result.write_text(
        json.dumps(
            {
                "scanId": scan.scan_id,
                "complete": True,
                "findings": [],
                "coverage": {**scan.coverage, "openQuestions": [question]},
            }
        )
    )
    (scan.scan_dir / "coverage.json").write_text(
        json.dumps(
            {
                **scan.coverage,
                "openQuestions": [
                    {"question": question, "provenance": {"workerId": worker_id, "attempt": 1}}
                ],
                "reviews": [{"workerId": worker_id, "attempt": 1, "completeness": "complete"}],
            }
        )
    )
    saved = workbench_api["saved_results"]
    saved.fail_scan(
        workbench_api["_WORKBENCH_DB_CONTEXT"],
        workbench_db,
        Namespace(scan_id=scan.scan_id, claim_token=None, cost_json=None, message="Stopped."),
    )
    coverage = json.loads((scan.scan_dir / "coverage.json").read_text())
    assert coverage["openQuestions"] == [
        {"question": question.strip(), "provenance": {"workerId": worker_id, "attempt": 1}}
    ]
