from __future__ import annotations

import argparse
import copy
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from workbench_test_support import checkpoint, register, run_workbench, write_completed_contract


@pytest.fixture
def pending_scan(tmp_path, workbench_api, monkeypatch, request):
    scenario = getattr(request, "param", "standard")
    mode = "standard" if scenario == "standard" else "deep"
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("pass\n" * 50)
    state = tmp_path / "state"
    scan = register(state, target, tmp_path / "scan", mode=mode)
    directory = Path(scan["scanDir"])
    child_title = None
    if scenario == "deep_child":
        child_dir = directory / "artifacts/deep-scan/passes/pass-1"
        child = register(state, target, child_dir, parent=scan["scanId"], role="deep_pass")
        write_completed_contract(
            child_dir,
            child["scanId"],
            target,
            relative_path="app.py",
            identity_anchor="unmerged-child",
        )
        child_findings = json.loads((child_dir / "findings.json").read_text())
        child_title = "Unmerged child evidence"
        child_findings["findings"][0]["title"] = child_title
        (child_dir / "findings.json").write_text(json.dumps(child_findings))
        run_workbench(state, "complete-scan", "--scan-id", child["scanId"])
        checkpoint(
            state,
            scan,
            terminal="capped",
            passes=[
                {
                    "directory": child_dir.relative_to(directory).as_posix(),
                    "scanId": child["scanId"],
                }
            ],
        )
    elif mode == "deep":
        checkpoint(state, scan, terminal="saturated")
    write_completed_contract(
        directory,
        scan["scanId"],
        target,
        relative_path="app.py",
        coverage_mode="deep_repository" if mode == "deep" else "repository",
    )
    documents = {
        key: json.loads((directory / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    documents["manifest"]["scan"]["complete"] = True
    expected = copy.deepcopy(documents["findings"]["findings"][0])
    empty = copy.deepcopy(documents)
    empty["findings"]["findings"] = []
    saved = workbench_api["saved_results"]
    monkeypatch.setenv("CODEX_SECURITY_STATE_DIR", str(state))
    args = argparse.Namespace(
        scan_id=scan["scanId"],
        claim_token=None,
        draft_path=None,
        checkpoint_path=None,
        expected_draft_digest=None,
    )
    with workbench_api["connect"]() as connection:

        def publish(draft):
            payload = {
                "documents": draft,
                "checkpoint": {
                    "scanId": scan["scanId"],
                    "complete": True,
                    "findings": draft["findings"]["findings"],
                    "coverage": draft["coverage"],
                },
            }
            monkeypatch.setattr(saved.sys, "stdin", io.StringIO(json.dumps(payload)))
            saved.write_scan_draft(workbench_api["_WORKBENCH_DB_CONTEXT"], connection, args)

        yield SimpleNamespace(
            publish=publish,
            saved=saved,
            documents=documents,
            empty=empty,
            expected=expected,
            directory=directory,
            state=state,
            scan_id=scan["scanId"],
            child_title=child_title,
        )


@pytest.mark.parametrize("pending_scan", ["standard", "deep", "deep_child"], indirect=True)
def test_completion_retains_checkpoint_after_failed_commit_and_later_draft(
    pending_scan, monkeypatch
):
    fixture = pending_scan
    saved, directory = fixture.saved, fixture.directory
    fixture.publish(fixture.empty)
    committed = (directory / "artifacts/scan-draft.json").read_bytes()
    write = saved.write_scan_local_bytes

    def fail_commit(root, relative, contents, **kwargs):
        if relative == "artifacts/scan-draft.json":
            raise OSError("Synthetic committed draft interruption")
        return write(root, relative, contents, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "write_scan_local_bytes", fail_commit)
        with pytest.raises(OSError, match="committed draft interruption"):
            fixture.publish(fixture.documents)
    assert (directory / "artifacts/scan-draft.json").read_bytes() == committed
    retained = {path.name: path.read_bytes() for path in (directory / "checkpoints").glob("*.json")}
    assert any(fixture.expected["title"] in value.decode() for value in retained.values())
    fixture.publish(fixture.empty)
    run_workbench(fixture.state, "prepare-scan-completion", "--scan-id", fixture.scan_id)
    findings = json.loads((directory / "findings.json").read_text())["findings"]
    assert {finding["title"] for finding in findings} == {
        fixture.expected["title"],
        *([fixture.child_title] if fixture.child_title else []),
    }
    retained_finding = next(
        finding for finding in findings if finding["title"] == fixture.expected["title"]
    )
    assert retained_finding["codeEvidence"] == fixture.expected["codeEvidence"]
    assert fixture.expected["title"] in (directory / "report.md").read_text()
    assert json.loads((directory / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert all(
        (directory / "checkpoints" / name).read_bytes() == value for name, value in retained.items()
    )


def test_later_commits_retire_accepted_markers_after_cleanup_interruption(
    pending_scan, monkeypatch
):
    fixture = pending_scan
    saved, directory = fixture.saved, fixture.directory
    remove = saved._remove_scan_local_file_if_exists
    rejected = copy.deepcopy(fixture.empty)
    rejected["coverage"]["surfaces"][0]["disposition"] = "rejected"

    def fail_cleanup(root, relative):
        if relative.startswith("checkpoints/pending/"):
            raise OSError("Synthetic checkpoint cleanup interruption")
        return remove(root, relative)

    with monkeypatch.context() as patch:
        patch.setattr(saved, "_remove_scan_local_file_if_exists", fail_cleanup)
        with pytest.raises(OSError, match="cleanup interruption"):
            fixture.publish(fixture.documents)
        accepted = (directory / "artifacts/scan-draft.json").read_bytes()
        with pytest.raises(OSError, match="cleanup interruption"):
            fixture.publish(rejected)
        assert (directory / "artifacts/scan-draft.json").read_bytes() == accepted
    committed = json.loads((directory / "artifacts/scan-draft.json").read_text())
    acknowledged = committed["reconciledCheckpointIds"]
    assert len(acknowledged) == 1
    evidence = (directory / "checkpoints" / acknowledged[0]).read_bytes()
    assert (directory / "checkpoints/pending" / acknowledged[0]).exists()
    # An explicit rejection in a later accepted draft must not be reopened by the marker.
    fixture.publish(rejected)
    assert not (directory / "checkpoints/pending" / acknowledged[0]).exists()
    fixture.publish(rejected)
    run_workbench(fixture.state, "prepare-scan-completion", "--scan-id", fixture.scan_id)
    assert json.loads((directory / "findings.json").read_text())["findings"] == []
    assert (
        json.loads((directory / "coverage.json").read_text())["surfaces"][0]["disposition"]
        == "rejected"
    )
    assert fixture.expected["title"] not in (directory / "report.md").read_text()
    assert (directory / "checkpoints" / acknowledged[0]).read_bytes() == evidence
    assert list((directory / "checkpoints/pending").glob("*.json")) == []


@pytest.mark.parametrize("pending_scan", ["standard", "deep"], indirect=True)
@pytest.mark.parametrize(
    ("document", "invalid"),
    [
        (None, "{malformed"),
        (None, "{}"),
        ("manifest", None),
        ("findings", []),
        ("coverage", "invalid"),
    ],
    ids=["invalid_json", "missing_documents", "null_manifest", "array_findings", "scalar_coverage"],
)
def test_cancel_recovers_immutable_checkpoint_when_committed_head_is_malformed(
    pending_scan, document, invalid
):
    fixture = pending_scan
    directory = fixture.directory
    fixture.publish(fixture.documents)
    checkpoints = {
        path.name: path.read_bytes() for path in (directory / "checkpoints").glob("*.json")
    }
    # Accepted evidence must survive even when no pending index remains.
    (directory / "checkpoints/pending").rmdir()
    contents = (
        json.dumps({**fixture.documents, document: invalid}) if document is not None else invalid
    )
    (directory / "artifacts/scan-draft.json").write_text(contents)
    findings_path = directory / "findings.json"
    current = json.loads(findings_path.read_text())
    current["findings"] = []
    findings_path.write_text(json.dumps(current))
    run_workbench(fixture.state, "cancel-scan", "--scan-id", fixture.scan_id)
    findings = json.loads(findings_path.read_text())["findings"]
    assert [finding["title"] for finding in findings] == [fixture.expected["title"]]
    assert findings[0]["codeEvidence"] == fixture.expected["codeEvidence"]
    assert json.loads((directory / "scan-manifest.json").read_text())["scan"]["sealedAt"]
    assert fixture.expected["title"] in (directory / "report.md").read_text()
    assert all(
        (directory / "checkpoints" / name).read_bytes() == contents
        for name, contents in checkpoints.items()
    )
