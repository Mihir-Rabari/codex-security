from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from workbench_test_support import (
    register,
    run_workbench,
    write_checkpoint,
    write_completed_contract,
)


def test_cost_receipts_replace_flat_and_wrapped_inputs_without_nesting(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    scan = register(state, target, scan_dir)
    usage = {"coverage": "unavailable", "source": "codex_rollout", "threadCount": 0}
    cost = {
        "model": "synthetic-model",
        "inputTokens": 10,
        "cachedInputTokens": 0,
        "cacheWriteInputTokens": 0,
        "outputTokens": 5,
        "estimatedUsd": 0.001,
    }
    for receipt in ({"usage": usage}, {"usage": usage, "cost": cost}, cost):
        saved = run_workbench(
            state,
            "preserve-scan-results",
            "--scan-id",
            scan["scanId"],
            "--cost-json",
            json.dumps(receipt),
        )["scan"]
        assert saved["usage"] == usage
        if "model" in receipt or "cost" in receipt:
            assert saved["cost"] == cost
    failed = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop."
    )
    assert failed["scan"]["cost"] == cost
    replacement = {**cost, "estimatedUsd": 0.002}
    repeated = run_workbench(
        state,
        "fail-scan",
        "--scan-id",
        scan["scanId"],
        "--message",
        "Synthetic stop.",
        "--cost-json",
        json.dumps({"usage": usage, "cost": replacement}),
    )
    assert repeated["scan"]["cost"] == replacement
    assert repeated["scan"]["usage"] == usage


def test_draft_acknowledges_only_reconciled_pending_checkpoints(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir)
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    documents = {
        key: json.loads((scan_dir / name).read_text())
        for key, name in (
            ("manifest", "scan-manifest.json"),
            ("findings", "findings.json"),
            ("coverage", "coverage.json"),
        )
    }
    earlier = write_checkpoint(
        scan_dir / "checkpoints", {"scanId": scan["scanId"], "findings": [], "coverage": {}}
    )
    concurrent = write_checkpoint(
        scan_dir / "checkpoints",
        {
            "scanId": scan["scanId"],
            "findings": [],
            "coverage": {"openQuestions": ["Pending review"]},
        },
    )
    drafts = scan_dir / "drafts"
    drafts.mkdir(mode=0o700)
    staged = drafts / f"{uuid.uuid4()}.json"
    staged.write_text(json.dumps({**documents, "reconciledCheckpointIds": [earlier.name]}))
    run_workbench(
        state, "write-scan-draft", "--scan-id", scan["scanId"], "--draft-path", str(staged)
    )
    pending = scan_dir / "checkpoints/pending"
    assert (pending / ".initialized").is_file()
    assert not (pending / earlier.name).exists()
    assert (pending / concurrent.name).read_bytes() == concurrent.read_bytes()
    assert earlier.is_file()  # The immutable evidence is retained after acknowledgment.
    incoming = drafts / f"{uuid.uuid4()}.checkpoint.json"
    incoming.write_text(
        json.dumps(
            {
                "scanId": scan["scanId"],
                "findings": [],
                "coverage": {"openQuestions": ["New review"]},
            }
        )
    )
    conflict = run_workbench(
        state,
        "write-scan-draft",
        "--scan-id",
        scan["scanId"],
        "--draft-path",
        str(staged),
        "--checkpoint-path",
        str(incoming),
        "--expected-draft-digest",
        "0" * 64,
        check=False,
    )
    assert conflict["returncode"] != 0
    assert "scan_draft_conflict" in conflict["stderr"]
    assert len(list(pending.glob("*.json"))) == 2


def test_stopped_scan_preserves_parent_with_malformed_historical_checkpoint(tmp_path: Path) -> None:
    target, state, scan_dir = tmp_path / "target", tmp_path / "state", tmp_path / "scan"
    target.mkdir()
    (target / "app.py").write_text("\n" * 50)
    scan = register(state, target, scan_dir, mode="deep")
    write_completed_contract(scan_dir, scan["scanId"], target, relative_path="app.py")
    contents = b"{incomplete"
    name = f"{hashlib.sha256(contents).hexdigest()}.json"
    history = scan_dir / "checkpoints"
    history.mkdir(mode=0o700)
    (history / name).write_bytes(contents)

    stopped = run_workbench(
        state, "fail-scan", "--scan-id", scan["scanId"], "--message", "Synthetic stop."
    )["scan"]

    assert stopped["findingCount"] == 1
    assert stopped["reportAvailable"] is True
    assert any("Preserved unreadable checkpoint" in warning for warning in stopped["warnings"])
    assert (history / name).read_bytes() == contents
    assert (history / "pending" / name).read_bytes() == contents
    manifest = json.loads((scan_dir / "scan-manifest.json").read_text())["scan"]
    assert manifest["status"] == "failed"
    assert manifest["sealedAt"]
    assert f"checkpoints/pending/{name}" not in manifest["preservedSources"]
