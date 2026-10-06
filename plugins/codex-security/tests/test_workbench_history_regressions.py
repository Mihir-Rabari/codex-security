from __future__ import annotations

import csv
import runpy
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from test_workbench_scan_history import (
    FINALIZER,
    SCRIPT,
    compare_scan_pair,
    confirmed_match,
    create_cli_scan,
    run_workbench,
    save_scan_matches,
)
from workbench_test_support import initialize_git_repository, write_completed_contract


@pytest.fixture
def history(tmp_path: Path):
    repository = tmp_path / "repository"
    repository.mkdir()
    return tmp_path / "state", tmp_path / "scans", repository


@pytest.fixture
def linked_history(history):
    state, root, parent = history
    repository = parent / "checkout"
    revision = initialize_git_repository(repository)
    linked = repository.with_name("linked-worktree")
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(linked)],
        check=True,
    )
    return state, root, repository, linked, revision


def test_legacy_descendant_scans_stay_inside_the_current_checkout_owner(history) -> None:
    state, root, repository = history
    child = repository / "nested"
    child.mkdir()
    previous = create_cli_scan(state, root, repository)
    legacy = create_cli_scan(state, root, child)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET target_id = NULL, target_device = NULL, target_inode = NULL "
            "WHERE id = ?",
            (legacy["scanId"],),
        )
        connection.execute(
            "UPDATE workspaces SET target_id = NULL WHERE target_path = ?", (str(child),)
        )
        connection.execute("DELETE FROM security_targets WHERE current_path = ?", (str(child),))
    repository.rename(repository.with_name("previous-checkout"))
    child.mkdir(parents=True)
    current = create_cli_scan(state, root, repository)

    for requested in (repository, child):
        scans = run_workbench(state, "list-scans", "--repository", str(requested))["scans"]
        assert [scan["scanId"] for scan in scans] == [current["scanId"]]
    for scan in (previous, legacy):
        result = run_workbench(state, "get-scan", "--scan-id", scan["scanId"], check=False)
        assert result["returncode"] != 0
        assert "checkout owner" in result["stderr"]


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_saved_comparisons_use_the_current_recorded_ownership_epoch(history, checkout) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    saved = save_scan_matches(state, before, after, confirmed_match(*occurrences))
    repository.rename(repository.with_name("offline-checkout"))
    if checkout != "missing":
        repository.mkdir()
    if checkout == "previous-epoch-missing":
        create_cli_scan(state, root, repository)
        repository.rename(repository.with_name("newer-offline-checkout"))

    if checkout == "missing":
        assert compare_scan_pair(state, before, after) == saved
    else:
        result = compare_scan_pair(state, before, after, check=False)
        assert result["returncode"] != 0
        assert "same repository target" in result["stderr"]


def test_explicit_reopen_overrides_a_matched_occurrences_newer_closure(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[0], "--status", "open"
    )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[1],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"]["findings"][
            0
        ]["triage"]["status"]
        == "closed"
    )

    run_workbench(
        state, "set-finding-triage", "--occurrence-id", occurrences[0], "--status", "open"
    )
    for occurrence in occurrences:
        finding = run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"][
            "findings"
        ][0]
        assert finding["triage"]["status"] == "open"
        assert finding["triage"].get("closeReason") is None
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM finding_decisions WHERE occurrence_id = ?", (occurrences[0],)
            ).fetchone()[0]
            == 2
        )


def test_finding_pages_honor_larger_limits(history) -> None:
    state, root, repository = history
    scan = create_cli_scan(
        state,
        root,
        repository,
        identity_anchor="first",
        extra_anchors=tuple(f"additional-{index}" for index in range(24)),
    )
    for arguments in (
        ("list-findings", "--scan-id", scan["scanId"]),
        ("list-global-findings", "--repository", str(repository)),
        ("list-global-findings",),
    ):
        result = run_workbench(state, *arguments, "--limit", "100")
        page = result.get("findingsPage", result)
        assert len(page["findings"]) == 25
        assert page["limit"] == 100
        assert page["nextOffset"] is None


@pytest.mark.parametrize("reason", ["already_fixed", "false_positive", "wont_fix"])
def test_matched_triage_agrees_in_details_comparisons_and_csv(history, reason) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(
        state, root, repository, identity_anchor="after", extra_anchors=("another-path",)
    )
    previous = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"]["findings"][
        0
    ]
    current = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"]
    save_scan_matches(
        state,
        before,
        after,
        confirmed_match(previous["occurrenceId"], [row["occurrenceId"] for row in current]),
    )
    for status in ("closed", "open"):
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            previous["occurrenceId"],
            "--status",
            status,
            *(
                ["--close-reason", reason, "--note", "Synthetic triage."]
                if status == "closed"
                else []
            ),
        )
        shown = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"]
        assert {row["status"] for row in shown} == {status}
        comparison = compare_scan_pair(state, before, after)
        assert comparison["findings"][0]["triage"] == {
            "status": status,
            "closeReason": reason if status == "closed" else None,
        }
        if status == "closed":
            assert comparison["summary"]["reopened"] == 0
        exported = run_workbench(
            state, "export-findings", "--scan-id", after["scanId"], "--format", "csv"
        )["export"]
        with Path(exported["path"]).open(newline="") as source:
            rows = list(csv.DictReader(source))
        assert {row["status"] for row in rows} == {status}
        assert {row["close_reason"] for row in rows} == {reason if status == "closed" else ""}


@pytest.mark.parametrize("reason", ["already_fixed", "false_positive", "wont_fix"])
def test_explicit_triage_updates_every_matched_worktree_occurrence(linked_history, reason) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(state, root, repository, target_revision=revision)
    after = create_cli_scan(state, root, linked, target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        targets = [row[0] for row in connection.execute("SELECT id FROM security_targets")]
    for status in ("closed", "open"):
        run_workbench(
            state,
            "set-finding-triage",
            "--occurrence-id",
            occurrences[0],
            "--status",
            status,
            *(
                ["--close-reason", reason, "--note", "Synthetic triage."]
                if status == "closed"
                else []
            ),
        )
        scopes = [
            ([], 2),
            (["--repository", str(repository)], 1),
            (["--repository", str(linked)], 1),
            *((["--target-id", target], 1) for target in targets),
        ]
        for scope, count in scopes:
            findings = run_workbench(state, "list-global-findings", *scope)["findings"]
            assert len(findings) == count
            assert {finding["status"] for finding in findings} == {status}


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_saved_linked_history_keeps_only_current_checkout_owners(linked_history, checkout) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(state, root, repository, target_revision=revision)
    after = create_cli_scan(state, root, linked, target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic linked triage.",
    )
    linked.rename(linked.with_name("offline-worktree"))
    if checkout != "missing":
        linked.mkdir()
    if checkout == "previous-epoch-missing":
        create_cli_scan(state, root, linked)
        linked.rename(linked.with_name("newer-offline-worktree"))

    if checkout == "missing":
        assert compare_scan_pair(state, before, after)["summary"]["persisting"] == 1
        for occurrence, scan in zip(occurrences, (before, after), strict=True):
            detail = run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"][
                "findings"
            ][0]
            assert detail["occurrenceCount"] == 2
            assert detail["knownScanIds"] == [before["scanId"], after["scanId"]]
            assert detail["status"] == "closed"
            listed = run_workbench(state, "list-findings", "--scan-id", scan["scanId"])[
                "findingsPage"
            ]["findings"][0]
            assert listed["occurrenceCount"] == 2
    else:
        rejected = run_workbench(
            state, "get-finding", "--occurrence-id", occurrences[1], check=False
        )
        assert rejected["returncode"] != 0
        assert "checkout owner" in rejected["stderr"]
        detail = run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"][
            "findings"
        ][0]
        assert "matches" not in detail
        assert "occurrenceCount" not in detail


@pytest.mark.parametrize("command", ["get-finding", "get-scan", "list-scans", "database-info"])
def test_saved_finding_reader_does_not_take_writer_admission(history, command) -> None:
    state, root, repository = history
    scan = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    arguments = (
        ["--occurrence-id", occurrence]
        if command == "get-finding"
        else ["--scan-id", scan["scanId"]]
        if command == "get-scan"
        else []
    )
    with sqlite3.connect(state / "workbench.sqlite3") as writer:
        writer.execute("BEGIN IMMEDIATE")
        result = run_workbench(state, command, *arguments, check=False)
        assert result["returncode"] == 0, result["stderr"]
        assert writer.in_transaction


def test_uncertain_match_does_not_split_later_stable_finding_identity(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="stable-anchor")
    independent = create_cli_scan(state, root, repository, identity_anchor="independent-anchor")
    later = create_cli_scan(state, root, repository, identity_anchor="stable-anchor")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in (before, independent, later)
    ]
    save_scan_matches(
        state,
        before,
        independent,
        uncertain=(
            {
                "beforeOccurrenceId": rows[0]["occurrenceId"],
                "afterOccurrenceId": rows[1]["occurrenceId"],
                "reason": "Synthetic independent root causes.",
            },
        ),
    )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        rows[0]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic triage decision.",
    )
    assert rows[0]["findingId"] == rows[2]["findingId"]
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    stable = [row for row in findings if row["findingId"] == rows[0]["findingId"]]
    assert len(stable) == 1
    assert stable[0]["occurrenceCount"] == 2
    assert stable[0]["status"] == "closed"


def test_late_worktree_comparison_keeps_index_and_detail_decision_consistent(
    linked_history,
) -> None:
    state, root, repository, linked, revision = linked_history
    before = create_cli_scan(
        state, root, repository, identity_anchor="before", target_revision=revision
    )
    after = create_cli_scan(state, root, linked, identity_anchor="after", target_revision=revision)
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[1],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[0])["scan"]["findings"][
            0
        ]["status"]
        == "closed"
    )
    for scope, count in (
        ([], 2),
        (["--repository", str(repository)], 1),
        (["--repository", str(linked)], 1),
    ):
        findings = run_workbench(state, "list-global-findings", *scope, "--include-resolved")[
            "findings"
        ]
        assert len(findings) == count
        assert {row["status"] for row in findings} == {"closed"}


def test_late_comparison_does_not_reopen_scans_started_before_decision(history) -> None:
    state, root, repository = history
    before = create_cli_scan(state, root, repository, identity_anchor="before")
    after = create_cli_scan(state, root, repository, identity_anchor="after")
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in (before, after)
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic triage decision.",
    )
    save_scan_matches(state, before, after, confirmed_match(*occurrences))
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrences[1])["scan"]["findings"][
            0
        ]["status"]
        == "closed"
    )
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(findings) == 1
    assert findings[0]["status"] == "closed"


@pytest.mark.parametrize("legacy_order", ["timestamps", "equal-time", "modern-clock-skew"])
def test_legacy_decision_migration_preserves_chronology_and_appends(history, legacy_order) -> None:
    state, root, repository = history
    scans = [create_cli_scan(state, root, repository) for _ in range(2)]
    occurrences = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0][
            "occurrenceId"
        ]
        for scan in scans
    ]
    database = state / "workbench.sqlite3"
    namespace = runpy.run_path(str(SCRIPT), run_name="legacy_decision_history_fixture")
    migration15 = next(sql for version, _, sql in namespace["MIGRATIONS"] if version == 15)
    backfill = next(
        statement
        for statement in namespace["sql_statements"](migration15)
        if statement.startswith("INSERT INTO finding_decisions")
    )
    with sqlite3.connect(database) as connection:
        if "decision_sequence" in {
            row[1] for row in connection.execute("PRAGMA table_info(finding_decisions)")
        }:
            connection.execute("ALTER TABLE finding_decisions DROP COLUMN decision_sequence")
        connection.execute("DELETE FROM schema_migrations WHERE version > 41")
        connection.execute("DELETE FROM finding_decisions")
        connection.execute("DELETE FROM finding_triage")
        # A legacy update can be newer than a row inserted later in the triage table.
        ordered = sorted(occurrences, reverse=True) if legacy_order == "equal-time" else occurrences
        for index, occurrence in enumerate(ordered):
            connection.execute(
                "INSERT INTO finding_triage VALUES (?, ?, ?, ?, ?)",
                (
                    occurrence,
                    "closed" if index == 0 else "open",
                    "false_positive" if index == 0 else None,
                    "Synthetic legacy decision",
                    "2099-10-06T10:00:00Z"
                    if index == 0 or legacy_order == "equal-time"
                    else "2099-10-05T10:00:00Z",
                ),
            )
        connection.execute(backfill)
        if legacy_order == "modern-clock-skew":
            connection.execute(
                "INSERT INTO finding_decisions VALUES ('modern-append', ?, 'open', NULL, 'Synthetic later append', '2000-01-01T00:00:00Z')",
                (ordered[1],),
            )
            connection.execute(
                "UPDATE finding_triage SET status = 'open', close_reason = NULL, updated_at = '2000-01-01T00:00:00Z' WHERE occurrence_id = ?",
                (ordered[1],),
            )
        old_rows = connection.execute(
            "SELECT id, occurrence_id, status, close_reason, note, created_at FROM finding_decisions ORDER BY id"
        ).fetchall()
    run_workbench(state, "database-info")
    result = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(result) == 1
    assert result[0]["status"] == ("open" if legacy_order == "modern-clock-skew" else "closed")
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT id, occurrence_id, status, close_reason, note, created_at FROM finding_decisions ORDER BY id"
            ).fetchall()
            == old_rows
        )
        before_sequence = connection.execute(
            "SELECT MAX(decision_sequence) FROM finding_decisions"
        ).fetchone()[0]
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrences[0],
        "--status",
        "open",
        "--note",
        "Synthetic reopened decision",
    )
    with sqlite3.connect(database) as connection:
        appended = connection.execute(
            "SELECT status, decision_sequence FROM finding_decisions WHERE decision_sequence > ? ORDER BY decision_sequence",
            (before_sequence,),
        ).fetchall()
    assert appended and all(status == "open" for status, _ in appended)
    assert [sequence for _, sequence in appended] == list(
        range(before_sequence + 1, before_sequence + len(appended) + 1)
    )


def test_stopped_sealed_occurrences_remain_in_complete_scan_history(history) -> None:
    state, root, repository = history
    stopped = create_cli_scan(state, root, repository, complete=False)
    scan_dir = Path(stopped["scanDir"])
    write_completed_contract(scan_dir, stopped["scanId"], repository)
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(scan_dir)], check=True)
    stopped_context = run_workbench(
        state, "fail-scan", "--scan-id", stopped["scanId"], "--message", "Synthetic interruption"
    )
    stopped_finding = stopped_context["scan"]["findings"][0]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        stopped_finding["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic accepted risk",
    )
    current = create_cli_scan(state, root, repository)
    finding = run_workbench(state, "list-global-findings", "--include-resolved")["findings"][0]
    assert finding["occurrenceCount"] == 2
    assert set(finding["knownScanIds"]) == {stopped["scanId"], current["scanId"]}
    assert finding["status"] == "closed"
    for scan in (stopped, current):
        indexed = run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][
            0
        ]
        assert indexed["occurrenceCount"] == 2
        assert set(indexed["knownScanIds"]) == {stopped["scanId"], current["scanId"]}
        assert indexed["status"] == "closed"
