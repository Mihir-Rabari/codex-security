from __future__ import annotations

import csv
import json
import runpy
import sqlite3
import subprocess
import sys
import uuid
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
        for column in ("scan_sequence", "decision_sequence"):
            if column in {
                row[1] for row in connection.execute("PRAGMA table_info(finding_decisions)")
            }:
                connection.execute(f"ALTER TABLE finding_decisions DROP COLUMN {column}")
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


@pytest.mark.parametrize("uncertain", [False, True])
def test_stable_recurrence_keeps_prior_uncertainty_until_later_coverage(history, uncertain) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository, identity_anchor="stable")
    repeated = create_cli_scan(state, root, repository, identity_anchor="stable")
    independent = create_cli_scan(state, root, repository, identity_anchor="independent")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in (first, repeated, independent)
    ]
    assert rows[0]["findingId"] == rows[1]["findingId"]
    if uncertain:
        comparison = save_scan_matches(
            state,
            first,
            independent,
            uncertain=(
                {
                    "beforeOccurrenceId": rows[0]["occurrenceId"],
                    "afterOccurrenceId": rows[2]["occurrenceId"],
                    "reason": "Synthetic comparison remains uncertain.",
                },
            ),
        )
        assert comparison["summary"]["unknown"] == 2
    findings = run_workbench(state, "list-global-findings", "--repository", str(repository))[
        "findings"
    ]
    stable = [row for row in findings if row["findingId"] == rows[0]["findingId"]]
    assert len(stable) == int(uncertain)
    repositories = run_workbench(state, "list-repositories")["repositories"]
    assert repositories[0]["openFindingsCount"] == 1 + int(uncertain)
    create_cli_scan(state, root, repository, finding=False)
    assert (
        run_workbench(state, "list-global-findings", "--repository", str(repository))["findings"]
        == []
    )


@pytest.mark.parametrize("artifact", ["scan-manifest.json", "coverage.json"])
@pytest.mark.parametrize("missing", [False, True])
def test_pruned_coverage_keeps_history_but_tampering_is_rejected(
    history, artifact, missing
) -> None:
    state, root, repository = history
    earlier = create_cli_scan(state, root, repository)
    later = create_cli_scan(state, root, repository, finding=False)
    path = Path(later["scanDir"]) / artifact
    if missing:
        path.unlink()
        findings = run_workbench(state, "list-global-findings")["findings"]
        assert [finding["scanId"] for finding in findings] == [earlier["scanId"]]
    else:
        path.write_text(path.read_text() + "\n")
        result = run_workbench(state, "list-global-findings", check=False)
        assert result["returncode"] != 0
        assert "changed" in result["stderr"]


def test_selected_repository_ignores_an_unrelated_tampered_scan(history) -> None:
    state, root, repository = history
    selected = create_cli_scan(state, root, repository)
    unrelated = repository.with_name("unrelated")
    unrelated.mkdir()
    create_cli_scan(state, root, unrelated)
    later = create_cli_scan(state, root, unrelated, finding=False)
    manifest = Path(later["scanDir"]) / "scan-manifest.json"
    manifest.write_text(manifest.read_text() + "\n")
    result = run_workbench(state, "list-repositories", "--target-id", selected["targetId"])
    assert len(result["repositories"]) == 1
    assert result["repositories"][0]["targetId"] == selected["targetId"]
    assert result["repositories"][0]["openFindingsCount"] == 1
    unfiltered = run_workbench(state, "list-repositories", check=False)
    assert unfiltered["returncode"] != 0
    assert "changed after completion" in unfiltered["stderr"]


@pytest.mark.parametrize("close_reason", ["already_fixed", "false_positive"])
def test_clock_rollback_keeps_a_new_decision_until_a_new_scan_is_admitted(
    history, close_reason
) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2099-10-06T10:00:00Z' WHERE id = ?", (first["scanId"],)
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        close_reason,
        "--note",
        "Synthetic explicit decision",
    )
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"]["findings"][0][
            "status"
        ]
        == "closed"
    )
    later = create_cli_scan(state, root, repository)
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2000-01-01T00:00:00Z' WHERE id = ?", (later["scanId"],)
        )
    findings = run_workbench(state, "list-global-findings", "--include-resolved")["findings"]
    assert len(findings) == 1
    assert findings[0]["scanId"] == later["scanId"]
    assert findings[0]["status"] == "open"


def test_historical_latest_decision_does_not_reopen_without_a_later_scan(history) -> None:
    state, root, repository = history
    first = create_cli_scan(state, root, repository)
    occurrence = run_workbench(state, "get-scan", "--scan-id", first["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        connection.execute(
            "UPDATE scans SET started_at = '2099-10-06T10:00:00Z' WHERE id = ?", (first["scanId"],)
        )
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "false_positive",
        "--note",
        "Synthetic historical dismissal",
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        # Rows preserved by the append-only migration have no recorded admission boundary.
        connection.execute("UPDATE finding_decisions SET scan_sequence = NULL")
    assert (
        run_workbench(state, "get-finding", "--occurrence-id", occurrence)["scan"]["findings"][0][
            "status"
        ]
        == "closed"
    )


@pytest.mark.parametrize("checkout", ["missing", "replaced", "previous-epoch-missing"])
def test_missing_repository_history(tmp_path: Path, history, checkout: str):
    state, root, repo = history
    scan = create_cli_scan(state, root, repo)
    repo.rename(tmp_path / "previous-repository")
    if checkout != "missing":
        repo.mkdir()
    if checkout == "previous-epoch-missing":
        scan = create_cli_scan(state, root, repo)
        repo.rename(tmp_path / "newer-offline-repository")
    missing = checkout != "replaced"
    listed = run_workbench(state, "list-scans", "--repository", str(repo))["scans"]
    assert [row["scanId"] for row in listed] == ([scan["scanId"]] if missing else [])
    findings = run_workbench(
        state, "list-global-findings", "--repository", str(repo), "--include-resolved"
    )["findings"]
    assert len(findings) == int(missing)


@pytest.mark.parametrize("reason", ["false_positive", "already_fixed"])
def test_newly_admitted_rediscovery_comparison(tmp_path: Path, history, reason: str):
    state, root, repo = history
    before = create_cli_scan(state, root, repo)
    occurrence = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        reason,
        "--note",
        "Synthetic decision.",
    )
    after = create_cli_scan(state, root, repo)
    result = compare_scan_pair(state, before, after)
    assert result["summary"]["reopened"] == 1


def test_historical_comparison_does_not_use_later_rediscovery(tmp_path: Path, history):
    state, root, repo = history
    before = create_cli_scan(state, root, repo)
    after = create_cli_scan(state, root, repo)
    occurrence = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"]["findings"][
        0
    ]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        occurrence,
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Synthetic decision.",
    )
    latest = create_cli_scan(state, root, repo)
    assert compare_scan_pair(state, after, latest)["summary"]["reopened"] == 1
    assert compare_scan_pair(state, before, after)["summary"]["reopened"] == 0


def test_semantic_alias_uncertainty_preserves_group(tmp_path: Path, history):
    state, root, repo = history
    scans = [
        create_cli_scan(state, root, repo, identity_anchor=a)
        for a in ["semantic-a", "semantic-b", "semantic-c"]
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in scans
    ]
    save_scan_matches(
        state, scans[0], scans[1], confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    save_scan_matches(
        state,
        scans[0],
        scans[2],
        uncertain=(
            {
                "beforeOccurrenceId": rows[0]["occurrenceId"],
                "afterOccurrenceId": rows[2]["occurrenceId"],
                "reason": "Synthetic uncertain recurrence.",
            },
        ),
    )
    listed = run_workbench(state, "list-global-findings")["findings"]
    assert len(listed) == 2
    assert {r["findingId"] for r in listed} & {rows[0]["findingId"], rows[1]["findingId"]}
    create_cli_scan(state, root, repo, finding=False)
    assert run_workbench(state, "list-global-findings")["findings"] == []


def test_clean_diff_does_not_resolve_unchanged_source(tmp_path: Path, history):
    state, root, repo = history
    repo.rmdir()
    initialize_git_repository(repo)
    (repo / "src").mkdir()
    (repo / "src" / "extract.py").write_text("synthetic archive extraction\n")
    subprocess.run(["git", "-C", str(repo), "add", "src"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "Synthetic source"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    previous = create_cli_scan(state, root, repo, target_revision=base)
    (repo / "README.md").write_text("Unrelated documentation change\n")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "Synthetic documentation change"], check=True
    )
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    scan = create_cli_scan(
        state,
        root,
        repo,
        complete=False,
        target={"kind": "refs", "paths": [], "base": base, "head": head},
    )
    directory = Path(scan["scanDir"])
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        snapshot = connection.execute(
            "SELECT target_snapshot_digest FROM scans WHERE id=?", (scan["scanId"],)
        ).fetchone()[0]
    write_completed_contract(
        directory,
        scan["scanId"],
        repo,
        target_kind="git_diff",
        target_revision=head,
        diff_base_revision=base,
        diff_head_revision=head,
        snapshot_digest=snapshot,
        coverage_mode="branch_diff",
        inventory_strategy="diff",
    )
    findings = json.loads((directory / "findings.json").read_text())
    findings["findings"] = []
    (directory / "findings.json").write_text(json.dumps(findings))
    subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
    run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
    assert [row["scanId"] for row in run_workbench(state, "list-global-findings")["findings"]] == [
        previous["scanId"]
    ]
    assert run_workbench(state, "list-repositories")["repositories"][0]["openFindingsCount"] == 1
    create_cli_scan(state, root, repo, finding=False, target_revision=head)
    assert run_workbench(state, "list-global-findings")["findings"] == []


@pytest.mark.parametrize("matched", [False, True])
def test_owned_remediation_finishes_after_match_closure(tmp_path: Path, history, matched: bool):
    state, root, repo = history
    before = create_cli_scan(state, root, repo, identity_anchor="older-source")
    before_occurrence = run_workbench(state, "get-scan", "--scan-id", before["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        before_occurrence,
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic older decision.",
    )
    after = create_cli_scan(state, root, repo, identity_anchor="newer-source")
    after_occurrence = run_workbench(state, "get-scan", "--scan-id", after["scanId"])["scan"][
        "findings"
    ][0]["occurrenceId"]
    request, token = str(uuid.uuid4()), str(uuid.uuid4())
    run_workbench(
        state,
        "request-finding-remediation",
        "--occurrence-id",
        after_occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
    )
    if matched:
        save_scan_matches(
            state, before, after, confirmed_match(before_occurrence, after_occurrence)
        )
    update = [
        "set-finding-remediation",
        "--occurrence-id",
        after_occurrence,
        "--request-id",
        request,
        "--action-token",
        token,
        "--expected-version",
        "1",
        "--state",
        "failed",
        "--summary",
        "Synthetic generation failure.",
    ]
    wrong = update.copy()
    wrong[wrong.index(token)] = str(uuid.uuid4())
    rejected = run_workbench(state, *wrong, check=False)
    assert rejected["returncode"] != 0
    assert "different action token" in rejected["stderr"]
    outcome = run_workbench(state, *update)
    row = next(r for r in outcome["scan"]["findings"] if r["occurrenceId"] == after_occurrence)
    assert row["remediationState"]["state"] == "failed"


@pytest.mark.parametrize("linked", [False, True])
def test_target_uncertainty_uses_confirmed_linked_history(tmp_path: Path, linked: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    sibling = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(sibling)],
        check=True,
    )
    scans = [
        create_cli_scan(
            state, root, repository, identity_anchor="semantic-a", target_revision=revision
        ),
        create_cli_scan(
            state,
            root,
            sibling if linked else repository,
            identity_anchor="semantic-b",
            target_revision=revision,
        ),
        create_cli_scan(
            state, root, repository, identity_anchor="semantic-c", target_revision=revision
        ),
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    save_scan_matches(
        state, scans[0], scans[1], confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    save_scan_matches(
        state,
        scans[1],
        scans[2],
        uncertain=(
            {
                "beforeOccurrenceId": rows[1]["occurrenceId"],
                "afterOccurrenceId": rows[2]["occurrenceId"],
                "reason": "Synthetic uncertain recurrence.",
            },
        ),
    )
    with sqlite3.connect(state / "workbench.sqlite3") as connection:
        target = connection.execute(
            "SELECT target_id FROM scans WHERE id=?", (scans[0]["scanId"],)
        ).fetchone()[0]
    unfiltered = run_workbench(state, "list-global-findings")["findings"]
    assert {r["findingId"] for r in unfiltered} & {rows[0]["findingId"], rows[1]["findingId"]}
    filtered = run_workbench(state, "list-global-findings", "--target-id", target)["findings"]
    assert {r["findingId"] for r in filtered} & {rows[0]["findingId"], rows[1]["findingId"]}
    assert len(filtered) == 2


@pytest.mark.parametrize("inherited", [False, True])
def test_reopened_comparison_reads_inherited_previous_closure(tmp_path: Path, inherited: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    sibling = tmp_path / "linked-worktree"
    subprocess.run(
        ["git", "-C", str(repository), "worktree", "add", "-q", "--detach", str(sibling)],
        check=True,
    )
    before = create_cli_scan(
        state, root, repository, identity_anchor="semantic-a", target_revision=revision
    )
    middle = create_cli_scan(
        state, root, sibling, identity_anchor="semantic-b", target_revision=revision
    )
    rows = [
        run_workbench(state, "get-scan", "--scan-id", s["scanId"])["scan"]["findings"][0]
        for s in [before, middle]
    ]
    run_workbench(
        state,
        "set-finding-triage",
        "--occurrence-id",
        rows[0 if inherited else 1]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "already_fixed",
        "--note",
        "Synthetic dismissal.",
    )
    save_scan_matches(
        state, before, middle, confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    later = create_cli_scan(
        state, root, sibling, identity_anchor="semantic-b", target_revision=revision
    )
    comparison = compare_scan_pair(state, middle, later)
    assert comparison["summary"]["reopened"] == 1


@pytest.mark.parametrize("repeat", [False, True])
def test_repeated_inherited_action_keeps_ledger_order(tmp_path: Path, repeat: bool):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    revision = initialize_git_repository(repository)
    scans = [
        create_cli_scan(state, root, repository, identity_anchor=anchor, target_revision=revision)
        for anchor in ["semantic-a", "semantic-b", "semantic-c", "independent-source"]
    ]
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in scans
    ]
    close = [
        "set-finding-triage",
        "--occurrence-id",
        rows[0]["occurrenceId"],
        "--status",
        "closed",
        "--close-reason",
        "wont_fix",
        "--note",
        "Synthetic dismissal.",
    ]
    run_workbench(state, *close)
    for index in [1, 2]:
        save_scan_matches(
            state,
            scans[0],
            scans[index],
            confirmed_match(rows[0]["occurrenceId"], rows[index]["occurrenceId"]),
        )
    if repeat:
        run_workbench(state, *close)
    run_workbench(
        state, "set-finding-triage", "--occurrence-id", rows[3]["occurrenceId"], "--status", "open"
    )
    save_scan_matches(
        state, scans[2], scans[3], confirmed_match(rows[2]["occurrenceId"], rows[3]["occurrenceId"])
    )
    detail = run_workbench(state, "get-finding", "--occurrence-id", rows[3]["occurrenceId"])[
        "scan"
    ]["findings"][0]
    assert detail["status"] == "open"


@pytest.mark.parametrize("unrelated_uncertainty", [False, True])
def test_unrelated_uncertainty_does_not_resurrect_resolved_alias(
    tmp_path: Path, unrelated_uncertainty: bool
):
    state, root = tmp_path / "state", tmp_path / "scans"
    repository = tmp_path / "repository"
    initialize_git_repository(repository)
    (repository / "src").mkdir()
    for name in ["a.py", "b.py"]:
        (repository / "src" / name).write_text("Synthetic source.\n")
    subprocess.run(["git", "-C", str(repository), "add", "src"], check=True)
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-qm", "Synthetic finding sources"], check=True
    )
    revision = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()

    def custom_scan(relative_path, anchor, *, paths=None, finding=True):
        scan = create_cli_scan(
            state,
            root,
            repository,
            complete=False,
            identity_anchor=anchor,
            paths=paths,
            target_revision=revision,
        )
        directory = Path(scan["scanDir"])
        with sqlite3.connect(state / "workbench.sqlite3") as connection:
            snapshot = connection.execute(
                "SELECT target_snapshot_digest FROM scans WHERE id=?", (scan["scanId"],)
            ).fetchone()[0]
        write_completed_contract(
            directory,
            scan["scanId"],
            repository,
            identity_anchor=anchor,
            relative_path=relative_path,
            include_paths=paths,
            coverage_mode="scoped_path" if paths else "repository",
            inventory_strategy="scoped_path" if paths else "repository",
            target_kind="git_revision",
            target_revision=revision,
            snapshot_digest=snapshot,
        )
        if not finding:
            artifact = directory / "findings.json"
            value = json.loads(artifact.read_text())
            value["findings"] = []
            artifact.write_text(json.dumps(value))
        subprocess.run([sys.executable, str(FINALIZER), "--scan-dir", str(directory)], check=True)
        run_workbench(state, "complete-scan", "--scan-id", scan["scanId"])
        return scan

    before = custom_scan("src/a.py", "semantic-a")
    after = custom_scan("src/b.py", "semantic-b")
    rows = [
        run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
        for scan in [before, after]
    ]
    save_scan_matches(
        state, before, after, confirmed_match(rows[0]["occurrenceId"], rows[1]["occurrenceId"])
    )
    custom_scan("src/b.py", "clean-scope", paths=["src/b.py"], finding=False)
    target = before["targetId"]
    assert run_workbench(state, "list-global-findings", "--target-id", target)["findings"] == []
    other = tmp_path / "unrelated-repository"
    other.mkdir()
    scans = [
        create_cli_scan(state, root, other, identity_anchor=anchor)
        for anchor in ["unrelated-a", "unrelated-b"]
    ]
    if unrelated_uncertainty:
        rows = [
            run_workbench(state, "get-scan", "--scan-id", scan["scanId"])["scan"]["findings"][0]
            for scan in scans
        ]
        save_scan_matches(
            state,
            scans[0],
            scans[1],
            uncertain=(
                {
                    "beforeOccurrenceId": rows[0]["occurrenceId"],
                    "afterOccurrenceId": rows[1]["occurrenceId"],
                    "reason": "Synthetic unrelated uncertainty.",
                },
            ),
        )
    findings = run_workbench(state, "list-global-findings", "--target-id", target)["findings"]
    assert findings == []
