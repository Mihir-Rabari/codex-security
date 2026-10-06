from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

TIMESTAMP = "2026-01-01T00:00:00Z"


def finding(index: int) -> dict:
    source = Path(__file__).resolve().parents[1] / "examples/completed-scan/findings.json"
    result = json.loads(source.read_text())["findings"][0]
    result["findingId"] = f"finding-{index}"
    result["fingerprints"]["primary"] = f"fingerprint-{index}"
    return result


def request(api, connection, action, **values):
    return api["local_dedupe"](
        connection,
        {
            "action": action,
            "space": "synthetic-v1",
            "model": "synthetic",
            "dimensions": 2,
            **values,
        },
        TIMESTAMP,
    )


def prepare(api, connection, findings, **values):
    repository_path = str(Path(__file__).resolve().parent)
    with connection:
        target_id = api["ensure_security_target"](connection, repository_path)
    return request(
        api,
        connection,
        "prepare",
        findings=findings,
        anchorRepositoryId=target_id,
        repositoryId=target_id,
        repositoryPath=repository_path,
        **values,
    )


def entry(prepared, **values):
    return {
        "findingId": prepared["finding"]["findingId"],
        "cacheKey": prepared["cacheKey"],
        "embedding": {"model": "synthetic", "vector": [1, 0]},
        **values,
    }


def test_cache_reuse_and_legacy_writes_clear_certification(workbench_api, workbench_db):
    first = prepare(workbench_api, workbench_db, [finding(1)])["entries"][0]
    assert first["needsEmbedding"]
    assert request(workbench_api, workbench_db, "embed", entries=[entry(first)]) == {}
    assert not prepare(workbench_api, workbench_db, [finding(1)])["entries"][0]["needsEmbedding"]
    assert prepare(workbench_api, workbench_db, [finding(1)], space="synthetic-v2")["entries"][0][
        "needsEmbedding"
    ]
    workbench_api["store_findings"](
        workbench_db,
        [{"finding": finding(1), "embedding": {"model": "synthetic", "vector": [0, 1]}}],
        TIMESTAMP,
    )
    assert prepare(workbench_api, workbench_db, [finding(1)])["entries"][0]["needsEmbedding"]


@pytest.mark.parametrize("failure", ["stale", "dimensions", "zero", "nonfinite"])
def test_embedding_batch_rolls_back_on_invalid_or_stale_input(workbench_api, workbench_db, failure):
    entries = prepare(workbench_api, workbench_db, [finding(1), finding(2)])["entries"]
    second = entry(entries[1])
    if failure == "stale":
        second["cacheKey"] = "old-input"
    else:
        second["embedding"]["vector"] = {
            "dimensions": [1],
            "zero": [0, 0],
            "nonfinite": [float("nan"), 0],
        }[failure]
    result = request(workbench_api, workbench_db, "embed", entries=[entry(entries[0]), second])
    assert result == {"error": "finding_changed" if failure == "stale" else "embedding_failed"}
    assert workbench_db.execute("SELECT COUNT(*) FROM finding_embeddings").fetchone()[0] == 0


def test_preparation_conflict_rolls_back_new_findings(workbench_api, workbench_db):
    prepare(workbench_api, workbench_db, [finding(1)])
    conflicting = finding(1)
    conflicting["identity"]["anchor"] = "different-anchor"
    assert prepare(workbench_api, workbench_db, [finding(2), conflicting]) == {
        "error": "finding_conflict"
    }
    assert workbench_db.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1


def test_embedding_cache_migration_preserves_existing_vectors(workbench_api, tmp_path):
    with closing(sqlite3.connect(tmp_path / "legacy.sqlite3")) as connection:
        connection.row_factory = sqlite3.Row
        workbench_api["apply_schema_migrations"](
            connection,
            tuple(m for m in workbench_api["MIGRATIONS"] if m[0] < 42),
            lambda: TIMESTAMP,
            workbench_api["backfill_security_targets"],
        )
        with connection:
            connection.execute(
                "INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, created_at, updated_at) "
                "VALUES ('legacy', 'legacy', 'rule', 'anchor', ?, ?)",
                (TIMESTAMP, TIMESTAMP),
            )
            connection.execute(
                "INSERT INTO finding_embeddings VALUES ('legacy', 'synthetic', '[1, 0]')"
            )
        workbench_api["apply_migrations"](connection)
        row = connection.execute("SELECT * FROM finding_embeddings").fetchone()
        assert dict(row) == {
            "finding_id": "legacy",
            "model": "synthetic",
            "vector_json": "[1, 0]",
            "cache_key": None,
        }
