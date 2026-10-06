import type { DatabaseSync } from "node:sqlite";
import { isDeepStrictEqual } from "node:util";
import { parseJson, stringifyJson } from "../helpers/json";

export interface Finding {
  findingId: string;
  fingerprints: { primary: string };
  ruleId: string;
  identity: { anchor: string; instance?: string };
  [key: string]: unknown;
}

export interface EmbeddedFinding {
  finding: Finding;
  embedding: { model: string; vector: number[] };
}

export function transaction<T>(
  database: DatabaseSync,
  begin: "BEGIN" | "BEGIN IMMEDIATE",
  action: () => T,
): T {
  database.exec(begin);
  try {
    const result = action();
    database.exec("COMMIT");
    return result;
  } catch (error) {
    try {
      database.exec("ROLLBACK");
    } catch {
      // SQLite can roll back automatically after a storage failure.
    }
    throw error;
  }
}

class FindingConflict extends Error {}

export function storeFindings(
  database: DatabaseSync,
  entries: readonly EmbeddedFinding[],
  timestamp: string,
  repositoryId?: string,
): { findingIds: string[] } | { error: "finding_conflict" } {
  try {
    return transaction(database, "BEGIN IMMEDIATE", () => {
      const existing = database.prepare(
        `SELECT fingerprint, rule_id, identity_anchor, identity_instance, details_json
        FROM findings WHERE id = ?`,
      );
      const upsert = database.prepare(
        `INSERT INTO findings (id, fingerprint, rule_id, identity_anchor, identity_instance,
          details_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET fingerprint = excluded.fingerprint,
          rule_id = excluded.rule_id, identity_anchor = excluded.identity_anchor,
          identity_instance = excluded.identity_instance, details_json = excluded.details_json,
          updated_at = excluded.updated_at`,
      );
      const embedding = database.prepare(
        `INSERT INTO finding_embeddings (finding_id, model, vector_json) VALUES (?, ?, ?)
        ON CONFLICT(finding_id) DO UPDATE SET model = excluded.model, vector_json = excluded.vector_json`,
      );
      const repository = database.prepare(
        "INSERT OR IGNORE INTO finding_repositories (repository_id, finding_id) VALUES (?, ?)",
      );
      for (const entry of entries) {
        const finding = entry.finding;
        const current = existing.get(finding.findingId);
        if (
          current &&
          (current.fingerprint !== finding.fingerprints.primary ||
            current.rule_id !== finding.ruleId ||
            current.identity_anchor !== finding.identity.anchor ||
            current.identity_instance !== (finding.identity.instance ?? null))
        ) {
          throw new FindingConflict(
            "The stored finding identity cannot be replaced.",
          );
        }
        // Keep unchanged JSON text so mixed-runtime writes do not invalidate embeddings.
        const details =
          typeof current?.details_json === "string" &&
          isDeepStrictEqual(parseJson(current.details_json), finding)
            ? current.details_json
            : stringifyJson(finding, 0);
        upsert.run(
          finding.findingId,
          finding.fingerprints.primary,
          finding.ruleId,
          finding.identity.anchor,
          finding.identity.instance ?? null,
          details,
          timestamp,
          timestamp,
        );
        if (repositoryId !== undefined)
          repository.run(repositoryId, finding.findingId);
        embedding.run(
          finding.findingId,
          entry.embedding.model,
          stringifyJson(entry.embedding.vector, 0),
        );
      }
      return { findingIds: entries.map(({ finding }) => finding.findingId) };
    });
  } catch (error) {
    if (
      error instanceof FindingConflict ||
      (error instanceof Error &&
        "errcode" in error &&
        (Number(error.errcode) & 0xff) === 19)
    ) {
      return { error: "finding_conflict" };
    }
    throw error;
  }
}

export function listStoredFindings(
  database: DatabaseSync,
  { limit, offset }: { limit: number; offset: number },
) {
  return transaction(database, "BEGIN", () => {
    const total = Number(
      database
        .prepare(
          "SELECT COUNT(*) AS total FROM findings WHERE details_json IS NOT NULL",
        )
        .get()!.total,
    );
    const rows = database
      .prepare(
        `SELECT details_json FROM findings WHERE details_json IS NOT NULL
        ORDER BY created_at, id LIMIT ? OFFSET ?`,
      )
      .all(limit, offset);
    const nextOffset = offset + rows.length;
    return {
      findings: rows.map(
        (row) => parseJson(String(row.details_json)) as Finding,
      ),
      limit,
      offset,
      total,
      nextOffset: nextOffset < total ? nextOffset : null,
    };
  });
}
