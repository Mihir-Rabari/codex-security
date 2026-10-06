import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { parseJson } from "../helpers/json";
import { transaction } from "./findings";

export interface DedupeGroup {
  groupId: string;
  findingIds: string[];
  createdAt: string;
}

function normalizedVector(vector: number[]): number[] {
  let maximum = 0;
  for (const value of vector) {
    if (!Number.isFinite(value))
      throw new RangeError("A stored embedding cannot be compared.");
    maximum = Math.max(maximum, Math.abs(value));
  }
  // Binary scaling is exact, avoiding extra rounding at the cosine cutoff.
  const scale = 2 ** Math.min(1023, Math.floor(Math.log2(maximum)));
  let squares = 0;
  for (const value of vector) squares += (value / scale) ** 2;
  const norm = scale * Math.sqrt(squares);
  if (norm === 0 || !Number.isFinite(norm))
    throw new RangeError("A stored embedding cannot be compared.");
  return vector.map((value) => value / norm);
}

export function findPotentialDuplicates(
  database: DatabaseSync,
  findingId: string,
  repositoryId?: string,
) {
  return transaction(database, "BEGIN", () => {
    const source =
      repositoryId === undefined
        ? "finding_embeddings AS embeddings"
        : "finding_repositories AS repositories JOIN finding_embeddings AS embeddings ON embeddings.finding_id = repositories.finding_id";
    const predicate =
      repositoryId === undefined ? "" : "repositories.repository_id = ? AND ";
    const scope = repositoryId === undefined ? [] : [repositoryId];
    const anchor = database
      .prepare(
        `SELECT embeddings.model, embeddings.vector_json FROM ${source}
       WHERE ${predicate}embeddings.finding_id = ?`,
      )
      .get(...scope, findingId);
    if (!anchor) return { error: "finding_not_indexed" as const };

    const rows = database.prepare(
      `SELECT embeddings.finding_id, embeddings.vector_json FROM ${source}
       JOIN findings ON findings.id = embeddings.finding_id
       WHERE ${predicate}embeddings.model = ? AND embeddings.finding_id != ?
       ORDER BY findings.created_at, findings.id`,
    );
    const ranked: { id: string; similarity: number }[] = [];
    try {
      const vector = normalizedVector(JSON.parse(anchor.vector_json as string));
      for (const row of rows.iterate(...scope, anchor.model, findingId)) {
        const candidate: number[] = JSON.parse(row.vector_json as string);
        if (candidate.length !== vector.length) continue;
        const other = normalizedVector(candidate);
        const similarity = vector.reduce(
          (total, value, index) => total + value * other[index],
          0,
        );
        if (similarity >= 0.55)
          ranked.push({ id: row.finding_id as string, similarity });
      }
    } catch (error) {
      if (error instanceof SyntaxError || error instanceof RangeError)
        return { error: "embedding_failed" as const };
      throw error;
    }
    // Stable sorting keeps insertion-time / finding-ID order for ties.
    ranked.sort((a, b) => b.similarity - a.similarity);
    const selected = [findingId, ...ranked.slice(0, 50).map(({ id }) => id)];
    const documents = new Map(
      database
        .prepare(
          `SELECT id, details_json FROM findings WHERE id IN (${selected.map(() => "?").join(",")})`,
        )
        .all(...selected)
        .map((row) => [
          row.id as string,
          parseJson(row.details_json as string),
        ]),
    );
    return {
      finding: documents.get(findingId),
      potentialDuplicates: selected.slice(1).map((id) => documents.get(id)),
    };
  });
}

export function storeDedupeGroups(
  database: DatabaseSync,
  groups: readonly (readonly string[])[],
  timestamp: string,
) {
  try {
    return transaction(database, "BEGIN IMMEDIATE", () => {
      const insertGroup = database.prepare(
        "INSERT INTO finding_dedupe_groups (id, created_at) VALUES (?, ?) ON CONFLICT(id) DO NOTHING",
      );
      const insertMember = database.prepare(
        "INSERT INTO finding_dedupe_group_members (group_id, finding_id) VALUES (?, ?) ON CONFLICT(group_id, finding_id) DO NOTHING",
      );
      const created = database.prepare(
        "SELECT created_at FROM finding_dedupe_groups WHERE id = ?",
      );
      const stored = new Map<string, DedupeGroup>();
      for (const group of groups) {
        const findingIds = [...new Set(group)].sort();
        // Finding IDs are ASCII; this encoding preserves existing group identities.
        const groupId =
          "fdg_" +
          createHash("sha256").update(JSON.stringify(findingIds)).digest("hex");
        insertGroup.run(groupId, timestamp);
        for (const findingId of findingIds)
          insertMember.run(groupId, findingId);
        stored.set(groupId, {
          groupId,
          findingIds,
          createdAt: created.get(groupId)!.created_at as string,
        });
      }
      return { groups: [...stored.values()] };
    });
  } catch (error) {
    if (
      error instanceof Error &&
      "errcode" in error &&
      (Number(error.errcode) & 0xff) === 19
    )
      return { error: "finding_conflict" as const };
    throw error;
  }
}

export function listDedupeGroups(database: DatabaseSync, findingId: string) {
  const groups = new Map<string, DedupeGroup>();
  const rows = database.prepare(`
    SELECT groups.id, groups.created_at, members.finding_id
    FROM finding_dedupe_group_members AS matched
    JOIN finding_dedupe_groups AS groups ON groups.id = matched.group_id
    JOIN finding_dedupe_group_members AS members ON members.group_id = groups.id
    WHERE matched.finding_id = ?
    ORDER BY groups.created_at, groups.id, members.finding_id
  `);
  for (const row of rows.iterate(findingId)) {
    const id = row.id as string;
    if (!groups.has(id))
      groups.set(id, {
        groupId: id,
        findingIds: [],
        createdAt: row.created_at as string,
      });
    groups.get(id)!.findingIds.push(row.finding_id as string);
  }
  return { groups: [...groups.values()] };
}
