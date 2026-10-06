import type { DatabaseSync, SQLOutputValue } from "node:sqlite";
import { parseJson } from "../helpers/json";
import { listDedupeGroups } from "./duplicates";
import { transaction } from "./findings";

const records = {
  findings: `
    SELECT findings.id, json_extract(details_json, '$.title') AS title,
      COALESCE(repositories.ids, '[]') AS repositoryIds,
      json_extract(details_json, '$.severity.level') AS severity,
      findings.created_at AS createdAt, findings.updated_at AS updatedAt
    FROM findings LEFT JOIN (
      SELECT finding_id, json_group_array(repository_id) AS ids
      FROM finding_repositories GROUP BY finding_id
    ) AS repositories ON repositories.finding_id = findings.id
    WHERE details_json IS NOT NULL`,
  groups: `
    SELECT groups.id, groups.id AS title,
      (SELECT json_group_array(DISTINCT repository_id)
       FROM finding_dedupe_group_members AS members
       JOIN finding_repositories ON finding_repositories.finding_id = members.finding_id
       WHERE members.group_id = groups.id) AS repositoryIds,
      groups.created_at AS createdAt, groups.created_at AS updatedAt,
      (SELECT COUNT(*) FROM finding_dedupe_group_members WHERE group_id = groups.id) AS memberCount
    FROM finding_dedupe_groups AS groups`,
};

const sorts = {
  activity: "updatedAt",
  newest: "createdAt",
  title: "dashboard_lower(title)",
  repository: "dashboard_lower(repository_label(repositoryIds))",
  severity:
    "CASE severity WHEN 'informational' THEN 0 WHEN 'low' THEN 1 " +
    "WHEN 'medium' THEN 2 WHEN 'high' THEN 3 WHEN 'critical' THEN 4 END",
  members: "memberCount",
};

export interface DashboardQuery {
  view: keyof typeof records;
  sort: keyof typeof sorts;
  direction?: "asc" | "desc";
  limit: number;
  offset: number;
  query?: string;
  repository?: string;
  id?: string;
}

function compare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function repositoryIds(value: string): string[] {
  return (JSON.parse(value) as string[]).sort(
    (left, right) =>
      compare(left.toLowerCase(), right.toLowerCase()) || compare(left, right),
  );
}

function item(
  row: Record<string, SQLOutputValue>,
): Record<string, SQLOutputValue | string[]> {
  return { ...row, repositoryIds: repositoryIds(row.repositoryIds as string) };
}

function detail(
  database: DatabaseSync,
  view: DashboardQuery["view"],
  selected: Record<string, SQLOutputValue>,
) {
  const id = selected.id as string;
  return view === "findings"
    ? {
        item: item(selected),
        finding: parseJson(
          database
            .prepare("SELECT details_json FROM findings WHERE id = ?")
            .get(id)!.details_json as string,
        ),
        groups: listDedupeGroups(database, id).groups,
      }
    : {
        item: item(selected),
        group: {
          groupId: id,
          createdAt: selected.createdAt,
          findingIds: database
            .prepare(
              "SELECT finding_id FROM finding_dedupe_group_members WHERE group_id = ? ORDER BY finding_id",
            )
            .all(id)
            .map((row) => row.finding_id),
        },
      };
}

/** Read one snapshot without loading artifacts or modifying stored data. */
export function dashboard(database: DatabaseSync, query: DashboardQuery) {
  database.function("dashboard_lower", { deterministic: true }, (value) =>
    (value as string).toLowerCase(),
  );
  database.function("repository_label", { deterministic: true }, (value) =>
    repositoryIds(value as string).join(", "),
  );
  const clauses: string[] = [];
  const values: string[] = [];
  if (query.query) {
    const columns = ["id", "title", "repositoryIds"];
    clauses.push(
      `(${columns.map((column) => `instr(dashboard_lower(COALESCE(${column}, '')), dashboard_lower(?)) > 0`).join(" OR ")})`,
    );
    values.push(...columns.map(() => query.query!));
  }
  if (query.repository) {
    clauses.push(
      "EXISTS (SELECT 1 FROM json_each(repositoryIds) WHERE value = ?)",
    );
    values.push(query.repository);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
  const direction = { asc: "ASC", desc: "DESC" }[query.direction ?? "desc"];
  let order = `${sorts[query.sort]} ${direction}`;
  if (query.view === "findings" && query.sort === "activity")
    order += `, ${sorts.severity} DESC`;
  order += ", id";
  const source = records[query.view];
  return transaction(database, "BEGIN", () => {
    const repositories = database
      .prepare(
        "SELECT DISTINCT repository_id AS id, repository_id AS label FROM finding_repositories ORDER BY repository_id",
      )
      .all()
      .map((row) => ({ ...row }));
    const total = database
      .prepare(`SELECT COUNT(*) AS count FROM (${source}) ${where}`)
      .get(...values)!.count as number;
    const rows = database
      .prepare(
        `SELECT * FROM (${source}) ${where} ORDER BY ${order} LIMIT ? OFFSET ?`,
      )
      .all(...values, query.limit, query.offset);
    const selected = query.id
      ? database.prepare(`SELECT * FROM (${source}) WHERE id = ?`).get(query.id)
      : undefined;
    const nextOffset = query.offset + rows.length;
    return {
      overview: {
        findings: database
          .prepare(
            "SELECT COUNT(*) AS count FROM findings WHERE details_json IS NOT NULL",
          )
          .get()!.count,
        groups: database
          .prepare("SELECT COUNT(*) AS count FROM finding_dedupe_groups")
          .get()!.count,
      },
      repositories,
      items: rows.map(item),
      total,
      limit: query.limit,
      offset: query.offset,
      nextOffset: nextOffset < total ? nextOffset : null,
      detail: selected ? detail(database, query.view, selected) : null,
    };
  });
}
