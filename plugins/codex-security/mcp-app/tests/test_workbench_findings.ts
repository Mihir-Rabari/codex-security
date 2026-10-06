import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import type * as Findings from "../src/workbench/findings.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { storeFindings, listStoredFindings } = (await importSource(
  "src/workbench/findings.ts",
)) as typeof Findings;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;
const { stringifyJson } = await importSource("src/helpers/json.ts");
const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function open(t: TestContext, path = ":memory:") {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  applyMigrations(database);
  return database;
}

function entry(id: string): Findings.EmbeddedFinding {
  return {
    finding: {
      findingId: id,
      fingerprints: { primary: `fingerprint-${id}` },
      ruleId: "synthetic-rule",
      identity: { anchor: "synthetic-anchor" },
      title: "Synthetic finding λ",
      evidence: { message: "complete\0diagnostic", lines: [1, 2] },
    },
    embedding: { model: "synthetic-model", vector: [1, 0] },
  };
}

test("import batches preserve identity, repository memberships and stable pages", (t) => {
  const database = open(t);
  const [a, b, c] = ["a", "b", "c"].map(entry);
  assert.deepEqual(storeFindings(database, [b, a], "created", "repository-a"), {
    findingIds: ["b", "a"],
  });
  storeFindings(database, [a], "updated", "repository-b");
  assert.deepEqual(listStoredFindings(database, { limit: 1, offset: 0 }), {
    findings: [a.finding],
    limit: 1,
    offset: 0,
    total: 2,
    nextOffset: 1,
  });
  assert.deepEqual(listStoredFindings(database, { limit: 1, offset: 1 }), {
    findings: [b.finding],
    limit: 1,
    offset: 1,
    total: 2,
    nextOffset: null,
  });
  const conflict = structuredClone(a);
  conflict.finding.identity.anchor = "different";
  assert.deepEqual(
    storeFindings(database, [c, conflict], "later", "repository-c"),
    {
      error: "finding_conflict",
    },
  );
  assert.deepEqual(
    listStoredFindings(database, { limit: 10, offset: 0 }).findings,
    [a.finding, b.finding],
  );
  assert.deepEqual(
    database
      .prepare(
        "SELECT repository_id FROM finding_repositories WHERE finding_id = 'a' ORDER BY repository_id",
      )
      .all()
      .map((row) => row.repository_id),
    ["repository-a", "repository-b"],
  );
  assert.equal(
    database.prepare("SELECT COUNT(*) AS total FROM finding_embeddings").get()!
      .total,
    2,
  );
  const duplicate = entry("duplicate");
  duplicate.finding.fingerprints = a.finding.fingerprints;
  assert.deepEqual(storeFindings(database, [c, duplicate], "later"), {
    error: "finding_conflict",
  });
  assert.equal(listStoredFindings(database, { limit: 10, offset: 0 }).total, 2);
});

test("Python and Node keep unchanged stored JSON and invalidate embeddings only for changed findings", async (t) => {
  const directory = await temporary.create("workbench-findings-");
  const path = join(directory, "workbench.sqlite3");
  const database = open(t, path);
  const item = entry("finding");
  item.finding.extensions = { opaqueId: 9007199254740993n };
  item.finding.severity = { score: 10 };
  storeFindings(database, [item], "initial");
  const details = () =>
    database
      .prepare("SELECT details_json FROM findings WHERE id = 'finding'")
      .get()!.details_json;
  const embeddingCount = () =>
    database.prepare("SELECT COUNT(*) AS total FROM finding_embeddings").get()!
      .total;
  const scripts = fileURLToPath(new URL("../../scripts/", import.meta.url));
  const pythonUpsert = (finding: Findings.Finding | string) =>
    execFileSync(
      process.env.PYTHON ?? "python",
      [
        "-I",
        "-c",
        `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_finding_index import upsert_finding
with sqlite3.connect(sys.argv[2]) as db:
    db.row_factory = sqlite3.Row
    upsert_finding(db, json.load(sys.stdin), "python")`,
        scripts,
        path,
      ],
      {
        input: typeof finding === "string" ? finding : stringifyJson(finding),
        encoding: "utf8",
      },
    );
  const original = details();
  assert.match(String(original), /9007199254740993/u);
  pythonUpsert(
    stringifyJson(
      Object.fromEntries(Object.entries(item.finding).reverse()),
    ).replace('"score": 10', '"score": 10.0'),
  );
  assert.equal(details(), original);
  assert.equal(embeddingCount(), 1);
  const changed = { ...item.finding, title: "Updated finding" };
  pythonUpsert(changed);
  assert.equal(embeddingCount(), 0);
  const pythonText = details();
  storeFindings(database, [{ ...item, finding: changed }], "node");
  assert.equal(details(), pythonText);
  assert.equal(embeddingCount(), 1);
  assert.deepEqual(
    listStoredFindings(database, { limit: 10, offset: 0 }).findings,
    [changed],
  );
  for (const [before, after] of [
    [true, 1],
    [1, true],
  ]) {
    storeFindings(
      database,
      [{ ...item, finding: { ...changed, extensions: { foo: before } } }],
      "node",
    );
    pythonUpsert({ ...changed, extensions: { foo: after } });
    assert.equal(JSON.parse(String(details())).extensions.foo, after);
    assert.equal(embeddingCount(), 0);
  }
});
