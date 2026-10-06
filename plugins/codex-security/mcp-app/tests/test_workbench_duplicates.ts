import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { after, test, type TestContext } from "node:test";
import { importSource } from "./import-module.ts";
import { createTemporaryDirectories } from "./support/temporary-directories.ts";
import { stringifyJson } from "../src/helpers/json.ts";
import type * as Duplicates from "../src/workbench/duplicates.ts";
import type * as Migrations from "../src/workbench/migrations.ts";

const { findPotentialDuplicates, storeDedupeGroups, listDedupeGroups } =
  (await importSource("src/workbench/duplicates.ts")) as typeof Duplicates;
const { applyMigrations } = (await importSource(
  "src/workbench/migrations.ts",
)) as typeof Migrations;

const temporary = createTemporaryDirectories(true);
after(() => temporary.cleanup());

function open(t: TestContext, path = ":memory:") {
  const database = new DatabaseSync(path);
  t.after(() => database.close());
  database.exec("PRAGMA foreign_keys = ON");
  applyMigrations(database);
  return database;
}

function finding(
  database: DatabaseSync,
  index: number | string,
  vector = [1, 0],
  repository = "synthetic-repository",
  model = "synthetic-model",
) {
  const findingId =
    typeof index === "number"
      ? `csf_${String(index).padStart(24, "0")}`
      : index;
  const document = { findingId, extensions: { opaqueId: 9007199254740993n } };
  database
    .prepare(
      `
    INSERT INTO findings
      (id, fingerprint, rule_id, identity_anchor, details_json, created_at, updated_at)
    VALUES (?, ?, 'synthetic-rule', ?, ?, 'created', 'updated')
  `,
    )
    .run(findingId, findingId, findingId, stringifyJson(document));
  database
    .prepare("INSERT INTO finding_embeddings VALUES (?, ?, ?)")
    .run(findingId, model, JSON.stringify(vector));
  database
    .prepare("INSERT INTO finding_repositories VALUES (?, ?)")
    .run(repository, findingId);
  return document;
}

test("duplicate retrieval filters before scoring and loads only the stable top 50 documents", (t) => {
  const database = open(t);
  const entries = Array.from({ length: 62 }, (_, index) =>
    finding(database, index + 1),
  );
  // Out-of-scope vectors and documents beyond the top 50 need not be readable.
  const foreign = finding(database, 100, [0, 0], "another-repository");
  finding(database, 101, [0, 0], "synthetic-repository", "another-model");
  finding(database, 102, [1, 0, 0]);
  database.exec("DROP TRIGGER invalidate_finding_embedding");
  for (const entry of entries.slice(51))
    database
      .prepare("UPDATE findings SET details_json = 'invalid JSON' WHERE id = ?")
      .run(entry.findingId);
  assert.deepEqual(
    findPotentialDuplicates(
      database,
      entries[0].findingId,
      "synthetic-repository",
    ),
    {
      finding: entries[0],
      potentialDuplicates: entries.slice(1, 51),
    },
  );
  assert.deepEqual(
    findPotentialDuplicates(
      database,
      foreign.findingId,
      "synthetic-repository",
    ),
    {
      error: "finding_not_indexed",
    },
  );
  assert.deepEqual(findPotentialDuplicates(database, entries[0].findingId), {
    error: "embedding_failed",
  });
});

test("cosine scoring handles large and scaled vectors without argument spreading", (t) => {
  const database = open(t);
  const vector = Array<number>(150_000).fill(0);
  vector[0] = 1e-300;
  const anchor = finding(database, 1, vector);
  vector[0] = 1e300;
  const candidate = finding(database, 2, vector);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    finding: anchor,
    potentialDuplicates: [candidate],
  });
  const update = database.prepare(
    "UPDATE finding_embeddings SET vector_json = ? WHERE finding_id = ?",
  );
  update.run(JSON.stringify([Number.MIN_VALUE, 0]), anchor.findingId);
  update.run(JSON.stringify([Number.MAX_VALUE, 0]), candidate.findingId);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    finding: anchor,
    potentialDuplicates: [candidate],
  });
  update.run("[0,0]", anchor.findingId);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    error: "embedding_failed",
  });
});

test("cosine scoring includes the threshold and excludes scores below it", (t) => {
  const database = open(t);
  const anchor = finding(database, 1, [7, 0]);
  const boundary = finding(database, 2, [0.55, Math.sqrt(1 - 0.55 ** 2)]);
  finding(database, 3, [0.54, Math.sqrt(1 - 0.54 ** 2)]);
  assert.deepEqual(findPotentialDuplicates(database, anchor.findingId), {
    finding: anchor,
    potentialDuplicates: [boundary],
  });
});

test("dedupe retries retain durable hashes, first timestamps, and overlapping groups", (t) => {
  const database = open(t);
  const a = finding(database, 1).findingId;
  const b = finding(database, 2).findingId;
  const c = finding(database, 3).findingId;
  const original = storeDedupeGroups(
    database,
    [
      [b, a],
      [b, c],
    ],
    "first",
  );
  assert.ok("groups" in original);
  assert.equal(
    original.groups[0].groupId,
    "fdg_e1bc8f7052a79c844323824d7f9e0707373dd9ed4391c477aa9694702baae619",
  );
  assert.deepEqual(
    storeDedupeGroups(
      database,
      [
        [a, b, a],
        [c, b],
      ],
      "later",
    ),
    original,
  );
  assert.deepEqual(
    listDedupeGroups(database, b).groups,
    [...original.groups].sort((left, right) =>
      left.groupId.localeCompare(right.groupId),
    ),
  );
  assert.equal(
    database.prepare("SELECT count(*) AS count FROM finding_embeddings").get()!
      .count,
    3,
  );
});

test("a missing member rolls back the entire dedupe batch and leaves the connection usable", (t) => {
  const database = open(t);
  const a = finding(database, 1).findingId;
  const b = finding(database, 2).findingId;
  assert.deepEqual(
    storeDedupeGroups(
      database,
      [
        [a, b],
        [b, "missing"],
      ],
      "created",
    ),
    {
      error: "finding_conflict",
    },
  );
  assert.deepEqual(listDedupeGroups(database, b), { groups: [] });
  assert.equal(
    database
      .prepare("SELECT count(*) AS count FROM finding_dedupe_groups")
      .get()!.count,
    0,
  );
  assert.ok("groups" in storeDedupeGroups(database, [[a, b]], "retry"));
});

test("Python and Node retries preserve Unicode group identities and timestamps", async (t) => {
  const path = join(
    await temporary.create("workbench-duplicates-"),
    "workbench.sqlite3",
  );
  const database = open(t, path);
  const ids = [
    "finding-λ",
    "finding-\u{10000}",
    "finding-\ue000",
    "finding-\u007f",
  ];
  for (const id of ids) finding(database, id);
  const original = JSON.parse(
    execFileSync(
      process.env.PYTHON ?? "python",
      [
        "-I",
        "-c",
        `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_findings import store_dedupe_groups
with sqlite3.connect(sys.argv[2]) as db:
    db.row_factory = sqlite3.Row
    print(json.dumps(store_dedupe_groups(db, json.load(sys.stdin), "first")))`,
        fileURLToPath(new URL("../../scripts/", import.meta.url)),
        path,
      ],
      { input: JSON.stringify([ids]), encoding: "utf8" },
    ),
  );
  assert.deepEqual(
    storeDedupeGroups(database, [[...ids].reverse()], "later"),
    original,
  );
  assert.deepEqual(listDedupeGroups(database, ids[0]), original);
  assert.equal(
    database
      .prepare("SELECT count(*) AS count FROM finding_dedupe_groups")
      .get()!.count,
    1,
  );
});

test("duplicate retrieval and group listing preserve NUL-bearing IDs and model scope", (t) => {
  const database = open(t);
  const anchor = finding(
    database,
    "finding\0anchor",
    [1, 0],
    "repository",
    "model\0suffix",
  );
  const duplicate = finding(
    database,
    "finding\0duplicate",
    [1, 0],
    "repository",
    "model\0suffix",
  );
  finding(database, "different-model", [1, 0], "repository", "model");
  assert.deepEqual(
    findPotentialDuplicates(database, anchor.findingId, "repository"),
    {
      finding: anchor,
      potentialDuplicates: [duplicate],
    },
  );
  const stored = storeDedupeGroups(
    database,
    [[duplicate.findingId, anchor.findingId]],
    "created",
  );
  assert.deepEqual(listDedupeGroups(database, duplicate.findingId), stored);
});
