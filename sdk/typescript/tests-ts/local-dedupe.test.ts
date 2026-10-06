import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { LocalDeduplication } from "../src/deduplication/local.js";
import {
  deduplicateScanDirectoryInternal,
  deduplicateScanInternal,
} from "../src/deduplication/scan.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
  type FindingEmbedder,
} from "../src/server/embeddings.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { workflowFixture } from "./support/workflow-fixture.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { emptyNeighborhoodReviewer } from "./support/deduplication.js";
import { screeningPairSlot } from "../src/deduplication/deduplication-reviewer.js";
import { rejecting } from "./support/errors.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Finding } from "../src/models.js";

const temporaryDirectories = createTemporaryDirectories();
afterEach(temporaryDirectories.cleanup);
const vector = [1, ...Array<number>(EMBEDDING_DIMENSIONS - 1).fill(0)];

async function fixture() {
  const value = await workflowFixture();
  temporaryDirectories.track(value.root);
  const options = {
    environment: value.environment,
    pluginRoot: PLUGIN_ROOT,
    python: await resolvePluginPython({ environment: value.environment }),
  };
  const embed = mock(async (findings: readonly Finding[]) =>
    findings.map(() => ({ model: EMBEDDING_MODEL, vector })),
  );
  const local = (
    embedder: FindingEmbedder = { embed },
    allRepositories = false,
  ) =>
    new LocalDeduplication(
      value.environment,
      allRepositories
        ? { allRepositories: true }
        : { repositoryId: "target_sha256_example" },
      undefined,
      undefined,
      embedder,
    );
  return {
    ...value,
    options,
    embed,
    local,
    store: new SqliteFindingsStore(value.environment),
  };
}

test("local dedupe indexes a sealed directory, reuses vectors and never calls the findings API", async () => {
  const f = await fixture();
  const original = await readFile(join(f.scanDir, "findings.json"), "utf8");
  const dependencies = {
    environment: f.environment,
    embedder: { embed: f.embed },
    reviewer: emptyNeighborhoodReviewer(),
    fetch: rejecting("Unexpected findings HTTP call"),
  };
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository },
    dependencies,
  );
  expect(result.deduplicationStatus).toBe("completed");
  expect(f.embed).toHaveBeenCalledTimes(1);
  const history = async (args: readonly string[], input?: string) =>
    args[0] === "get-scan"
      ? {
          scan: {
            scanId: f.document.scanId,
            scanDir: f.scanDir,
            targetPath: f.repository,
            progress: { status: "complete" },
          },
        }
      : await runWorkbench(f.options, args, input);
  expect(
    await deduplicateScanInternal(
      f.document.scanId,
      {},
      { ...dependencies, runWorkbench: history },
    ),
  ).toEqual(result);
  expect(f.embed).toHaveBeenCalledTimes(1);
  expect(await readFile(join(f.scanDir, "findings.json"), "utf8")).toBe(
    original,
  );
});

test("saved-scan local review persists a group with an existing repository finding", async () => {
  const f = await fixture();
  const anchor = f.document.findings[0]!;
  const neighbor = {
    ...anchor,
    findingId: "csf_neighbor",
    fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
  };
  await f.store.insert(
    [{ finding: neighbor, embedding: { model: EMBEDDING_MODEL, vector } }],
    "target_sha256_example",
  );
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository },
    {
      environment: f.environment,
      embedder: { embed: f.embed },
      fetch: rejecting("Unexpected HTTP call"),
      reviewer: {
        async screen(findings) {
          return {
            decisions: Object.fromEntries(
              findings
                .slice(1)
                .map((_, index) => [
                  screeningPairSlot(index),
                  { decision: "SAME", rationale: "Same control" },
                ]),
            ),
          };
        },
        async reviewPair(findings) {
          return {
            decision: "SAME",
            rationale: "Same control",
            canonicalFindingId: findings[0]!.findingId,
            mergedFinding: findings[0]!,
          };
        },
      },
    },
  );
  expect(result.duplicateGroups).toHaveLength(1);
  expect(new Set(result.duplicateGroups[0])).toEqual(
    new Set([anchor.findingId, neighbor.findingId]),
  );
  expect(await f.store.listDedupeGroups(anchor.findingId)).toHaveLength(1);
  expect(f.embed).toHaveBeenCalledTimes(2);
});

test("scope preparation refreshes legacy embeddings, preserves current bodies, and protects concurrent writes", async () => {
  const f = await fixture();
  const original = f.document.findings[0]!;
  const newer = { ...original, title: "Current stored evidence" };
  const other = {
    ...original,
    findingId: "csf_other",
    fingerprints: { ...original.fingerprints, primary: "other" },
  };
  await f.store.insert(
    [{ finding: newer, embedding: { model: EMBEDDING_MODEL, vector } }],
    "target_sha256_example",
  );
  await f.store.insert(
    [{ finding: other, embedding: { model: EMBEDDING_MODEL, vector } }],
    "other-repository",
  );
  const local = f.local();
  await local.prepare([original], "target_sha256_example");
  expect(f.embed.mock.calls.map(([findings]) => findings[0]!.title)).toEqual([
    newer.title,
  ]);
  expect(
    (await local.potentialDuplicates(original.findingId)).potentialDuplicates,
  ).toEqual([]);
  const all = f.local(undefined, true);
  await all.prepare([original], "target_sha256_example");
  expect(
    (await all.potentialDuplicates(original.findingId)).potentialDuplicates.map(
      (v) => v.findingId,
    ),
  ).toEqual([other.findingId]);
  await all.storeDedupeGroups([[original.findingId, other.findingId]]);
  expect(await f.store.listDedupeGroups(original.findingId)).toHaveLength(1);
  await f.store.insert(
    [
      {
        finding: { ...newer, title: "Concurrent update" },
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    "target_sha256_example",
  );
  await expect(local.potentialDuplicates(original.findingId)).rejects.toThrow(
    "Findings changed",
  );
  await expect(local.storeDedupeGroups([])).rejects.toThrow("Findings changed");
});

test("embedding writes reject stale content and resume completed preparation after failure", async () => {
  const f = await fixture();
  const finding = f.document.findings[0]!;
  const racing = f.local({
    async embed(findings) {
      await f.store.insert([
        {
          finding: { ...finding, title: "Concurrent body" },
          embedding: { model: EMBEDDING_MODEL, vector },
        },
      ]);
      return await f.embed(findings);
    },
  });
  await expect(
    racing.prepare([finding], "target_sha256_example"),
  ).rejects.toThrow("Findings changed");
  const local = f.local();
  await local.prepare([finding], "target_sha256_example");
  expect(
    (await local.potentialDuplicates(finding.findingId)).finding.title,
  ).toBe("Concurrent body");
  const unavailable = f.local({
    embed: rejecting("Missing embedding credentials"),
  });
  await unavailable.prepare([finding], "target_sha256_example");
  const differentProvider = new LocalDeduplication(
    {
      ...f.environment,
      CODEX_SECURITY_EMBEDDINGS_URL: "https://synthetic.invalid/embeddings",
    },
    { repositoryId: "target_sha256_example" },
    undefined,
    undefined,
    { embed: rejecting("Missing embedding credentials") },
  );
  await expect(
    differentProvider.prepare([finding], "target_sha256_example"),
  ).rejects.toThrow("Missing embedding credentials");
});

test("local workflow replays a lost group acknowledgement without publication or more embeddings", async () => {
  const f = await fixture();
  let loseAcknowledgement = true;
  const workbench = async (args: readonly string[], input?: string) => {
    const result = await runWorkbench(f.options, args, input);
    if (
      args[0] === "local-dedupe" &&
      JSON.parse(input!).action === "commit" &&
      loseAcknowledgement
    ) {
      loseAcknowledgement = false;
      throw new Error("Lost group acknowledgement");
    }
    return result;
  };
  const options = { repository: f.repository, workflowId: "local-workflow" };
  const dependencies = {
    environment: f.environment,
    runWorkbench: workbench,
    embedder: { embed: f.embed },
    reviewer: emptyNeighborhoodReviewer(),
    fetch: rejecting("Unexpected publication"),
  };
  await expect(
    deduplicateScanDirectoryInternal(f.scanDir, options, dependencies),
  ).rejects.toThrow("Lost group acknowledgement");
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    options,
    dependencies,
  );
  expect(result.deduplicationStatus).toBe("completed");
  expect(f.embed).toHaveBeenCalledTimes(1);
  const workflow = await new FindingWorkflow(
    options.workflowId,
    f.environment,
  ).get();
  expect(workflow?.destination).toStartWith("sqlite:");
  expect(workflow?.stages.publish.status).toBe("pending");
  expect(workflow?.stages.dedupe.status).toBe("completed");
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      { ...options, findingsUrl: "http://synthetic.invalid" },
      dependencies,
    ),
  ).rejects.toThrow("different destination");
});

test("empty input does not embed unrelated history and cancellation stops preparation", async () => {
  const f = await fixture();
  await f.store.insert(
    [
      {
        finding: f.document.findings[0]!,
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    "target_sha256_example",
  );
  await f
    .local({ embed: rejecting("Empty scan must not embed") })
    .prepare([], "target_sha256_example");
  const controller = new AbortController();
  controller.abort(new Error("Canceled"));
  const local = new LocalDeduplication(
    f.environment,
    { allRepositories: true },
    controller.signal,
    undefined,
    { embed: f.embed },
  );
  await expect(
    local.prepare(f.document.findings, "target_sha256_example"),
  ).rejects.toThrow("Canceled");
  expect(f.embed).not.toHaveBeenCalled();
});
