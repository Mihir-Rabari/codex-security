import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
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
  const hash = (text: string) =>
    createHash("sha256").update(text).digest("hex");
  const targetId = `target_sha256_${hash(`local-workspace\0${value.repository}`)}`;
  for (const finding of value.document.findings) {
    const fingerprint = `codex-security/v1:sha256:${hash(["codex-security/v1", targetId, finding.ruleId, finding.identity.anchor, finding.identity.instance ?? ""].join("\0"))}`;
    finding.fingerprints.primary = fingerprint;
    finding.findingId = `csf_${hash(fingerprint).slice(0, 24)}`;
    finding.occurrenceId = `occ_${hash([value.document.scanId, fingerprint].join("\0")).slice(0, 24)}`;
  }
  const findingsText = JSON.stringify(value.document);
  await writeFile(join(value.scanDir, "findings.json"), findingsText);
  const manifestPath = join(value.scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.scan.target.targetId = targetId;
  manifest.scan.artifacts.find(
    (artifact: { path: string }) => artifact.path === "findings.json",
  ).sha256 = hash(findingsText);
  await writeFile(manifestPath, JSON.stringify(manifest));
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
      allRepositories ? { allRepositories: true } : { repositoryId: targetId },
      value.repository,
      undefined,
      undefined,
      embedder,
    );
  return {
    ...value,
    targetId,
    options,
    embed,
    local,
    store: new SqliteFindingsStore(value.environment),
  };
}

test.each([
  [undefined, "https://api.openai.com/v1/embeddings"],
  ["", "https://api.openai.com/v1/embeddings"],
  [
    "https://embeddings.example.com/custom/v1/embeddings?api-version=synthetic",
    "https://embeddings.example.com/custom/v1/embeddings?api-version=synthetic",
  ],
])(
  "local dedupe uses the configured embeddings endpoint %p",
  async (endpoint, expected) => {
    const f = await fixture();
    const request = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        model: EMBEDDING_MODEL,
        data: [{ index: 0, embedding: vector }],
      }),
    );
    try {
      const local = new LocalDeduplication(
        {
          ...f.environment,
          OPENAI_API_KEY: "synthetic-embeddings-key",
          CODEX_SECURITY_EMBEDDINGS_URL: endpoint,
        },
        { repositoryId: f.targetId },
        f.repository,
      );
      await local.prepare(f.document.findings, f.targetId);
      expect(request).toHaveBeenCalledTimes(1);
      expect(request.mock.calls[0]?.[0]).toBe(expected);
      expect(request.mock.calls[0]?.[1]?.headers).toMatchObject({
        Authorization: "Bearer synthetic-embeddings-key",
      });
    } finally {
      request.mockRestore();
    }
  },
);

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
    f.targetId,
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
    f.targetId,
  );
  await f.store.insert(
    [{ finding: other, embedding: { model: EMBEDDING_MODEL, vector } }],
    "other-repository",
  );
  const local = f.local();
  await local.prepare([original], f.targetId);
  expect(f.embed.mock.calls.map(([findings]) => findings[0]!.title)).toEqual([
    newer.title,
  ]);
  expect(
    (await local.potentialDuplicates(original.findingId)).potentialDuplicates,
  ).toEqual([]);
  const all = f.local(undefined, true);
  await all.prepare([original], f.targetId);
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
    f.targetId,
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
  await expect(racing.prepare([finding], f.targetId)).rejects.toThrow(
    "Findings changed",
  );
  const local = f.local();
  await local.prepare([finding], f.targetId);
  expect(
    (await local.potentialDuplicates(finding.findingId)).finding.title,
  ).toBe("Concurrent body");
  const unavailable = f.local({
    embed: rejecting("Missing embedding credentials"),
  });
  await unavailable.prepare([finding], f.targetId);
  const differentProvider = new LocalDeduplication(
    {
      ...f.environment,
      CODEX_SECURITY_EMBEDDINGS_URL: "https://synthetic.invalid/embeddings",
    },
    { repositoryId: f.targetId },
    f.repository,
    undefined,
    undefined,
    { embed: rejecting("Missing embedding credentials") },
  );
  await expect(
    differentProvider.prepare([finding], f.targetId),
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
    f.targetId,
  );
  await f
    .local({ embed: rejecting("Empty scan must not embed") })
    .prepare([], f.targetId);
  const controller = new AbortController();
  controller.abort(new Error("Canceled"));
  const local = new LocalDeduplication(
    f.environment,
    { allRepositories: true },
    f.repository,
    controller.signal,
    undefined,
    { embed: f.embed },
  );
  await expect(local.prepare(f.document.findings, f.targetId)).rejects.toThrow(
    "Canceled",
  );
  expect(f.embed).not.toHaveBeenCalled();
});

test("sealed artifacts cannot select a different local repository corpus", async () => {
  const f = await fixture();
  await f.store.insert(
    [
      {
        finding: f.document.findings[0]!,
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    f.targetId,
  );
  const differentRepository = join(f.root, "other-checkout");
  await mkdir(differentRepository);
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      { repository: differentRepository },
      {
        environment: f.environment,
        embedder: { embed: f.embed },
        reviewer: emptyNeighborhoodReviewer(),
      },
    ),
  ).rejects.toThrow("scan target does not match");
  expect(f.embed).not.toHaveBeenCalled();
});

test("local workbench calls receive cancellation and cannot report success after a canceled commit", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const reason = new Error("Canceled during group commit");
  const actions: string[] = [];
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      { repository: f.repository, signal: controller.signal },
      {
        environment: f.environment,
        embedder: { embed: f.embed },
        reviewer: emptyNeighborhoodReviewer(),
        runWorkbench: async (args, input, signal) => {
          expect(signal).toBe(controller.signal);
          const result = await runWorkbench(
            { ...f.options, signal },
            args,
            input,
          );
          if (args[0] === "local-dedupe") {
            const { action } = JSON.parse(input!);
            actions.push(action);
            if (action === "commit") controller.abort(reason);
          }
          return result;
        },
      },
    ),
  ).rejects.toBe(reason);
  expect(actions).toEqual(["prepare", "embed", "neighbors", "commit"]);
});
