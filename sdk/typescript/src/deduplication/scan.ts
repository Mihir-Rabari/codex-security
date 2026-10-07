import { loadContractWithScanDirectory } from "../contract.js";
import {
  bundledPluginRoot,
  runWorkbench,
  codexSecurityStateDirectory,
} from "../runtime.js";
import {
  resolveCompletedScan,
  type SavedScanDependencies,
} from "../saved-scan.js";
import { savedScanWorkbench } from "../saved-scan-bootstrap.js";
import { CodexReviewRunner } from "./codex-review.js";
import {
  FindingDeduplicator,
  deduplicationConcurrency,
  type DeduplicationResult,
} from "./deduplication.js";
import {
  CodexDeduplicationReviewer,
  type DeduplicationReviewer,
} from "./deduplication-reviewer.js";
import { FindingsClient, type FindingsRequest } from "../findings-client.js";
import type { FindingSearchScope } from "../finding-retrieval.js";
import {
  FindingWorkflow,
  workflowDestination,
  workflowDigest,
} from "../finding-workflow.js";
import { publishScanToCustomInternal } from "../custom-publish.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "./checkpointed-review.js";
import { normalizeRepository } from "../targets.js";
import { LocalDeduplication, type FindingEmbeddingBinding } from "./local.js";
import { readCodexHomeConfig } from "../auth.js";
import { CodexSecurityError } from "../errors.js";

export interface DeduplicateScanOptions {
  /** Resume the named findings workflow; remote mode includes custom publication. */
  workflowId?: string;
  /** Optional Findings API. Omit to prepare and deduplicate findings in local SQLite. */
  findingsUrl?: string;
  /** Custom vector space for local deduplication; cannot be combined with findingsUrl. */
  embedding?: FindingEmbeddingBinding;
  /** Search all repositories instead of the scan's targetId. Defaults to false. */
  allRepositories?: boolean;
  /** Shared concurrency limit for deduplication jobs. Defaults to 8. */
  concurrency?: number;
  signal?: AbortSignal;
}

export interface DeduplicateScanDirectoryOptions extends DeduplicateScanOptions {
  /** Local repository checkout used to review duplicate candidates. */
  repository: string;
  /** Require the sealed artifacts to belong to this scan. */
  expectedScanId?: string;
}

export interface DeduplicateScanResult extends DeduplicationResult {
  scanId: string;
}

/** Review a saved scan against embedding candidates and persist accepted duplicate groups. */
export async function deduplicateScan(
  scanId: string,
  options: DeduplicateScanOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanInternal(scanId, options);
}

/** Review a complete, sealed scan directory without resolving local scan history. */
export async function deduplicateScanDirectory(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
): Promise<DeduplicateScanResult> {
  return await deduplicateScanDirectoryInternal(scanDirectory, options);
}

type DeduplicateScanDependencies = Partial<SavedScanDependencies> & {
  environment?: NodeJS.ProcessEnv;
  reviewer?: DeduplicationReviewer;
  reviewRunner?: Pick<CodexReviewRunner, "run">;
  fetch?: FindingsRequest;
};

/** @internal */
export async function deduplicateScanDirectoryInternal(
  scanDirectory: string,
  options: DeduplicateScanDirectoryOptions,
  dependencies: DeduplicateScanDependencies = {},
): Promise<DeduplicateScanResult> {
  options.signal?.throwIfAborted();
  deduplicationConcurrency(options.concurrency);
  return await deduplicateResolvedScan(
    scanDirectory,
    await normalizeRepository(options.repository, options.signal),
    options.expectedScanId,
    options,
    dependencies,
    await bundledPluginRoot(),
    true,
  );
}

/** @internal */
export async function deduplicateScanInternal(
  scanId: string,
  options: DeduplicateScanOptions,
  dependencies: DeduplicateScanDependencies = {},
): Promise<DeduplicateScanResult> {
  options.signal?.throwIfAborted();
  deduplicationConcurrency(options.concurrency);
  const environment = dependencies.environment ?? process.env;
  const pluginRoot = await bundledPluginRoot();
  const scan = await resolveCompletedScan(scanId, {
    currentDirectory: dependencies.currentDirectory ?? (() => process.cwd()),
    runWorkbench:
      (dependencies.runWorkbench &&
        ((args, input) =>
          dependencies.runWorkbench!(args, input, options.signal))) ??
      (await savedScanWorkbench(scanId, {
        environment,
        pluginRoot,
        currentDirectory: dependencies.currentDirectory?.() ?? process.cwd(),
        signal: options.signal,
      })),
  });
  return await deduplicateResolvedScan(
    scan.scanDir,
    scan["targetPath"] as string,
    scan.scanId,
    options,
    dependencies,
    pluginRoot,
    false,
  );
}

async function deduplicateResolvedScan(
  selectedDirectory: string,
  repositoryPath: string,
  expectedScanId: string | undefined,
  options: DeduplicateScanOptions,
  dependencies: DeduplicateScanDependencies,
  pluginRoot: string,
  bindRepository: boolean,
): Promise<DeduplicateScanResult> {
  const environment = dependencies.environment ?? process.env;
  if (options.embedding !== undefined && options.findingsUrl !== undefined)
    throw new CodexSecurityError(
      "Custom embeddings are only supported for local deduplication.",
    );
  const { contract, scanDirectory } = await loadContractWithScanDirectory(
    selectedDirectory,
    {
      pluginRoot,
      expectedScanId,
      signal: options.signal,
    },
  );
  const scanId = contract.manifest.scan.id;
  const scope: FindingSearchScope =
    options.allRepositories === true
      ? { allRepositories: true }
      : { repositoryId: contract.manifest.scan.target.targetId };
  const injectedWorkbench = dependencies.runWorkbench;
  const workbench: typeof runWorkbench | undefined =
    injectedWorkbench &&
    (({ signal }, args, input) =>
      injectedWorkbench(args, input, signal ?? options.signal));
  const local =
    options.findingsUrl === undefined
      ? new LocalDeduplication(
          environment,
          scope,
          repositoryPath,
          options.signal,
          workbench,
          options.embedding,
        )
      : undefined;
  const client =
    local ??
    new FindingsClient(
      options.findingsUrl!,
      options.signal,
      dependencies.fetch,
    );
  const workflow =
    options.workflowId === undefined
      ? undefined
      : new FindingWorkflow(
          options.workflowId,
          environment,
          workbench,
          undefined,
          repositoryPath,
        );
  if (workflow) {
    await workflow.protectArtifacts(scanDirectory);
    await workflow.bind({
      ...(bindRepository ? { repositoryPath } : {}),
      scanId,
      scanDir: scanDirectory,
      artifactDigest: workflowDigest(contract),
      destination: local
        ? `sqlite:${codexSecurityStateDirectory(environment)}`
        : workflowDestination(options.findingsUrl!),
      scope,
    });
    await workflow.complete("scan", null);
    if (!local)
      await publishScanToCustomInternal(
        scanDirectory,
        {
          findingsUrl: options.findingsUrl!,
          workflowId: options.workflowId,
          expectedScanId: scanId,
          signal: options.signal,
        },
        {
          environment,
          fetch: dependencies.fetch,
          runWorkbench: workbench,
        },
      );
  }
  const dedupe = async (): Promise<DeduplicateScanResult> => {
    if (local) {
      await (
        workflow ?? new FindingWorkflow(scanId, environment)
      ).protectArtifacts(scanDirectory);
      await local.prepare(
        contract.findings.findings,
        contract.manifest.scan.target.targetId,
      );
    }
    const saved = (await workflow?.get())?.stages.dedupe;
    if (saved?.pendingWrite) {
      if (
        local &&
        (saved.pendingWrite.local?.inputDigest !== local.inputDigest ||
          workflowDigest(saved.pendingWrite.local.source) !==
            workflowDigest(await workflow!.sourceSnapshot(repositoryPath)))
      ) {
        throw new CodexSecurityError(
          "Local deduplication inputs changed. Use a new workflow ID to review them.",
        );
      }
      await client.storeDedupeGroups(saved.pendingWrite.groups);
      return saved.result as DeduplicateScanResult;
    }
    const runner =
      dependencies.reviewRunner ??
      new CodexReviewRunner(
        environment,
        undefined,
        options.signal,
        repositoryPath,
      );
    const source = workflow
      ? await workflow.sourceSnapshot(repositoryPath)
      : undefined;
    const checkpoints = workflow
      ? new CheckpointedReviewRunner(
          workflow,
          runner,
          source!,
          scope,
          await reviewSettingsDigest(environment),
        )
      : undefined;
    const deduplicator = new FindingDeduplicator(
      {
        potentialDuplicates: (findingId) =>
          client.potentialDuplicates(findingId, scope),
      },
      dependencies.reviewer ??
        new CodexDeduplicationReviewer(
          checkpoints ?? runner,
          await readCodexHomeConfig(environment, options.signal),
        ),
      options.signal,
      options.concurrency,
    );
    const reviewed = await deduplicator.run(
      contract.findings.findings.map((finding) => finding.findingId),
    );
    await checkpoints?.assertSourceUnchanged();
    options.signal?.throwIfAborted();
    const result: DeduplicateScanResult = { scanId, ...reviewed };
    await workflow?.prepareDedupe(result, {
      groups: result.duplicateGroups,
      ...(local
        ? { local: { inputDigest: local.inputDigest, source: source! } }
        : {}),
    });
    await client.storeDedupeGroups(result.duplicateGroups);
    return result;
  };
  return workflow ? await workflow.run("dedupe", dedupe) : await dedupe();
}
