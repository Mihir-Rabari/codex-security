#!/usr/bin/env node
import type { CalibrationCase } from "../types.ts";

import { runGit as gitCommand } from "../sastbench/scripts/hydrate-sastbench-repos.mts";
import fs from "node:fs";
import {
  DEFAULT_DATASET,
  selectedVariants,
  targetRepoPath,
} from "./generate-calibration-tests.mts";
import path from "node:path";

const DEFAULT_REPO_ROOT = path.join(
  import.meta.dirname,
  "..",
  "artifacts",
  "calibration-repos",
);

function parseArgs(argv: string[]) {
  const args = {
    dataset: DEFAULT_DATASET,
    repoRoot: DEFAULT_REPO_ROOT,
    caseId: null as string | null,
    variantId: null as string | null,
    dryRun: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dataset") {
      args.dataset = path.resolve(argv[++index]);
    } else if (arg === "--repo-root") {
      args.repoRoot = path.resolve(argv[++index]);
    } else if (arg === "--case") {
      args.caseId = argv[++index];
    } else if (arg === "--variant") {
      args.variantId = argv[++index];
    } else if (arg === "--dry-run") {
      args.dryRun = true;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function plannedJobs(
  dataset: { cases: CalibrationCase[] },
  args: { repoRoot: string; caseId?: string | null; variantId?: string | null },
) {
  return selectedVariants(dataset, args).map(({ testCase, variant }) => ({
    caseId: testCase.case_id,
    variantId: variant.variant_id,
    repoUrl: testCase.repo.url,
    checkoutRef: variant.checkout_ref,
    targetDir: targetRepoPath(args.repoRoot, testCase, variant),
  }));
}

function runGit(args: string[], directory: string, stderr?: "ignore" | "pipe") {
  return gitCommand(
    [
      `--git-dir=${path.join(directory, ".git")}`,
      `--work-tree=${directory}`,
      ...args,
    ],
    directory,
    stderr,
  );
}

function gitOutput(args: string[], cwd: string) {
  try {
    return runGit(args, cwd, "ignore");
  } catch {
    return null;
  }
}

function ensureGitCheckout(job: ReturnType<typeof plannedJobs>[number]) {
  fs.mkdirSync(path.dirname(job.targetDir), { recursive: true });

  if (!fs.existsSync(job.targetDir)) {
    fs.mkdirSync(job.targetDir, { recursive: true });
  }

  if (gitOutput(["rev-parse", "--show-prefix"], job.targetDir) !== "") {
    const entries = fs.readdirSync(job.targetDir);
    if (entries.length > 0) {
      throw new Error(
        `Refusing to hydrate into non-empty non-git directory: ${job.targetDir}`,
      );
    }
    runGit(["init"], job.targetDir);
    runGit(["remote", "add", "origin", job.repoUrl], job.targetDir);
  } else {
    const originUrl = gitOutput(["remote", "get-url", "origin"], job.targetDir);
    if (!originUrl) {
      runGit(["remote", "add", "origin", job.repoUrl], job.targetDir);
    } else if (originUrl !== job.repoUrl) {
      runGit(["remote", "set-url", "origin", job.repoUrl], job.targetDir);
    }
  }

  const currentHead = gitOutput(["rev-parse", "HEAD"], job.targetDir);
  if (currentHead === job.checkoutRef) {
    return "already current";
  }

  runGit(["fetch", "--depth", "1", "origin", job.checkoutRef], job.targetDir);
  runGit(["checkout", "--detach", "FETCH_HEAD"], job.targetDir);
  return "hydrated";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const dataset = JSON.parse(fs.readFileSync(args.dataset, "utf8"));
  const jobs = plannedJobs(dataset, args);

  const variantWord = jobs.length === 1 ? "variant" : "variants";
  console.log(
    `${args.dryRun ? "would hydrate" : "hydrating"} ${jobs.length} calibration ${variantWord}`,
  );
  for (const job of jobs) {
    if (args.dryRun) {
      console.log(
        `${job.caseId}/${job.variantId} <- ${job.repoUrl} @ ${job.checkoutRef}`,
      );
      console.log(`  ${job.targetDir}`);
    } else {
      console.log(
        `${ensureGitCheckout(job)}: ${job.caseId}/${job.variantId} @ ${job.checkoutRef}`,
      );
    }
  }
}

if (
  process.argv[1] &&
  fs.existsSync(process.argv[1]) &&
  import.meta.filename === fs.realpathSync(process.argv[1])
) {
  main();
}
