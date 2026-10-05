import { gitText } from "./support/shell.js";
import { emptyPage } from "./support/linear-pagination.js";
import { resolving } from "./support/promises.js";
import { parse as parseToml } from "smol-toml";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { execFile, execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { Writable } from "node:stream";
import { promisify, stripVTControlCharacters } from "node:util";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import type { LinearClientFactory } from "../src/linear.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import {
  temporaryDirectory,
  createTemporaryDirectories,
} from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";

const CURRENT_REPOSITORY = resolve("/current/repository");
const SAVED_REPOSITORY = resolve("/saved/repository");
const STATE_DIRECTORY = resolve("/tmp/codex-security-state");

function resultWithFindings(severities: readonly SeverityLevel[]) {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Summary ${index + 1}`,
      locations: [
        { path: `src/finding-${index + 1}.ts`, startLine: index + 1 },
      ],
    });
  });
  return result;
}

function savedScan(
  result: ReturnType<typeof resultWithFindings>,
  scanId = "scan-1",
  targetPath = SAVED_REPOSITORY,
): JsonObject {
  return {
    scan: {
      scanId,
      targetPath,
      findings: result.findings.findings as unknown as JsonObject[],
    },
  };
}

function completePatches(
  args: readonly string[],
  output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
  status: "verified" | "blocked" = "verified",
): Finding[] {
  const prompt = output?.appServer?.prompt ?? args.at(-1)!;
  const findings = JSON.parse(prompt.split("\n").at(-1)!) as Finding[];
  output?.stdout.write(
    JSON.stringify({
      patches: findings.map((finding) => ({
        occurrenceId: finding.occurrenceId,
        status,
        files: status === "verified" ? [finding.locations[0]!.path] : [],
        ...(status === "verified"
          ? { verification: "The exploit fails and focused tests pass." }
          : { reason: "The required service is unavailable." }),
      })),
    }),
  );
  return findings;
}

function patchRiskSummary() {
  return [
    "### Recommendation: human review required",
    "",
    "The patch has moderate impact and low regression likelihood.",
    "",
    "- Protection: focused tests passed",
    "- Recovery: revert the patch commit",
  ].join("\n");
}

function patchRiskAssessment() {
  const summary = patchRiskSummary();
  return {
    report: [
      "<!-- codex-security:patch-risk-summary:start -->",
      summary,
      "<!-- codex-security:patch-risk-summary:end -->",
      "",
      "```json",
      '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
      "```",
    ].join("\n"),
  };
}

function patchRiskReport() {
  return [
    patchRiskSummary(),
    "",
    "```json",
    '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
    "```",
  ].join("\n");
}

async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const { stdout, stderr, runCli } = createCliTest(main, {
    stderr: options.interactive,
  });

  const current = dependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
  });
  if (options.interactive) {
    current.confirmPatchReview = async (question) => {
      stderr.stream.write(`\n${question} (y/N)\n`);
      return options.review ?? true;
    };
  }
  options.configure?.(current);
  return {
    exitCode: await runCli(arguments_, current),
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

describe("scan and patch workflow", () => {
  test.each([
    ["gh", "bin"],
    ["glab", "node_modules/.bin"],
  ])(
    "keeps the full worktree outside the trusted %s PATH",
    async (provider, path) => {
      const root = await temporaryDirectory("codex-security-provider-path-");
      const repository = join(root, "repository");
      const component = join(repository, "component");
      const repositoryTools = join(repository, path!);
      const trustedTools = join(root, "trusted");
      const marker = join(root, "provider.json");
      const preload = join(root, "provider.mjs");
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const executable = `${provider}${process.platform === "win32" ? ".exe" : ""}`;
      try {
        await mkdir(component, { recursive: true });
        await mkdir(repositoryTools, { recursive: true });
        await mkdir(trustedTools);
        for (const directory of [repositoryTools, trustedTools])
          await copyFile(node, join(directory, executable));
        await writeFile(
          preload,
          `
import { writeFileSync } from "node:fs";
import { basename } from "node:path";
if (["pr", "mr"].includes(basename(process.argv[1] ?? ""))) {
  writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ executable: process.execPath, credential: process.env.GH_TOKEN === "synthetic-token" }));
  process.exit(17);
}
`,
        );
        await writeFile(join(component, "app.ts"), "original\n");
        await writeFile(
          join(repository, ".gitignore"),
          "bin/\nnode_modules/\n",
        );
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git(
          "remote",
          "add",
          "origin",
          `https://${provider === "glab" ? "gitlab.com" : "github.example.test"}/example/repository.git`,
        );
        const child = Bun.spawn(
          [
            process.execPath,
            "-e",
            `import { main } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)}; process.exitCode = await main(["patch", "Synthetic issue", "--create-pr"]);`,
          ],
          {
            cwd: component,
            env: {
              PATH: [repositoryTools, trustedTools, process.env["PATH"]].join(
                delimiter,
              ),
              SystemRoot: process.env["SystemRoot"],
              PATHEXT: process.env["PATHEXT"],
              HOME: root,
              USERPROFILE: root,
              CODEX_SECURITY_STATE_DIR: join(root, "state"),
              NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
              GH_TOKEN: "synthetic-token",
              CI: "1",
            },
            stdout: "pipe",
            stderr: "pipe",
          },
        );
        const stderr = await new Response(child.stderr).text();
        expect(await child.exited, stderr).toBe(2);
        expect(JSON.parse(await readFile(marker, "utf8"))).toEqual({
          executable: join(trustedTools, executable),
          credential: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each([
    "ordinary",
    "HEAD filename",
    "relative Git environment",
    "absolute symlink Git environment",
    "relative symlink Git environment",
    "relative provider configuration",
    "nested Git metadata after patch",
    "removed component",
    "removed component replaced by a file",
    "removed component with relative Git environment",
    "removed component with relative index",
    "removed component with relative common directory",
    "removed component with relative object directory",
    "removed component with relative symlink Git environment",
    "removed component with relative provider configuration",
    "removed component with relative GitLab configuration",
    "removed component with removed provider configuration",
    ...(process.platform === "win32"
      ? []
      : [
          "removed component replaced by a directory link",
          "trailing space",
          "carriage return",
        ]),
  ])(
    "assesses and publishes root-relative patch files from a subdirectory: %s",
    async (kind) => {
      const directory = await temporaryDirectory(
        "codex-security-subdirectory-pr-",
      );
      const repository = join(
        directory,
        kind === "trailing space"
          ? "repository "
          : kind === "carriage return"
            ? "repository\r"
            : "repository",
      );
      const subdirectory = join(repository, "sub");
      const removesComponent = kind.startsWith("removed component");
      const replacesComponent = kind.includes("replaced by");
      const changedFiles = removesComponent
        ? [
            "shared.ts",
            ...(replacesComponent ? ["sub"] : []),
            "sub/.codex/config.toml",
            "sub/app.ts",
          ]
        : ["shared.ts", "sub/app.ts"];
      const alias = join(directory, "alias");
      const linkedGitRoot = `${kind.includes("relative symlink Git environment") ? relative(subdirectory, alias) : alias}${process.platform === "win32" ? "" : `${sep}..`}`;
      const gitEnvironment = kind.includes("relative Git environment")
        ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
        : kind.includes("symlink Git environment")
          ? {
              GIT_DIR: `${linkedGitRoot}${sep}.git`,
              GIT_WORK_TREE: linkedGitRoot,
            }
          : kind.includes("relative index")
            ? { GIT_INDEX_FILE: ".git/custom-index" }
            : kind.includes("relative common directory")
              ? { GIT_COMMON_DIR: "../metadata" }
              : kind.includes("relative object directory")
                ? { GIT_OBJECT_DIRECTORY: "../metadata/objects" }
                : {};
      const providerConfiguration = kind.includes(
        "removed provider configuration",
      )
        ? join(subdirectory, "provider-config")
        : join(directory, "provider-config");
      const providerEnvironment = kind.includes("provider configuration")
        ? { GH_CONFIG_DIR: relative(subdirectory, providerConfiguration) }
        : kind.includes("relative GitLab configuration")
          ? { GLAB_CONFIG_DIR: relative(subdirectory, providerConfiguration) }
          : {};
      const remote = join(directory, "remote.git");
      const git = repositoryGit(repository);
      try {
        await mkdir(join(subdirectory, ".codex"), { recursive: true });
        if (kind.includes("symlink Git environment"))
          await symlink(
            process.platform === "win32" ? repository : subdirectory,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
        if (Object.keys(providerEnvironment).length > 0) {
          await mkdir(providerConfiguration);
          await writeFile(
            join(providerConfiguration, "config.yml"),
            "git_protocol: https\n",
          );
          if (kind.includes("removed provider configuration")) {
            await writeFile(
              join(repository, ".gitignore"),
              "provider-config/\n",
            );
          }
        }
        await writeFile(
          join(subdirectory, ".codex", "config.toml"),
          '[mcp_servers.component]\ncommand = "synthetic-component-server"\n',
        );
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        git("config", "diff.relative", "true");
        if (
          kind.includes("relative common directory") ||
          kind.includes("relative object directory")
        ) {
          // Git2.43 checks these paths before and after entering the worktree.
          for (const parent of [directory, repository])
            await symlink(
              join(repository, ".git"),
              join(parent, "metadata"),
              process.platform === "win32" ? "junction" : "dir",
            );
          await writeFile(join(repository, ".gitignore"), "metadata/\n");
        }
        for (const file of ["sub/app.ts", "shared.ts"])
          await writeFile(join(repository, file), "original\n");
        if (kind === "HEAD filename")
          await writeFile(join(repository, "HEAD"), "ordinary source file\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        const originalIndex = kind.includes("relative index")
          ? await readFile(join(repository, ".git/index"))
          : undefined;
        if (kind.includes("relative index"))
          await copyFile(
            join(repository, ".git/index"),
            join(repository, ".git/custom-index"),
          );
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          [
            "patch",
            "Synthetic issue",
            "--assess-patch-risk",
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: subdirectory,
            environment: {
              ...process.env,
              ...gitEnvironment,
              ...providerEnvironment,
            },
            onCodex: async (_args, output, environment) => {
              const assessing = output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              );
              expect(output?.appServer?.directory).toBe(
                removesComponent && assessing ? repository : subdirectory,
              );
              if (!(removesComponent && assessing))
                expect(
                  await readFile(
                    join(
                      output!.appServer!.directory!,
                      ".codex",
                      "config.toml",
                    ),
                    "utf8",
                  ),
                ).toContain("synthetic-component-server");
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                expect(
                  execFileSync("git", ["rev-parse", "--show-toplevel"], {
                    cwd: output.appServer.directory,
                    env: environment,
                    encoding: "utf8",
                  }).replace(/\n$/u, ""),
                ).toBe(
                  kind === "nested Git metadata after patch"
                    ? subdirectory
                    : repository,
                );
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
                expect(artifact.changedFiles).toEqual(changedFiles);
                const patch = await readFile(artifact.path, "utf8");
                expect(patch).toContain("a/sub/app.ts");
                expect(patch).toContain("a/shared.ts");
                output.stdout.write(patchRiskAssessment().report);
              } else {
                if (removesComponent) {
                  await rm(subdirectory, { recursive: true });
                  if (kind.includes("replaced by a file"))
                    await writeFile(subdirectory, "replacement file\n");
                  if (kind.includes("replaced by a directory link")) {
                    const outside = join(directory, "other-checkout");
                    await mkdir(outside);
                    await writeFile(join(outside, "app.ts"), "original\n");
                    const other = repositoryGit(outside);
                    other("init", "--initial-branch=main");
                    other("config", "user.name", "Synthetic User");
                    other("config", "user.email", "synthetic@example.test");
                    other("add", ".");
                    other("commit", "-m", "Synthetic other checkout");
                    await symlink(
                      outside,
                      subdirectory,
                      process.platform === "win32" ? "junction" : "dir",
                    );
                  }
                } else {
                  await writeFile(join(subdirectory, "app.ts"), "fixed\n");
                  if (kind === "nested Git metadata after patch") {
                    const nested = repositoryGit(subdirectory);
                    nested("init", "--initial-branch=main");
                    nested("config", "user.name", "Synthetic User");
                    nested("config", "user.email", "synthetic@example.test");
                    nested("add", ".");
                    nested("commit", "-m", "Synthetic nested checkout");
                  }
                }
                await writeFile(join(repository, "shared.ts"), "fixed\n");
                output?.stdout.write("Patch complete.");
              }
              return 0;
            },
            onRepositoryCommand: async (command, args, directory, options) => {
              if (command === "git") {
                if (
                  providerEnvironment.GLAB_CONFIG_DIR !== undefined &&
                  args[0] === "remote"
                )
                  return "https://gitlab.com/example/repository.git";
                if (
                  args[0] === "ls-remote" &&
                  args[2] === "https://gitlab.com/example/repository.git"
                )
                  args = [...args.slice(0, 2), remote, ...args.slice(3)];
                return runGitRepositoryCommand(command, args, directory, {
                  ...options,
                  environment: {
                    ...gitEnvironment,
                    ...options?.environment,
                    // Local Git transport forwards relative paths to its receiver.
                    ...(kind.includes("relative symlink Git environment") &&
                    args[0] === "push"
                      ? {
                          GIT_DIR: join(repository, ".git"),
                          GIT_WORK_TREE: repository,
                        }
                      : {}),
                  },
                });
              }
              const configName =
                providerEnvironment.GH_CONFIG_DIR !== undefined
                  ? "GH_CONFIG_DIR"
                  : "GLAB_CONFIG_DIR";
              const configuration =
                options?.environment?.[configName] ??
                providerEnvironment[configName];
              if (configuration !== undefined)
                expect(
                  await readFile(
                    resolve(
                      options?.directory ?? directory,
                      configuration,
                      "config.yml",
                    ),
                    "utf8",
                  ),
                ).toBe("git_protocol: https\n");
              return args[1] === "create"
                ? "https://github.example.test/example/repository/pull/17"
                : "";
            },
          },
        );
        const missingConfiguration = kind.includes(
          "removed provider configuration",
        );
        const linkedComponent = kind.includes("replaced by a directory link");
        expect(outcome.exitCode, outcome.stderr).toBe(
          missingConfiguration || linkedComponent ? 2 : 0,
        );
        const result = JSON.parse(outcome.stdout);
        expect(result.repository).toBe(subdirectory);
        expect(result.applied).toBe(true);
        expect(result.files).toEqual(
          changedFiles.map((file) =>
            relative(subdirectory, join(repository, file)).split(sep).join("/"),
          ),
        );
        expect(
          result.files.map((file: string) => resolve(result.repository, file)),
        ).toEqual(changedFiles.map((file) => join(repository, file)));
        if (!linkedComponent)
          expect(git("show", "--format=", "--name-only", "HEAD", "--")).toBe(
            changedFiles.join("\n"),
          );
        if (missingConfiguration) {
          expect(outcome.stderr).toContain("ENOENT");
          expect(outcome.stderr).toContain(providerConfiguration);
        } else if (linkedComponent) {
          expect(outcome.stderr).toContain("beyond a symbolic link");
          expect(git("branch", "--show-current")).toBe("main");
          expect(git("diff", "--cached", "--name-only")).toBe("");
        } else
          expect(git("rev-parse", "HEAD")).toBe(
            git("rev-parse", "@{upstream}"),
          );
        if (linkedComponent)
          expect(await readFile(join(subdirectory, "app.ts"), "utf8")).toBe(
            "original\n",
          );
        else if (removesComponent)
          await expect(
            readFile(join(subdirectory, "app.ts")),
          ).rejects.toThrow();
        if (originalIndex !== undefined) {
          expect(await readFile(join(repository, ".git/index"))).toEqual(
            originalIndex,
          );
          expect(
            gitText(["status", "--porcelain"], {
              cwd: repository,
              env: {
                ...process.env,
                GIT_INDEX_FILE: join(repository, ".git/custom-index"),
              },
            }),
          ).toBe("");
        } else if (!linkedComponent)
          expect(git("status", "--porcelain")).toBe("");
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test.each([
    "absolute environment",
    "relative environment",
    "relative common directory",
    "relative index file",
    "relative object directory",
    "configuration",
  ])(
    "preserves discovered Git metadata for a separate worktree: %s",
    async (kind) => {
      const root = await temporaryDirectory(
        "codex-security-separate-worktree-",
      );
      const repository = join(root, "repository");
      const worktree = join(root, "worktree");
      const remote = join(root, "remote.git");
      const gitEnvironment =
        kind === "configuration"
          ? {}
          : {
              GIT_WORK_TREE:
                kind === "relative environment"
                  ? relative(repository, worktree)
                  : worktree,
              ...(kind === "relative common directory"
                ? { GIT_COMMON_DIR: "../repository/.git" }
                : {}),
              ...(kind === "relative index file"
                ? { GIT_INDEX_FILE: "../repository/.git/custom-index" }
                : {}),
              ...(kind === "relative object directory"
                ? { GIT_OBJECT_DIRECTORY: "../repository/.git/objects" }
                : {}),
            };
      const git = (...args: string[]) =>
        gitText(args, {
          cwd: repository,
          env: { ...process.env, ...gitEnvironment },
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      try {
        await mkdir(repository);
        await mkdir(worktree);
        repositoryGit(repository)("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        if (kind === "configuration") git("config", "core.worktree", worktree);
        await writeFile(join(worktree, "app.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        repositoryGit(repository)("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--assess-patch-risk", "--create-pr"],
          {
            currentDirectory: repository,
            environment: { ...process.env, ...gitEnvironment },
            onCodex: async (_args, output) => {
              expect(output?.appServer?.directory).toBe(repository);
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
                expect(artifact.changedFiles).toEqual(["app.ts"]);
                output.stdout.write(patchRiskAssessment().report);
              } else {
                await writeFile(join(worktree, "app.ts"), "fixed\n");
                output?.stdout.write("Patch complete.");
              }
              return 0;
            },
            onRepositoryCommand: (command, args, directory, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, directory, {
                    ...options,
                    environment: { ...gitEnvironment, ...options?.environment },
                  })
                : args[1] === "create"
                  ? "https://github.example.test/example/repository/pull/17"
                  : "",
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(git("show", "HEAD:app.ts")).toBe("fixed");
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
        expect(git("status", "--porcelain")).toBe("");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["scan", "patch", "direct"])(
    "keeps %s results when pull request preflight fails",
    async (command) => {
      const onCodex = mock(() => 0);
      const outcome = await runWorkflow(
        [
          command === "direct" ? "patch" : command,
          ...(command === "scan"
            ? ["--patch"]
            : command === "direct"
              ? ["Synthetic issue"]
              : ["--scan", "scan-1"]),
          "--create-pr",
          "--json",
        ],
        {
          result: resultWithFindings(["high"]),
          onCodex,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", SAVED_REPOSITORY),
          onRepositoryCommand: (command, args) => {
            if (command === "gh")
              throw new Error("GitHub authentication failed.");
            return args.includes("--name-only") &&
              !args.includes("HEAD") &&
              !args.includes("--cached")
              ? "src/finding-1.ts\0"
              : "";
          },
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(onCodex).not.toHaveBeenCalled();
      expect(outcome.stderr).toContain("GitHub authentication failed.");
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        ...(command === "direct"
          ? { repository: CURRENT_REPOSITORY, applied: false, files: [] }
          : { patches: [] }),
        ...(command === "patch"
          ? { scanId: "scan-1", repository: SAVED_REPOSITORY }
          : {}),
      });
    },
  );

  test.skipIf(Bun.which("gh") === null).each([
    ["github", "open"],
    ["github", "closed"],
    ["gitlab", "open"],
    ["gitlab", "closed"],
  ])(
    "checks actual request state and bounded metadata with %s: %s",
    async (provider, state) => {
      const root = await temporaryDirectory("codex-security-gh-color-");
      const url = "https://forge.example.test/example/repository/pull/15";
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch: () =>
          Response.json([
            provider === "github"
              ? {
                  url,
                  state: state === "open" ? "OPEN" : "CLOSED",
                  headRefOid: "saved-commit",
                }
              : {
                  web_url: url,
                  state: state === "open" ? "opened" : "closed",
                  sha: "saved-commit",
                  description: "synthetic description ".repeat(60_000),
                },
          ]),
      });
      try {
        const outcome = await runWorkflow(
          ["patch", "--resume-pr", "codex-security/patch-scan-1"],
          {
            onRepositoryCommand: async (command, args) => {
              if (command === "git")
                return args[0] === "remote"
                  ? `https://${provider === "gitlab" ? "gitlab.com" : "github.example.test"}/example/repository.git`
                  : "saved-commit";
              const { stdout } = await promisify(execFile)(
                Bun.which("gh")!,
                [
                  "api",
                  new URL("fixture", server.url).href,
                  "--jq",
                  args[args.indexOf("--jq") + 1]!,
                ],
                {
                  env: {
                    PATH: process.env["PATH"],
                    SystemRoot: process.env["SystemRoot"],
                    HOME: root,
                    USERPROFILE: root,
                    GH_CONFIG_DIR: join(root, "gh"),
                    GH_TOKEN: "synthetic-token",
                    GH_NO_UPDATE_NOTIFIER: "1",
                    CLICOLOR_FORCE: provider === "github" ? "1" : "0",
                  },
                  encoding: "utf8",
                },
              );
              return stdout.trim();
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(state === "open" ? 0 : 2);
        if (state === "open") expect(outcome.stderr).toContain(url);
        else {
          expect(outcome.stderr).toContain("no longer open");
          expect(outcome.stderr).not.toContain("Retry from this repository");
        }
      } finally {
        server.stop(true);
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each([false, true])(
    "shows progress during baseline preparation and cleans up on failure: %p",
    async (failSnapshot) => {
      const result = resultWithFindings(["high"]);
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      let snapshotHadProgress = false;
      let resultSnapshotHadProgress = false;
      let modelStarted = false;
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (_command, args) => {
          if (args.includes("add") && !modelStarted) {
            snapshotHadProgress = stderr
              .text()
              .includes("Patching 1/1 · Finding 1");
            if (failSnapshot) throw new Error("Baseline snapshot failed.");
          }
          if (args.includes("add") && modelStarted)
            resultSnapshotHadProgress =
              setInterval.mock.calls.length > clearInterval.mock.calls.length;
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
        onCodex: (args, output) => {
          modelStarted = true;
          completePatches(args, output);
          return 0;
        },
      });
      current.setInterval = setInterval;
      current.clearInterval = clearInterval;

      const status = await runCli(
        ["scan", "--patch", "--patch-severity", "high"],
        current,
      );

      expect(snapshotHadProgress).toBe(true);
      expect(resultSnapshotHadProgress).toBe(!failSnapshot);
      expect(modelStarted).toBe(!failSnapshot);
      expect(status).toBe(failSnapshot ? 2 : 0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      if (failSnapshot)
        expect(stderr.text()).toContain("Baseline snapshot failed.");
    },
  );

  test("puts patch runner diagnostics on a new line after the timer", async () => {
    for (const status of [1, 2]) {
      const result = resultWithFindings(["high"]);
      const stdout = capture();
      let errors = "";
      const stderr = Object.assign(
        new Writable({
          write(chunk, _encoding, callback) {
            errors += chunk.toString();
            callback();
          },
        }),
        { isTTY: true },
      );
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: async (_args, output) => {
          await new Promise<void>((resolve, reject) => {
            output!.stderr.write(
              "codex-security: Patch response failed.\n",
              (error) => {
                if (error) reject(error);
                else resolve();
              },
            );
          });
          return status;
        },
      });

      await main(
        ["patch", "--scan", "scan-1", "--json"],
        stdout.stream,
        stderr,
        current,
      );

      expect(stripVTControlCharacters(errors)).toContain(
        "\ncodex-security: Patch response failed.\n",
      );
      expect(JSON.parse(stdout.text()).patches[0].status).toBe("failed");
    }
  });

  test.each(["A long finding title ".repeat(12), "界".repeat(100)])(
    "keeps a long patch timer on one terminal row: %s",
    async (title) => {
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.title = title;
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      Object.assign(stderr.stream, { columns: 36 });
      let now = 0;
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          now = 84_000;
          setIntervalMock.mock.lastCall?.[0]?.();
          expect(completePatches(args, output)[0]!.title).toBe(title);
          return 0;
        },
      });
      const setIntervalMock = mock(current.setInterval);
      current.now = () => now;
      current.setInterval = setIntervalMock;
      current.clearInterval = () => {};

      expect(
        await runCli(["patch", "--scan", "scan-1", "--json"], current),
      ).toBe(0);

      const frames = stripVTControlCharacters(stderr.text())
        .split(/[\r\n]/u)
        .filter((line) => /^\[\d+:\d+\] Patching/u.test(line));
      expect(frames).toHaveLength(2);
      for (const frame of frames) {
        expect(Bun.stringWidth(frame)).toBeLessThan(36);
        expect(frame).toEndWith("…");
      }
    },
  );

  test("shows each patch and live activity before it finishes, with clean JSON output", async () => {
    for (const args of [
      ["scan", "--patch", "--patch-severity", "high"],
      ["patch", "--scan", "scan-1", "--json"],
    ]) {
      const result = resultWithFindings(["high", "high"]);
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

      let now = 0;
      let index = 0;
      const timers = new Map<NodeJS.Timeout, () => void>();
      const current = dependencies({
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          index += 1;
          const label = `Patching ${index}/2 · Finding ${index}`;
          expect(stderr.text()).toContain(label);
          expect(stderr.text()).not.toContain(`VERIFIED  Finding ${index}`);
          for (const delta of ["Checking ", "the ", "fix."]) {
            output!.appServer!.onEvent!({
              method: "item/reasoning/summaryTextDelta",
              params: { itemId: "reasoning-1", delta },
            });
          }
          expect(stderr.text().match(/Codex: Checking/gu) ?? []).toHaveLength(
            index - 1,
          );
          output!.appServer!.onEvent!({
            method: "item/completed",
            params: {
              item: {
                id: "reasoning-1",
                type: "reasoning",
                summary: ["Checking the fix."],
              },
            },
          });
          expect(stderr.text()).toContain("Codex: Checking the fix.");
          now += 84_000;
          for (const tick of [...timers.values()]) tick();
          expect(stderr.text()).toContain(`[01:24] ${label}`);
          completePatches(args, output);
          return 0;
        },
      });
      current.now = () => now;
      current.setInterval = (callback) => {
        const timer = {} as NodeJS.Timeout;
        timers.set(timer, callback);
        return timer;
      };
      current.clearInterval = (timer) => {
        timers.delete(timer);
      };

      expect(await runCli(args, current), stderr.text()).toBe(0);
      expect(index).toBe(2);
      expect(timers.size).toBe(0);
      const progress = stderr.text();
      expect(progress.indexOf("VERIFIED  Finding 1")).toBeLessThan(
        progress.indexOf("Patching 2/2"),
      );
      expect(progress).toContain("VERIFIED  Finding 2");
      expect(progress.match(/Codex: Checking the fix\./gu)).toHaveLength(2);
      if (args.includes("--json")) {
        expect(JSON.parse(stdout.text()).patches).toMatchObject([
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ]);
      }
      expect(stdout.text()).not.toContain("\u001B");
    }
  });

  test("uses plain patch progress for noninteractive runs", async () => {
    const saved = ["patch", "--scan", "scan-1", "--json"];
    for (const [interactive, environment, args] of [
      [false, {}, saved],
      [true, { CI: "1" }, saved],
      [true, { TERM: "dumb" }, saved],
      [true, {}, ["scan", "--patch", "--headless"]],
      [true, {}, ["scan", "--patch", "--json"]],
    ] as const) {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        [...args],
        {
          result,
          environment,
          onWorkbench: () => savedScan(result),
        },
        { interactive },
      );
      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain("Patching 1/1 · Finding 1");
      expect(outcome.stderr).not.toContain("\u001B");
    }
  });

  test("stops patch progress on interruption or an agent error", async () => {
    for (const status of [130, "error"] as const) {
      const result = resultWithFindings(["high", "high"]);
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: () => {
            if (status === "error") throw new Error("Agent failed");
            return status;
          },
        },
        {
          interactive: true,
          configure: (current) => {
            current.setInterval = setInterval;
            current.clearInterval = clearInterval;
          },
        },
      );
      expect(outcome.exitCode).not.toBe(0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      expect(outcome.stderr).toContain("\u001B[?25h");
      expect(outcome.stderr).not.toContain("Patching 2/2");
      expect(outcome.stderr).toContain(
        status === "error" ? "Agent failed" : "Patch operation was interrupted",
      );
    }
  });
  test("exposes the validation prompt in patch help and schema", async () => {
    const help = await runWorkflow(["patch", "--help"]);
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("--validation-prompt-file");
    const schema = await runWorkflow(["patch", "--schema", "--json"]);
    expect(schema.exitCode).toBe(0);
    expect(
      JSON.parse(schema.stdout).options.properties.validationPromptFile,
    ).toMatchObject({ type: "string" });
  });

  test.each(["literal", "file", "linear"])(
    "passes custom validation instructions to the %s patch task",
    async (source) => {
      const repository = await temporaryDirectory("patch-validation-");
      const validation =
        "Start the local app. Exercise the fix and a legitimate request. Stop the app.\n";
      try {
        await writeFile(join(repository, "validation.md"), validation);
        await writeFile(
          join(repository, "issues.md"),
          "Synthetic security issue",
        );
        let calls = 0;
        const outcome = await runWorkflow(
          [
            "patch",
            ...(source === "linear"
              ? [
                  "--linear-issue",
                  "SEC-123",
                  "--linear-api-key",
                  "lin_api_SYNTHETIC",
                ]
              : [source === "file" ? "issues.md" : "Synthetic security issue"]),
            "--validation-prompt-file",
            "validation.md",
            "--json",
          ],
          {
            currentDirectory: repository,
            linearClient: () =>
              ({
                issue: async () => ({
                  identifier: "SEC-123",
                  title: "Synthetic security issue",
                  description: "Synthetic issue details",
                  url: "https://linear.app/example/issue/SEC-123",
                  comments: emptyPage,
                }),
              }) as unknown as ReturnType<LinearClientFactory>,
            onCodex: (_args, output) => {
              calls++;
              expect(output?.appServer?.directory).toBe(repository);
              expect(output?.appServer?.prompt).toContain(
                JSON.stringify(validation),
              );
              expect(output?.appServer?.prompt).toContain(
                "$codex-security:fix-finding",
              );
              const issues = JSON.parse(
                output!.appServer!.prompt.split("\n").at(-1)!,
              );
              expect(issues).toHaveLength(1);
              expect(issues[0]).toContain("Synthetic security issue");
              output?.stdout.write("Fixed; runtime validation passed.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode).toBe(0);
        expect(calls).toBe(1);
        expect(JSON.parse(outcome.stdout).report).toBe(
          "Fixed; runtime validation passed.",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("reads validation from the invocation directory once for all saved findings", async () => {
    const directory = await temporaryDirectory("saved-patch-validation-");
    const repository = join(directory, "repository");
    const validation = "Build the app and run the regression tests.\n";
    const result = resultWithFindings(["high", "medium"]);
    let calls = 0;
    try {
      await mkdir(repository);
      await writeFile(join(directory, "validation.md"), validation);
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--validation-prompt-file",
          "validation.md",
          "--json",
        ],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            calls++;
            expect(output?.appServer?.directory).toBe(repository);
            expect(output?.appServer?.prompt).toContain(
              JSON.stringify(validation),
            );
            await rm(join(directory, "validation.md"), { force: true });
            completePatches(args, output, calls === 1 ? "verified" : "blocked");
            return 0;
          },
        },
      );
      expect(calls).toBe(2);
      expect(outcome.exitCode).toBe(1);
      expect(
        JSON.parse(outcome.stdout).patches.map(
          (patch: { status: string }) => patch.status,
        ),
      ).toEqual(["verified", "blocked"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["linked", "root"],
    ["explicit", "root"],
    ["linked", "subdirectory"],
    ["explicit", "subdirectory"],
    ["linked", "nested-worktree"],
    ["explicit", "nested-worktree"],
  ])(
    "checks the invocation checkout boundary for %s prompts from a %s",
    async (kind, invocation) => {
      const root = await temporaryDirectory("patch-prompt-boundary-");
      const checkout = join(root, "invocation");
      const directory =
        invocation === "root" ? checkout : join(checkout, "nested", "cwd");
      const repository = join(root, "repository");
      const outside = join(root, "outside");
      const result = resultWithFindings(["high"]);
      let started = false;
      try {
        await Promise.all(
          [directory, repository, outside].map((path) =>
            mkdir(path, { recursive: true }),
          ),
        );
        execFileSync("git", ["init", "--quiet", checkout]);
        if (invocation === "nested-worktree")
          execFileSync("git", ["init", "--quiet", dirname(directory)]);
        await writeFile(
          join(outside, "validation.md"),
          "Run the synthetic regression test.",
        );
        await symlink(
          outside,
          join(checkout, "validation"),
          process.platform === "win32" ? "junction" : "dir",
        );
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            "scan-1",
            "--validation-prompt-file",
            kind === "linked"
              ? relative(
                  directory,
                  join(checkout, "validation", "validation.md"),
                )
              : join(outside, "validation.md"),
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () => savedScan(result, "scan-1", repository),
            onCodex: (args, output) => {
              started = true;
              completePatches(args, output);
              return 0;
            },
          },
        );
        expect(started).toBe(kind === "explicit");
        expect(outcome.exitCode).toBe(kind === "explicit" ? 0 : 2);
        if (kind === "linked")
          expect(outcome.stderr).toContain("directory links outside");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["missing", "empty", "directory"])(
    "rejects a %s validation prompt before starting a patch",
    async (kind) => {
      const directory = await temporaryDirectory("invalid-patch-validation-");
      try {
        const path = join(directory, "validation.md");
        if (kind === "empty") await writeFile(path, " \n");
        if (kind === "directory") await mkdir(path);
        const onCodex = mock<() => number>().mockReturnValue(0);
        const outcome = await runWorkflow(
          [
            "patch",
            "Synthetic security issue",
            "--validation-prompt-file",
            path,
            "--json",
          ],
          {
            currentDirectory: directory,
            onCodex,
          },
        );
        expect(outcome.exitCode).toBe(2);
        expect(onCodex).not.toHaveBeenCalled();
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          ok: false,
          applied: false,
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("assesses patch risk only when the patch flag is selected", async () => {
    for (const enabled of [false, true]) {
      const result = resultWithFindings(["high"]);
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          "--auth",
          "chatgpt",
          "--scan",
          "scan-1",
          "--json",
          ...(enabled ? ["--assess-patch-risk"] : []),
        ],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: (args, output) => {
            expect(args).toContain('model="gpt-6.1-sol"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(output?.auth).toBe("chatgpt");
            completePatches(args, output);
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async (request) => {
              expect(request.auth).toBe("chatgpt");
              expect(request.configuration.model).toBe("gpt-6.1-sol");
              expect(request.configuration.effort).toBe("max");
              assessments += 1;
              return patchRiskAssessment();
            };
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(enabled ? 1 : 0);
      expect(outcome.stderr.includes("Patch risk assessment:")).toBe(enabled);
      const resultBody = JSON.parse(outcome.stdout) as JsonObject;
      expect("patchRisk" in resultBody).toBe(enabled);
      if (enabled) {
        expect(resultBody["patchRisk"]).toEqual({
          report: patchRiskReport(),
        });
      }
    }
  });

  test("preserves patch-risk details in display and publication summaries", async () => {
    const result = resultWithFindings(["high"]);
    const detail = "Diagnostic detail: token=SYNTHETIC_RISK_VALUE";
    const report = patchRiskAssessment().report.replace(
      patchRiskSummary(),
      `${patchRiskSummary()}\n\n${detail}`,
    );
    const repositoryCommands: Array<{
      command: string;
      args: readonly string[];
    }> = [];
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (command, args) => {
          repositoryCommands.push({ command, args });
          if (command === "git") {
            if (args[0] === "remote") {
              return "https://github.example.test/example/repository.git";
            }
            return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
          }
          return args[1] === "create"
            ? "https://github.example.test/example/repository/pull/15"
            : "";
        },
      },
      {
        configure: (current) => {
          Object.assign(current, {
            assessPatchRisk: async () => ({ report }),
          });
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(outcome.stderr).toContain("Patch risk assessment:");
    expect(outcome.stderr).toContain(patchRiskSummary());
    expect(outcome.stderr).toContain(detail);
    expect(JSON.parse(outcome.stdout).patchRisk.report).toContain(detail);
    const published = repositoryCommands.find(
      ({ command, args }) => command === "gh" && args[1] === "create",
    )?.args;
    const persisted = repositoryCommands.find(
      ({ command, args }) =>
        command === "git" &&
        args[0] === "config" &&
        args[2]?.endsWith(".codexSecurityPatchPullRequestBody"),
    )?.args;
    expect(published).toBeDefined();
    expect(persisted).toBeDefined();
    for (const body of [published?.at(-1), persisted?.at(-1)]) {
      expect(body).toContain(patchRiskSummary());
      expect(body).toContain(detail);
    }
  });

  test("assesses only changes made during a literal patch run", async () => {
    const directory = await temporaryDirectory("codex-security-patch-risk-");
    const repository = join(directory, "repository");
    await mkdir(join(repository, "sub"), { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", "--", "app.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(repository, "app.ts"), "original\nuser change\n");

      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          "Synthetic issue",
          "--assess-patch-risk",
          "--codex",
          "analytics.enabled=false",
          "--codex",
          'model_provider="synthetic.gateway"',
          "--codex",
          'model_providers={"synthetic.gateway"={name="Synthetic",base_url="https://gateway.example.test/v1",wire_api="responses",env_key="SYNTHETIC_KEY"}}',
        ],
        {
          currentDirectory: join(repository, "sub"),
          onCodex: async (args, output) => {
            expect(args).toContain('model="gpt-6.1-sol"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(args).toContain("analytics.enabled=false");
            expect(args).toContain('model_provider="synthetic.gateway"');
            expect(output?.modelProvider).toBe("synthetic.gateway");
            expect(output?.codexOverrides).toMatchObject({
              model_providers: {
                "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
              },
            });
            expect(
              parseToml(
                args.find((arg) => arg.startsWith("model_providers="))!,
              ),
            ).toMatchObject({
              model_providers: {
                "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
              },
            });
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; sha256: string };
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("+patch change");
              expect(patch).not.toContain("+user change");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "app.ts"),
              "original\nuser change\npatch change\n",
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(outcome.stderr).toContain("Patch risk assessment:");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("creates a draft pull request with the Linear patch-risk summary", async () => {
    const directory = await temporaryDirectory(
      "codex-security-linear-patch-pr-",
    );
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/17";
    const expectedBody = [
      "Applies a security fix generated for SEC-123.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const git = repositoryGit(repository);

    try {
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "checkout-hook.sh"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");

      const outcome = await runWorkflow(
        [
          "patch",
          "--linear-issue",
          "SEC-123",
          "--linear-api-key",
          "lin_api_SYNTHETIC",
          "--assess-patch-risk",
          "--create-pr",
        ],
        {
          currentDirectory: join(repository, "src"),
          linearClient: () =>
            ({
              issue: async () => ({
                identifier: "SEC-123",
                title: "Synthetic checkout hook issue",
                description:
                  "The trusted checkout hook resolves an untrusted module.",
                url: "https://linear.app/example/issue/SEC-123",
                comments: async () => ({
                  nodes: [],
                  pageInfo: { hasNextPage: false },
                  fetchNext: async () => undefined,
                }),
              }),
            }) as unknown as ReturnType<LinearClientFactory>,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { changedFiles: string[]; path: string };
              expect(artifact.changedFiles).toEqual(["src/checkout-hook.sh"]);
              expect(await readFile(artifact.path, "utf8")).toContain("+safe");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            expect(output?.appServer?.prompt).toContain("SEC-123");
            await writeFile(
              join(repository, "src", "checkout-hook.sh"),
              "safe\n",
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            expect(commandOptions?.directory ?? workingDirectory).toBe(
              join(repository, "src"),
            );
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe(
        "codex-security/patch-SEC-123",
      );
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/checkout-hook.sh",
      );
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-SEC-123"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-SEC-123",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedBody,
      ]);
      expect(outcome.stderr).toContain("Patch risk assessment:");
      expect(outcome.stderr).toContain(`Pull request: ${url}`);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(pullRequestArguments.at(-1)).not.toContain(
        "trusted checkout hook",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("assesses a patch larger than the repository command buffer", async () => {
    const directory = await temporaryDirectory("codex-security-large-patch-");
    const repository = join(directory, "repository");
    await mkdir(repository, { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "large.txt"), "original\n");
      git("add", "--", "large.txt");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic large issue", "--assess-patch-risk"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; sha256: string };
              const patch = await readFile(artifact.path);
              expect(patch.byteLength).toBeGreaterThan(1024 * 1024);
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "large.txt"),
              "x".repeat(2 * 1024 * 1024),
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([false, true])(
    "patches selected scan findings with analytics.enabled=%p in the scanned repository and returns JSON",
    async (analyticsEnabled) => {
      const result = resultWithFindings(["critical", "high", "medium", "low"]);
      const invocations: Array<{
        args: readonly string[];
        directory: string | undefined;
        prompt: string | undefined;
      }> = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [
          "scan",
          "../other/repository",
          "--patch",
          "--codex",
          `analytics.enabled=${analyticsEnabled}`,
          "--codex",
          "features.goals=false",
          "--patch-severity",
          "high",
          "--fail-on-severity",
          "high",
          "--json",
        ],
        {
          result,
          onCodex: (args, output) => {
            invocations.push({
              args,
              directory: output?.appServer?.directory,
              prompt: output?.appServer?.prompt,
            });
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
      ]);
      expect(invocations).toHaveLength(2);
      for (const invocation of invocations) {
        expect(invocation.args[0]).toBe("app-server");
        expect(invocation.args).toContain(
          `analytics.enabled=${analyticsEnabled}`,
        );
        expect(invocation.args).not.toContain("features.goals=false");
        expect(invocation.directory).toBe(
          resolve(CURRENT_REPOSITORY, "../other/repository"),
        );
        expect(invocation.prompt).toContain("Return exactly one JSON object");
      }
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        manifest: result.manifest,
        findings: result.findings,
        patchSeverity: "high",
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ],
      });
      expect(outcome.stderr).toContain("Patching 2 confirmed findings...");
    },
  );

  test("continues with separate patch tasks when one finding fails", async () => {
    const result = resultWithFindings(["critical", "high", "medium"]);
    const tasks: string[] = [];
    const outcome = await runWorkflow(["scan", "--patch", "--json"], {
      result,
      onCodex: (args, output) => {
        expect(args[0]).toBe("app-server");
        const [finding] = JSON.parse(
          output!.appServer!.prompt.split("\n").at(-1)!,
        ) as Finding[];
        tasks.push(finding!.occurrenceId);
        if (finding!.occurrenceId === "occ_2") return 1;
        completePatches(args, output);
        return 0;
      },
    });

    expect(tasks).toEqual(["occ_1", "occ_2", "occ_3"]);
    expect(outcome.exitCode).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        { occurrenceId: "occ_1", status: "verified" },
        {
          occurrenceId: "occ_2",
          status: "failed",
          reason: "Patch command exited with status 1.",
        },
        { occurrenceId: "occ_3", status: "verified" },
      ],
    });
  });

  test.each(["synthetic.provider", "openai"])(
    "preserves %s command-provider authentication when patching after a scan",
    async (provider) => {
      const home = join(tmpdir(), "synthetic-auth-home");
      let providerOverride: string | undefined;
      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--auth",
          "api-key",
          "--json",
          "--codex",
          `model_provider=${JSON.stringify(provider)}`,
          "--codex",
          `model_providers={${JSON.stringify(provider)}={name="Synthetic",auth={command="./synthetic-auth",args=["--json"]}}}`,
        ],
        {
          result: resultWithFindings(["high"]),
          environment: {
            CODEX_HOME: home,
          },
          onCodex: (args, output) => {
            providerOverride = args.find((arg) =>
              arg.startsWith("model_providers="),
            );
            expect(output?.modelProvider).toBe(provider);
            expect(output?.codexOverrides).toMatchObject({
              model_providers: {
                [provider]: {
                  auth: {
                    command: "./synthetic-auth",
                    args: ["--json"],
                  },
                },
              },
            });
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(parseToml(providerOverride!)).toEqual({
        model_providers: {
          [provider]: {
            name: "Synthetic",
            auth: { command: "./synthetic-auth", args: ["--json"], cwd: home },
          },
        },
      });
    },
  );

  test("passes the scan model, provider, and selected authentication to patching", async () => {
    const result = resultWithFindings(["high"]);
    let invocation: readonly string[] = [];
    let authentication: string | undefined;
    const chatgpt = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "chatgpt",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "high",
        "--json",
      ],
      {
        result,
        environment: {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_KEY_123",
          CODEX_SECURITY_STATE_DIR: STATE_DIRECTORY,
        },
        onCodex: (args, output, selectedEnvironment) => {
          invocation = args;
          authentication = output?.auth;
          expect(selectedEnvironment?.["CODEX_SECURITY_STATE_DIR"]).toBe(
            STATE_DIRECTORY,
          );
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(chatgpt.exitCode).toBe(0);
    expect(invocation).toContain('model="gpt-5.6-terra"');
    expect(invocation).toContain('model_reasoning_effort="high"');
    expect(authentication).toBe("chatgpt");

    const attributed = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "api-key",
        "--safety-identifier",
        "synthetic-user",
        "--codex",
        'model_reasoning_effort="ultra"',
        "--json",
      ],
      {
        result,
        environment: { OPENAI_API_KEY: "synthetic-key" },
        onCodex: (args, output) => {
          invocation = args;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(attributed.exitCode).toBe(0);
    expect(invocation).toContain('safety_identifier="synthetic-user"');
    expect(invocation).toContain('model_reasoning_effort="ultra"');

    for (const selection of [
      ["--provider", "fireworks"],
      ["--codex", 'model_provider="fireworks"'],
      [
        "--codex",
        'profile="synthetic"',
        "--codex",
        'profiles.synthetic.model_provider="fireworks"',
      ],
    ]) {
      const provider = await runWorkflow(
        [
          "scan",
          "--patch",
          ...selection,
          "--model",
          "accounts/fireworks/models/example",
          "--json",
        ],
        {
          result,
          environment: { FIREWORKS_API_KEY: "SYNTHETIC_FIREWORKS_KEY_123" },
          onCodex: (args, output) => {
            invocation = args;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(provider.exitCode).toBe(0);
      expect(invocation).toContain('model_provider="fireworks"');
      expect(
        invocation.some(
          (argument) =>
            argument.startsWith("model_providers=") &&
            argument.includes('"env_key"="FIREWORKS_API_KEY"'),
        ),
      ).toBe(true);
    }
  });

  test("publishes only verified patch files and preserves unrelated staged changes", async () => {
    const directory = await temporaryDirectory("codex-security-patch-pr-");
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/15";
    const result = resultWithFindings(["high", "medium"]);
    result.findings.findings[0]!.title = "Synthetic private finding";
    const expectedPullRequestBody = [
      "Applies verified security fixes from a completed scan.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const githubCommands: string[][] = [];
    await mkdir(join(repository, "src"), { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
      await writeFile(join(repository, "unrelated.ts"), "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");
      await writeFile(join(repository, "unrelated.ts"), "staged separately\n");
      git("add", "--", "unrelated.ts");

      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan",
          "--severity",
          "high",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => savedScan(result, "scan", repository),
          onCodex: async (args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              expect(output.command).toBe("patch");
              expect(output.appServer?.sandbox).toBe("read-only");
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:start -->",
              );
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:end -->",
              );
              const artifact = JSON.parse(
                output
                  .appServer!.prompt.split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as {
                path: string;
                sourceType: string;
                changedFiles: string[];
                sha256: string;
              };
              const patch = await readFile(artifact.path);
              expect(artifact.sourceType).toBe("patch_file");
              expect(artifact.changedFiles).toEqual(["src/finding-1.ts"]);
              expect(patch.toString()).toEndWith("+fixed  \n");
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "src", "finding-1.ts"),
              "fixed  \n",
            );
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            expect(workingDirectory).toBe(repository);
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            githubCommands.push([...args]);
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/finding-1.ts",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.ts");
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-scan"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-scan",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedPullRequestBody,
      ]);
      expect(
        git(
          "config",
          "--get",
          "branch.codex-security/patch-scan.codexSecurityPatchPullRequestBody",
        ),
      ).toBe(expectedPullRequestBody);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(JSON.stringify(pullRequestArguments)).not.toContain(
        "Synthetic private finding",
      );
      expect(githubCommands.some((args) => args[1] === "comment")).toBe(false);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        pullRequest: { branch: "codex-security/patch-scan", url },
        patchRisk: { report: patchRiskReport() },
      });
      expect(outcome.stdout).not.toContain("codex-security:patch-risk-summary");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["github", "push"],
    ["github", "create"],
    ["gitlab", "push"],
    ["gitlab", "create"],
  ])(
    "resumes %s publication after %s fails without patching again",
    async (provider, failure) => {
      const directory = await temporaryDirectory("codex-security-pr-retry-");
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const branch = "codex-security/patch-scan-1";
      const gitlab = provider === "gitlab";
      const origin = "https://gitlab.com/example/subgroup/repository.git";
      const url = gitlab
        ? "https://gitlab.com/example/subgroup/repository/-/merge_requests/16"
        : "https://github.example.test/example/repository/pull/16";
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushCalls = 0;
      let created = 0;
      let failOnce = true;
      let publishedUrl = "";
      await mkdir(join(repository, "src"), { recursive: true });
      const git = repositoryGit(repository);

      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
        await writeFile(join(repository, "unrelated.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");

        const fixtures: Parameters<typeof dependencies>[0] = {
          currentDirectory: repository,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            modelCalls += 1;
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (gitlab && args[0] === "remote") {
                expect(args).toEqual(["remote", "get-url", "--push", "origin"]);
                return origin;
              }
              if (gitlab && args[0] === "ls-remote") {
                expect(args[2]).toBe(origin);
                return git(
                  ...args.map((value) => (value === origin ? remote : value)),
                );
              }
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return git(...args);
            }
            expect(command).toBe(gitlab ? "glab" : "gh");
            if (args[1] === "list")
              return publishedUrl
                ? JSON.stringify({
                    url: publishedUrl,
                    head: git("rev-parse", `refs/heads/${branch}`),
                    state: gitlab ? "opened" : "OPEN",
                  })
                : "";
            expect(args[1]).toBe("create");
            if (failure === "create" && failOnce) {
              failOnce = false;
              throw new Error("Synthetic PR service failure");
            }
            created += 1;
            publishedUrl = url;
            return url;
          },
        };

        const first = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          fixtures,
        );
        expect(first.exitCode).toBe(2);
        expect(first.stderr).toContain(`patch --resume-pr ${branch}`);
        const commit = git("rev-parse", "HEAD");
        expect(
          git("config", "--get", `branch.${branch}.codexSecurityPatchCommit`),
        ).toBe(commit);
        if (failure === "create") {
          expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        }
        await writeFile(join(repository, "unrelated.ts"), "later local work\n");

        const retry = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          fixtures,
        );
        expect(retry.exitCode).toBe(0);
        expect(JSON.parse(retry.stdout)).toEqual({
          pullRequest: { branch, url },
        });
        expect(modelCalls).toBe(1);
        expect(created).toBe(1);
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        expect(git("diff", "--name-only")).toBe("unrelated.ts");

        const pushes = pushCalls;
        const repeated = await runWorkflow(
          ["patch", "--resume-pr", branch],
          fixtures,
        );
        expect(repeated.exitCode).toBe(0);
        expect(created).toBe(1);
        expect(pushCalls).toBe(pushes);
        expect(modelCalls).toBe(1);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("refuses to resume a missing or changed patch commit", async () => {
    for (const saved of ["", "saved-commit"]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            expect(command).toBe("git");
            return args[0] === "config" ? saved : "changed-commit";
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        saved ? "changed since verification" : "No verified patch commit",
      );
      expect(onCodex).toHaveBeenCalledTimes(0);
    }
  });

  test("rejects new patch inputs when resuming publication", async () => {
    for (const input of [
      ["--scan", "scan-1"],
      ["--model", "gpt-6-astra"],
      ["--linear-issue", "SEC-123"],
      ["--create-pr"],
      ["--assess-patch-risk"],
      ["--validation-prompt-file", "validation.md"],
      ["--external-sandbox"],
      ["occ_1"],
    ]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const onRepositoryCommand = mock<() => string>().mockReturnValue("");
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", ...input],
        {
          onCodex,
          onRepositoryCommand,
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("--resume-pr cannot be combined");
      expect(onCodex).not.toHaveBeenCalled();
      expect(onRepositoryCommand).not.toHaveBeenCalled();
    }
  });

  test("does not publish blocked, unchanged, or repository-external patches", async () => {
    for (const status of ["blocked", "no_change", "outside"] as const) {
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: status === "outside" ? "verified" : status,
                    files: status === "outside" ? ["../outside.ts"] : [],
                    ...(status === "blocked"
                      ? { reason: "A required service is unavailable." }
                      : { verification: "Focused checks pass." }),
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            commandStarted ||=
              (command !== "git" && args[1] !== "list") ||
              ["checkout", "commit", "push"].includes(args[0]!);
            return status === "outside" && args.includes("--name-only")
              ? "src/finding-1.ts\0"
              : "";
          },
        },
      );

      expect(commandStarted).toBe(false);
      expect(outcome.exitCode).toBe(
        status === "blocked" ? 1 : status === "outside" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout)).not.toHaveProperty("pullRequest");
      if (status === "outside") {
        expect(outcome.stderr).toContain(
          "Patch files must remain inside the scanned repository.",
        );
      }
    }
  });

  test("keeps completed scan results when publication preflight fails", async () => {
    const outcome = await runWorkflow(
      ["scan", "--patch", "--create-pr", "--json"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          if (command === "gh")
            throw new Error("GitHub authentication failed.");
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("GitHub authentication failed.");
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [],
    });
  });

  test.each([
    ["blocked", undefined],
    ["failed", undefined],
    ["malformed", undefined],
    ["verified", undefined],
    ["verified", " \n\t "],
    ["no_change", undefined],
    ["no_change", " \n\t "],
  ] as const)(
    "keeps %s patch results with verification %j unresolved",
    async (status, verification) => {
      const reason = "The requested check did not complete.";
      const outcome = await runWorkflow(
        ["scan", "--patch", "--fail-on-severity", "high", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              status === "malformed"
                ? "The patch is probably fixed."
                : JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status,
                        files: [],
                        verification,
                        ...(status === "blocked" || status === "failed"
                          ? { reason }
                          : {}),
                      },
                    ],
                  }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status === "blocked" ? 1 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status: status === "blocked" ? "blocked" : "failed",
            reason:
              status === "verified" || status === "no_change"
                ? "Patch verification was not reported."
                : status === "malformed"
                  ? "Patch results were not valid JSON."
                  : reason,
          },
        ],
      });
    },
  );

  test("does not patch incomplete scans or allow patching during a dry run", async () => {
    const onCodex = mock<() => number>().mockReturnValue(0);
    const incomplete = resultWithFindings(["high"]);
    incomplete.coverage.completeness = "partial";
    const partial = await runWorkflow(["scan", "--patch", "--json"], {
      result: incomplete,
      onCodex,
    });
    expect(partial.exitCode).toBe(2);
    expect(onCodex).not.toHaveBeenCalled();

    const dryRun = await runWorkflow(["scan", "--patch", "--dry-run"]);
    expect(dryRun.exitCode).toBe(2);
    expect(dryRun.stderr).toContain(
      "--patch cannot be combined with --dry-run",
    );
  });

  test("reviews full findings and honors individual interactive patch selections", async () => {
    for (const [argv, selection, expected] of [
      [
        ["scan"],
        { severity: "medium", occurrenceIds: ["occ_1", "occ_2"] },
        ["occ_1", "occ_2"],
      ],
      [
        ["scan", "--patch"],
        { severity: "low", occurrenceIds: ["occ_1", "occ_3"] },
        ["occ_1", "occ_3"],
      ],
      [["scan"], null, []],
    ] as const) {
      let reviewed: readonly Finding[] = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [...argv],
        {
          result: resultWithFindings(["high", "medium", "low"]),
          onCodex: (args, output) => {
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
        {
          interactive: true,
          configure: (value) => {
            value.patchEditor = async (repository, candidates) => {
              expect(repository).toBe(CURRENT_REPOSITORY);
              reviewed = candidates;
              return selection === null
                ? null
                : {
                    severity: selection.severity,
                    occurrenceIds: [...selection.occurrenceIds],
                  };
            };
          },
        },
      );
      expect(outcome.exitCode).toBe(0);
      expect(reviewed.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
        "occ_3",
      ]);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        ...expected,
      ]);
      if (argv[1] === "--patch") {
        expect(outcome.stderr).not.toContain(
          "Review and patch these findings?",
        );
      } else {
        expect(outcome.stderr).toContain("Review and patch these findings?");
      }
    }
  });

  test("shows normal scan findings before optionally opening patch review", async () => {
    for (const review of [true, false]) {
      let opened = false;
      let patched = false;
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (args, output) => {
            patched = true;
            completePatches(args, output);
            return 0;
          },
        },
        {
          interactive: true,
          review,
          configure: (value) => {
            value.patchEditor = async () => {
              opened = true;
              return { severity: "high", occurrenceIds: ["occ_1"] };
            };
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr.indexOf("FINDINGS")).toBeLessThan(
        outcome.stderr.indexOf("Review and patch these findings? (y/N)"),
      );
      expect(opened).toBe(review);
      expect(patched).toBe(review);
    }
  });

  test("does not offer patch review when there are no actionable findings", async () => {
    for (const severities of [[], ["informational"]] as const) {
      const confirmPatchReview = mock(resolving(true));
      const patchEditor = mock(resolving(null));
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(severities),
          environment: { NO_COLOR: "1" },
        },
        {
          interactive: true,
          configure: (value) => {
            value.confirmPatchReview = confirmPatchReview;
            value.patchEditor = patchEditor;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain(`FINDINGS  ${severities.length}`);
      expect(outcome.stderr).not.toContain("Review and patch these findings?");
      expect(confirmPatchReview).not.toHaveBeenCalled();
      expect(patchEditor).not.toHaveBeenCalled();
    }
  });

  test("sanitizes interactive patch status", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    finding.title = "\u001B[31mUnsafe title\u001B[0m\nforged line";
    finding.locations[0]!.path = "src/\u001B[31mquery.ts\u001B[0m";
    const outcome = await runWorkflow(
      ["scan"],
      { result },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
          });
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stderr).toContain("VERIFIED  Unsafe title forged line");
    expect(outcome.stderr).not.toContain("Unsafe title\u001B[0m");
  });

  test("passes separate instructions only for interactively selected findings", async () => {
    const prompts: string[] = [];
    const patched: Finding[] = [];
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high", "medium", "low"]),
        onCodex: (args, output) => {
          prompts.push(output!.appServer!.prompt);
          patched.push(...completePatches(args, output));
          return 0;
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "low",
            occurrenceIds: ["occ_1", "occ_3"],
            instructions: {
              occ_1: "Reuse the shared validator.\nDo not add a dependency.",
              occ_2: "This unselected guidance must not reach the model.",
              occ_3: "Preserve the public API.",
            },
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_3",
    ]);

    expect(prompts).toHaveLength(2);
    for (const [index, prompt] of prompts.entries()) {
      const lines = prompt.split("\n");
      const instructionsLine = lines.findIndex((line) =>
        line.startsWith("Follow these user-provided patch instructions"),
      );
      expect(instructionsLine).toBeGreaterThan(-1);
      expect(JSON.parse(lines[instructionsLine + 1]!)).toEqual(
        index === 0
          ? { occ_1: "Reuse the shared validator.\nDo not add a dependency." }
          : { occ_3: "Preserve the public API." },
      );
      expect(prompt).not.toContain("This unselected guidance");
    }
    expect(patched[0]).not.toHaveProperty("instructions");
  });

  test("creates a draft pull request when selected in the interactive review", async () => {
    let published = false;
    const url = "https://github.example.test/example/repository/pull/13";
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          published ||= command === "gh" && args[1] === "create";
          return command === "gh" && args[1] === "create"
            ? url
            : args.includes("--name-only")
              ? "src/finding-1.ts\0"
              : "";
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
            createPullRequest: true,
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(published).toBe(true);
    expect(outcome.stderr).toContain(`Pull request: ${url}`);
  });

  test("patches a saved scan by severity and supports structured output", async () => {
    const result = resultWithFindings(["high", "medium"]);
    let patched: Finding[] = [];
    let workingDirectory = "";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--severity", "high", "--json"],
      {
        onWorkbench: (args): JsonObject => {
          expect(args).toEqual(["get-scan", "--scan-id", "scan-1"]);
          return savedScan(result);
        },
        onCodex: (args, output) => {
          workingDirectory = output!.appServer!.directory;
          patched = completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(workingDirectory).toBe(SAVED_REPOSITORY);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual(["occ_1"]);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      scanId: "scan-1",
      repository: SAVED_REPOSITORY,
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
    });
  });

  test.each([
    [
      "https://github.example.test/example/repository.git",
      { GITLAB_HOST: "gitlab.com" },
      "gh",
    ],
    ["https://gitlab.com/example/subgroup/repository.git", {}, "glab"],
    ["git@gitlab.com:example/subgroup/repository.git", {}, "glab"],
    ["ssh://git@gitlab.com:2222/example/subgroup/repository.git", {}, "glab"],
    [
      "git@gitlab.example.test:example/subgroup/repository.git",
      { GITLAB_HOST: "gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_HOST: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_URI: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GL_HOST: "gitlab.example.test" },
      "glab",
    ],
    ["https://gitlab.example.test/example/repository.git", {}, "gh"],
  ] as const)(
    "publishes saved-finding patches for origin %s with environment %j using %s",
    async (origin, environment, client) => {
      const result = resultWithFindings(["high"]);
      const url =
        client === "glab"
          ? "https://gitlab.example.test/example/repository/-/merge_requests/14"
          : "https://github.example.test/example/repository/pull/14";
      const publicationCommands: Array<readonly string[]> = [];
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          environment,
          onWorkbench: () => savedScan(result),
          onRepositoryCommand: (command, args, target) => {
            expect(target).toBe(SAVED_REPOSITORY);
            if (command === "git") {
              if (args.includes("--show-toplevel")) return SAVED_REPOSITORY;
              if (args.includes("--cached")) return "";
              if (args[0] === "remote") {
                expect(args).toEqual(["remote", "get-url", "--push", "origin"]);
                return origin;
              }
              return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
            }
            expect(command).toBe(client);
            publicationCommands.push(args);
            return args[1] === "create" ? url : "";
          },
        },
        {
          configure: (current) => {
            Object.assign(current, {
              assessPatchRisk: async () => patchRiskAssessment(),
            });
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(publicationCommands.map((args) => args[1])).toEqual([
        "list",
        "list",
        "create",
      ]);
      if (client === "glab") {
        expect(publicationCommands.slice(1)).toEqual([
          [
            "mr",
            "list",
            "--all",
            "--source-branch",
            "codex-security/patch-scan-1",
            "--output",
            "json",
            "--jq",
            ".[0] | select(. != null) | {url: .web_url, head: .sha, state}",
            "--repo",
            origin,
          ],
          [
            "mr",
            "create",
            "--draft",
            "--head",
            origin,
            "--source-branch",
            "codex-security/patch-scan-1",
            "--title",
            "fix: patch verified security findings",
            "--description",
            expect.stringContaining(patchRiskSummary()),
            "--yes",
            "--repo",
            origin,
          ],
        ]);
      }
      expect(outcome.stderr).toContain(
        `${client === "glab" ? "Merge" : "Pull"} request: ${url}`,
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        scanId: "scan-1",
        pullRequest: { branch: "codex-security/patch-scan-1", url },
      });
    },
  );

  test.each(["patch", "scan"])(
    "escapes controls in %s pull request failures while preserving error details",
    async (command) => {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr"]
          : ["scan", ".", "--patch", "--create-pr"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onRepositoryCommand: throwing(
            "GitHub rejected github_pat_SYNTHETIC_SECRET_123\u001b[2J\ncontinued",
          ),
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "GitHub rejected github_pat_SYNTHETIC_SECRET_123 [2J continued\n",
      );
      expect(outcome.stderr).not.toContain("\u001b");
    },
  );

  test("resolves a finding identifier to its saved scan and checkout", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    const calls: Array<readonly string[]> = [];
    let patched: Finding[] = [];
    const outcome = await runWorkflow(["patch", "occ_1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-global-findings") {
          return {
            findings: [
              { ...finding, scanId: "scan-1" } as unknown as JsonObject,
            ],
          };
        }
        return savedScan(result);
      },
      onCodex: (args, output) => {
        patched = completePatches(args, output);
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-global-findings", "--status", "open"],
      ["get-scan", "--scan-id", "scan-1", "--occurrence-id", "occ_1"],
    ]);
    expect(patched).toEqual([finding]);
  });

  test("selects the latest completed scan for the current repository", async () => {
    const result = resultWithFindings(["high"]);
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "latest"], {
      currentDirectory: SAVED_REPOSITORY,
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-scans") {
          return { scans: [{ scanId: "scan-complete" }] };
        }
        return savedScan(result, "scan-complete");
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", SAVED_REPOSITORY, "--status", "complete"],
      ["get-scan", "--scan-id", "scan-complete"],
    ]);
  });

  test("reads every page when saved scan findings are truncated", async () => {
    const result = resultWithFindings(["high", "medium"]);
    const patched: Finding[] = [];
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "scan-1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "get-scan") {
          return {
            scan: {
              scanId: "scan-1",
              targetPath: SAVED_REPOSITORY,
              findings: [],
              findingsTruncated: true,
            },
          };
        }
        const secondPage = args.includes("--offset");
        return {
          findingsPage: {
            findings: [
              result.findings.findings[
                secondPage ? 1 : 0
              ] as unknown as JsonObject,
            ],
            nextOffset: secondPage ? null : 1,
          },
        };
      },
      onCodex: (args, output) => {
        patched.push(...completePatches(args, output));
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_2",
    ]);
    expect(calls).toEqual([
      ["get-scan", "--scan-id", "scan-1"],
      ["list-findings", "--scan-id", "scan-1", "--status", "open"],
      [
        "list-findings",
        "--scan-id",
        "scan-1",
        "--status",
        "open",
        "--offset",
        "1",
      ],
    ]);
  });

  test("rejects a severity threshold without an explicit patch request", async () => {
    const outcome = await runWorkflow(["scan", "--patch-severity", "high"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("--patch-severity requires --patch");
  });

  test("requires patching and a clean supplied-issue checkout before creating a pull request", async () => {
    const scan = await runWorkflow(["scan", "--create-pr"]);
    expect(scan.exitCode).toBe(2);
    expect(scan.stderr).toContain("--create-pr requires --patch");

    const directory = await temporaryDirectory("codex-security-dirty-pr-");
    const git = repositoryGit(directory);
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", "--", "app.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(directory, "app.ts"), "user change\n");
      const onCodex = mock<() => number>().mockReturnValue(0);
      const literal = await runWorkflow(
        ["patch", "Synthetic security issue", "--create-pr"],
        {
          currentDirectory: directory,
          onCodex,
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );
      expect(literal.exitCode).toBe(2);
      expect(literal.stderr).toContain(
        "Pull request creation for supplied issues requires a clean working tree.",
      );
      expect(onCodex).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

test.each(["linked", "explicit"])(
  "preserves the selected worktree boundary for an external %s validation prompt",
  async (kind) => {
    const root = await temporaryDirectory("patch-external-validation-");
    const repository = join(root, "repository");
    const invocation = join(root, "invocation");
    const outside = join(root, "outside");
    const gitEnvironment = {
      GIT_DIR: join(repository, ".git"),
      GIT_WORK_TREE: repository,
    };
    let started = false;
    try {
      for (const directory of [repository, invocation, outside])
        await mkdir(directory);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      await writeFile(
        join(outside, "validation.md"),
        "Run the synthetic regression test.",
      );
      await symlink(
        outside,
        join(repository, "validation"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--validation-prompt-file",
          join(
            kind === "linked" ? join(repository, "validation") : outside,
            "validation.md",
          ),
          "--json",
        ],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, directory, options) =>
            runGitRepositoryCommand(command, args, directory, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: (_args, output) => {
            started = true;
            expect(output?.appServer?.prompt).toContain(
              "Run the synthetic regression test.",
            );
            return 1;
          },
        },
      );
      expect(started, outcome.stderr).toBe(kind === "explicit");
      if (kind === "linked")
        expect(outcome.stderr).toContain("directory links outside");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each([
  "ordinary",
  "removed component",
  "explicit Git environment",
  "removed component with explicit Git environment",
])(
  "preserves disposable assessment worktrees and explicit Git settings: %s",
  async (kind) => {
    const root = await temporaryDirectory("patch-disposable-assessment-");
    const repository = join(root, "repository");
    const component = join(repository, "sub");
    const disposable = join(root, "disposable");
    const gitEnvironment = kind.includes("explicit Git environment")
      ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
      : {};
    try {
      await mkdir(component, { recursive: true });
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(component, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("worktree", "add", "--detach", disposable, "HEAD");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: component,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, directory, options) =>
            runGitRepositoryCommand(command, args, directory, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output, environment) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const selected = gitText(
                ["-C", disposable, "rev-parse", "--show-toplevel"],
                { cwd: output.appServer.directory, env: environment },
              ).trim();
              expect(selected).toBe(
                kind.includes("explicit Git environment")
                  ? repository
                  : disposable,
              );
              output.stdout.write(patchRiskAssessment().report);
            } else {
              if (kind.startsWith("removed component"))
                await rm(component, { recursive: true });
              else await writeFile(join(component, "app.ts"), "fixed\n");
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

describe("patch publication integrity", () => {
  const fixtures = createTemporaryDirectories();
  afterEach(fixtures.cleanup);
  test.each(["commit", "commit result", "checkpoint"])(
    "preserves local work when patch %s fails",
    async (failure) => {
      const directory = await fixtures.create("patch-creation-failure-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
      await writeFile(join(directory, "other.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-creation-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      await writeFile(join(directory, "other.ts"), "staged work\n");
      git("add", "other.ts");
      const base = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command !== "git") return "";
            if (failure === "commit result" && args.includes("commit")) {
              runGitRepositoryCommand(command, args, cwd, options);
              throw new Error("Synthetic commit result failure");
            }
            if (
              (failure === "commit" && args.includes("commit")) ||
              (failure === "checkpoint" && args[0] === "config")
            )
              throw new Error(`Synthetic ${failure} failure`);
            return runGitRepositoryCommand(command, args, cwd, options);
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(`Synthetic ${failure} failure`);
      expect(outcome.stderr).not.toContain("Retry from this repository");
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("other.ts");
      if (failure === "commit") {
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("rev-parse", "HEAD")).toBe(base);
        expect(git("write-tree")).toBe(index);
        expect(
          git(
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/codex-security/patch-scan-1",
          ),
        ).toBe("");
      } else {
        expect(git("branch", "--show-current")).toBe(
          "codex-security/patch-scan-1",
        );
        expect(git("rev-parse", "HEAD")).not.toBe(base);
        expect(outcome.stderr).toContain("checkpoint could not be saved");
      }
    },
  );

  test.each(["gh", "glab"])(
    "refuses a %s resume when the published head differs from the saved commit",
    async (client) => {
      const onCodex = mock(() => 0);
      let pushes = 0;
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", "--json"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (args[0] === "config")
                return args.at(-1)?.endsWith("PatchCommit")
                  ? "verified-commit"
                  : "Synthetic body";
              if (args[0] === "rev-parse") return "verified-commit";
              if (args[0] === "remote")
                return `https://${client === "glab" ? "gitlab.com" : "github.example.test"}/example/repository.git`;
              if (args[0] === "push") pushes += 1;
              return "";
            }
            expect(command).toBe(client);
            return JSON.stringify({
              url: "https://example.test/requests/1",
              head: "earlier-commit",
              state: "OPEN",
            });
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("does not match the saved patch commit");
      expect(outcome.stderr).not.toContain("Retry from this repository");
      expect(pushes).toBe(0);
      expect(onCodex).not.toHaveBeenCalled();
    },
  );

  test.each(["staged", "unstaged", "assume-unchanged"])(
    "keeps %s same-file edits out of saved patch publication",
    async (dirty) => {
      for (const command of ["patch", "scan"]) {
        const directory = await fixtures.create("patch-publication-");
        const git = repositoryGit(directory);
        const result = resultWithFindings(["high"]);
        await mkdir(join(directory, "src"));
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(
          join(directory, "src/finding-1.ts"),
          "unsafe\noriginal\n",
        );
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const originalHead = git("rev-parse", "HEAD");
        await writeFile(
          join(directory, "src/finding-1.ts"),
          "unsafe\nlocal edit\n",
        );
        if (dirty === "staged") git("add", ".");
        if (dirty === "assume-unchanged")
          git("update-index", "--assume-unchanged", "src/finding-1.ts");
        const originalIndex = git("write-tree");
        const remote = await fixtures.create("patch-publication-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          command === "patch"
            ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
            : ["scan", directory, "--patch", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            result,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (args, output) => {
              await writeFile(
                join(directory, "src/finding-1.ts"),
                "fixed\nlocal edit\n",
              );
              completePatches(args, output);
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(originalHead);
        expect(git("write-tree")).toBe(originalIndex);
        expect(git("ls-remote", "origin")).toBe("");
        expect(
          await readFile(join(directory, "src/finding-1.ts"), "utf8"),
        ).toBe("fixed\nlocal edit\n");
      }
    },
  );

  test.each(["local", "remote", "push remote", "OPEN", "CLOSED", "MERGED"])(
    "checks an existing %s patch publication before starting the model",
    async (existing) => {
      const directory = await fixtures.create("patch-repeat-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-repeat-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      if (existing === "local") git("branch", "codex-security/patch-scan-1");
      if (existing === "push remote") {
        const pushRemote = await fixtures.create("patch-repeat-push-remote-");
        git("init", "--bare", pushRemote);
        git("remote", "set-url", "--push", "origin", pushRemote);
      }
      if (existing === "remote" || existing === "push remote")
        git("push", "origin", "HEAD:refs/heads/codex-security/patch-scan-1");
      const result = resultWithFindings(["high"]);
      const onCodex = mock(() => 0);
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : existing === "remote" || existing === "push remote"
                ? ""
                : JSON.stringify({
                    url: "https://github.example.test/example/repository/pull/1",
                    head: git("rev-parse", "HEAD"),
                    state: existing,
                  }),
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(onCodex).not.toHaveBeenCalled();
      expect(outcome.stderr).toContain("already exists");
    },
  );

  test.each([130, 143])(
    "retains completed and partial patch changes after exit %s",
    async (status) => {
      const directory = await fixtures.create("patch-interrupted-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high", "high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      for (const index of [1, 2])
        await writeFile(join(directory, `src/finding-${index}.ts`), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (args, output) => {
            calls += 1;
            await writeFile(
              join(directory, `src/finding-${calls}.ts`),
              "changed\n",
            );
            if (calls === 2) return status;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        filesChanged: 2,
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          {
            occurrenceId: "occ_2",
            status: "failed",
            files: ["src/finding-2.ts"],
          },
        ],
      });
    },
  );

  test.each(["outer", "nested"])(
    "ignores %s build output when a repository contains a gitlink",
    async (location) => {
      const directory = await fixtures.create("patch-git-ignore-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, ".gitignore"), "build.log\n");
      const nested = join(directory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, ".gitignore"), "build.log\n");
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(
              join(location === "outer" ? directory : nested, "build.log"),
              "build finished\n",
            );
            output?.stdout.write("No source changes were needed.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: false,
        files: [],
      });
      expect(git("status", "--porcelain")).toBe("");
    },
  );

  test.each([false, true])(
    "resolves pre-existing dirty paths from the Git root for a subdirectory scan: overlap=%s",
    async (overlap) => {
      const directory = await fixtures.create(
        "patch-subdirectory-publication-",
      );
      const git = repositoryGit(directory);
      const scanned = join(directory, "package");
      await mkdir(scanned);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "package.json"), "root original\n");
      await writeFile(join(scanned, "package.json"), "unsafe\noriginal\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const dirty = overlap ? "package/package.json" : "package.json";
      await writeFile(join(directory, dirty), "unsafe\nlocal edit\n");
      git("add", dirty);
      const originalHead = git("rev-parse", "HEAD");
      const originalIndex = git("write-tree");
      const remote = await fixtures.create("patch-subdirectory-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "package.json";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: scanned,
          onWorkbench: () => savedScan(result, "scan-1", scanned),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? ""
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(
              join(scanned, "package.json"),
              overlap ? "fixed\nlocal edit\n" : "fixed\noriginal\n",
            );
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(overlap ? 2 : 0);
      if (overlap) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(originalHead);
        expect(git("write-tree")).toBe(originalIndex);
        expect(git("ls-remote", "origin")).toBe("");
      } else {
        expect(git("diff", "--cached", "--name-only")).toBe("package.json");
        expect(git("diff", "--name-only", originalHead, "HEAD")).toBe(
          "package/package.json",
        );
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      }
    },
  );

  test.each([
    ["committed", "root"],
    ["uncommitted", "root"],
    ["committed", "component"],
    ["uncommitted", "component"],
  ])(
    "preserves supplied-issue submodule publication with %s changes from %s",
    async (state, invocation) => {
      const directory = await fixtures.create("patch-submodule-publication-");
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      await mkdir(nested, { recursive: true });
      const component = join(checkout, "component");
      await mkdir(component);
      const currentDirectory =
        invocation === "component" ? component : checkout;
      const git = repositoryGit(checkout);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
        run("config", "commit.gpgsign", "false");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      const original = inner("rev-parse", "HEAD");
      await writeFile(join(nested, "app.ts"), "fixed\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested fix");
      const fixed = inner("rev-parse", "HEAD");
      inner("checkout", original);
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      git("config", "diff.relative", "true");
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const remote = join(directory, "remote.git");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let published = false;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "list") return "";
            published = true;
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async () => {
            if (state === "committed") inner("checkout", fixed);
            else await writeFile(join(nested, "app.ts"), "fixed\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        state === "committed" ? 0 : 2,
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: (state === "committed"
          ? ["dependency", "dependency/app.ts"]
          : ["dependency/app.ts"]
        ).map((file) =>
          relative(currentDirectory, join(checkout, file)).split(sep).join("/"),
        ),
      });
      expect(published).toBe(state === "committed");
      if (state === "committed") {
        expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
          "dependency",
        );
        expect(git("rev-parse", "HEAD:dependency")).toBe(fixed);
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      } else {
        expect(outcome.stderr).toContain("submodule");
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("branch", "--format=%(refname)")).toBe("refs/heads/main");
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
      }
    },
  );

  test("keeps the original branch when a verified file belongs to a nested repository", async () => {
    const directory = await fixtures.create("patch-nested-publication-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const nested = join(directory, "nested");
    await mkdir(nested);
    const inner = repositoryGit(nested);
    inner("init", "--initial-branch=main");
    inner("config", "user.name", "Synthetic User");
    inner("config", "user.email", "synthetic@example.test");
    await writeFile(join(nested, "app.ts"), "unsafe\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const remote = await fixtures.create("patch-nested-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "nested/app.ts";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : "",
        onCodex: async (args, output) => {
          await writeFile(join(nested, "app.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("submodule");
    expect(git("branch", "--show-current")).toBe("main");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("write-tree")).toBe(index);
    expect(
      git(
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/codex-security/patch-scan-1",
      ),
    ).toBe("");
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
  });

  test.skipIf(process.platform === "win32")(
    "preserves trailing spaces in worktree roots during risk assessment and publication",
    async () => {
      for (const flag of ["--assess-patch-risk", "--create-pr"]) {
        const parent = await fixtures.create("patch-space-root-");
        const directory = join(parent, "checkout ");
        await mkdir(directory);
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(directory, "app.ts"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const remote = await fixtures.create("patch-space-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", flag, "--json"],
          {
            currentDirectory: directory,
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (_args, output) => {
              await writeFile(join(directory, "app.ts"), "fixed\n");
              output?.stdout.write("Fixed and checked.");
              return 0;
            },
          },
          {
            configure: (current) => {
              current.assessPatchRisk = async (request) => {
                expect(request.repository).toBe(directory);
                return patchRiskAssessment();
              };
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout)).toMatchObject({ applied: true });
      }
    },
  );

  test("patches a repository with a Git tree listing larger than one MiB", async () => {
    const directory = await fixtures.create("patch-large-tree-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const name = "a".repeat(70);
    await Promise.all(
      Array.from({ length: 10000 }, (_, index) =>
        writeFile(
          join(directory, `${name}${index.toString().padStart(5, "0")}.ts`),
          "original\n",
        ),
      ),
    );
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: directory,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        await writeFile(join(directory, "fix.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["fix.ts"],
    });
  });

  test.each([
    "unborn",
    "nested",
    "nested environment",
    "nested objects",
    "nested common",
  ])("detects local patches in %s Git repositories", async (kind) => {
    const directory = await fixtures.create("patch-git-state-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(directory, "app.ts"), "unsafe\n");
    let path = "app.ts";
    if (kind.startsWith("nested")) {
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const nested = join(directory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      path = "nested/app.ts";
    }
    const gitEnvironment =
      kind === "nested environment"
        ? { GIT_DIR: ".git", GIT_WORK_TREE: directory }
        : kind === "nested objects"
          ? { GIT_OBJECT_DIRECTORY: join(directory, ".git", "objects") }
          : kind === "nested common"
            ? { GIT_COMMON_DIR: join(directory, ".git") }
            : {};
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: directory,
      onRepositoryCommand: (command, args, cwd, options) =>
        runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...gitEnvironment, ...options?.environment },
        }),
      onCodex: async (_args, output) => {
        await writeFile(join(directory, path), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: [path],
    });
  });
  test("keeps the outer executable boundary for nested patch snapshots", async () => {
    const repository = await fixtures.create("patch-nested-executable-");
    const nested = join(repository, "dependency");
    await mkdir(nested);
    const git = repositoryGit(repository);
    const inner = repositoryGit(nested);
    for (const run of [git, inner]) {
      run("init", "--initial-branch=main");
      run("config", "user.name", "Synthetic User");
      run("config", "user.email", "synthetic@example.test");
    }
    await writeFile(join(nested, "app.ts"), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    const trusted = await resolveTrustedExecutable(
      "git",
      process.env,
      repository,
    );
    expect(trusted).not.toBeNull();
    const bin = join(repository, "bin");
    await mkdir(bin);
    const repositoryGitPath = join(bin, basename(trusted!.executable));
    await copyFile(trusted!.executable, repositoryGitPath);
    await chmod(repositoryGitPath, 0o755);
    const environment = {
      ...process.env,
      PATH: [bin, process.env["PATH"]].join(delimiter),
    };
    let nestedCommands = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      onRepositoryCommand: async (command, args, cwd, options) => {
        // Exercise the same resolver used by the default command dependency.
        const selected = await resolveTrustedExecutable(
          command,
          environment,
          cwd,
        );
        expect(selected?.executable).not.toBe(repositoryGitPath);
        if (cwd === nested || args.includes(nested)) nestedCommands++;
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        await writeFile(join(nested, "app.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(nestedCommands).toBeGreaterThan(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["dependency/app.ts"],
    });
  });

  test("refuses a sparse gitlink redirected outside the patch checkout", async () => {
    const directory = await fixtures.create("patch-sparse-gitlink-");
    const repository = join(directory, "repository");
    const nested = join(repository, "dependency");
    const external = join(directory, "external");
    await mkdir(nested, { recursive: true });
    await mkdir(external);
    const git = repositoryGit(repository);
    const inner = repositoryGit(nested);
    const outside = repositoryGit(external);
    for (const run of [git, inner, outside]) {
      run("init", "--initial-branch=main");
      run("config", "user.name", "Synthetic User");
      run("config", "user.email", "synthetic@example.test");
    }
    for (const [path, run] of [
      [nested, inner],
      [external, outside],
    ] as const) {
      await writeFile(join(path, "app.ts"), "original\n");
      run("add", ".");
      run("commit", "-m", "Synthetic baseline");
    }
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    git("config", "core.sparseCheckout", "true");
    await writeFile(
      join(repository, ".git", "info", "sparse-checkout"),
      "/*\n!/dependency\n",
    );
    git("update-index", "--skip-worktree", "dependency");
    await rm(nested, { recursive: true });
    await symlink(
      external,
      nested,
      process.platform === "win32" ? "junction" : "dir",
    );
    const outsideFile = join(external, "uncommitted.txt");
    await writeFile(
      outsideFile,
      "Synthetic bytes outside the selected checkout\n",
    );
    const blob = outside("hash-object", outsideFile);
    const index = outside("write-tree");
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    let modelCalls = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async () => {
        modelCalls++;
        return 0;
      },
    });
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    expect(outside("write-tree")).toBe(index);
    expect(modelCalls).toBe(0);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("outside");
    expect(await readFile(outsideFile, "utf8")).toBe(
      "Synthetic bytes outside the selected checkout\n",
    );
  });

  test.each(["worktree", "metadata"])(
    "refuses a nested checkout rebound to external %s before writing objects",
    async (binding) => {
      const directory = await fixtures.create("patch-nested-binding-");
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      const external = join(directory, "external");
      await mkdir(nested, { recursive: true });
      await mkdir(external);
      const git = repositoryGit(checkout);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      const outsideFile = join(external, "outside.txt");
      await writeFile(
        outsideFile,
        "Synthetic bytes outside the selected checkout\n",
      );
      const blob = git("hash-object", outsideFile);
      expect(() => inner("cat-file", "-e", blob)).toThrow();
      let objects = inner;
      if (binding === "worktree") {
        inner("config", "core.worktree", external);
      } else {
        const outside = repositoryGit(external);
        outside("init", "--initial-branch=main");
        outside("config", "user.name", "Synthetic User");
        outside("config", "user.email", "synthetic@example.test");
        outside("add", ".");
        outside("commit", "-m", "Synthetic external baseline");
        await rm(join(nested, ".git"), { recursive: true });
        await writeFile(
          join(nested, ".git"),
          `gitdir: ${join(external, ".git")}\n`,
        );
        await writeFile(
          join(nested, "app.ts"),
          "Synthetic unpublished target bytes\n",
        );
        objects = outside;
      }
      const snapshotBlob = git("hash-object", join(nested, "app.ts"));
      if (binding === "metadata")
        expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      let modelCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: checkout,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async () => {
            modelCalls++;
            return 0;
          },
        },
      );
      if (binding === "worktree")
        expect(() => inner("cat-file", "-e", blob)).toThrow();
      else expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      expect(modelCalls).toBe(0);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toMatch(/worktree|metadata/u);
    },
  );

  test.each(["nested"])(
    "retains changed files when %s Git patch assessment cannot produce an outer patch",
    async (kind) => {
      const directory = await fixtures.create("patch-git-state-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      let path = "app.ts";
      if (kind === "nested") {
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const nested = join(directory, "nested");
        await mkdir(nested);
        const inner = repositoryGit(nested);
        inner("init", "--initial-branch=main");
        inner("config", "user.name", "Synthetic User");
        inner("config", "user.email", "synthetic@example.test");
        await writeFile(join(nested, "app.ts"), "unsafe\n");
        inner("add", ".");
        inner("commit", "-m", "Synthetic nested baseline");
        path = "nested/app.ts";
      }
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(join(directory, path), "fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("No completed patch changes to assess.");
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: [path],
      });
    },
  );
});

function repositoryGit(repository: string) {
  return (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repository,
      encoding: "utf8",
      maxBuffer: Infinity,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
}

const runGitRepositoryCommand: NonNullable<
  NonNullable<Parameters<typeof dependencies>[0]>["onRepositoryCommand"]
> = (command, args, workingDirectory, options) => {
  expect(command).toBe("git");
  const result = gitText(args, {
    cwd: options?.directory ?? workingDirectory,
    env: { ...process.env, ...options?.environment },
    maxBuffer: options?.maxBuffer,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return options?.trim === false ? result : result.trim();
};

test.each(["untracked", "tracked"])(
  "keeps unrelated %s edits made during assessment out of publication",
  async (kind) => {
    const root = await temporaryDirectory("patch-assessment-publication-");
    const repository = join(root, "repository");
    const remote = join(root, "remote.git");
    const git = repositoryGit(repository);
    try {
      await mkdir(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (kind === "tracked")
        await writeFile(join(repository, "user-notes.txt"), "original notes\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          onRepositoryCommand: (command, args, directory, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, directory, options)
              : args[1] === "create"
                ? "https://github.example.test/example/repository/pull/17"
                : "",
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              expect(artifact.changedFiles).toEqual(["app.ts"]);
              await writeFile(
                join(repository, "user-notes.txt"),
                "unrelated notes from concurrent work\n",
              );
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(git("show", "--format=", "--name-only", "HEAD", "--")).toBe(
        "app.ts",
      );
      expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
      expect(git("status", "--porcelain")).toBe(
        `${kind === "tracked" ? "M" : "??"} user-notes.txt`,
      );
      expect(await readFile(join(repository, "user-notes.txt"), "utf8")).toBe(
        "unrelated notes from concurrent work\n",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each(["untracked", "tracked"])(
  "keeps unrelated %s edits made after patch capture out of publication",
  async (kind) => {
    const root = await temporaryDirectory("patch-assessment-publication-");
    const repository = join(root, "repository");
    const remote = join(root, "remote.git");
    const git = repositoryGit(repository);
    try {
      await mkdir(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (kind === "tracked")
        await writeFile(join(repository, "user-notes.txt"), "original notes\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let patched = false;
      let injected = false;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          onRepositoryCommand: async (command, args, directory, options) => {
            if (command !== "git")
              return args[1] === "create"
                ? "https://github.example.test/example/repository/pull/17"
                : "";
            const result = await runGitRepositoryCommand(
              command,
              args,
              directory,
              options,
            );
            if (patched && !injected && args.includes("--name-only")) {
              injected = true;
              await writeFile(
                join(repository, "user-notes.txt"),
                "unrelated notes from concurrent work\n",
              );
            }
            return result;
          },
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              expect(artifact.changedFiles).toEqual(["app.ts"]);

              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              patched = true;
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(git("show", "--format=", "--name-only", "HEAD", "--")).toBe(
        "app.ts",
      );
      expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
      expect(git("status", "--porcelain")).toBe(
        `${kind === "tracked" ? "M" : "??"} user-notes.txt`,
      );
      expect(await readFile(join(repository, "user-notes.txt"), "utf8")).toBe(
        "unrelated notes from concurrent work\n",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
