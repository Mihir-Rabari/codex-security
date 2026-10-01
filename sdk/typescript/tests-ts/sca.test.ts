import { execFileSync } from "node:child_process";
import {
  mkdir,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import {
  Codex,
  type CodexOptions,
  type ThreadEvent,
  type ThreadOptions,
} from "@openai/codex-sdk";
import Ajv from "ajv";
import { afterEach, expect, spyOn, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import type { JsonObject } from "../src/config.js";
import { estimateScanCost, ScanCostTracker } from "../src/cost.js";
import {
  ScanInterruptedError,
  ScanCostLimitExceededError,
  OutputInsideProtectedRootError,
} from "../src/index.js";
import type { OsvScanResult } from "../src/sca-osv.js";
import type { ScaResult, TriageFinding } from "../src/sca-types.js";
import {
  resolveCodexCommand,
  resolvePluginPython,
  runCodexCommand,
  type WorkbenchCommandOptions,
} from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import {
  createApiTestFixtures,
  preparedRuntime,
} from "./support/api-events.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

function scanner(outputDir: string, matched = true): OsvScanResult {
  return {
    status: "completed",
    diagnostics: [],
    scanner: {
      name: "osv-scanner",
      version: "2.6.0",
      argv: [],
      invocations: [
        {
          argv: ["scan", "source", "--", "package-lock.json"],
          exitCode: matched ? 1 : 0,
          rawOutputPath: join(outputDir, "osv-output.json"),
          stderrPath: join(outputDir, "osv-stderr.log"),
        },
      ],
      startedAt: "2026-01-01T00:00:00Z",
      completedAt: "2026-01-01T00:00:01Z",
      exitCode: matched ? 1 : 0,
      rawOutputPath: join(outputDir, "osv-output.json"),
      stderrPath: join(outputDir, "osv-stderr.log"),
      advisoryMode: "online",
      advisorySnapshotId: null,
    },
    coverage: {
      status: "complete",
      inputs: [
        {
          path: "package-lock.json",
          sha256: "abc",
          format: "npm",
          status: "scanned",
          reason: null,
        },
      ],
      configFiles: [],
      limitations: [],
      unresolvedPackages: 0,
    },
    components: [
      {
        id: "component-1",
        name: "synthetic-package",
        version: "1.0.0",
        ecosystem: "npm",
        sourcePath: "package-lock.json",
        dependencyGroups: [],
      },
    ],
    matches: matched
      ? [
          {
            id: "match-1",
            componentId: "component-1",
            advisoryIds: ["SYNTHETIC-1"],
            aliases: [],
            sourceAdvisories: [
              { id: "SYNTHETIC-1", summary: "Synthetic advisory" },
            ],
            severity: null,
            fixedVersions: ["1.0.1"],
            advisoryModifiedAt: [],
          },
        ]
      : [],
  };
}
function triage(): TriageFinding {
  return {
    triage_item_id: "triage-1",
    input_id: "match-1",
    source_type: "advisory",
    title: "Synthetic package use",
    normalized_input: {
      vulnerable_component: "synthetic-package",
      claimed_source: "unknown",
      claimed_sink: "unknown",
      claimed_control: "unknown",
      affected_version_or_path: "1.0.0",
      preconditions: [],
      impact: "unknown",
      references: [],
    },
    verdict: "needs_review",
    confidence: "low",
    affected_locations: [],
    reachable_path: [],
    boundary_assessment: {
      product_surface: "unknown",
      source_trust: "unknown",
      boundary_crossed: null,
      policy_basis: "No policy",
    },
    exploitability_stack_rank: {
      rank_queue: "needs_review",
      rank: 1,
      rationale: "Missing context",
      drivers: [],
    },
    evidence: [],
    counterevidence: [],
    proof_gaps: ["No usage context"],
    recommended_next_step: "Review package use",
    fix_finding_handoff: null,
  };
}
async function fixture(
  options: {
    matched?: boolean;
    turns?: (
      | "completed"
      | "truncated"
      | "malformed"
      | "cancelled"
      | "source_changed"
      | "duplicate_id"
      | "unauthorized"
      | "forbidden"
    )[];
    dependencyInput?: {
      path: string;
      format: ScaResult["coverage"]["inputs"][number]["format"];
      ecosystem: string;
    };
    scannerStatus?: OsvScanResult["status"];
    missing?: boolean;
    error?: string;
    malformed?: boolean;
    runtimeError?: boolean;
    controller?: AbortController;
    abortAt?: "scanner" | "model";
    model?: string;
    dirtyRepository?: boolean;
    changeSourceAt?: "scanner" | "model";
    changeRevision?: boolean;
    snapshotErrorAt?: 1 | 2;
    workbenchSnapshot?: boolean;
    mcpConfig?: string;
    mcpOverrides?: JsonObject;
    linkedCodex?: boolean;
    codexLauncher?: string;
    advisoryDetails?: string;
  } = {},
) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const outputDir = join(root, "sca");
  await Promise.all([
    mkdir(repository, { mode: 0o700 }),
    mkdir(codexHome, { mode: 0o700 }),
  ]);
  if (options.mcpConfig !== undefined)
    await writeFile(join(codexHome, "config.toml"), options.mcpConfig);
  let codexPath = options.codexLauncher;
  if (options.linkedCodex) {
    const nativePath = resolveCodexCommand({}).command;
    const launcherDirectory = join(root, "linked-runtime");
    await symlink(
      dirname(nativePath),
      launcherDirectory,
      process.platform === "win32" ? "junction" : "dir",
    );
    codexPath = join(launcherDirectory, basename(nativePath));
  }
  if (options.dirtyRepository)
    execFileSync("git", ["init", "--quiet"], { cwd: repository });
  const sourcePath = join(repository, "usage.txt");
  await writeFile(sourcePath, "synthetic initial source context");
  let snapshotCalls = 0;
  let revision = "synthetic-revision";
  const changeSource = async () => {
    if (options.changeRevision) revision = "synthetic-next-revision";
    else await writeFile(sourcePath, "synthetic changed source context");
  };
  const calls = { runtime: 0, model: 0, scanner: 0 };
  const captured: {
    codex?: CodexOptions;
    thread?: ThreadOptions;
    prompt?: string;
    evidence?: ScaResult;
  } = {};
  const turns: {
    options: ThreadOptions | undefined;
    prompt: string;
    evidence: ScaResult;
  }[] = [];
  const sourceCalls: WorkbenchCommandOptions[] = [];
  const pythonResolutions: Parameters<typeof resolvePluginPython>[0][] = [];
  const environment = {
    PATH: process.env["PATH"] ?? "",
    ...Object.fromEntries(
      ["SystemRoot", "TEMP", "TMP"].flatMap((name) =>
        process.env[name] === undefined ? [] : [[name, process.env[name]!]],
      ),
    ),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    OPENAI_API_KEY: "synthetic-sca-key",
    ...(codexPath === undefined ? {} : { CODEX_CLI_PATH: codexPath }),
  };
  const sourceSnapshot = async (path: string) => {
    expect(path).toBe(repository);
    if (++snapshotCalls === options.snapshotErrorAt)
      throw new Error("synthetic source snapshot unavailable");
    return {
      repository,
      revision,
      refsDigest: "synthetic-refs",
      content: await readFile(sourcePath, "utf8"),
    };
  };
  const client = new TestClient(
    {
      codexOverrides: {
        model: options.model ?? "gpt-5.6-sol",
        model_reasoning_effort: "high",
        ...(options.mcpOverrides === undefined
          ? {}
          : { mcp_servers: options.mcpOverrides }),
      },
    },
    {
      environment,
      repositoryRevision: async () => revision,
      ...(options.workbenchSnapshot
        ? {
            runWorkbench: async (
              workbenchOptions: WorkbenchCommandOptions,
              args: readonly string[],
              input?: string,
            ) => {
              expect(args).toEqual(["finding-workflow"]);
              const request = JSON.parse(input!);
              expect(request.action).toBe("source");
              sourceCalls.push(workbenchOptions);
              return { source: await sourceSnapshot(request.repository) };
            },
          }
        : { sourceSnapshot }),
      runOsvScan: async (input) => {
        calls.scanner++;
        expect(input.environment).toEqual(environment);
        if (options.changeSourceAt === "scanner") await changeSource();
        if (options.abortAt === "scanner")
          options.controller!.abort("cancel after scanner");
        const result = scanner(input.outputDir, options.matched ?? true);
        if (options.turns !== undefined)
          result.matches = options.turns.map((_, index) => ({
            ...result.matches[0]!,
            id: `match-${index + 1}`,
          }));
        if (options.advisoryDetails !== undefined)
          result.matches[0]!.sourceAdvisories[0]!["details"] =
            options.advisoryDetails;
        if (options.dependencyInput) {
          const dependency = options.dependencyInput;
          Object.assign(result.coverage.inputs[0]!, {
            path: dependency.path,
            format: dependency.format,
          });
          Object.assign(result.components[0]!, {
            sourcePath: dependency.path,
            ecosystem: dependency.ecosystem,
          });
          result.scanner.invocations![0]!.argv = [
            "scan",
            "source",
            "--",
            dependency.path,
          ];
        }
        if (options.scannerStatus !== undefined) {
          result.status = options.scannerStatus;
          result.coverage.status =
            options.scannerStatus === "completed"
              ? "complete"
              : options.scannerStatus;
        }
        return result;
      },
      prepareRuntime: async () => {
        calls.runtime++;
        const saved = JSON.parse(
          await readFile(join(outputDir, "sca-result.json"), "utf8"),
        );
        expect(saved.matches).toHaveLength(options.turns?.length ?? 1);
        expect(saved.status).toBe("partial");
        expect(saved.assessments[0].status).toBe("not_started");
        if (options.runtimeError)
          throw new Error("synthetic authentication unavailable");
        return { ...preparedRuntime(codexHome), environment };
      },
      resolvePluginPython: async (input) => {
        if (!options.workbenchSnapshot) return "/managed/python";
        pythonResolutions.push(input);
        return await resolvePluginPython(input);
      },
      createCodex: (codex) => {
        captured.codex = codex;
        calls.model++;
        return {
          startThread: (thread) => {
            captured.thread = thread;
            return {
              id: null,
              async runStreamed(prompt) {
                captured.prompt = String(prompt);
                captured.evidence = JSON.parse(
                  await readFile(join(outputDir, "sca-result.json"), "utf8"),
                );
                turns.push({
                  options: thread,
                  prompt: String(prompt),
                  evidence: captured.evidence!,
                });
                const turnNumber = turns.length;
                const behavior = options.turns?.[turnNumber - 1];
                const finding = {
                  ...triage(),
                  input_id: `match-${turnNumber}`,
                  triage_item_id: `triage-${behavior === "duplicate_id" ? 1 : turnNumber}`,
                };
                return {
                  events: (async function* (): AsyncGenerator<ThreadEvent> {
                    yield {
                      type: "thread.started",
                      thread_id:
                        turnNumber === 1
                          ? "sca-thread"
                          : `sca-thread-${turnNumber}`,
                    };
                    if (behavior === "cancelled") {
                      options.controller!.abort("cancel during later triage");
                      throw new Error("interrupted");
                    }
                    if (behavior === "source_changed") await changeSource();
                    if (
                      behavior === "unauthorized" ||
                      behavior === "forbidden"
                    ) {
                      yield {
                        type: "error",
                        message: `synthetic ${behavior === "unauthorized" ? "401 Unauthorized" : "403 Forbidden"}`,
                      };
                      return;
                    }
                    if (behavior === "truncated") {
                      yield {
                        type: "turn.failed",
                        error: { message: "synthetic output truncated" },
                      };
                      return;
                    }
                    if (options.abortAt === "model") {
                      options.controller!.abort("cancel during triage");
                      throw new Error("interrupted");
                    }
                    if (options.error) throw new Error(options.error);
                    if (options.changeSourceAt === "model")
                      await changeSource();
                    yield {
                      type: "item.completed",
                      item: {
                        id: "message",
                        type: "agent_message",
                        text:
                          options.malformed || behavior === "malformed"
                            ? "invalid JSON"
                            : JSON.stringify({
                                schema_version: "triage-finding/v0",
                                repository: {
                                  path: repository,
                                  revision: "synthetic-revision",
                                },
                                findings: options.missing ? [] : [finding],
                              }),
                      },
                    };
                    yield {
                      type: "turn.completed",
                      usage: {
                        input_tokens: 1000,
                        cached_input_tokens: 0,
                        cache_write_input_tokens: 0,
                        output_tokens: 1000,
                        reasoning_output_tokens: 0,
                      },
                    };
                  })(),
                };
              },
            };
          },
        };
      },
    },
  );
  return {
    client,
    repository,
    outputDir,
    calls,
    captured,
    turns,
    sourceCalls,
    pythonResolutions,
    environment,
    codexHome,
  };
}

(process.platform === "win32" ? test.skip : test)(
  "dependency triage keeps the installed npm JavaScript launcher and grants its native runtime",
  async () => {
    const launcher = createRequire(import.meta.url).resolve(
      "@openai/codex/bin/codex.js",
    );
    const f = await fixture({ codexLauncher: launcher });
    await using security = f.client;
    const result = await security.scanDependencies({
      repositoryPath: f.repository,
      outputDir: f.outputDir,
    });
    expect(result.status).toBe("completed");
    expect(f.captured.codex!.codexPathOverride).toBe(launcher);
    expect(f.captured.thread!.additionalDirectories).toContain(
      dirname(launcher),
    );
    expect(f.captured.thread!.additionalDirectories).toContain(
      dirname(resolveCodexCommand({}).command),
    );
    expect(f.captured.codex!.env!["CODEX_CLI_PATH"]).toBe(launcher);
  },
);

test("dependency triage disables inherited MCP servers and grants the linked native runtime", async () => {
  const mcpConfig =
    '[mcp_servers."synthetic.inherited"]\ncommand = "synthetic-inherited"\n';
  const f = await fixture({
    mcpConfig,
    mcpOverrides: {
      "synthetic.configured": {
        command: "synthetic-configured",
        enabled: true,
      },
    },
    linkedCodex: true,
  });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("completed");
  const options = f.captured.codex!;
  expect(options.env!["CODEX_HOME"]).toBe(f.codexHome);
  expect(options.configOverrides!.map((value) => parseToml(value))).toEqual([
    {
      mcp_servers: {
        "synthetic.inherited": { enabled: false },
        "synthetic.configured": {
          command: "synthetic-configured",
          enabled: false,
        },
      },
    },
  ]);
  const effective = await runCodexCommand(
    resolveCodexCommand(f.environment),
    [
      "-C",
      f.outputDir,
      ...options.configOverrides!.flatMap((value) => ["--config", value]),
      "mcp",
      "list",
      "--json",
    ],
    options.env!,
  );
  expect(effective.success).toBe(true);
  expect(
    JSON.parse(effective.stdout).map(
      (server: { name: string; enabled: boolean }) => ({
        name: server.name,
        enabled: server.enabled,
      }),
    ),
  ).toEqual([
    { name: "synthetic.configured", enabled: false },
    { name: "synthetic.inherited", enabled: false },
  ]);
  expect(await readFile(join(f.codexHome, "config.toml"), "utf8")).toBe(
    mcpConfig,
  );
  const launcherPath = f.environment.CODEX_CLI_PATH!;
  const runtimeDirectory = dirname(await realpath(launcherPath));
  expect(runtimeDirectory).not.toBe(dirname(launcherPath));
  expect(f.captured.thread!.additionalDirectories).toEqual([
    f.repository,
    PLUGIN_ROOT,
    dirname(launcherPath),
    runtimeDirectory,
  ]);

  // Exercise the pinned SDK's argument/environment boundary without a model call.
  const receipt = join(f.outputDir, "child.json");
  const preload = join(f.outputDir, "synthetic-codex.mjs");
  await writeFile(
    preload,
    `import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(receipt)}, JSON.stringify({ argv: process.argv.slice(2), home: process.env.CODEX_HOME }));
for (const event of [
  { type: "thread.started", thread_id: "synthetic-thread" },
  { type: "item.completed", item: { id: "message", type: "agent_message", text: "synthetic response" } },
  { type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } }
]) console.log(JSON.stringify(event));
process.exit(0);
`,
  );
  const node = execFileSync("node", ["-p", "process.execPath"], {
    encoding: "utf8",
  }).trim();
  const turn = await new Codex({
    ...options,
    codexPathOverride: node,
    env: {
      ...options.env,
      NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
    },
  })
    .startThread(f.captured.thread)
    .run("synthetic SDK boundary probe");
  expect(turn.finalResponse).toBe("synthetic response");
  const child = JSON.parse(await readFile(receipt, "utf8"));
  expect(child.home).toBe(f.codexHome);
  expect(child.argv).toContain(options.configOverrides![0]);
  expect(
    child.argv.flatMap((value: string, index: number, argv: string[]) =>
      value === "--add-dir" ? [argv[index + 1]] : [],
    ),
  ).toEqual(f.captured.thread!.additionalDirectories);
  expect(await readFile(join(f.codexHome, "config.toml"), "utf8")).toBe(
    mcpConfig,
  );
});

test("dependency triage preserves scanner evidence when MCP configuration cannot be read", async () => {
  const f = await fixture({ mcpConfig: "[invalid TOML\n" });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("partial");
  expect(result.matches).toHaveLength(1);
  expect(result.assessments[0]!.status).toBe("failed");
  expect(f.calls.model).toBe(0);
  expect(result.diagnostics.join("\n")).toContain(
    "Could not read MCP configuration for a read-only helper",
  );
});

test("large advisory records stay readable without exceeding Codex's input limit", async () => {
  const advisoryDetails = "Synthetic advisory detail. ".repeat(50_000);
  const f = await fixture({ advisoryDetails });
  await using security = f.client;
  const result = await security.scanDependencies({
    repositoryPath: f.repository,
    outputDir: f.outputDir,
  });
  expect(result.status).toBe("completed");
  expect(JSON.stringify(f.captured.evidence).length).toBeGreaterThan(1 << 20);
  expect(Array.from(f.captured.prompt!).length).toBeLessThan(1 << 20);
  expect(f.captured.prompt).toContain(
    JSON.stringify(join(f.outputDir, "sca-result.json")),
  );
  expect(f.captured.thread!.workingDirectory).toBe(f.outputDir);
  expect(f.captured.evidence!.matches).toHaveLength(1);
  expect(
    f.captured.evidence!.matches[0]!.sourceAdvisories[0]!["details"] ===
      advisoryDetails,
  ).toBe(true);
  expect(f.captured.evidence!.assessments[0]!.status).toBe("not_started");
});

test.each([
  { path: "package-lock.json", format: "npm", ecosystem: "npm" },
  { path: "uv.lock", format: "uv", ecosystem: "PyPI" },
  { path: "go.mod", format: "go", ecosystem: "Go" },
  { path: "Cargo.lock", format: "cargo", ecosystem: "crates.io" },
  { path: "gradle.lockfile", format: "gradle", ecosystem: "Maven" },
  { path: "Gemfile.lock", format: "bundler", ecosystem: "RubyGems" },
  { path: "composer.lock", format: "composer", ecosystem: "Packagist" },
  { path: "packages.lock.json", format: "nuget", ecosystem: "NuGet" },
] as const)(
  "dependency scan persists and assesses $ecosystem with schema-valid artifacts",
  async (dependencyInput) => {
    const { client, repository, outputDir, calls, captured } = await fixture({
      dependencyInput,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("completed");
    expect(result.assessments[0]).toMatchObject({
      status: "completed",
      verdict: "needs_review",
    });
    expect(calls).toEqual({ runtime: 1, model: 1, scanner: 1 });
    expect(captured.codex!.config).toMatchObject({
      model: "gpt-5.6-sol",
      model_reasoning_effort: "high",
      default_permissions: "codex_security_policy",
      features: { plugins: false, apps: false },
      mcp_servers: {},
    });
    expect(captured.thread).toMatchObject({
      threadSource: "security_dependency_triage",
      approvalPolicy: "never",
      networkAccessEnabled: false,
      webSearchMode: "disabled",
      additionalDirectories: [
        repository,
        PLUGIN_ROOT,
        dirname(resolveCodexCommand().command),
      ],
    });
    expect(captured.prompt).toContain("triage-finding");
    expect(captured.prompt).toContain(
      JSON.stringify(join(outputDir, "sca-result.json")),
    );
    expect(captured.evidence!.matches[0]!.id).toBe("match-1");
    expect(captured.evidence!.components[0]!.ecosystem).toBe(
      dependencyInput.ecosystem,
    );
    expect(captured.evidence!.components[0]!.sourcePath).toBe(
      dependencyInput.path,
    );
    expect(result.components[0]?.ecosystem).toBe(dependencyInput.ecosystem);
    expect(result.coverage.inputs[0]?.format).toBe(dependencyInput.format);
    expect(result.model.threadId).toBe("sca-thread");
    expect(typeof result.model.skillDigest).toBe("string");
    expect(result.model.costUsd).toBeGreaterThan(0);
    const ajv = new Ajv({ strict: false });
    ajv.addSchema(
      JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, "schemas/triage-result.schema.json"),
          "utf8",
        ),
      ),
      "triage-result.schema.json",
    );
    const validate = ajv.compile(
      JSON.parse(
        await readFile(
          join(PLUGIN_ROOT, "schemas/sca-result.schema.json"),
          "utf8",
        ),
      ),
    );
    validate(result);
    expect(validate.errors).toBeNull();
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
    expect(await readFile(join(outputDir, "report.md"), "utf8")).toContain(
      "SYNTHETIC-1",
    );
  },
);

test("complete zero-match scan needs no authentication or model", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    matched: false,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("completed");
  expect(result.assessments).toEqual([]);
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test("completed assessment cannot promote incomplete matching coverage", async () => {
  const { client, repository, outputDir } = await fixture({
    scannerStatus: "partial",
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("partial");
  expect(result.coverage.status).toBe("partial");
  expect(result.assessments[0]!.status).toBe("completed");
});

test("failed matching without assessable matches retains its failure status", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    scannerStatus: "failed",
    matched: false,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("failed");
  expect(result.coverage.status).toBe("failed");
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test.each(["runtime", "model", "malformed", "missing"])(
  "%s failure retains matches and records unavailable assessment",
  async (failure) => {
    const { client, repository, outputDir } = await fixture({
      runtimeError: failure === "runtime",
      error: failure === "model" ? "synthetic transport failure" : undefined,
      malformed: failure === "malformed",
      missing: failure === "missing",
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("complete");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8"))
        .matches,
    ).toHaveLength(1);
  },
);

test.each(["scanner", "model"] as const)(
  "cancellation at %s preserves facts and existing interruption error",
  async (abortAt) => {
    const controller = new AbortController();
    const { client, repository, outputDir } = await fixture({
      controller,
      abortAt,
    });
    await using security = client;
    try {
      await security.scanDependencies({
        repositoryPath: repository,
        outputDir,
        signal: controller.signal,
      });
      throw new Error("expected interruption");
    } catch (error) {
      expect(error).toBeInstanceOf(ScanInterruptedError);
      expect((error as ScanInterruptedError).scanDir).toBe(outputDir);
    }
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.status).toBe("partial");
    expect(saved.matches).toHaveLength(1);
    expect(saved.assessments[0]!.status).toBe("cancelled");
  },
);

test("requested cost limit interrupts while retaining completed evidence", async () => {
  const { client, repository, outputDir } = await fixture();
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      maxCostUsd: 0.000001,
    }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  const saved = JSON.parse(
    await readFile(join(outputDir, "sca-result.json"), "utf8"),
  ) as ScaResult;
  expect(saved.matches).toHaveLength(1);
  expect(saved.status).toBe("partial");
  expect(saved.model.costUsd).toBeGreaterThan(0.000001);
});

test.each(["truncated", "malformed", "duplicate_id"] as const)(
  "a later %s response preserves saved assessments and continues independent matches",
  async (failure) => {
    const { client, repository, outputDir, turns } = await fixture({
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "completed",
    ]);
    expect(turns).toHaveLength(3);
    expect(turns[1]!.evidence.assessments.map((item) => item.status)).toEqual([
      "completed",
      "not_started",
      "not_started",
    ]);
    expect(turns[2]!.evidence.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "not_started",
    ]);
    for (const [index, turn] of turns.entries()) {
      expect(turn.evidence.matches).toHaveLength(3);
      expect(turn.prompt).toContain(JSON.stringify(`match-${index + 1}`));
      expect(turn.options).toEqual(turns[0]!.options);
      expect(turn.options).toMatchObject({
        workingDirectory: outputDir,
        approvalPolicy: "never",
        networkAccessEnabled: false,
        webSearchMode: "disabled",
      });
      expect(turn.options!.additionalDirectories).toContain(repository);
      expect(turn.options!.additionalDirectories).toContain(PLUGIN_ROOT);
    }
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test("cumulative match costs stop the next thread without discarding completed assessments", async () => {
  const { client, repository, outputDir, turns } = await fixture({
    turns: ["completed", "completed", "completed"],
  });
  const perTurn = estimateScanCost("gpt-5.6-sol", {
    input_tokens: 1000,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 1000,
    reasoning_output_tokens: 0,
  })!.estimatedUsd;
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      maxCostUsd: perTurn * 1.5,
    }),
  ).rejects.toBeInstanceOf(ScanCostLimitExceededError);
  expect(turns).toHaveLength(2);
  const saved = JSON.parse(
    await readFile(join(outputDir, "sca-result.json"), "utf8"),
  ) as ScaResult;
  expect(saved.status).toBe("partial");
  expect(saved.model.costUsd).toBeCloseTo(perTurn * 2);
  expect(saved.assessments.map((item) => item.status)).toEqual([
    "completed",
    "completed",
    "cancelled",
  ]);
});

test.each(["unauthorized", "forbidden"] as const)(
  "a later %s event stops assessment without retrying the remaining matches",
  async (failure) => {
    const { client, repository, outputDir, turns } = await fixture({
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(turns).toHaveLength(2);
    expect(result.status).toBe("partial");
    expect(result.assessments.map((item) => item.status)).toEqual([
      "completed",
      "failed",
      "failed",
    ]);
    expect(result.assessments[1]!.error).toContain(
      failure === "unauthorized" ? "401 Unauthorized" : "403 Forbidden",
    );
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each(["source_changed", "cancelled"] as const)(
  "a later %s turn stops remaining work and preserves assessments of the original source",
  async (failure) => {
    const controller = new AbortController();
    const { client, repository, outputDir, turns } = await fixture({
      controller,
      turns: ["completed", failure, "completed"],
    });
    await using security = client;
    const operation = security.scanDependencies({
      repositoryPath: repository,
      outputDir,
      signal: controller.signal,
    });
    if (failure === "cancelled")
      await expect(operation).rejects.toBeInstanceOf(ScanInterruptedError);
    else expect((await operation).status).toBe("partial");
    expect(turns).toHaveLength(2);
    const saved = JSON.parse(
      await readFile(join(outputDir, "sca-result.json"), "utf8"),
    ) as ScaResult;
    expect(saved.matches).toHaveLength(3);
    expect(saved.status).toBe("partial");
    expect(saved.assessments.map((item) => item.status)).toEqual([
      "completed",
      failure === "cancelled" ? "cancelled" : "failed",
      failure === "cancelled" ? "cancelled" : "failed",
    ]);
    if (failure === "source_changed")
      expect(saved.diagnostics.join("\n")).toContain(
        "earlier assessments describe the original source",
      );
  },
);

test.each([
  { failure: "throw", requested: true },
  { failure: "null", requested: true },
  { failure: "throw", requested: false },
  { failure: "null", requested: false },
])(
  "final cost verification $failure enforces requested limit: $requested",
  async ({ failure, requested }) => {
    const { client, repository, outputDir } = await fixture();
    await using security = client;
    const originalStop = ScanCostTracker.prototype.stop;
    const stop = spyOn(ScanCostTracker.prototype, "stop").mockImplementation(
      async function (this: ScanCostTracker, usage?: unknown) {
        const snapshot = await originalStop.call(this, usage);
        if (failure === "throw")
          throw new Error("synthetic final cost tracking failure");
        return { ...snapshot, cost: null };
      },
    );
    try {
      const operation = security.scanDependencies({
        repositoryPath: repository,
        outputDir,
        ...(requested ? { maxCostUsd: 1 } : {}),
      });
      if (requested) {
        const error = await operation.then(
          () => null,
          (error: unknown) => error,
        );
        expect(error).toBeInstanceOf(ScanInterruptedError);
        expect((error as ScanInterruptedError).cause).toMatchObject({
          message:
            failure === "throw"
              ? "synthetic final cost tracking failure"
              : "Could not verify the dependency assessment cost limit.",
        });
      } else {
        expect((await operation).status).toBe("completed");
      }
      const saved = JSON.parse(
        await readFile(join(outputDir, "sca-result.json"), "utf8"),
      ) as ScaResult;
      expect(saved.status).toBe(requested ? "partial" : "completed");
      expect(saved.matches).toHaveLength(1);
      expect(saved.assessments[0]!.status).toBe("completed");
      if (failure === "throw")
        expect(saved.diagnostics.join("\n")).toContain(
          "synthetic final cost tracking failure",
        );
    } finally {
      stop.mockRestore();
    }
  },
);

test("unknown model with a requested budget cannot silently assess without cost enforcement", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    model: "unknown-model",
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
    maxCostUsd: 1,
  });
  expect(result.status).toBe("partial");
  expect(calls.model).toBe(0);
  expect(result.matches).toHaveLength(1);
});

test("SCA preserves output-path protections and argument validation", async () => {
  const { client, repository, calls } = await fixture();
  await using security = client;
  await expect(
    security.scanDependencies({
      repositoryPath: repository,
      outputDir: join(repository, "output"),
    }),
  ).rejects.toBeInstanceOf(OutputInsideProtectedRootError);
  await expect(
    security.scanDependencies({ repositoryPath: repository, maxCostUsd: -1 }),
  ).rejects.toThrow("positive USD");
  expect(calls.scanner).toBe(0);
});

test("stable initially dirty source can complete dependency assessment", async () => {
  const { client, repository, outputDir } = await fixture({
    dirtyRepository: true,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.repository.dirty).toBe(true);
  expect(result.status).toBe("completed");
  expect(result.assessments[0]!.status).toBe("completed");
});

test.each([
  { changeSourceAt: "scanner" as const, changeRevision: false },
  { changeSourceAt: "model" as const, changeRevision: false },
  { changeSourceAt: "model" as const, changeRevision: true },
])(
  "source drift at $changeSourceAt (revision: $changeRevision) rejects stale assessments and retains OSV facts",
  async (change) => {
    const { client, repository, outputDir } = await fixture({
      ...change,
      dirtyRepository: true,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.repository.dirty).toBe(true);
    expect(result.repository.revision).toBe("synthetic-revision");
    expect(result.status).toBe("partial");
    expect(result.coverage.status).toBe("complete");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    expect(result.diagnostics.join("\n")).toContain("Source changed");
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test.each([1, 2] as const)(
  "source snapshot failure at capture %i preserves OSV evidence without accepting an assessment",
  async (snapshotErrorAt) => {
    const { client, repository, outputDir, calls } = await fixture({
      snapshotErrorAt,
    });
    await using security = client;
    const result = await security.scanDependencies({
      repositoryPath: repository,
      outputDir,
    });
    expect(result.status).toBe("partial");
    expect(result.matches).toHaveLength(1);
    expect(result.assessments[0]).toMatchObject({
      status: "failed",
      verdict: null,
    });
    expect(result.diagnostics.join("\n")).toContain(
      "synthetic source snapshot unavailable",
    );
    expect(calls.runtime).toBe(snapshotErrorAt === 1 ? 0 : 1);
    expect(calls.model).toBe(snapshotErrorAt === 1 ? 0 : 1);
    expect(
      JSON.parse(await readFile(join(outputDir, "sca-result.json"), "utf8")),
    ).toEqual(result);
  },
);

test("zero-match inventory completes even when a source snapshot is unavailable", async () => {
  const { client, repository, outputDir, calls } = await fixture({
    matched: false,
    snapshotErrorAt: 1,
  });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
  });
  expect(result.status).toBe("completed");
  expect(result.assessments).toEqual([]);
  expect(calls).toEqual({ runtime: 0, model: 0, scanner: 1 });
});

test("dependency source snapshots preserve per-scan process environment, protected root, and cancellation", async () => {
  const controller = new AbortController();
  const {
    client,
    repository,
    outputDir,
    sourceCalls,
    pythonResolutions,
    environment,
  } = await fixture({ workbenchSnapshot: true });
  await using security = client;
  const result = await security.scanDependencies({
    repositoryPath: repository,
    outputDir,
    signal: controller.signal,
  });
  expect(result.status).toBe("completed");
  expect(sourceCalls).toHaveLength(2);
  expect(pythonResolutions[0]).toMatchObject({
    environment,
    protectedRoot: repository,
  });
  for (const call of sourceCalls) {
    expect(call.environment).toEqual(environment);
    expect(call.signal).toBe(pythonResolutions[0]!.signal);
    expect(call.signal!.aborted).toBe(false);
  }
  controller.abort("synthetic cancellation");
  expect(sourceCalls[0]!.signal!.aborted).toBe(true);
  expect(sourceCalls[1]!.signal!.aborted).toBe(true);
});
