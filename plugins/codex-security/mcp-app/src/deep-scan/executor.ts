import {
  accessSync,
  constants as fsConstants,
  existsSync,
  promises as fs,
  readdirSync,
  statSync,
} from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import {
  delimiter,
  dirname,
  isAbsolute,
  join,
  resolve,
  win32,
} from "node:path";
import { readCodexSessionTurn } from "../codex-session.js";
import {
  Codex,
  type CodexOptions,
  type CyberAccessProgram,
  type ThreadEvent,
} from "@openai/codex-sdk";
import { parse as parseToml } from "smol-toml";
import {
  createCodexProfileClient,
  preflightProviderDefinitions,
  profileConfigOverrides,
} from "../../../scripts/codex_profile.mjs";
import { executablePathForSpawn } from "./executable-path.js";
import {
  classifyCodexWorkerError,
  DeepScanNonRetryableError,
} from "./errors.js";
import {
  DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
  deepScanPermissionProfileFallbackError,
  preflightDeepScanWorkerPermissionProfile,
} from "./permission-profile-preflight.js";
import type { DeepWorkerParentSandbox } from "./parent-sandbox.js";
import type {
  CodexWorkerDiagnostic,
  CodexWorkerExecutor,
  CodexWorkerRequest,
  CodexWorkerResult,
} from "./types.js";

export interface CodexSdkWorkerModelSettings {
  /** Resolved by the execution owner, including when reconstructing a scan. */
  codexOptions?: CodexOptions;
  model?: string;
  reasoningEffort?: string;
  cyberAccessProgram?: CyberAccessProgram;
  /** Recorded selections override defaults while preserving private SDK transport. */
  runtimeSettings?: CodexSdkWorkerRuntimeSettings;
  artifactContext?: CodexSdkWorkerArtifactContext;
  parentSandbox?: DeepWorkerParentSandbox;
}

/** The coordinator supplies scan identity; worker tools never choose paths. */
export interface CodexSdkWorkerArtifactContext {
  pluginRoot: string;
  repoRoot: string;
  scanId: string;
  scope?: string;
  scanRoot?: string;
  pythonCommand?: string;
}

interface CodexSdkWorkerRuntimeSettings {
  environment?: Record<string, string>;
  config: Record<string, unknown>;
  preflightProviderOverrides?: string[];
  nativeProfile?: string;
  cyberAccessProgram?: CyberAccessProgram;
}

export class CodexSdkWorkerExecutor implements CodexWorkerExecutor {
  private runtimeModelConfig?: Promise<NonNullable<CodexOptions["config"]>>;
  private runtimeSettings?: Promise<CodexSdkWorkerRuntimeSettings>;

  constructor(
    private readonly modelSettings: CodexSdkWorkerModelSettings = {},
  ) {}

  async run(request: CodexWorkerRequest): Promise<CodexWorkerResult> {
    try {
      const parentSandbox = this.modelSettings.parentSandbox;
      if (!parentSandbox) {
        throw new DeepScanNonRetryableError(
          "Deep Scan cannot start a read-only worker without verified parent sandbox metadata.",
        );
      }
      const workerProfile = workerPermissionProfile(parentSandbox);
      const resolved = this.modelSettings.codexOptions;
      const originalCwd = process.cwd();
      const childEnv = await snapshotWorkerEnvironment(resolved?.env);
      // Snapshot the SDK's per-scan config once for this coordinator, including resumes.
      const inheritedRuntime = await (this.runtimeSettings ??=
        workerRuntimeSettings(childEnv));
      const runtimeSettings =
        this.modelSettings.runtimeSettings === undefined
          ? inheritedRuntime
          : restoredWorkerRuntime(
              inheritedRuntime,
              this.modelSettings.runtimeSettings,
            );
      for (const [name, value] of Object.entries(
        runtimeSettings.environment ?? {},
      )) {
        if (process.platform === "win32") {
          for (const key of Object.keys(childEnv)) {
            if (key.toUpperCase() === name.toUpperCase()) delete childEnv[key];
          }
        }
        childEnv[name] = value;
      }
      if (resolved?.apiKey !== undefined)
        childEnv.CODEX_API_KEY = resolved.apiKey;
      const selectedConfig = await (this.runtimeModelConfig ??= resolved?.config
        ? Promise.resolve(resolved.config)
        : workerModelConfig(childEnv));
      const modelConfig: NonNullable<CodexOptions["config"]> = {
        ...runtimeSettings.config,
        ...selectedConfig,
        features: {
          ...(isRecord(runtimeSettings.config.features)
            ? runtimeSettings.config.features
            : {}),
          ...(isRecord(selectedConfig.features) ? selectedConfig.features : {}),
        } as NonNullable<CodexOptions["config"]>,
        ...(this.modelSettings.model
          ? { model: this.modelSettings.model }
          : {}),
      };
      // The preflight file has catalog defaults; the private profile owns routing.
      if (runtimeSettings.nativeProfile !== undefined)
        delete modelConfig.model_providers;
      // Keep one native configuration for the policy check and the worker turn.
      // Worker-owned tool and permission settings take precedence over inheritance.
      const configOverrides = [
        ...(resolved?.configOverrides ?? []),
        ...profileConfigOverrides({
          ...modelConfig,
          ...(this.modelSettings.reasoningEffort
            ? { model_reasoning_effort: this.modelSettings.reasoningEffort }
            : {}),
          mcp_servers: {
            // A disabled server still needs a valid transport during native resolution.
            "codex-security": { command: "node", enabled: false },
            ...this.compactArtifactServer(request),
          },
          ...workerSubagentConfig(
            request.subagents,
            modelConfig.features,
            modelConfig.agents,
          ),
          approval_policy: "never",
          default_permissions: DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID,
          [`permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}`]:
            workerProfile,
        }),
      ];
      const openAiApiKey = environmentVariable(
        childEnv,
        "OPENAI_API_KEY",
        process.platform,
      )?.trim();
      const codexApiKey = environmentVariable(
        childEnv,
        "CODEX_API_KEY",
        process.platform,
      )?.trim();
      const codexPath = resolveCodexPath(
        resolved?.codexPathOverride === undefined
          ? childEnv
          : { ...childEnv, CODEX_CLI_PATH: resolved.codexPathOverride },
        process.platform,
        process.arch,
        originalCwd,
      );
      const { useOpenAiApiKey } =
        await preflightDeepScanWorkerPermissionProfile({
          codexPath,
          cwd: request.workingDirectory,
          configOverrides: [
            ...configOverrides,
            ...(resolved?.baseUrl
              ? profileConfigOverrides({ openai_base_url: resolved.baseUrl })
              : []),
          ],
          providerConfigOverrides: runtimeSettings.preflightProviderOverrides,
          expectedProfile: workerProfile,
          env: childEnv,
          allowOpenAiApiKeyFallback: Boolean(openAiApiKey && !codexApiKey),
          signal: request.signal,
        });
      const prompt = await fs.readFile(request.promptPath, "utf8");
      const codexOptions = {
        ...resolved,
        codexPathOverride: executablePathForSpawn(codexPath),
        env: childEnv,
        // Codex exec reads CODEX_API_KEY; the SDK maps apiKey to that variable.
        // Keep native credentials unless the worker has no configured account.
        ...(useOpenAiApiKey ? { apiKey: openAiApiKey } : {}),
        // Raw overrides preserve literal filesystem and MCP keys.
        configOverrides,
      };
      delete codexOptions.config;
      const codex =
        runtimeSettings.nativeProfile === undefined
          ? new Codex(codexOptions)
          : createCodexProfileClient<ThreadEvent>({
              ...codexOptions,
              profileName: runtimeSettings.nativeProfile,
            });
      const threadOptions = {
        ...(this.modelSettings.model
          ? { model: this.modelSettings.model }
          : {}),
        threadSource: "security_scan",
        skipGitRepoCheck: true,
        workingDirectory: request.workingDirectory,
      } as const;
      const thread = request.resumeThreadId
        ? codex.resumeThread!(request.resumeThreadId, threadOptions)
        : codex.startThread(threadOptions);
      const input = request.resumeThreadId
        ? (request.continuationPrompt ?? prompt)
        : prompt;
      const controller = new AbortController();
      const forwardAbort = () => controller.abort(request.signal.reason);
      if (request.signal.aborted) {
        forwardAbort();
      } else {
        request.signal.addEventListener("abort", forwardAbort, { once: true });
      }

      try {
        const { events } = await thread.runStreamed(input, {
          signal: controller.signal,
          cyberAccessProgram:
            this.modelSettings.cyberAccessProgram ??
            runtimeSettings.cyberAccessProgram,
        });
        const diagnostics: CodexWorkerDiagnostic[] = [];
        const turn = await readCodexSessionTurn({
          thread,
          events,
          stopOnCompletion: true,
          onEvent: async (event) => {
            if (
              event.type === "thread.started" &&
              typeof event.thread_id === "string"
            ) {
              await request.onThreadStarted?.(event.thread_id);
            } else if (
              event.type === "item.completed" &&
              isRecord(event.item)
            ) {
              const fallbackError =
                event.item.type === "error" &&
                typeof event.item.message === "string"
                  ? deepScanPermissionProfileFallbackError(event.item.message)
                  : undefined;
              if (fallbackError) {
                controller.abort(fallbackError);
                throw fallbackError;
              }
              appendSafeItemDiagnostic(diagnostics, event.item);
            } else if (event.type === "turn.completed") {
              request.signal.removeEventListener("abort", forwardAbort);
            } else if (event.type === "turn.failed") {
              throw new Error((event.error as { message: string }).message);
            } else if (
              event.type === "error" &&
              typeof event.message === "string"
            ) {
              const fallbackError = deepScanPermissionProfileFallbackError(
                event.message,
              );
              if (fallbackError) {
                controller.abort(fallbackError);
                throw fallbackError;
              }
              // Codex exec emits retry-in-progress notifications as error events.
              appendCodeModeFrameDiagnostic(diagnostics, event.message);
            }
          },
        });
        if (turn.status !== "completed") {
          const detail = turn.lastStreamError
            ? `: ${turn.lastStreamError}`
            : "";
          throw new Error(
            `Codex worker stream ended before turn.completed${detail}`,
          );
        }
        return {
          threadId: turn.threadId ?? thread.id ?? undefined,
          ...(diagnostics.length > 0 ? { diagnostics } : {}),
        };
      } finally {
        request.signal.removeEventListener("abort", forwardAbort);
      }
    } catch (error) {
      throw classifyCodexWorkerError(error);
    }
  }

  private compactArtifactServer(request: CodexWorkerRequest): Record<
    string,
    {
      command: string;
      args: string[];
      env: Record<string, string>;
      required: true;
      startup_timeout_sec: number;
      tool_timeout_sec: number;
    }
  > {
    const scan = this.modelSettings.artifactContext;
    if (!scan) return {};

    const assigned = request.artifactContext;
    if (!assigned) {
      throw new Error(
        "Deep Scan worker has no coordinator-bound artifact context.",
      );
    }
    const expectedLayout = request.kind === "dedup" ? "reducer" : "worker";
    if (assigned.layout !== expectedLayout) {
      throw new Error(
        "Deep Scan worker artifact context does not match its assigned phase.",
      );
    }
    if (
      (expectedLayout === "reducer") !==
      (assigned.deepReducer !== undefined)
    ) {
      throw new Error(
        "Deep Scan reducer requires its coordinator-bound source assignments.",
      );
    }

    return {
      // Keep every qualified worker tool within Codex's existing name limit.
      cs_artifacts: {
        command: process.execPath,
        args: [
          join(scan.pluginRoot, "mcp", "server.mjs"),
          "--artifact-writer",
          "--stdio",
        ],
        env: {
          CODEX_SECURITY_ARTIFACT_ROOT: assigned.root,
          CODEX_SECURITY_REPO_ROOT: scan.repoRoot,
          CODEX_SECURITY_ARTIFACT_LAYOUT: assigned.layout,
          CODEX_SECURITY_SCAN_ID: scan.scanId,
          CODEX_SECURITY_PLUGIN_ROOT: scan.pluginRoot,
          ...(scan.scope !== undefined
            ? { CODEX_SECURITY_SCOPE: scan.scope }
            : {}),
          ...(scan.pythonCommand !== undefined
            ? { CODEX_SECURITY_PYTHON_COMMAND: scan.pythonCommand }
            : {}),
          ...(assigned.deepReducer
            ? {
                CODEX_SECURITY_REDUCER_CONTEXT_JSON: JSON.stringify(
                  assigned.deepReducer,
                ),
              }
            : {}),
        },
        required: true,
        startup_timeout_sec: 180,
        tool_timeout_sec: 86_400,
      },
    };
  }
}

function workerSubagentConfig(
  subagents: number,
  inheritedFeatures: unknown,
  inheritedAgents: unknown,
) {
  return {
    // V1 counts children; V2 counts the root plus its children. Keeping its
    // feature disabled lets the model choose either runtime without rejecting
    // inherited agents.max_threads configuration.
    ...(subagents > 0
      ? {
          agents: {
            ...(isRecord(inheritedAgents) ? inheritedAgents : {}),
            max_threads: subagents,
          },
        }
      : {}),
    features: {
      ...(isRecord(inheritedFeatures) ? inheritedFeatures : {}),
      multi_agent_v2: {
        enabled: false,
        max_concurrent_threads_per_session: subagents + 1,
      },
      ...(subagents === 0
        ? {
            // V1 rejects max_threads=0. Worker prompts request no children;
            // preserve host tool exclusions instead of weakening them.
            enable_fanout: false,
          }
        : {}),
    },
  };
}

type TomlValue = string | number | boolean | TomlValue[] | TomlObject;
type TomlObject = { [key: string]: TomlValue };

function workerPermissionProfile(sandbox: DeepWorkerParentSandbox): TomlObject {
  return {
    extends: ":read-only",
    // Object.fromEntries preserves literal keys such as "__proto__" without
    // letting a denied path mutate the serializer object prototype.
    filesystem: Object.fromEntries([
      [":root", "read"],
      ...Array.from(sandbox.filesystemDenies, (key) => [key, "deny"]),
      ...Array.from(sandbox.literalFilesystemDenies ?? [], (key) => [
        key,
        { ".": "deny" },
      ]),
      ...(sandbox.globScanMaxDepth === undefined
        ? []
        : [["glob_scan_max_depth", sandbox.globScanMaxDepth]]),
    ]),
    network: { enabled: false },
  };
}

function workerPermissionProfileConfigOverrides(profile: TomlObject): string[] {
  return [
    `default_permissions=${tomlString(DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID)}`,
    `permissions.${DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID}=${tomlInlineValue(profile)}`,
  ];
}

function tomlInlineValue(value: TomlValue): string {
  if (typeof value === "string") return tomlString(value);
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (Array.isArray(value)) return `[${value.map(tomlInlineValue).join(",")}]`;
  return `{${Object.entries(value)
    .map(([key, entry]) => `${tomlKey(key)}=${tomlInlineValue(entry)}`)
    .join(",")}}`;
}

function tomlKey(value: string): string {
  return /^[A-Za-z0-9_-]+$/.test(value) ? value : tomlString(value);
}

function tomlString(value: string): string {
  return JSON.stringify(value).replace(/\u007f/g, "\\u007f");
}

/**
 * Convert SDK item failures into bounded classifications without retaining the
 * command, output, or paths carried by the event. Those fields can contain
 * repository contents and credentials, while the coordinator only needs the
 * reason a later deterministic artifact check failed.
 */
function appendSafeItemDiagnostic(
  diagnostics: CodexWorkerDiagnostic[],
  item: unknown,
): void {
  if (!isRecord(item) || typeof item.type !== "string") return;
  if (item.type === "error") {
    appendCodeModeFrameDiagnostic(diagnostics, item.message);
    return;
  }
  if (item.status !== "failed") return;
  if (
    item.type === "mcp_tool_call" &&
    isRecord(item.error) &&
    appendCodeModeFrameDiagnostic(diagnostics, item.error.message)
  )
    return;
  if (item.type === "command_execution") {
    const output =
      typeof item.aggregated_output === "string" ? item.aggregated_output : "";
    if (isSandboxNamespaceExhaustion(output)) {
      appendUniqueDiagnostic(diagnostics, {
        code: "sandbox_namespace_exhausted",
        message:
          "Codex worker sandbox namespace creation failed (bwrap ENOSPC).",
      });
    }
    return;
  }
  if (item.type === "file_change") {
    appendUniqueDiagnostic(diagnostics, {
      code: "file_change_failed",
      message: "Codex worker file change failed.",
    });
    return;
  }
  if (
    item.type === "mcp_tool_call" &&
    (item.server === "cs_artifacts" ||
      item.server === "codex_security_artifacts") &&
    typeof item.tool === "string"
  ) {
    if (isRecord(item.result) && Array.isArray(item.result.content)) {
      for (const content of item.result.content) {
        if (
          isRecord(content) &&
          content.type === "text" &&
          appendCodeModeFrameDiagnostic(diagnostics, content.text)
        )
          return;
      }
    }
    const reason = isRecord(item.result)
      ? "returned an error"
      : isRecord(item.error)
        ? "transport failed"
        : "failed";
    appendUniqueDiagnostic(diagnostics, {
      code: "artifact_tool_failed",
      message: `Codex worker artifact tool ${item.tool} ${reason}.`,
    });
  }
}

function appendCodeModeFrameDiagnostic(
  diagnostics: CodexWorkerDiagnostic[],
  message: unknown,
): boolean {
  // Codex exposes this transport error as text, without a structured code.
  // Preserve only its complete numeric template, never surrounding tool output.
  if (typeof message !== "string") return false;
  const match =
    /^code-mode delegate response exceeds the IPC frame limit: code-mode IPC frame length [0-9]+ exceeds [0-9]+ bytes$/u.exec(
      message,
    );
  if (match?.[0] !== message) return false;
  const diagnostic: CodexWorkerDiagnostic = {
    code: "artifact_tool_failed",
    message,
  };
  const index = diagnostics.findIndex(
    (existing) => existing.code === diagnostic.code,
  );
  if (index === -1) diagnostics.push(diagnostic);
  else diagnostics[index] = diagnostic;
  return true;
}

function isSandboxNamespaceExhaustion(output: string): boolean {
  return /bwrap:\s*Creating new namespace failed:.*(?:ENOSPC|max_[a-z_]*_namespaces exceeded|Resource temporarily unavailable)/is.test(
    output,
  );
}

function appendUniqueDiagnostic(
  diagnostics: CodexWorkerDiagnostic[],
  diagnostic: CodexWorkerDiagnostic,
): void {
  if (!diagnostics.some((existing) => existing.code === diagnostic.code)) {
    diagnostics.push(diagnostic);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

// These are the existing non-secret selections written by the SDK preflight
// adapter. Reading only summary left provider selection in a shared home.
function workerModelSelection(
  config: NonNullable<CodexOptions["config"]>,
): TomlObject {
  const result: TomlObject = {};
  for (const key of [
    "model",
    "model_provider",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "service_tier",
    "model_providers",
  ]) {
    const value = config[key];
    if (value !== undefined) result[key] = value;
  }
  return result;
}

async function workerModelConfig(
  environment: Record<string, string>,
): Promise<NonNullable<CodexOptions["config"]>> {
  const configPath = environmentVariable(
    environment,
    "CODEX_SECURITY_CONFIG_PATH",
    process.platform,
  );
  if (!configPath) return {};
  const config = parseToml(await fs.readFile(configPath, "utf8"));
  const profiles = config.profiles;
  const profile =
    typeof config.profile === "string" && isRecord(profiles)
      ? profiles[config.profile]
      : undefined;
  return workerModelSelection({
    ...config,
    ...(isRecord(profile) ? profile : {}),
  } as NonNullable<CodexOptions["config"]>);
}

/** Keep private SDK transport while recorded selections replace current defaults. */
function restoredWorkerRuntime(
  inherited: CodexSdkWorkerRuntimeSettings,
  recorded: CodexSdkWorkerRuntimeSettings,
): CodexSdkWorkerRuntimeSettings {
  const config = { ...inherited.config };
  for (const key of [
    "model",
    "model_provider",
    "model_reasoning_effort",
    "model_reasoning_summary",
    "service_tier",
  ]) {
    delete config[key];
  }
  const features = isRecord(config.features) ? { ...config.features } : {};
  delete features.api_key_cyber_access_programs;
  delete features.api_key_model_discovery;
  return {
    ...inherited,
    ...recorded,
    cyberAccessProgram: recorded.cyberAccessProgram,
    config: {
      ...config,
      ...recorded.config,
      features: {
        ...features,
        ...(isRecord(recorded.config.features) ? recorded.config.features : {}),
      },
    },
  };
}

async function workerRuntimeSettings(
  environment: Record<string, string>,
): Promise<CodexSdkWorkerRuntimeSettings> {
  const configPath = environmentVariable(
    environment,
    "CODEX_SECURITY_CONFIG_PATH",
    process.platform,
  );
  if (!configPath) return { config: {} };
  const config = parseToml(await fs.readFile(configPath, "utf8"));
  const profiles = config.profiles;
  const profile =
    typeof config.profile === "string" && isRecord(profiles)
      ? profiles[config.profile]
      : undefined;
  const selected = { ...config, ...(isRecord(profile) ? profile : {}) };
  const inherited = Object.fromEntries(
    ["model_reasoning_summary", "service_tier"].map((key) => [
      key,
      selected[key],
    ]),
  );
  const settings: CodexSdkWorkerRuntimeSettings = { config: inherited };
  const workerConfigPath = environmentVariable(
    environment,
    "CODEX_SECURITY_DEEP_SCAN_CONFIG_PATH",
    process.platform,
  );
  const snapshot = workerConfigPath
    ? parseToml(await fs.readFile(workerConfigPath, "utf8")).worker_runtime
    : undefined;
  const {
    environment: workerEnvironment,
    native_profile: nativeProfile,
    model_providers: legacyProviders,
    ...workerConfig
  } = isRecord(snapshot) ? snapshot : {};
  if (isRecord(workerEnvironment)) {
    settings.environment = workerEnvironment as Record<string, string>;
  }
  if (typeof nativeProfile === "string") {
    // Match Codex's plain profile-v2 names before constructing a private file path.
    if (nativeProfile.length === 0 || /[^A-Za-z0-9_-]/.test(nativeProfile)) {
      throw new DeepScanNonRetryableError(
        `invalid --profile value ${JSON.stringify(nativeProfile)}; pass a plain name such as "work"`,
      );
    }
    settings.nativeProfile = nativeProfile;
    const codexHome =
      environmentVariable(environment, "CODEX_HOME", process.platform) ||
      join(homedir(), ".codex");
    const nativeProfileConfig = parseToml(
      await fs.readFile(
        join(codexHome, `${nativeProfile}.config.toml`),
        "utf8",
      ),
    );
    if (isRecord(nativeProfileConfig.model_providers)) {
      const providers = preflightProviderDefinitions(
        nativeProfileConfig.model_providers,
      );
      if (Object.keys(providers).length > 0) {
        settings.preflightProviderOverrides = profileConfigOverrides({
          model_providers: providers,
        });
      }
    }
  }
  if (
    settings.nativeProfile === undefined &&
    isRecord(legacyProviders) &&
    Object.keys(legacyProviders).length > 0
  ) {
    throw new DeepScanNonRetryableError(
      "This Deep Scan provider snapshot needs private native profile support. Update the SDK and bundled plugin together.",
    );
  }
  const security = config.codex_security;
  if (isRecord(security) && typeof security.cyber_access_program === "string") {
    settings.cyberAccessProgram =
      security.cyber_access_program as CyberAccessProgram;
  }
  const features = isRecord(config.features) ? config.features : {};
  settings.config = {
    ...inherited,
    ...workerConfig,
    features: {
      ...Object.fromEntries(
        ["api_key_cyber_access_programs", "api_key_model_discovery"].map(
          (key) => [key, features[key]],
        ),
      ),
      ...(isRecord(workerConfig.features) ? workerConfig.features : {}),
    },
  };
  return settings;
}

async function snapshotWorkerEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): Promise<Record<string, string>> {
  const environment = Object.fromEntries(
    Object.entries(source).filter(
      (entry): entry is [string, string] => entry[1] !== undefined,
    ),
  ) as Record<string, string>;
  if (process.platform === "win32") {
    // process.env is case-insensitive on Windows; a plain object is not.
    // Keep its selected values while giving the child one spelling per key.
    for (const name of [
      "CODEX_CLI_PATH",
      "CODEX_HOME",
      "CODEX_MANAGED_PACKAGE_ROOT",
      "LOCALAPPDATA",
    ]) {
      const value = environmentVariable(source, name, process.platform);
      for (const key of Object.keys(environment)) {
        if (key.toUpperCase() === name) delete environment[key];
      }
      if (value !== undefined) environment[name] = value;
    }
  }
  const codexHome = environment.CODEX_HOME;
  if (
    codexHome !== undefined &&
    codexHome.length > 0 &&
    (!isAbsolute(codexHome) || isNativeWindowsRootRelativePath(codexHome))
  ) {
    // Keep the original home and credentials; only make the same path stable
    // after the worker switches cwd. Never create, copy, or mutate a home.
    // This runs before a worker cwd is passed to either child. realpath must
    // receive the original spelling; lexical resolve() would change
    // symlink/.. meaning.
    environment.CODEX_HOME = await fs.realpath(codexHome);
  }
  return environment;
}

export function resolveCodexPath(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  architecture: NodeJS.Architecture = process.arch,
  originalCwd: string = process.cwd(),
): string {
  const searchPath = searchPathForPlatform(env, platform);
  const configured = environmentVariable(
    env,
    "CODEX_CLI_PATH",
    platform,
  )?.trim();
  if (configured && (platform !== "win32" || !isWindowsAppsPath(configured))) {
    if (isBareCommandName(configured)) {
      const executableName =
        platform === "win32" && !configured.toLowerCase().endsWith(".exe")
          ? `${configured}.exe`
          : configured;
      const fromSearchPath =
        platform === "win32"
          ? configured === "codex" || configured === "codex.exe"
            ? resolveWindowsCodexFromSearchPath(
                searchPath,
                architecture,
                originalCwd,
              )
            : resolveWindowsDirectFromSearchPath(
                searchPath,
                executableName,
                originalCwd,
              )
          : resolveFromSearchPath(searchPath, executableName, originalCwd);
      if (fromSearchPath) return fromSearchPath;
    }
    return absoluteCodexPath(configured, platform, originalCwd);
  }

  if (platform !== "win32") {
    return (
      resolveFromSearchPath(searchPath, "codex", originalCwd) ??
      resolve(originalCwd, "codex")
    );
  }

  const managedPackageRoot = environmentVariable(
    env,
    "CODEX_MANAGED_PACKAGE_ROOT",
    platform,
  )?.trim();
  if (managedPackageRoot) {
    const managedBinary = resolveWindowsPackageBinary(
      absoluteCodexPath(managedPackageRoot, platform, originalCwd),
      architecture,
    );
    if (managedBinary && !isWindowsAppsPath(managedBinary))
      return managedBinary;
  }

  const pathBinary = resolveWindowsCodexFromSearchPath(
    searchPath,
    architecture,
    originalCwd,
  );
  if (pathBinary) return pathBinary;

  const localAppData = environmentVariable(
    env,
    "LOCALAPPDATA",
    platform,
  )?.trim();
  return (
    resolveWindowsCachedBinary(
      localAppData
        ? absoluteCodexPath(localAppData, platform, originalCwd)
        : undefined,
    ) ?? resolve(originalCwd, "codex.exe")
  );
}

function searchPathForPlatform(
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): string | undefined {
  if (platform !== "win32") return env.PATH?.trim() ? env.PATH : undefined;
  return Object.entries(env).find(
    ([name, value]) => name.toLowerCase() === "path" && value?.trim(),
  )?.[1];
}

function environmentVariable(
  env: NodeJS.ProcessEnv,
  name: string,
  platform: NodeJS.Platform,
): string | undefined {
  const value = env[name];
  if (value !== undefined || platform !== "win32") return value;
  return Object.entries(env).find(([key]) => key.toUpperCase() === name)?.[1];
}

function isBareCommandName(value: string): boolean {
  return (
    !value.includes("/") && !value.includes("\\") && !/^[A-Za-z]:/.test(value)
  );
}

function resolveFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string,
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(resolve(originalCwd, directory), executableName);
    if (isExecutableFile(candidate)) return candidate;
  }
  return undefined;
}

function resolveWindowsDirectFromSearchPath(
  searchPath: string | undefined,
  executableName: string,
  originalCwd: string,
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const candidate = join(resolve(originalCwd, directory), executableName);
    if (!isWindowsAppsPath(candidate) && existsSync(candidate))
      return candidate;
  }
  return undefined;
}

function resolveWindowsCodexFromSearchPath(
  searchPath: string | undefined,
  architecture: NodeJS.Architecture,
  originalCwd: string,
): string | undefined {
  for (const directory of searchPath?.split(delimiter) ?? []) {
    const absoluteDirectory = resolve(originalCwd, directory);
    const directBinary = join(absoluteDirectory, "codex.exe");
    if (!isWindowsAppsPath(directBinary) && existsSync(directBinary))
      return directBinary;

    const packageRoot = join(
      absoluteDirectory,
      "node_modules",
      "@openai",
      "codex",
    );
    const nativeBinary = resolveWindowsPackageBinary(packageRoot, architecture);
    if (nativeBinary && !isWindowsAppsPath(nativeBinary)) return nativeBinary;
  }
  return undefined;
}

function isWindowsAppsPath(candidate: string): boolean {
  return /(?:^|[\\/])windowsapps(?:[\\/]|$)/iu.test(candidate);
}

function resolveWindowsCachedBinary(
  localAppData: string | undefined,
): string | undefined {
  const root = localAppData?.trim();
  if (!root) return undefined;

  const cacheRoot = join(root, "OpenAI", "Codex", "bin");
  let selected: { path: string; modifiedAt: number } | undefined;
  try {
    for (const entry of readdirSync(cacheRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !/^[a-f0-9]{8,128}$/iu.test(entry.name))
        continue;
      const candidate = join(cacheRoot, entry.name, "codex.exe");
      let metadata: ReturnType<typeof statSync>;
      try {
        metadata = statSync(candidate);
      } catch {
        continue;
      }
      if (
        !metadata.isFile() ||
        metadata.size === 0 ||
        isWindowsAppsPath(candidate)
      )
        continue;
      if (
        !selected ||
        metadata.mtimeMs > selected.modifiedAt ||
        (metadata.mtimeMs === selected.modifiedAt && candidate > selected.path)
      ) {
        selected = { path: candidate, modifiedAt: metadata.mtimeMs };
      }
    }
  } catch {
    return undefined;
  }
  return selected?.path;
}

function isExecutableFile(value: string): boolean {
  try {
    if (!statSync(value).isFile()) return false;
    accessSync(value, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function absoluteCodexPath(
  value: string,
  platform: NodeJS.Platform,
  originalCwd: string,
): string {
  if (platform === "win32" && isNativeWindowsRootRelativePath(value)) {
    // A rooted Windows path still depends on the original drive.
    return win32.resolve(originalCwd, value);
  }
  if (isAbsolute(value) || (platform === "win32" && win32.isAbsolute(value))) {
    return value;
  }
  return resolve(originalCwd, value);
}

function isNativeWindowsRootRelativePath(value: string): boolean {
  if (process.platform !== "win32") return false;
  const root = win32.parse(value).root;
  return root === "\\" || root === "/";
}

function resolveWindowsPackageBinary(
  packageRoot: string,
  architecture: NodeJS.Architecture,
): string | undefined {
  const packageJson = join(packageRoot, "package.json");
  if (!existsSync(packageJson)) return undefined;

  const targetTriple =
    architecture === "arm64"
      ? "aarch64-pc-windows-msvc"
      : architecture === "x64"
        ? "x86_64-pc-windows-msvc"
        : undefined;
  if (!targetTriple) return undefined;

  try {
    const platformPackageJson = createRequire(packageJson).resolve(
      `@openai/codex-win32-${architecture}/package.json`,
    );
    const nativeBinary = join(
      dirname(platformPackageJson),
      "vendor",
      targetTriple,
      "bin",
      "codex.exe",
    );
    return existsSync(nativeBinary) ? nativeBinary : undefined;
  } catch {
    return undefined;
  }
}
