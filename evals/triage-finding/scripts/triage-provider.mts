import { execFileSync } from "node:child_process";
import { accessSync, constants, realpathSync } from "node:fs";
import path from "node:path";
import type { ApiProvider, ProviderOptions } from "promptfoo";

type CodexProvider = ApiProvider & {
  callApiInternal(
    prompt: Parameters<ApiProvider["callApi"]>[0],
    context: Parameters<ApiProvider["callApi"]>[1],
    options: Parameters<ApiProvider["callApi"]>[2],
    config: ProviderOptions["config"],
  ): ReturnType<ApiProvider["callApi"]>;
};

// Resolve the throwaway runtime when the provider runs, not when Promptfoo
// persists its configuration for --resume or --retry-errors.
export default class TriageProvider implements ApiProvider {
  declare private readonly options: ProviderOptions;
  declare config: ProviderOptions["config"];
  declare private provider: Promise<ApiProvider> | undefined;
  constructor(options: ProviderOptions) {
    this.options = options;
    this.config = options.config;
  }

  id() {
    return `file://${import.meta.filename}`;
  }

  async callApi(...args: Parameters<ApiProvider["callApi"]>) {
    this.provider ??= import("promptfoo").then(async ({ loadApiProvider }) => {
      const provider = (await loadApiProvider("openai:codex-sdk:gpt-5.5", {
        basePath: this.config.basePath,
        options: this.options,
      })) as CodexProvider;
      const callApiInternal = provider.callApiInternal.bind(provider);
      // The pinned Codex provider merges prompt overrides and renders case
      // variables before this call. Keep that upstream behavior for each case.
      provider.callApiInternal = (prompt, context, options, config) => {
        const runtimeRoot = process.env.TRIAGE_RUNTIME_ROOT;
        if (!runtimeRoot) {
          throw new Error(
            "Run this evaluation through scripts/run-promptfoo.mts.",
          );
        }
        const requestedNode =
          (config.cli_env?.CODEX_MCP_NODE_PATH ??
            process.env.CODEX_MCP_NODE_PATH ??
            process.execPath) || process.execPath;
        const environment = { ...process.env, ...config.cli_env };
        const resolveNodeCommand = (command: string) =>
          /[/\\]/.test(command)
            ? command
            : execFileSync(
                process.platform === "win32"
                  ? path.join(process.env.SystemRoot!, "System32", "where.exe")
                  : "/bin/sh",
                process.platform === "win32"
                  ? [command]
                  : ["-c", 'command -v "$1"', "triage-node", command],
                {
                  cwd: runtimeRoot,
                  env: environment,
                  encoding: "utf8",
                },
              )
                .trim()
                .split(/\r?\n/)[0];
        let nodeCommand: string;
        try {
          nodeCommand = resolveNodeCommand(requestedNode);
          accessSync(
            path.resolve(runtimeRoot, nodeCommand),
            process.platform === "win32" ? constants.F_OK : constants.X_OK,
          );
        } catch {
          nodeCommand = resolveNodeCommand("node");
        }
        const nodePath = realpathSync(path.resolve(runtimeRoot, nodeCommand));
        return callApiInternal(prompt, context, options, {
          ...config,
          working_dir: runtimeRoot,
          cli_env: { ...config.cli_env, CODEX_MCP_NODE_PATH: nodePath },
          additional_directories: [
            ...(config.additional_directories ?? []),
            path.dirname(nodePath),
          ],
        });
      };
      return provider;
    });
    return (await this.provider).callApi(...args);
  }

  async cleanup() {
    if (this.provider) await (await this.provider).cleanup?.();
  }
}
