import { execFileSync } from "node:child_process";
import { accessSync, constants, realpathSync } from "node:fs";
import path from "node:path";
import type { ApiProvider, ProviderOptions } from "promptfoo";

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
    this.provider ??= import("promptfoo").then(({ loadApiProvider }) => {
      if (!process.env.TRIAGE_RUNTIME_ROOT) {
        throw new Error(
          "Run this evaluation through scripts/run-promptfoo.mts.",
        );
      }
      let requestedNode =
        this.config.cli_env?.CODEX_MCP_NODE_PATH ??
        process.env.CODEX_MCP_NODE_PATH ??
        process.execPath;
      const environment = { ...process.env, ...this.config.cli_env };
      try {
        accessSync(
          path.resolve(process.env.TRIAGE_RUNTIME_ROOT, requestedNode),
          process.platform === "win32" ? constants.F_OK : constants.X_OK,
        );
      } catch {
        requestedNode = "node";
      }
      const nodeCommand = /[/\\]/.test(requestedNode)
        ? requestedNode
        : execFileSync(
            process.platform === "win32"
              ? path.join(process.env.SystemRoot!, "System32", "where.exe")
              : "/bin/sh",
            process.platform === "win32"
              ? [requestedNode]
              : ["-c", 'command -v "$1"', "triage-node", requestedNode],
            {
              cwd: process.env.TRIAGE_RUNTIME_ROOT,
              env: environment,
              encoding: "utf8",
            },
          )
            .trim()
            .split(/\r?\n/)[0];
      const nodePath = realpathSync(
        path.resolve(process.env.TRIAGE_RUNTIME_ROOT, nodeCommand),
      );
      return loadApiProvider("openai:codex-sdk:gpt-5.5", {
        basePath: this.config.basePath,
        options: {
          ...this.options,
          config: {
            ...this.config,
            working_dir: process.env.TRIAGE_RUNTIME_ROOT,
            cli_env: { ...this.config.cli_env, CODEX_MCP_NODE_PATH: nodePath },
            additional_directories: [
              ...(this.config.additional_directories ?? []),
              path.dirname(nodePath),
            ],
          },
        },
      });
    });
    return (await this.provider).callApi(...args);
  }

  async cleanup() {
    if (this.provider) await (await this.provider).cleanup?.();
  }
}
