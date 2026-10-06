import { execFileSync } from "node:child_process";
import { accessSync, constants, realpathSync } from "node:fs";
import path from "node:path";
import nunjucks from "nunjucks";
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
    const { loadApiProvider } = await import("promptfoo");
    const config = { ...this.config, ...args[1]?.prompt?.config };
    const render = (value: string) =>
      args[1]?.vars &&
      !["1", "true", "yes", "yup", "yeppers"].includes(
        (process.env.PROMPTFOO_DISABLE_TEMPLATING ?? "").toLowerCase(),
      )
        ? nunjucks.renderString(value, args[1].vars)
        : value;
    if (!process.env.TRIAGE_RUNTIME_ROOT) {
      throw new Error("Run this evaluation through scripts/run-promptfoo.mts.");
    }
    let requestedNode =
      render(
        config.cli_env?.CODEX_MCP_NODE_PATH ??
          process.env.CODEX_MCP_NODE_PATH ??
          process.execPath,
      ) || process.execPath;
    const environment = {
      ...process.env,
      ...Object.fromEntries(
        Object.entries(config.cli_env ?? {}).map(([key, value]) => [
          key,
          render(String(value)),
        ]),
      ),
    };
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
    this.provider ??= loadApiProvider("openai:codex-sdk:gpt-5.5", {
      basePath: this.config.basePath,
      options: {
        ...this.options,
        config: {
          ...this.config,
          working_dir: process.env.TRIAGE_RUNTIME_ROOT,
        },
      },
    });
    return (await this.provider).callApi(
      args[0],
      {
        ...args[1],
        prompt: {
          raw: args[0],
          label: args[0],
          ...args[1]?.prompt,
          config: {
            ...args[1]?.prompt?.config,
            cli_env: { ...config.cli_env, CODEX_MCP_NODE_PATH: nodePath },
            additional_directories: [
              ...(config.additional_directories ?? []),
              path.dirname(nodePath),
            ],
          },
        },
      },
      args[2],
    );
  }

  async cleanup() {
    if (this.provider) await (await this.provider).cleanup?.();
  }
}
